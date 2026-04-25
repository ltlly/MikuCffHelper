"""基于"分发器识别 → 真实块前向模拟"的 CFF 去平坦化 pass。

设计参照：
  - Tim Blazytko 的支配树识别法 (synthesis.to/2021/03/03/flattening_detection.html)：
      flattening_score(D) = #{被 D 支配的块} / #{函数总块数}
      若存在被 D 支配的块跳回 D（back-edge），则 D 是 dispatcher 入口候选
      用作"这个函数是否被 CFF 混淆"的门控，避免对正常函数误识别状态机
  - CaDeCFF / FlowSight (2025) 的"真实块"语义：含外部副作用 (call / store /
    return) 的块为 OO Block；分发器内只做控制转移
  - Chisel (OOPSLA 2024) 的 CFE 形式化：去混淆 trace 是混淆 trace 的子序列，
    保留所有副作用，删去状态机内部状态写入与分发判断

算法 (静态版本)：
  1. 门控：用支配树法找 flattening_score ≥ 阈值且有 back-edge 的块。找不到
     就不动，这是非 CFF 函数
  2. 状态变量识别：dispatcher 入口及其后继中的常量比较左操作数变量；要求
     被赋予 ≥2 unique 常量值（过滤常量传播假阳性）
  3. 对每个 "state = const" SetVar：从该指令出发，在仅由 goto / 状态相关
     if / 状态 SetVar 组成的子图内做整型解释，直到落到一个真实块的入口
  4. 安全检查：目标必须是一个基本块的入口（不是块中段），且不在 dispatcher
     子图内
  5. 修补：把赋值替换成 [赋值副本; goto target]，副本保留以维持外部可见
     副作用集合

形式化等价性：
  令原 trace 为 T，去混淆后 trace 为 T'。
  - 真实块体未改 → 副作用 (call/store/return) 完全保留
  - 真实块之间的转移由整型模拟给出，与原状态机分发的具体执行结果一致
  - 状态写入仍在赋值副本中执行 → 状态变量在外部读取时数值正确
  - 删去的只是 dispatcher 内部的状态比较跳转 → T' 是 T 的子序列
  ∴ 对外可见副作用集合等价 (CFE 反向)

性能：
  - 单 pass 30s 时间预算
  - 整型解释器（无 z3，避免 z3 4.16 在某些表达式下的崩溃）
"""

import time
from typing import Dict, List, Optional, Set, Tuple

from binaryninja import (
    AnalysisContext,
    Function,
    ILSourceLocation,
    MediumLevelILBasicBlock,
    MediumLevelILConst,
    MediumLevelILFunction,
    MediumLevelILGoto,
    MediumLevelILIf,
    MediumLevelILInstruction,
    MediumLevelILLabel,
    MediumLevelILOperation,
    MediumLevelILSetVar,
    Variable,
)

from ...utils import log_error  # noqa: E402  (放底部以避免循环依赖)

_MAX_OUTER_ITERS = 6
_MAX_FORWARD_STEPS = 512
_TIME_BUDGET_SECONDS = 15.0
_FLATTENING_SCORE_THRESHOLD = 0.3
_MIN_BLOCKS_FOR_CFF = 5

_WIDTH_TO_MASK = {1: 0xFF, 2: 0xFFFF, 4: 0xFFFFFFFF, 8: 0xFFFFFFFFFFFFFFFF}


def _mask(width: int) -> int:
    return _WIDTH_TO_MASK.get(width, (1 << (width * 8)) - 1)


def _to_signed(value: int, width: int) -> int:
    bits = width * 8
    value &= (1 << bits) - 1
    if value & (1 << (bits - 1)):
        return value - (1 << bits)
    return value


# --------------------------------------------------------------------------
# 整型解释器
# --------------------------------------------------------------------------


def _eval(expr: MediumLevelILInstruction, env: Dict[Variable, int]) -> Optional[int]:
    op = expr.operation
    if op == MediumLevelILOperation.MLIL_CONST:
        return expr.constant & _mask(expr.size or 4)
    if op == MediumLevelILOperation.MLIL_CONST_PTR:
        return expr.constant & _mask(expr.size or 8)
    if op == MediumLevelILOperation.MLIL_VAR:
        v = env.get(expr.src)
        return None if v is None else v & _mask(expr.size or 4)
    if op == MediumLevelILOperation.MLIL_VAR_FIELD:
        if getattr(expr, "offset", 0) != 0:
            return None
        v = env.get(expr.src)
        return None if v is None else v & _mask(expr.size or 4)
    if op == MediumLevelILOperation.MLIL_ZX:
        v = _eval(expr.src, env)
        return v if v is None else v & _mask(expr.size or 4)
    if op == MediumLevelILOperation.MLIL_SX:
        v = _eval(expr.src, env)
        if v is None:
            return None
        return _to_signed(v, expr.src.size or 4) & _mask(expr.size or 4)
    if op == MediumLevelILOperation.MLIL_LOW_PART:
        v = _eval(expr.src, env)
        return v if v is None else v & _mask(expr.size or 4)
    if op == MediumLevelILOperation.MLIL_NEG:
        v = _eval(expr.src, env)
        return v if v is None else (-v) & _mask(expr.size or 4)
    if op == MediumLevelILOperation.MLIL_NOT:
        v = _eval(expr.src, env)
        return v if v is None else (~v) & _mask(expr.size or 4)
    if not (hasattr(expr, "left") and hasattr(expr, "right")):
        return None
    lv = _eval(expr.left, env)
    rv = _eval(expr.right, env)
    if lv is None or rv is None:
        return None
    width = expr.size or expr.left.size or 4
    m = _mask(width)
    if op == MediumLevelILOperation.MLIL_ADD:
        return (lv + rv) & m
    if op == MediumLevelILOperation.MLIL_SUB:
        return (lv - rv) & m
    if op == MediumLevelILOperation.MLIL_MUL:
        return (lv * rv) & m
    if op == MediumLevelILOperation.MLIL_AND:
        return (lv & rv) & m
    if op == MediumLevelILOperation.MLIL_OR:
        return (lv | rv) & m
    if op == MediumLevelILOperation.MLIL_XOR:
        return (lv ^ rv) & m
    if op == MediumLevelILOperation.MLIL_LSL:
        return (lv << (rv & 0x3F)) & m
    if op == MediumLevelILOperation.MLIL_LSR:
        return (lv & m) >> (rv & 0x3F)
    if op == MediumLevelILOperation.MLIL_ASR:
        signed = _to_signed(lv, width)
        return (signed >> (rv & 0x3F)) & m
    return None


def _eval_if(if_instr: MediumLevelILIf, env: Dict[Variable, int]) -> Optional[bool]:
    cond = if_instr.condition
    if not (hasattr(cond, "left") and hasattr(cond, "right")):
        return None
    lv = _eval(cond.left, env)
    rv = _eval(cond.right, env)
    if lv is None or rv is None:
        return None
    width = cond.left.size or 4
    m = _mask(width)
    lu = lv & m
    ru = rv & m
    op = cond.operation
    if op == MediumLevelILOperation.MLIL_CMP_E:
        return lu == ru
    if op == MediumLevelILOperation.MLIL_CMP_NE:
        return lu != ru
    if op == MediumLevelILOperation.MLIL_CMP_ULT:
        return lu < ru
    if op == MediumLevelILOperation.MLIL_CMP_ULE:
        return lu <= ru
    if op == MediumLevelILOperation.MLIL_CMP_UGT:
        return lu > ru
    if op == MediumLevelILOperation.MLIL_CMP_UGE:
        return lu >= ru
    ls = _to_signed(lu, width)
    rs = _to_signed(ru, width)
    if op == MediumLevelILOperation.MLIL_CMP_SLT:
        return ls < rs
    if op == MediumLevelILOperation.MLIL_CMP_SLE:
        return ls <= rs
    if op == MediumLevelILOperation.MLIL_CMP_SGT:
        return ls > rs
    if op == MediumLevelILOperation.MLIL_CMP_SGE:
        return ls >= rs
    return None


# --------------------------------------------------------------------------
# 1. 门控：CFF 检测（Blazytko 支配树法）
# --------------------------------------------------------------------------


def _detect_dispatcher_entry(
    mlil: MediumLevelILFunction,
) -> Optional[MediumLevelILBasicBlock]:
    """Blazytko 支配树法。O(N+E) 计算 dominator 子树大小，O(E) 查 back-edge。"""
    bbs = list(mlil.basic_blocks)
    n = len(bbs)
    if n < _MIN_BLOCKS_FOR_CFF:
        return None

    # 用 dominator_tree_children 计算每个块的 dominator 子树大小
    # 对每个块做一次 DFS 总共 O(N) 次访问，全函数 O(N²) worst case 但 dominator
    # 树扁平时远小于 N²
    subtree_size: Dict[int, int] = {}

    def _size(b: MediumLevelILBasicBlock) -> int:
        if b.start in subtree_size:
            return subtree_size[b.start]
        s = 1
        for c in b.dominator_tree_children:
            s += _size(c)
        subtree_size[b.start] = s
        return s

    # 反向映射：每个块支配多少节点
    for b in bbs:
        _size(b)

    # 检查每个块是否有 back-edge 自被它支配的块
    # 反向映射 start -> bb 以便快速判断"在子树里"
    bb_by_start: Dict[int, MediumLevelILBasicBlock] = {b.start: b for b in bbs}

    def _in_subtree(d: MediumLevelILBasicBlock, target: int) -> bool:
        # target 是否在 d 的 dominator 子树里 ⇔ d ∈ target_bb.dominators
        tb = bb_by_start.get(target)
        if tb is None:
            return False
        return d in tb.dominators

    best_score = 0.0
    best_bb: Optional[MediumLevelILBasicBlock] = None
    for d in bbs:
        size = subtree_size.get(d.start, 0)
        if size < 3:
            continue
        score = size / n
        if score < _FLATTENING_SCORE_THRESHOLD:
            continue
        # back-edge 检查：d 的所有 incoming_edges 中是否有源点在 d 的子树里
        has_back_edge = False
        for edge in d.incoming_edges:
            if _in_subtree(d, edge.source.start):
                has_back_edge = True
                break
        if not has_back_edge:
            continue
        if score > best_score:
            best_score = score
            best_bb = d
    return best_bb


# --------------------------------------------------------------------------
# 2. 状态变量识别
# --------------------------------------------------------------------------


def _collect_state_vars(
    mlil: MediumLevelILFunction,
    dispatcher_entry: MediumLevelILBasicBlock,
) -> Set[Variable]:
    """识别 dispatcher 中作为常量比较左操作数的变量。

    保持单变量级别的宽松过滤（unique 常量值 ≥ 2），让真实 CFF 内层状态
    机也能被识别。
    """
    candidates: Set[Variable] = set()
    visited: Set[int] = set()
    queue: List[MediumLevelILBasicBlock] = [dispatcher_entry]
    while queue:
        b = queue.pop(0)
        if b.start in visited:
            continue
        visited.add(b.start)
        if b.length == 0:
            continue
        last = mlil[b.end - 1]
        if isinstance(last, MediumLevelILIf):
            cond = last.condition
            if (
                hasattr(cond, "left")
                and hasattr(cond, "right")
                and isinstance(cond.right, MediumLevelILConst)
            ):
                left = cond.left
                if hasattr(left, "src") and isinstance(left.src, Variable):
                    candidates.add(left.src)
            for edge in b.outgoing_edges:
                queue.append(edge.target)
        elif isinstance(last, MediumLevelILGoto):
            tgt = mlil.get_basic_block_at(last.dest)
            if tgt is not None:
                queue.append(tgt)

    unique_vals: Dict[Variable, Set[int]] = {var: set() for var in candidates}
    for instr in mlil.instructions:
        if not isinstance(instr, MediumLevelILSetVar):
            continue
        if instr.dest not in candidates:
            continue
        if isinstance(instr.src, MediumLevelILConst):
            unique_vals[instr.dest].add(instr.src.constant & _mask(instr.size or 4))
    return {v for v, s in unique_vals.items() if len(s) >= 2}


def _function_looks_like_cff(
    mlil: MediumLevelILFunction,
    state_vars: Set[Variable],
) -> bool:
    """函数级 CFF 启发式过滤：避免 Rust match / C++ stdlib 小常量分发被
    误判为 OLLVM CFF (task #16 发现)。

    判据（必须 *同时* 满足）：
      1) 跨所有 state var 的 unique 常量值总数 ≥ 4 (OLLVM 通常多 case)
      2) 值域跨度 max - min ≥ 0x10000000 (OLLVM 状态值是 32-bit 随机；
         Rust SIMD 常量 0x8000_0000_0000_{0,1,3} 跨度只有 3；
         C++ 异常 0,1 跨度只有 1)

    单看平均值不够（Rust SIMD 常量平均也很大）；单看 unique 数也不够
    (有些函数有几个真大值)。两个一起能可靠区分 CFF。
    """
    if not state_vars:
        return False
    all_vals: Set[int] = set()
    for var in state_vars:
        for instr in mlil.instructions:
            if (
                isinstance(instr, MediumLevelILSetVar)
                and instr.dest == var
                and isinstance(instr.src, MediumLevelILConst)
            ):
                all_vals.add(instr.src.constant & _mask(instr.size or 4))
    if len(all_vals) < 4:
        return False
    spread = max(all_vals) - min(all_vals)
    return spread >= 0x10000000


# --------------------------------------------------------------------------
# 3. 前向模拟 (state-only 子图内)
# --------------------------------------------------------------------------


# --------------------------------------------------------------------------
# 副作用集合：用于 dispatcher 子图识别 + patch 前后等价性验证
# --------------------------------------------------------------------------

# 有外部副作用的 MLIL 操作。一个块若含其中任何一个，就一定不是 dispatcher 块。
# 参照 Chisel OOPSLA'24 的 CFE 形式化：dispatcher 不能引入新的可见副作用。
_SIDE_EFFECT_OPS: Set = {
    MediumLevelILOperation.MLIL_CALL,
    MediumLevelILOperation.MLIL_CALL_UNTYPED,
    MediumLevelILOperation.MLIL_CALL_SSA,
    MediumLevelILOperation.MLIL_CALL_UNTYPED_SSA,
    MediumLevelILOperation.MLIL_TAILCALL,
    MediumLevelILOperation.MLIL_TAILCALL_UNTYPED,
    MediumLevelILOperation.MLIL_TAILCALL_SSA,
    MediumLevelILOperation.MLIL_TAILCALL_UNTYPED_SSA,
    MediumLevelILOperation.MLIL_SYSCALL,
    MediumLevelILOperation.MLIL_SYSCALL_UNTYPED,
    MediumLevelILOperation.MLIL_SYSCALL_SSA,
    MediumLevelILOperation.MLIL_SYSCALL_UNTYPED_SSA,
    MediumLevelILOperation.MLIL_STORE,
    MediumLevelILOperation.MLIL_STORE_SSA,
    MediumLevelILOperation.MLIL_STORE_STRUCT,
    MediumLevelILOperation.MLIL_STORE_STRUCT_SSA,
    MediumLevelILOperation.MLIL_RET,
    MediumLevelILOperation.MLIL_RET_HINT,
    MediumLevelILOperation.MLIL_NORET,
    MediumLevelILOperation.MLIL_TRAP,
    MediumLevelILOperation.MLIL_BP,
    MediumLevelILOperation.MLIL_INTRINSIC,
    MediumLevelILOperation.MLIL_INTRINSIC_SSA,
}


def _collect_side_effect_signatures(mlil: MediumLevelILFunction) -> Set[Tuple[int, int]]:
    """收集 MLIL 中所有副作用指令的 (op_id, address) 签名。

    递归遍历每条顶层指令的子表达式：因为 call 经常作为 SetVar 的 src 出现
    （`var = func()`），不能只扫描顶层。

    用于 patch 前后的等价性验证：deflate 不应丢失任何副作用。
    """
    sigs: Set[Tuple[int, int]] = set()

    def visitor(operand_name, expr, type_name, parent):
        if isinstance(expr, MediumLevelILInstruction) and expr.operation in _SIDE_EFFECT_OPS:
            sigs.add((int(expr.operation), expr.address))

    for top in mlil.instructions:
        try:
            list(top.traverse(visitor))
        except Exception:
            # traverse 在某些 BN 版本上可能 raise；退化为只扫顶层
            if top.operation in _SIDE_EFFECT_OPS:
                sigs.add((int(top.operation), top.address))
    return sigs


def _verify_no_side_effect_loss(
    before: Set[Tuple[int, int]],
    after: Set[Tuple[int, int]],
    function_name: str,
) -> bool:
    """验证 patch 后副作用集合 ⊇ patch 前。

    dispatcher 内部的状态写入不属于副作用集合（不在 _SIDE_EFFECT_OPS 中），
    所以 deflate 删除/重排状态写入不会减少签名集。
    若发现丢失，返回 False 并 log，但不能回滚（MLIL 已修改）。
    """
    lost = before - after
    if not lost:
        return True
    log_error(
        f"[deflate verifier] Function {function_name}: lost {len(lost)} "
        f"side-effect signatures after patch! Logical equivalence broken."
    )
    for op_id, addr in sorted(lost, key=lambda x: x[1])[:10]:
        log_error(f"  lost: op_id={op_id} addr={hex(addr)}")
    return False


# --------------------------------------------------------------------------
# 真实块转移图重建：synthesis 风格的 fallback / 诊断
# --------------------------------------------------------------------------


def build_real_block_transition_graph(
    mlil: MediumLevelILFunction,
) -> Dict[int, Set[int]]:
    """重建真实块之间的直接转移图 (synthesis 风格)。

    对每个真实块 R，枚举它内部所有 "state = const" SetVar，对每个常量值
    forward_resolve 找出对应的下一个真实块 R'，把 R → R' 加入图。

    这不会修改 MLIL；它给出的是 *deflate 想表达的真实控制流骨架*，可用作：
      - 失败诊断：哪些真实块之间的转移没被 patch
      - 合成 fallback：未来用这个骨架做 program synthesis 直接生成新函数
        (类似 Chisel 的 CFS - Control-Flow Skeleton)

    返回 {real_block_start: set(reachable_real_block_starts)}
    """
    dispatcher_entry = _detect_dispatcher_entry(mlil)
    if dispatcher_entry is None:
        return {}
    state_vars = _collect_state_vars(mlil, dispatcher_entry)
    if not state_vars:
        return {}
    dispatcher_blocks = _identify_dispatcher_subgraph(
        mlil, dispatcher_entry, state_vars
    )
    if not dispatcher_blocks:
        return {}

    graph: Dict[int, Set[int]] = {}
    real_blocks = [
        b for b in mlil.basic_blocks if b.start not in dispatcher_blocks
    ]

    for R in real_blocks:
        succ_real_blocks: Set[int] = set()
        # 直接边 (R 直接 goto/if 到另一个真实块，没经过 dispatcher)
        for edge in R.outgoing_edges:
            if edge.target.start not in dispatcher_blocks:
                succ_real_blocks.add(edge.target.start)
        # 通过 dispatcher 的间接边
        for idx in range(R.start, R.end):
            instr = mlil[idx]
            if (
                isinstance(instr, MediumLevelILSetVar)
                and instr.dest in state_vars
                and isinstance(instr.src, MediumLevelILConst)
            ):
                tgt = _forward_resolve(mlil, instr, state_vars, dispatcher_blocks)
                if tgt is not None:
                    succ_real_blocks.add(tgt)
        if succ_real_blocks:
            graph[R.start] = succ_real_blocks
    return graph


def _tarjan_scc(adj: Dict[int, List[int]]) -> List[List[int]]:
    """迭代版 Tarjan SCC。避免大函数 (>1000 块) 的递归栈溢出。

    输入：邻接表 adj[node_id] = [successor_id, ...]
    输出：SCC 列表，每个 SCC 是 node_id 列表
    """
    index_counter = [0]
    stack: List[int] = []
    lowlinks: Dict[int, int] = {}
    index_map: Dict[int, int] = {}
    on_stack: Dict[int, bool] = {}
    sccs: List[List[int]] = []

    for root in list(adj.keys()):
        if root in index_map:
            continue
        # 显式栈帧：(node, child_iterator)
        work: List[Tuple[int, "iter"]] = [(root, iter(adj.get(root, [])))]
        index_map[root] = index_counter[0]
        lowlinks[root] = index_counter[0]
        index_counter[0] += 1
        stack.append(root)
        on_stack[root] = True

        while work:
            u, it = work[-1]
            advanced = False
            for w in it:
                if w not in adj:
                    continue
                if w not in index_map:
                    index_map[w] = index_counter[0]
                    lowlinks[w] = index_counter[0]
                    index_counter[0] += 1
                    stack.append(w)
                    on_stack[w] = True
                    work.append((w, iter(adj.get(w, []))))
                    advanced = True
                    break
                if on_stack.get(w, False):
                    lowlinks[u] = min(lowlinks[u], index_map[w])
            if not advanced:
                # u 的所有后继处理完毕
                work.pop()
                if lowlinks[u] == index_map[u]:
                    scc: List[int] = []
                    while True:
                        w = stack.pop()
                        on_stack[w] = False
                        scc.append(w)
                        if w == u:
                            break
                    sccs.append(scc)
                if work:
                    parent = work[-1][0]
                    lowlinks[parent] = min(lowlinks[parent], lowlinks[u])

    return sccs


def _block_is_pure_dispatcher(
    mlil: MediumLevelILFunction,
    b: MediumLevelILBasicBlock,
    state_vars: Set[Variable],
) -> bool:
    """块的副作用是否仅限于状态变量。

    判据 (CFE 形式化)：
      - 不含任何外部副作用指令 (call / store / ret / intrinsic / trap)
      - 所有 SetVar 的目标必须是状态变量
      - if 的条件 *允许读非状态变量*：因为条件求值不产生副作用，
        且 if 的两个分支都还在 dispatcher SCC 内（由 SCC 约束保证）

    比之前的 _is_state_only_instr 更严格（显式禁止副作用 op）也更宽松（允许
    if 读非状态变量），更贴近"dispatcher 不引入新可见副作用"的本质。
    """
    for idx in range(b.start, b.end):
        instr = mlil[idx]
        op = instr.operation
        if op in _SIDE_EFFECT_OPS:
            return False
        if isinstance(instr, MediumLevelILSetVar):
            if instr.dest not in state_vars:
                return False
            continue
        # MLIL_GOTO / MLIL_IF / 等等，没有副作用，OK
    return True


def _identify_dispatcher_subgraph(
    mlil: MediumLevelILFunction,
    dispatcher_entry: MediumLevelILBasicBlock,
    state_vars: Set[Variable],
) -> Set[int]:
    """形式化识别 dispatcher 子图：含 dispatcher_entry 的 SCC ∩ pure-dispatcher 块。

    返回 block.start 集合。
    """
    bbs = list(mlil.basic_blocks)
    bb_by_start = {b.start: b for b in bbs}

    # 构建邻接表
    adj: Dict[int, List[int]] = {}
    for b in bbs:
        adj[b.start] = [e.target.start for e in b.outgoing_edges]

    sccs = _tarjan_scc(adj)

    # 找含 dispatcher_entry 的 SCC
    dispatcher_scc: Optional[Set[int]] = None
    for scc in sccs:
        if dispatcher_entry.start in scc:
            dispatcher_scc = set(scc)
            break
    if dispatcher_scc is None or len(dispatcher_scc) < 2:
        return set()

    # SCC ∩ pure-dispatcher 块
    result: Set[int] = set()
    for start in dispatcher_scc:
        b = bb_by_start.get(start)
        if b is None:
            continue
        if _block_is_pure_dispatcher(mlil, b, state_vars):
            result.add(start)
    return result


def _seed_env_from_block(
    mlil: MediumLevelILFunction,
    define_instr: MediumLevelILSetVar,
    state_vars: Set[Variable],
) -> Dict[Variable, int]:
    """组装前向模拟的初始环境：当前 define 的常量值 + 同 block 内、当前指令
    之前对其它状态变量的常量赋值。

    这处理 task #8 的"多状态变量交互"：dispatcher 可能同时检查多个状态变量
    （例如 if (state1 == X && state2 == Y)），如果只 seed 一个变量，其它
    变量未知会导致 if 无法决断。
    """
    env: Dict[Variable, int] = {}
    bb = mlil.get_basic_block_at(define_instr.instr_index)
    if bb is not None:
        for idx in range(bb.start, define_instr.instr_index):
            instr = mlil[idx]
            if (
                isinstance(instr, MediumLevelILSetVar)
                and instr.dest in state_vars
                and isinstance(instr.src, MediumLevelILConst)
            ):
                env[instr.dest] = instr.src.constant & _mask(instr.size or 4)
    env[define_instr.dest] = define_instr.src.constant & _mask(
        define_instr.size or 4
    )
    return env


def _walk_block_tail(
    mlil: MediumLevelILFunction,
    bb: MediumLevelILBasicBlock,
    after_idx: int,
    env: Dict[Variable, int],
    state_vars: Set[Variable],
) -> Optional[int]:
    """从同一个 block 内的 after_idx+1 开始，往后走到块的终结指令，返回控制
    流去向的下一个 instr_index。

    沿途允许遇到：
      - 状态变量的 SetVar (更新 env)
      - 终结的 goto / if (返回去向)
    禁止遇到：
      - 非状态 SetVar / call / store / 其它有副作用的指令（说明 define 不在
        块尾，简单 patch 会漏掉这些副作用）
    """
    current = after_idx + 1
    while current < bb.end:
        instr = mlil[current]
        if isinstance(instr, MediumLevelILGoto):
            return instr.dest
        if isinstance(instr, MediumLevelILIf):
            branch = _eval_if(instr, env)
            if branch is None:
                return None
            return instr.true if branch else instr.false
        if isinstance(instr, MediumLevelILSetVar):
            if instr.dest not in state_vars:
                return None  # 真实赋值，不能跳过
            v = _eval(instr.src, env)
            if v is None:
                env.pop(instr.dest, None)
            else:
                env[instr.dest] = v & _mask(instr.size or 4)
            current += 1
            continue
        return None  # call/store/...
    return None


def _walk_dispatcher_block(
    mlil: MediumLevelILFunction,
    bb: MediumLevelILBasicBlock,
    env: Dict[Variable, int],
    state_vars: Set[Variable],
) -> Optional[int]:
    """走完一个 dispatcher 块，返回它的下一个 instr_index 去向。
    dispatcher 块内只可能有 goto / 状态相关 if / 状态 SetVar (由 SCC 副作用
    筛选保证)。
    """
    current = bb.start
    while current < bb.end:
        instr = mlil[current]
        if isinstance(instr, MediumLevelILGoto):
            return instr.dest
        if isinstance(instr, MediumLevelILIf):
            branch = _eval_if(instr, env)
            if branch is None:
                return None
            return instr.true if branch else instr.false
        if isinstance(instr, MediumLevelILSetVar):
            v = _eval(instr.src, env)
            if v is None:
                env.pop(instr.dest, None)
            else:
                env[instr.dest] = v & _mask(instr.size or 4)
            current += 1
            continue
        return None
    return None


def _forward_resolve(
    mlil: MediumLevelILFunction,
    define_instr: MediumLevelILSetVar,
    state_vars: Set[Variable],
    dispatcher_blocks: Set[int],
) -> Optional[int]:
    """从 state SetVar 出发，先走完 define 所在块的尾巴（必须是 state-only 的
    尾），进入 dispatcher 子图后逐 *基本块* 模拟，直到落到一个真实块入口。

    步骤：
      1. seed env (含 define 常量 + 同 block 内之前对其它 state var 的常量赋值)
      2. _walk_block_tail：走完 define 所在块剩余部分，返回下一个 instr_index
      3. 进入循环：判断该 instr_index 所在块。若是真实块 → 它就是 target。
         若是 dispatcher 块 → _walk_dispatcher_block 走完，再进下一轮。

    安全约束：target 必须是 bb.start（落到块入口而非块中段）。
    """
    if not isinstance(define_instr.src, MediumLevelILConst):
        return None
    env = _seed_env_from_block(mlil, define_instr, state_vars)

    define_bb = mlil.get_basic_block_at(define_instr.instr_index)
    if define_bb is None:
        return None

    # Step 1: 走完 define 所在块的尾巴
    current = _walk_block_tail(
        mlil, define_bb, define_instr.instr_index, env, state_vars
    )
    if current is None:
        return None

    # Step 2: 在 dispatcher 子图内逐块模拟
    visited_blocks: Set[int] = {define_bb.start}
    for _ in range(_MAX_FORWARD_STEPS):
        bb = mlil.get_basic_block_at(current)
        if bb is None:
            return None
        # 必须落到块入口
        if current != bb.start:
            return None
        if bb.start in visited_blocks:
            return None  # 闭环
        visited_blocks.add(bb.start)

        if bb.start not in dispatcher_blocks:
            # 到达真实块入口
            return current

        # dispatcher 块：走完它
        nxt = _walk_dispatcher_block(mlil, bb, env, state_vars)
        if nxt is None:
            return None
        current = nxt

    return None


# --------------------------------------------------------------------------
# 主 pass
# --------------------------------------------------------------------------


def pass_deflate_hard(analysis_context: AnalysisContext) -> None:
    function: Function = analysis_context.function
    mlil = function.mlil
    if mlil is None:
        return

    # patch 前快照外部副作用签名集合，pass 结束后对比验证等价性
    side_effects_before = _collect_side_effect_signatures(mlil)
    function_name = function.name

    deadline = time.time() + _TIME_BUDGET_SECONDS

    for _ in range(_MAX_OUTER_ITERS):
        if time.time() > deadline:
            break

        # 1. 门控：函数是 CFF 吗？(Blazytko 支配树法)
        dispatcher_entry = _detect_dispatcher_entry(mlil)
        if dispatcher_entry is None:
            break

        # 2. 状态变量识别
        state_vars = _collect_state_vars(mlil, dispatcher_entry)
        if not state_vars:
            break

        # 2.5 函数级 CFF 启发式：避免 Rust match / C++ stdlib 等小常量分发
        # 被误判为 OLLVM CFF (task #16 发现的假阳性)
        if not _function_looks_like_cff(mlil, state_vars):
            break

        # 3. 形式化 dispatcher 子图：含 dispatcher_entry 的 SCC ∩ pure-dispatcher 块
        dispatcher_blocks = _identify_dispatcher_subgraph(
            mlil, dispatcher_entry, state_vars
        )
        if not dispatcher_blocks:
            break

        # 4. 收集所有 state SetVar (= const)
        patches: List[Tuple[MediumLevelILSetVar, int]] = []
        for instr in mlil.instructions:
            if time.time() > deadline:
                break
            if (
                not isinstance(instr, MediumLevelILSetVar)
                or instr.dest not in state_vars
                or not isinstance(instr.src, MediumLevelILConst)
            ):
                continue
            target = _forward_resolve(mlil, instr, state_vars, dispatcher_blocks)
            if target is None or target == instr.instr_index:
                continue
            patches.append((instr, target))

        if not patches:
            break

        # 4. 修补：相同 (state_var, value, target) 的 patch 共享同一个 mini-block
        #    避免每个 define 都生成独立的 [copy + goto] 块，缓解 mini-block
        #    膨胀（task #15 在 sub_412bec 76→118 上观察到的问题）
        mini_block_cache: Dict[Tuple[int, int, int], "MediumLevelILLabel"] = {}
        for define, target_idx in patches:
            try:
                # 缓存键：(state_var.identifier, const_value, target_idx)
                # 同 key 共享一个 mini-block 入口标签
                key = (
                    define.dest.identifier,
                    define.src.constant & _mask(define.size or 4),
                    target_idx,
                )
                cached_label = mini_block_cache.get(key)
                if cached_label is None:
                    target_label = MediumLevelILLabel()
                    target_label.operand = target_idx
                    new_block_label = MediumLevelILLabel()
                    mlil.mark_label(new_block_label)
                    mlil.append(
                        mlil.copy_expr(define),
                        ILSourceLocation.from_instruction(define),
                    )
                    mlil.append(
                        mlil.goto(
                            target_label,
                            ILSourceLocation.from_instruction(define),
                        )
                    )
                    cached_label = new_block_label
                    mini_block_cache[key] = cached_label
                mlil.replace_expr(
                    define.expr_index,
                    mlil.goto(
                        cached_label,
                        ILSourceLocation.from_instruction(define),
                    ),
                )
            except Exception:
                continue

        mlil.finalize()
        mlil.generate_ssa_form()

    mlil.finalize()
    mlil.generate_ssa_form()

    # 等价性自动验证：patch 后副作用签名集合应仍 ⊇ patch 前
    side_effects_after = _collect_side_effect_signatures(mlil)
    _verify_no_side_effect_loss(side_effects_before, side_effects_after, function_name)
