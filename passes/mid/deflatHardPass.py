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
    MediumLevelILVar,
    Variable,
    VariableSourceType,
)

from ...utils import log_error, log_info  # noqa: E402  (放底部以避免循环依赖)
from ...utils.cff_core import (  # noqa: E402
    detect_flattening_candidate as _detect_cff_candidate_linear,
)
from ...utils.state_machine import StateMachine  # noqa: E402

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


_CMP_OPS = {
    MediumLevelILOperation.MLIL_CMP_E,
    MediumLevelILOperation.MLIL_CMP_NE,
    MediumLevelILOperation.MLIL_CMP_ULT,
    MediumLevelILOperation.MLIL_CMP_ULE,
    MediumLevelILOperation.MLIL_CMP_UGT,
    MediumLevelILOperation.MLIL_CMP_UGE,
    MediumLevelILOperation.MLIL_CMP_SLT,
    MediumLevelILOperation.MLIL_CMP_SLE,
    MediumLevelILOperation.MLIL_CMP_SGT,
    MediumLevelILOperation.MLIL_CMP_SGE,
}


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
    if op in _CMP_OPS:
        cmp_val = _eval_cmp(op, lv, rv, width)
        return None if cmp_val is None else cmp_val & m
    return None


def _eval_cmp(op: MediumLevelILOperation, lv: int, rv: int, width: int) -> Optional[int]:
    """比较运算：返回 0/1（掩码到 width）。_eval 与 _eval_if 共用。"""
    m = _mask(width)
    lu = lv & m
    ru = rv & m
    if op == MediumLevelILOperation.MLIL_CMP_E:
        return int(lu == ru)
    if op == MediumLevelILOperation.MLIL_CMP_NE:
        return int(lu != ru)
    if op == MediumLevelILOperation.MLIL_CMP_ULT:
        return int(lu < ru)
    if op == MediumLevelILOperation.MLIL_CMP_ULE:
        return int(lu <= ru)
    if op == MediumLevelILOperation.MLIL_CMP_UGT:
        return int(lu > ru)
    if op == MediumLevelILOperation.MLIL_CMP_UGE:
        return int(lu >= ru)
    ls = _to_signed(lu, width)
    rs = _to_signed(ru, width)
    if op == MediumLevelILOperation.MLIL_CMP_SLT:
        return int(ls < rs)
    if op == MediumLevelILOperation.MLIL_CMP_SLE:
        return int(ls <= rs)
    if op == MediumLevelILOperation.MLIL_CMP_SGT:
        return int(ls > rs)
    if op == MediumLevelILOperation.MLIL_CMP_SGE:
        return int(ls >= rs)
    return None


def _eval_if(if_instr: MediumLevelILIf, env: Dict[Variable, int]) -> Optional[bool]:
    cond = if_instr.condition
    if not (hasattr(cond, "left") and hasattr(cond, "right")):
        # x86/64 BN 常把比较物化成 `cond:N = a == b`，if 的条件是
        # MLIL_VAR(cond:N) 而不是 cmp 表达式本身。此时直接求 cond 值。
        v = _eval(cond, env)
        return None if v is None else bool(v & _mask(cond.size or 4))
    lv = _eval(cond.left, env)
    rv = _eval(cond.right, env)
    if lv is None or rv is None:
        return None
    width = cond.left.size or 4
    val = _eval_cmp(cond.operation, lv, rv, width)
    return None if val is None else bool(val)


# --------------------------------------------------------------------------
# 1. 门控：CFF 检测（Blazytko 支配树法）
# --------------------------------------------------------------------------


def _detect_dispatcher_entry(
    mlil: MediumLevelILFunction,
    exclude: Optional[Set[int]] = None,
    threshold: Optional[float] = None,
) -> Optional[MediumLevelILBasicBlock]:
    """Blazytko 支配树法（线性实现）。

    subtree 判定使用 utils.cff_core.DominatorInfo 的 DFS interval，把
    ``d in bb.dominators`` 的列表成员判断替换为 O(1)；整体 O(V+E)。

    threshold 缺省 _FLATTENING_SCORE_THRESHOLD (0.3，严格门控非 CFF 函数)。
    嵌套 dispatcher 在外层 case body 内，支配子树相对函数总块数小，调用方
    可以在 iter 2+ 用更低阈值 (例如 0.1) 拾起内层 dispatcher。
    """
    eff_threshold = (
        _FLATTENING_SCORE_THRESHOLD if threshold is None else threshold
    )
    return _detect_cff_candidate_linear(
        mlil,
        exclude=exclude,
        threshold=eff_threshold,
        min_blocks=_MIN_BLOCKS_FOR_CFF,
        min_subtree_blocks=3,
    )


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
    """函数级 CFF 启发式：一遍扫描预计算每个变量的 const 值集。

    旧实现对每个 state var 重扫全部指令 O(S×I)；这里改为 O(I)。
    """
    if not state_vars:
        return False
    values_by_var: Dict[int, Set[int]] = {}
    for instr in mlil.instructions:
        if (
            isinstance(instr, MediumLevelILSetVar)
            and isinstance(instr.src, MediumLevelILConst)
        ):
            values_by_var.setdefault(instr.dest.identifier, set()).add(
                instr.src.constant & _mask(instr.size or 4)
            )
    all_vals: Set[int] = set()
    for var in state_vars:
        all_vals.update(values_by_var.get(var.identifier, set()))
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


def _collect_side_effect_signatures_semantic(
    mlil: MediumLevelILFunction,
) -> "Counter":
    """按语义收集副作用签名（地址无关的 multiset）。

    pass_clear / jump_to 重写会移动指令地址，按 (op,address) 比对会把
    「同一条 call/store 被复制或搬移」误报为丢失。这里：
    - call 类操作保留 callee 常量地址；
    - store / ret / trap 等只计数 op。
    """
    from collections import Counter

    sigs: Counter = Counter()

    def visitor(operand_name, expr, type_name, parent):
        if not isinstance(expr, MediumLevelILInstruction):
            return
        if expr.operation not in _SIDE_EFFECT_OPS:
            return
        target = None
        try:
            dest = getattr(expr, "dest", None)
            if dest is not None and hasattr(dest, "constant"):
                target = dest.constant
        except Exception:
            pass
        key = (int(expr.operation), target) if target is not None else (int(expr.operation),)
        sigs[key] += 1

    for top in mlil.instructions:
        try:
            list(top.traverse(visitor))
        except Exception:
            if top.operation in _SIDE_EFFECT_OPS:
                sigs[(int(top.operation),)] += 1
    return sigs


def _verify_no_side_effect_loss_semantic(
    before,
    after,
    function_name: str,
) -> bool:
    """语义签名 multiset 比对：after 中每类副作用数量必须 ≥ before。"""
    missing = []
    for key, count in before.items():
        if after.get(key, 0) < count:
            missing.append((key, count, after.get(key, 0)))
    if not missing:
        return True
    log_error(
        f"[deflate verifier] Function {function_name}: semantic side-effect "
        f"loss {len(missing)} kinds!"
    )
    for key, b, a in missing[:10]:
        log_error(f"  lost: {key} before={b} after={a}")
    return False


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


def _is_compiler_temp(var: Variable) -> bool:
    """BN 物化比较/中间值产生的临时/寄存器/flag 变量。

    path replay 下这些写入会被复制进 mini-block，因此把含它们的块纳入
    dispatcher 不再丢语义；只有可回放的写入才允许放宽。
    """
    name = getattr(var, "name", "") or ""
    if name.startswith("temp") or name.startswith("cond"):
        return True
    try:
        st = var.source_type
        return st in (
            VariableSourceType.RegisterVariableSourceType,
            VariableSourceType.FlagVariableSourceType,
        )
    except Exception:
        return False


def _block_is_pure_dispatcher(
    mlil: MediumLevelILFunction,
    b: MediumLevelILBasicBlock,
    state_vars: Set[Variable],
    dead_vars: Optional[Set[int]] = None,
    allow_compiler_temps: bool = False,
) -> bool:
    """块的副作用是否仅限于「可回放」的 SetVar。

    dead_vars / allow_compiler_temps 都只在调用方启用 path replay 时传
    True/集合：这些写入会被 mini-block 原样回放，所以允许放进 dispatcher
    子图不会改变语义。其它调用方（synthesize 等）不传，保持旧严格行为。
    """
    for idx in range(b.start, b.end):
        instr = mlil[idx]
        op = instr.operation
        if op in _SIDE_EFFECT_OPS:
            return False
        if isinstance(instr, MediumLevelILSetVar):
            if instr.dest in state_vars:
                continue
            if allow_compiler_temps and (
                _is_compiler_temp(instr.dest)
                or (dead_vars is not None and instr.dest.identifier in dead_vars)
            ):
                continue
            return False
        # MLIL_GOTO / MLIL_IF / 等等，没有副作用，OK
    return True


def _identify_dispatcher_subgraph(
    mlil: MediumLevelILFunction,
    dispatcher_entry: MediumLevelILBasicBlock,
    state_vars: Set[Variable],
    dead_vars: Optional[Set[int]] = None,
    allow_compiler_temps: bool = False,
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
        if _block_is_pure_dispatcher(
            mlil, b, state_vars, dead_vars, allow_compiler_temps
        ):
            result.add(start)
    # 不变量：dispatcher_entry 一定属于 dispatcher (按定义)。即使它的内容
    # 没通过 _block_is_pure_dispatcher (例如包含 BN 拆出来的 var-rename
    # SetVar)，也强制纳入。否则 forward_resolve 会把它当成"真实块"返回，
    # synthesize_switch 上观察到 sub_40db18 所有 transitions 都目标=
    # dispatcher_entry 的退化情况。
    result.add(dispatcher_entry.start)
    return result


def _collect_dead_var_ids(mlil: MediumLevelILFunction) -> Set[int]:
    """收集「写后从不读」的变量 id。

    define 块尾的非状态 SetVar 若属于该集合，跳过它在语义上完全等价
    （值没有任何读者），因此 _walk_block_tail 可以安全跨过它。注意只允许
    跳过 *死* store，有读者的局部 store 仍严格拒绝 —— 历史上无条件放宽
    曾在 sub_40831c 造成 SE_LOST=11。
    """
    read_ids: Set[int] = set()
    written_ids: Set[int] = set()
    for instr in mlil.instructions:
        for var in getattr(instr, "vars_read", []) or []:
            read_ids.add(var.identifier)
        if isinstance(instr, MediumLevelILSetVar):
            written_ids.add(instr.dest.identifier)
    return written_ids - read_ids


def _seed_env_from_block(
    mlil: MediumLevelILFunction,
    define_instr: MediumLevelILSetVar,
    state_vars: Set[Variable],
    dispatcher_blocks: Optional[Set[int]] = None,
) -> Dict[Variable, int]:
    """组装前向模拟的初始环境：当前 define 的常量值 + 同 block 内、当前指令
    之前对其它状态变量的常量赋值。

    多状态变量交互 (task #8)：dispatcher 可能同时检查多个状态变量
    （例如 if (state1 == X && state2 == Y)），如果只 seed 一个变量，其它
    变量未知会导致 if 无法决断。

    曾尝试 alias 同值 seed (sub_45985c 类 dispatcher 内 `x7_1 = x6_6` 拷贝
    在 forward 路径绕过 rename 块时导致 env 没 alias 值，cmp 无法评估)。
    多轮安全约束试验 (alias 单定义 / alias 在 dispatcher_blocks 内 / 等)
    都不能避免 sub_40831c 类 SE_LOST，回退保正确性 — alias-aware
    forward_resolve 留作后续研究。

    dispatcher_blocks 参数保留以兼容外部调用，当前实现不使用。
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


def _filter_replay_indices(
    mlil: MediumLevelILFunction,
    replay: Tuple[int, ...],
    state_vars: Set[Variable],
    skipped: Tuple[int, ...],
) -> Tuple[int, ...]:
    """按数据流裁剪 path replay，只保留「跳过路径外仍被读取」的写入。

    等价性论证：patch 后不会再执行的指令集合是 skipped（tail + dispatcher
    路径上的 SetVar/goto/if）。只有被 skipped 之外指令读取的变量才需要由
    mini-block 保持其值；从这些变量出发，反向传播 src 依赖，保留 replay
    中对应写入。状态变量写入一律保留（视为外部可见）。
    """
    skipped_set = set(skipped)
    needed_ids: Set[int] = set()
    # skipped 之外被读取的变量 → 必须在 mini-block 中保持其值
    for instr in mlil.instructions:
        if instr.instr_index in skipped_set:
            continue
        for var in getattr(instr, "vars_read", []) or []:
            needed_ids.add(var.identifier)
        if isinstance(instr, MediumLevelILSetVar) and instr.dest in state_vars:
            needed_ids.add(instr.dest.identifier)
    # 状态变量写入总是保留（外部可观察）
    for idx in replay:
        instr = mlil[idx]
        if isinstance(instr, MediumLevelILSetVar) and instr.dest in state_vars:
            needed_ids.add(instr.dest.identifier)

    # 反向依赖传播：需要 dest 的指令，其 src 依赖的变量若由 replay 内
    # 前面的指令定义，也要保留那些定义。
    changed = True
    while changed:
        changed = False
        for idx in replay:
            instr = mlil[idx]
            if not isinstance(instr, MediumLevelILSetVar):
                continue
            if instr.dest.identifier not in needed_ids:
                continue
            for var in getattr(instr, "vars_read", []) or []:
                if var.identifier not in needed_ids:
                    needed_ids.add(var.identifier)
                    changed = True
    return tuple(
        idx
        for idx in replay
        if isinstance(mlil[idx], MediumLevelILSetVar)
        and mlil[idx].dest.identifier in needed_ids
    )
def _walk_block_tail(
    mlil: MediumLevelILFunction,
    bb: MediumLevelILBasicBlock,
    after_idx: int,
    env: Dict[Variable, int],
    state_vars: Set[Variable],
    dead_vars: Optional[Set[int]] = None,
    replay: Optional[List[int]] = None,
    skipped: Optional[List[int]] = None,
) -> Optional[int]:
    """从同一个 block 内的 after_idx+1 开始，往后走到块的终结指令，返回控制
    流去向的下一个 instr_index。

    沿途允许遇到：
      - 状态变量的 SetVar (更新 env)
      - 终结的 goto / if (返回去向)
      - 可回放的非状态 SetVar（编译器临时 / 写后无读者），此时指令序号会
        追加到 replay，由 mini-block 原样重放，保证语义不丢
    禁止遇到：
      - 有读者且非编译器临时的 SetVar / call / store / 其它副作用指令

    skipped 收集 patch 后不再执行的所有指令序号（含 goto/if），供 replay
    数据流裁剪判断哪些变量仍会被路径外代码读取。
    """
    current = after_idx + 1
    while current < bb.end:
        instr = mlil[current]
        if skipped is not None:
            skipped.append(instr.instr_index)
        if isinstance(instr, MediumLevelILGoto):
            return instr.dest
        if isinstance(instr, MediumLevelILIf):
            branch = _eval_if(instr, env)
            if branch is None:
                return None
            return instr.true if branch else instr.false
        if isinstance(instr, MediumLevelILSetVar):
            if instr.dest not in state_vars:
                if replay is not None and (
                    _is_compiler_temp(instr.dest)
                    or (dead_vars is not None and instr.dest.identifier in dead_vars)
                ):
                    replay.append(instr.instr_index)
                    current += 1
                    continue
                return None  # 有读者且不能回放的赋值，不能跳过
            if replay is not None:
                replay.append(instr.instr_index)
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
    replay: Optional[List[int]] = None,
    skipped: Optional[List[int]] = None,
) -> Optional[int]:
    """走完一个 dispatcher 块，返回它的下一个 instr_index 去向。
    dispatcher 块内只可能有 goto / 状态相关 if / SetVar（由纯块过滤保证）。

    replay 非 None 时，块内每个 SetVar 的 instr_index 都会被记录；
    skipped 非 None 时记录所有经过的指令序号（含 goto/if）。
    """
    current = bb.start
    while current < bb.end:
        instr = mlil[current]
        if skipped is not None:
            skipped.append(instr.instr_index)
        if isinstance(instr, MediumLevelILGoto):
            return instr.dest
        if isinstance(instr, MediumLevelILIf):
            branch = _eval_if(instr, env)
            if branch is None:
                return None
            return instr.true if branch else instr.false
        if isinstance(instr, MediumLevelILSetVar):
            if replay is not None:
                replay.append(instr.instr_index)
            v = _eval(instr.src, env)
            if v is None:
                env.pop(instr.dest, None)
            else:
                env[instr.dest] = v & _mask(instr.size or 4)
            current += 1
            continue
        return None
    return None


def _env_key(env: Dict[Variable, int]) -> Tuple[Tuple[int, int], ...]:
    """把 env 变成可哈希、与遍历顺序无关的缓存键。"""
    return tuple(sorted((var.identifier, value) for var, value in env.items()))


def _trace_dispatcher_path(
    mlil: MediumLevelILFunction,
    start: int,
    env: Dict[Variable, int],
    state_vars: Set[Variable],
    dispatcher_blocks: Set[int],
    replay: Optional[List[int]] = None,
    skipped: Optional[List[int]] = None,
) -> Tuple[Optional[int], Tuple[int, ...], Tuple[int, ...], Tuple[int, ...]]:
    """不感知「当前 define 在哪个块」地模拟 dispatcher 子图。

    返回 (final_target, path, replayed_path, skipped_path)：
    - final_target 非 None：落到真实块入口
    - final_target None：无法决断 / 走到块中段 / dispatcher 内成环 / 超步数
    - path 是途中经过的 dispatcher block start 序列
    - replayed_path 是途中所有 SetVar instr_index 序列
    - skipped_path 是途中所有执行过的指令序号（SetVar/goto/if）
    """
    path: List[int] = []
    replay_local: List[int] = [] if replay is None else replay
    skipped_local: List[int] = [] if skipped is None else skipped
    visited: Set[int] = set()
    current = start
    for _ in range(_MAX_FORWARD_STEPS):
        bb = mlil.get_basic_block_at(current)
        if bb is None or current != bb.start:
            return None, tuple(path), tuple(replay_local), tuple(skipped_local)
        if bb.start in visited:
            return None, tuple(path), tuple(replay_local), tuple(skipped_local)
        visited.add(bb.start)
        if bb.start not in dispatcher_blocks:
            return current, tuple(path), tuple(replay_local), tuple(skipped_local)
        path.append(bb.start)
        nxt = _walk_dispatcher_block(
            mlil, bb, env, state_vars, replay_local, skipped_local
        )
        if nxt is None:
            return None, tuple(path), tuple(replay_local), tuple(skipped_local)
        current = nxt
    return None, tuple(path), tuple(replay_local), tuple(skipped_local)


def _forward_resolve_with_replay(
    mlil: MediumLevelILFunction,
    define_instr: MediumLevelILSetVar,
    state_vars: Set[Variable],
    dispatcher_blocks: Set[int],
    resolve_memo: Optional[
        Dict[
            Tuple[int, Tuple],
            Tuple[
                Optional[int],
                Tuple[int, ...],
                Tuple[int, ...],
                Tuple[int, ...],
            ],
        ]
    ] = None,
    dead_vars: Optional[Set[int]] = None,
) -> Tuple[Optional[int], Tuple[int, ...]]:
    """_forward_resolve 的 path-replay 版本：额外返回 (target, replay)。

    replay 是「原 define 之后、目标真实块之前」沿途 SetVar 的 instr_index
    按数据流裁剪后的集合；mini-block 按此顺序复制这些写入后再 goto target，
    因此放宽 pure 过滤跳过它们不影响语义。target 为 None 时 replay 为空。
    """
    if not isinstance(define_instr.src, MediumLevelILConst):
        return None, ()
    env = _seed_env_from_block(mlil, define_instr, state_vars, dispatcher_blocks)

    define_bb = mlil.get_basic_block_at(define_instr.instr_index)
    if define_bb is None:
        return None, ()

    tail_replay: List[int] = []
    tail_skipped: List[int] = []
    current = _walk_block_tail(
        mlil, define_bb, define_instr.instr_index, env, state_vars,
        dead_vars, tail_replay, tail_skipped,
    )
    if current is None:
        return None, ()

    if resolve_memo is not None:
        key = (current, _env_key(env))
        trace = resolve_memo.get(key)
        if trace is None:
            trace = _trace_dispatcher_path(
                mlil, current, env, state_vars, dispatcher_blocks,
                skipped=tail_skipped,
            )
            resolve_memo[key] = trace
    else:
        trace = _trace_dispatcher_path(
            mlil, current, env, state_vars, dispatcher_blocks,
            skipped=tail_skipped,
        )

    target, path, dispatcher_replay, skipped_path = trace
    if target is None:
        return None, ()
    # 老循环等价：路径若回到 define 块 (visited 已含它) 会提前 None；
    # target == define_bb.start 的情形 (tail 直接自环回来) 同理。
    if target == define_bb.start or define_bb.start in path:
        return None, ()
    replay = _filter_replay_indices(
        mlil, tuple(tail_replay) + dispatcher_replay, state_vars,
        skipped_path,
    )
    return target, replay


def _forward_resolve(
    mlil: MediumLevelILFunction,
    define_instr: MediumLevelILSetVar,
    state_vars: Set[Variable],
    dispatcher_blocks: Set[int],
    resolve_memo: Optional[
        Dict[
            Tuple[int, Tuple],
            Tuple[
                Optional[int],
                Tuple[int, ...],
                Tuple[int, ...],
                Tuple[int, ...],
            ],
        ]
    ] = None,
    dead_vars: Optional[Set[int]] = None,
) -> Optional[int]:
    """从 state SetVar 出发，先走完 define 所在块的尾巴，进入 dispatcher
    子图后逐 *基本块* 模拟，直到落到一个真实块入口。

    安全约束：
      - target 必须是 bb.start（落到块入口而非块中段）
      - cycle 检测用 block_start：保守，避免 chain transition 时被错认为
        新路径而走出错误的目标 (sub_40831c 上观察到 visited_states 用
        (block, env) 时 SE_LOST=11，因为 BN 见到我们错误的 jump_to 后
        把"原本经过 chain 才到的"handler 当不可达清掉)

    resolve_memo：可选的 dispatcher 段模拟缓存。键 (tail 去向, env) 的
    模拟路径与具体 define 块无关；命中后只需验证当前 define 块不在路径上，
    语义与无缓存版本完全一致。MLIL / dispatcher_blocks / state_vars 在缓存
    存活期间必须保持不变。
    """
    return _forward_resolve_with_replay(
        mlil, define_instr, state_vars, dispatcher_blocks,
        resolve_memo, dead_vars,
    )[0]


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
    iter_idx = 0
    total_patched = 0

    for _ in range(_MAX_OUTER_ITERS):
        iter_idx += 1
        if time.time() > deadline:
            log_info(f"[deflate] {function_name}: deadline reached at iter {iter_idx}")
            break

        # 1. 门控：函数是 CFF 吗？(Blazytko 支配树法)
        dispatcher_entry = _detect_dispatcher_entry(mlil)
        if dispatcher_entry is None:
            if iter_idx == 1:
                log_info(f"[deflate] {function_name}: no dispatcher detected (Blazytko score)")
            break

        # 2. 状态变量识别
        state_vars = _collect_state_vars(mlil, dispatcher_entry)
        if not state_vars:
            # 兜底：dispatcher 用 temp 比较真实 state（cdong x86 样本是
            # `temp = state; cmp temp, const`），fast 收集会漏。慢路径
            # find_state_var 能抓回被赋多个大常量的 var；它更宽松，因此
            # 后续仍要过 _function_looks_like_cff 门控。
            state_vars = set(StateMachine.find_state_var(function))
        if not state_vars:
            if iter_idx == 1:
                log_info(f"[deflate] {function_name}: no state vars at 0x{dispatcher_entry.start:x}")
            break

        # 2.5 函数级 CFF 启发式：避免 Rust match / C++ stdlib 等小常量分发
        # 被误判为 OLLVM CFF (task #16 发现的假阳性)
        if not _function_looks_like_cff(mlil, state_vars):
            if iter_idx == 1:
                log_info(f"[deflate] {function_name}: failed CFF heuristic")
            break

        # 3. 形式化 dispatcher 子图：含 dispatcher_entry 的 SCC ∩ pure-dispatcher 块
        # deflate 开启 path replay：temp/寄存器/死栈写允许进入子图，它们的
        # 写入会在 mini-block 中原样回放（见第 4 步），语义不丢。
        dead_vars = _collect_dead_var_ids(mlil)
        dispatcher_blocks = _identify_dispatcher_subgraph(
            mlil, dispatcher_entry, state_vars, dead_vars, True
        )
        if not dispatcher_blocks:
            if iter_idx == 1:
                log_info(f"[deflate] {function_name}: SCC ∩ pure-dispatcher empty")
            break

        # 4. 收集所有 state SetVar (= const)
        # MLIL 在本轮收集期间保持不变，dispatcher 段模拟可安全按
        # (tail 去向, env) 共享；重复 state 值 / 多状态 define 不再重复走
        # cmp-tree 深度。
        resolve_memo: Dict[
            Tuple[int, Tuple],
            Tuple[
                Optional[int],
                Tuple[int, ...],
                Tuple[int, ...],
                Tuple[int, ...],
            ],
        ] = {}
        patches: List[Tuple[MediumLevelILSetVar, int, Tuple[int, ...]]] = []
        for instr in mlil.instructions:
            if time.time() > deadline:
                break
            if (
                not isinstance(instr, MediumLevelILSetVar)
                or instr.dest not in state_vars
                or not isinstance(instr.src, MediumLevelILConst)
            ):
                continue
            target, replay = _forward_resolve_with_replay(
                mlil, instr, state_vars, dispatcher_blocks, resolve_memo,
                dead_vars,
            )
            if target is None or target == instr.instr_index:
                continue
            patches.append((instr, target, replay))

        if not patches:
            if iter_idx == 1:
                log_info(
                    f"[deflate] {function_name}: forward_resolve resolved 0/N "
                    f"state SetVars at 0x{dispatcher_entry.start:x}"
                )
            break
        total_patched += len(patches)

        # 4. 修补：相同 (state_var, value, target, replay 序列) 的 patch 共享
        #    同一个 mini-block，避免每个 define 都生成独立块。replay 不同时
        #    必须用不同 mini-block，否则回放的写入序列不一样。
        mini_block_cache: Dict[Tuple[int, int, int, Tuple[int, ...]], "MediumLevelILLabel"] = {}
        for define, target_idx, replay in patches:
            try:
                key = (
                    define.dest.identifier,
                    define.src.constant & _mask(define.size or 4),
                    target_idx,
                    replay,
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
                    # path replay：按执行顺序重放 define 之后、目标真实块
                    # 之前的所有 SetVar 写入。原 trace 会执行这些写入，
                    # 去混淆后的短跳路径也必须执行，保证局部变量/寄存器
                    # 可见值与原语义一致。
                    for idx in replay:
                        src_instr = mlil[idx]
                        mlil.append(
                            mlil.copy_expr(src_instr),
                            ILSourceLocation.from_instruction(src_instr),
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

    if total_patched > 0:
        log_info(f"[deflate] {function_name}: patched {total_patched} state SetVars across {iter_idx} iters")

    # 等价性自动验证：patch 后副作用签名集合应仍 ⊇ patch 前
    side_effects_after = _collect_side_effect_signatures(mlil)
    _verify_no_side_effect_loss(side_effects_before, side_effects_after, function_name)
