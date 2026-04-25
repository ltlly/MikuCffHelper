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

_MAX_OUTER_ITERS = 6
_MAX_FORWARD_STEPS = 1024
_TIME_BUDGET_SECONDS = 30.0
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

    # 验证：被赋予 ≥2 unique 常量值
    unique_vals: Dict[Variable, Set[int]] = {var: set() for var in candidates}
    for instr in mlil.instructions:
        if not isinstance(instr, MediumLevelILSetVar):
            continue
        if instr.dest not in candidates:
            continue
        if isinstance(instr.src, MediumLevelILConst):
            unique_vals[instr.dest].add(instr.src.constant & _mask(instr.size or 4))
    return {v for v, s in unique_vals.items() if len(s) >= 2}


# --------------------------------------------------------------------------
# 3. 前向模拟 (state-only 子图内)
# --------------------------------------------------------------------------


def _is_state_only_instr(
    instr: MediumLevelILInstruction, state_vars: Set[Variable]
) -> bool:
    """该指令本身是否属于 dispatcher 子图。"""
    if isinstance(instr, MediumLevelILGoto):
        return True
    if isinstance(instr, MediumLevelILIf):
        return set(instr.vars_read).issubset(state_vars)
    if isinstance(instr, MediumLevelILSetVar):
        if instr.dest not in state_vars:
            return False
        return set(instr.vars_read).issubset(state_vars)
    return False


def _forward_resolve(
    mlil: MediumLevelILFunction,
    define_instr: MediumLevelILSetVar,
    state_vars: Set[Variable],
) -> Optional[int]:
    """从 state SetVar 出发沿 dispatcher 子图前向模拟，返回离开 dispatcher 子图
    时进入的真实块入口 instr_index。

    安全约束：
      - 路径上每条指令必须是 state-only（goto / 状态相关 if / 状态 SetVar）
      - 离开 dispatcher 时，落点 *必须是基本块入口* (即 instr.dest 跳转到的)，
        否则放弃 patch（避免 jump 到块中段）
    """
    if not isinstance(define_instr.src, MediumLevelILConst):
        return None
    env: Dict[Variable, int] = {
        define_instr.dest: define_instr.src.constant & _mask(define_instr.size or 4)
    }
    visited: Set[int] = set()
    current = define_instr.instr_index + 1
    n = len(mlil)

    for _ in range(_MAX_FORWARD_STEPS):
        if current >= n or current in visited:
            return None
        visited.add(current)
        instr = mlil[current]

        # 离开 dispatcher 子图（碰到第一条非 state-only 指令）
        if not _is_state_only_instr(instr, state_vars):
            bb = mlil.get_basic_block_at(current)
            if bb is None:
                return None
            # 必须落到块入口才能 goto 这里
            if current != bb.start:
                return None
            return current

        if isinstance(instr, MediumLevelILGoto):
            current = instr.dest
            continue
        if isinstance(instr, MediumLevelILIf):
            branch = _eval_if(instr, env)
            if branch is None:
                return None
            current = instr.true if branch else instr.false
            continue
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


# --------------------------------------------------------------------------
# 主 pass
# --------------------------------------------------------------------------


def pass_deflate_hard(analysis_context: AnalysisContext) -> None:
    function: Function = analysis_context.function
    mlil = function.mlil
    if mlil is None:
        return

    deadline = time.time() + _TIME_BUDGET_SECONDS

    for _ in range(_MAX_OUTER_ITERS):
        if time.time() > deadline:
            break

        # 1. 门控：函数是 CFF 吗？
        dispatcher_entry = _detect_dispatcher_entry(mlil)
        if dispatcher_entry is None:
            break

        # 2. 状态变量
        state_vars = _collect_state_vars(mlil, dispatcher_entry)
        if not state_vars:
            break

        # 3. 收集所有 state SetVar (= const)
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
            target = _forward_resolve(mlil, instr, state_vars)
            if target is None or target == instr.instr_index:
                continue
            patches.append((instr, target))

        if not patches:
            break

        # 4. 修补
        for define, target_idx in patches:
            try:
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
                mlil.replace_expr(
                    define.expr_index,
                    mlil.goto(
                        new_block_label,
                        ILSourceLocation.from_instruction(define),
                    ),
                )
            except Exception:
                continue

        mlil.finalize()
        mlil.generate_ssa_form()

    mlil.finalize()
    mlil.generate_ssa_form()
