"""通用 CFF 去平坦化 pass（新框架原型）。

与现有 deflate_hard / synthesize_switch 的区别：

1. 状态变量识别使用 ``utils.cff_core.find_state_class``：
   - 直连路径兼容标准 OLLVM；
   - alias-only 变种（``alias = state`` 后比较 alias）用变量拷贝图
     union-find 归并。

2. dispatcher 检测使用 ``DominatorInfo`` 的 O(1) subtree 判定，整体 O(V+E)。

3. dispatcher 决策块识别不再要求「只写状态变量」：
   - 允许 ``flag = (state == const)`` 布尔 flag 变量；
   - 允许 alias 拷贝；
   - 真实块（写非状态数据 / 状态常量 / 外部副作用）作为 transition 终点，
     不会在模拟时被跳过，保证等价性。

4. 重写形态为 **P3 guarded jump_to（preamble-preserving）**：
   - 不删 dispatcher 入口的前导数据拷贝，而是在 guard 里重放这些拷贝；
   - resolved state → 对应真实块；unresolved state → 原 dispatcher 入口
     cmp-tree 兜底；
   - 原真实块内容完全保留，只有「回 dispatcher 的边」被重定向到 guard。

等价性论证：
   guard 重放的是 dispatcher 入口块内 idempotent 的本地 SetVar 前导；
   resolved 路径 = 原 dispatcher 决策树产生的同一 target；unresolved 路径
   仍走原 cmp-tree。对外可见副作用序列不变（CFE 子序列）。
"""

import time
from typing import Dict, List, Optional, Set, Tuple

from binaryninja import (
    AnalysisContext,
    ILSourceLocation,
    MediumLevelILConst,
    MediumLevelILGoto,
    MediumLevelILIf,
    MediumLevelILLabel,
    MediumLevelILInstruction,
    MediumLevelILOperation,
    MediumLevelILSetVar,
    MediumLevelILVar,
    MediumLevelILVarSsa,
)

from .deflatHardPass import (
    _collect_side_effect_signatures,
    _tarjan_scc,
    _verify_no_side_effect_loss,
)
from ...utils.cff_core import (
    EnvEvaluator,
    StateClass,
    collect_state_case_values,
    detect_flattening_candidate,
    find_state_class,
    mask,
)
from ...utils import log_info

_TIME_BUDGET_SECONDS = 15.0
_MAX_BATCH_STEPS = 200_000
_MIN_TRANSITIONS = 2


def _instruction_has_side_effect(
    instr: MediumLevelILInstruction, side_effect_ops: Set
) -> bool:
    """递归检查子表达式，避免 SetVar(src=call()) 这类嵌套副作用漏判。"""
    if instr.operation in side_effect_ops:
        return True

    found = []

    def visitor(operand_name, expr, type_name, parent):
        if isinstance(expr, MediumLevelILInstruction) and expr.operation in side_effect_ops:
            found.append(True)

    try:
        list(instr.traverse(visitor))
    except Exception:
        return False
    return bool(found)


def _is_state_comparison(
    expr: MediumLevelILInstruction, state_class: StateClass
) -> bool:
    """expr 是否为 ``(state|alias) op const`` / ``const op (state|alias)``。"""
    op = expr.operation
    if op not in {
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
    }:
        return False
    if not (hasattr(expr, "left") and hasattr(expr, "right")):
        return False
    left, right = expr.left, expr.right
    if isinstance(right, MediumLevelILConst):
        var = getattr(getattr(left, "src", None), "identifier", None)
        return var is not None and state_class.contains_id(var)
    if isinstance(left, MediumLevelILConst):
        var = getattr(getattr(right, "src", None), "identifier", None)
        return var is not None and state_class.contains_id(var)
    return False


def _classify_route_blocks(
    mlil: MediumLevelILFunction,
    scc_starts: Set[int],
    dispatcher_entry_start: int,
    state_class: StateClass,
    side_effect_ops: Set,
) -> Set[int]:
    """把 dispatcher SCC 分为「决策路由块」与「真实块」。

    决策路由块要求（dispatcher 入口强制纳入）：
    - 无 call/store/ret/... 副作用；
    - 所有非终结 SetVar 只能是：
        * 状态类的非 const 拷贝（alias 更新），或
        * ``flag = (state op const)`` 布尔 flag；
    - 状态常量赋值块视为真实块（handler），不跳过。
    """
    route: Set[int] = set()
    for start in scc_starts:
        bb = mlil.get_basic_block_at(start)
        if bb is None or bb.length == 0:
            continue
        if start == dispatcher_entry_start:
            route.add(start)
            continue

        ok = True
        for idx in range(bb.start, bb.end - 1):
            instr = mlil[idx]
            if _instruction_has_side_effect(instr, side_effect_ops):
                ok = False
                break
            if isinstance(instr, MediumLevelILSetVar):
                if instr.dest.identifier in state_class.var_ids:
                    if isinstance(instr.src, MediumLevelILConst):
                        # 状态常量赋值 → handler，不是路由块
                        ok = False
                        break
                    continue
                if _is_state_comparison(instr.src, state_class):
                    # flag = (state == K)
                    continue
                ok = False
                break
            # 非终结指令只允许 SetVar；goto/if 应只出现在块尾
            ok = False
            break

        if not ok:
            continue
        # 块尾必须是 goto / if，且无副作用
        last = mlil[bb.end - 1]
        if isinstance(last, (MediumLevelILGoto, MediumLevelILIf)):
            if not _instruction_has_side_effect(last, side_effect_ops):
                route.add(start)
    return route


def _resolve_dispatch_map(
    mlil: MediumLevelILFunction,
    state_class: StateClass,
    route_starts: Set[int],
    dispatcher_entry_start: int,
    side_effect_ops: Set,
    deadline: float,
) -> Dict[int, int]:
    """批量路由解析：所有状态值共享 dispatcher 路径前缀。

    实现是 worklist 式的「值集合在决策块上传播」：
    - 同一个块对当前活跃的值集合只解释一次；
    - terminator 条件把活跃值按 true/false 分裂，各自继续；
    - 每条值路径受 `visited_by_value` 循环检测约束；
    - 总步数 = Σ 每块活跃值数，比逐值模拟共享更多前缀，且受
      _MAX_BATCH_STEPS 预算限制，超预算/无法求值 → unresolved 走原树兜底。

    这离理想 O(U log K) 还差 equality-hash / interval-map 两个优化，但已经把
    「每个 define 各自从头走 dispatcher」的结构性重复去掉了。
    """
    transitions: Dict[int, int] = {}
    # 初始：一个状态值 = 一个环境，全部从 dispatcher 入口出发
    initial = [
        (value, {var: value for var in state_class.vars})
        for value in sorted(state_class.assigned_values)
    ]
    worklist: List[Tuple[int, List[Tuple[int, Dict]]]] = [
        (dispatcher_entry_start, initial)
    ]
    visited_by_value: Dict[int, Set[int]] = {}
    total_steps = 0

    while worklist:
        if time.time() > deadline or total_steps > _MAX_BATCH_STEPS:
            break
        block_start, entries = worklist.pop()
        if not entries:
            continue
        total_steps += len(entries)

        bb = mlil.get_basic_block_at(block_start)
        if bb is None or block_start != bb.start:
            continue
        if block_start not in route_starts:
            for value, _env in entries:
                transitions[value] = block_start
            continue

        # 循环检测：每个值只允许经过同一路由块一次
        fresh: List[Tuple[int, Dict]] = []
        for value, env in entries:
            visited = visited_by_value.setdefault(value, set())
            if block_start in visited:
                continue
            visited.add(block_start)
            fresh.append((value, env))
        entries = fresh
        if not entries:
            continue

        next_groups: List[Tuple[int, List[Tuple[int, Dict]]]] = []
        broken = False
        for idx in range(bb.start, bb.end):
            instr = mlil[idx]
            if _instruction_has_side_effect(instr, side_effect_ops):
                broken = True
                break
            if isinstance(instr, MediumLevelILGoto):
                next_groups.append((instr.dest, entries))
                break
            if isinstance(instr, MediumLevelILIf):
                true_entries: List[Tuple[int, Dict]] = []
                false_entries: List[Tuple[int, Dict]] = []
                for value, env in entries:
                    branch = EnvEvaluator.eval_if(instr, env)
                    if branch is None:
                        continue
                    (true_entries if branch else false_entries).append((value, env))
                if true_entries:
                    next_groups.append((instr.true, true_entries))
                if false_entries:
                    next_groups.append((instr.false, false_entries))
                break
            if isinstance(instr, MediumLevelILSetVar):
                for value, env in entries:
                    if instr.dest.identifier in state_class.var_ids:
                        # 状态类写入按位/算术语义求值
                        result = EnvEvaluator.eval(instr.src, env)
                    else:
                        # flag 变量写入按布尔语义求值，保证 env 中恒为 0/1
                        cond = EnvEvaluator.eval_cond(instr.src, env)
                        result = None if cond is None else int(cond)
                    if result is None:
                        env.pop(instr.dest, None)
                    else:
                        env[instr.dest] = result & mask(instr.size or 4)
                continue
            broken = True
            break

        if broken:
            continue
        worklist.extend(next_groups)
    return transitions


def _redirect_edges_to_dispatcher(
    mlil: MediumLevelILFunction,
    dispatcher_entry_start: int,
    route_starts: Set[int],
    guard_label: MediumLevelILLabel,
) -> int:
    """把真实块末尾指向 dispatcher 入口的边重定向到 guard。

    只改 exact dispatcher_entry 的边；其它边（含直接落到下一个真实块的分支）
    保持不动，避免改变不需要经过 dispatcher 的路径。
    """
    target_idx = dispatcher_entry_start
    guard_idx = guard_label.operand
    redirected = 0
    for b in list(mlil.basic_blocks):
        if b.start in route_starts:
            continue
        if b.length == 0:
            continue
        last = mlil[b.end - 1]
        loc = ILSourceLocation.from_instruction(last)
        try:
            if isinstance(last, MediumLevelILGoto):
                if last.dest != target_idx:
                    continue
                new_label = MediumLevelILLabel()
                new_label.operand = guard_idx
                mlil.replace_expr(last.expr_index, mlil.goto(new_label, loc))
                redirected += 1
            elif isinstance(last, MediumLevelILIf):
                if last.true != target_idx and last.false != target_idx:
                    continue
                new_true = MediumLevelILLabel()
                new_true.operand = guard_idx if last.true == target_idx else last.true
                new_false = MediumLevelILLabel()
                new_false.operand = guard_idx if last.false == target_idx else last.false
                cond_copy = mlil.copy_expr(last.condition)
                new_if = mlil.if_expr(cond_copy, new_true, new_false, loc)
                mlil.replace_expr(last.expr_index, new_if)
                redirected += 1
        except Exception:
            continue
    return redirected


def _install_preamble_guarded_jump_to(
    mlil: MediumLevelILFunction,
    state_class: StateClass,
    transitions: Dict[int, int],
    case_values: Set[int],
    dispatcher_entry_start: int,
    route_starts: Set[int],
) -> Optional[int]:
    """P3：guard 内重放 dispatcher 入口前导，再 jump_to。

    成功条件：
    - 至少 _MIN_TRANSITIONS 个 resolved value；
    - dispatcher 入口的非终结指令全部是本地 SetVar（否则拒绝复制）；
    - 至少重定向一条真实块回边。
    """
    if len(transitions) < _MIN_TRANSITIONS:
        return None
    entry_bb = mlil.get_basic_block_at(dispatcher_entry_start)
    if entry_bb is None or entry_bb.length == 0:
        return None

    preamble: List[MediumLevelILInstruction] = []
    for idx in range(entry_bb.start, entry_bb.end - 1):
        instr = mlil[idx]
        if not isinstance(instr, MediumLevelILSetVar):
            # dispatcher 入口出现非 SetVar 前导，先保守拒绝
            return None
        # 只允许 idempotent 拷贝/常量赋值，保证 guard 重放 + 未解析路径
        # 再走原 dispatcher 入口时语义不改变
        if not isinstance(
            instr.src,
            (MediumLevelILConst, MediumLevelILVar, MediumLevelILVarSsa),
        ):
            return None
        preamble.append(instr)

    anchor = mlil[entry_bb.start]
    loc = ILSourceLocation.from_instruction(anchor)
    primary_size = state_class.primary.type.width if state_class.primary.type else 4

    try:
        guard_label = MediumLevelILLabel()
        mlil.mark_label(guard_label)

        # 重放 dispatcher 入口前导（idempotent 本地 SetVar）
        for instr in preamble:
            mlil.append(mlil.copy_expr(instr), loc)

        label_map: Dict[int, MediumLevelILLabel] = {}
        for value, target_idx in transitions.items():
            lbl = MediumLevelILLabel()
            lbl.operand = target_idx
            label_map[value] = lbl
        unresolved = (case_values | set(state_class.assigned_values)) - set(
            transitions.keys()
        )
        for value in unresolved:
            lbl = MediumLevelILLabel()
            lbl.operand = dispatcher_entry_start
            label_map[value] = lbl

        if not label_map:
            return None

        dest_expr = mlil.var(primary_size, state_class.primary, loc)
        mlil.append(mlil.jump_to(dest_expr, label_map, loc))

        redirected = _redirect_edges_to_dispatcher(
            mlil, dispatcher_entry_start, route_starts, guard_label
        )
        if redirected == 0:
            return None
    except Exception:
        return None
    return int(guard_label.operand)


def pass_general_cff(analysis_context: AnalysisContext) -> bool:
    """新框架入口：linear detect → alias-aware state → P3 guarded jump_to。"""
    function = analysis_context.function
    mlil = function.mlil
    if mlil is None:
        return False

    from .deflatHardPass import _SIDE_EFFECT_OPS

    side_effects_before = _collect_side_effect_signatures(mlil)
    fname = function.name
    deadline = time.time() + _TIME_BUDGET_SECONDS

    dispatcher_entry = detect_flattening_candidate(mlil)
    if dispatcher_entry is None:
        return False

    state_class = find_state_class(mlil, dispatcher_entry)
    if state_class is None:
        log_info(f"[general] {fname}: no state class at 0x{dispatcher_entry.start:x}")
        return False

    # dispatcher SCC
    bbs = list(mlil.basic_blocks)
    adj = {b.start: [e.target.start for e in b.outgoing_edges] for b in bbs}
    sccs = _tarjan_scc(adj)
    dispatcher_scc: Optional[Set[int]] = None
    for scc in sccs:
        if dispatcher_entry.start in scc:
            dispatcher_scc = set(scc)
            break
    if dispatcher_scc is None or len(dispatcher_scc) < 2:
        log_info(f"[general] {fname}: dispatcher SCC too small")
        return False

    route_starts = _classify_route_blocks(
        mlil,
        dispatcher_scc,
        dispatcher_entry.start,
        state_class,
        _SIDE_EFFECT_OPS,
    )
    route_starts.add(dispatcher_entry.start)

    transitions = _resolve_dispatch_map(
        mlil,
        state_class,
        route_starts,
        dispatcher_entry.start,
        _SIDE_EFFECT_OPS,
        deadline,
    )
    if len(transitions) < _MIN_TRANSITIONS:
        log_info(
            f"[general] {fname}: resolved {len(transitions)}/{len(state_class.assigned_values)} values"
        )
        return False
    if len(set(transitions.values())) < 2:
        log_info(f"[general] {fname}: all transitions collapse to one target")
        return False

    # case_values 覆盖检查：dispatcher SCC 内全部状态比较常量
    case_values = collect_state_case_values(mlil, state_class, dispatcher_scc)
    guard_label_op = _install_preamble_guarded_jump_to(
        mlil,
        state_class,
        transitions,
        case_values,
        dispatcher_entry.start,
        route_starts,
    )
    if guard_label_op is None:
        log_info(f"[general] {fname}: P3 install failed")
        return False

    mlil.finalize()
    mlil.generate_ssa_form()

    side_effects_after = _collect_side_effect_signatures(mlil)
    _verify_no_side_effect_loss(side_effects_before, side_effects_after, fname)
    log_info(
        f"[general] {fname}: P3 installed guard=0x{guard_label_op:x} "
        f"transitions={len(transitions)} case_values={len(case_values)}"
    )
    return True
