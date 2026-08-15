"""通用 CFF 去平坦化 pass（新框架原型）。

与现有 deflate_hard / synthesize_switch 的区别：

1. 状态变量识别使用 ``utils.cff_core.find_state_classes``：
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
from bisect import bisect_left, bisect_right
from itertools import product
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
    find_state_classes,
    mask,
    to_signed,
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
        if not isinstance(last, (MediumLevelILGoto, MediumLevelILIf)):
            continue
        if _instruction_has_side_effect(last, side_effect_ops):
            continue
        # if 块的条件必须依赖状态类（直接比较，或同块内 flag 定义）；
        # LLIL split 后 handler 可能是纯 if-only 块（如 if (x7_2 == 2)），
        # 仅凭「块内无 SetVar」会把它误判成 dispatcher 决策块。
        if isinstance(last, MediumLevelILIf) and not _is_state_comparison(
            last.condition, state_class
        ):
            cond_var = getattr(getattr(last.condition, "src", None), "identifier", None)
            if cond_var is None:
                continue
            flag_def_ok = False
            for idx in range(bb.start, bb.end - 1):
                instr = mlil[idx]
                if (
                    isinstance(instr, MediumLevelILSetVar)
                    and instr.dest.identifier == cond_var
                    and _is_state_comparison(instr.src, state_class)
                ):
                    flag_def_ok = True
                    break
            if not flag_def_ok:
                continue
        route.add(start)
    return route


def _partition_by_state_compare(
    cond: MediumLevelILInstruction,
    entries: List[Tuple[Tuple, Dict]],
    state_var_ids: Set[int],
) -> Optional[Tuple[List[Tuple[Tuple, Dict]], List[Tuple[Tuple, Dict]]]]:
    """把 entries 按 ``(state|alias) op const`` 快速分裂为 true/false。

    - CMP_E/CMP_NE 用哈希表 O(m)；
    - 有符号/无符号 range 比较把当前状态值排序后 bisect，O(m log m)。

    无法识别为直接状态比较（例如 flag 变量、AND/OR 组合）时返回 None，
    调用方回退到逐 entry 的 EnvEvaluator。
    """
    op = cond.operation
    if not (hasattr(cond, "left") and hasattr(cond, "right")):
        return None
    left, right = cond.left, cond.right

    state_var = None
    const_expr = None
    reversed_ = False
    if isinstance(right, MediumLevelILConst):
        src = getattr(getattr(left, "src", None), "identifier", None)
        if src is not None and src in state_var_ids:
            state_var = getattr(left, "src", None)
            const_expr = right
    elif isinstance(left, MediumLevelILConst):
        src = getattr(getattr(right, "src", None), "identifier", None)
        if src is not None and src in state_var_ids:
            state_var = getattr(right, "src", None)
            const_expr = left
            reversed_ = True
    if state_var is None or const_expr is None:
        return None

    c = const_expr.constant & mask(const_expr.size or state_var.type.width or 4)
    # 归一到 value op const 方向
    if reversed_:
        rev = {
            MediumLevelILOperation.MLIL_CMP_SLT: MediumLevelILOperation.MLIL_CMP_SGT,
            MediumLevelILOperation.MLIL_CMP_SLE: MediumLevelILOperation.MLIL_CMP_SGE,
            MediumLevelILOperation.MLIL_CMP_SGT: MediumLevelILOperation.MLIL_CMP_SLT,
            MediumLevelILOperation.MLIL_CMP_SGE: MediumLevelILOperation.MLIL_CMP_SLE,
            MediumLevelILOperation.MLIL_CMP_ULT: MediumLevelILOperation.MLIL_CMP_UGT,
            MediumLevelILOperation.MLIL_CMP_ULE: MediumLevelILOperation.MLIL_CMP_UGE,
            MediumLevelILOperation.MLIL_CMP_UGT: MediumLevelILOperation.MLIL_CMP_ULT,
            MediumLevelILOperation.MLIL_CMP_UGE: MediumLevelILOperation.MLIL_CMP_ULE,
        }
        op = rev.get(op, op)

    # 取每个 entry 的当前状态值；失败则整体回退逐值求值
    keyed = []
    for value, env in entries:
        v = env.get(state_var)
        if v is None:
            return None
        keyed.append((v & mask(state_var.type.width or 4), value, env))

    if op == MediumLevelILOperation.MLIL_CMP_E:
        by_key: Dict[int, List[Tuple[int, Dict]]] = {}
        for key, value, env in keyed:
            by_key.setdefault(key, []).append((value, env))
        others = [(value, env) for key, value, env in keyed if key != c]
        return (by_key.get(c, []), others)
    if op == MediumLevelILOperation.MLIL_CMP_NE:
        by_key = {}
        for key, value, env in keyed:
            by_key.setdefault(key, []).append((value, env))
        others = [(value, env) for key, value, env in keyed if key != c]
        return (others, by_key.get(c, []))

    range_ops = {
        MediumLevelILOperation.MLIL_CMP_ULT,
        MediumLevelILOperation.MLIL_CMP_ULE,
        MediumLevelILOperation.MLIL_CMP_UGT,
        MediumLevelILOperation.MLIL_CMP_UGE,
        MediumLevelILOperation.MLIL_CMP_SLT,
        MediumLevelILOperation.MLIL_CMP_SLE,
        MediumLevelILOperation.MLIL_CMP_SGT,
        MediumLevelILOperation.MLIL_CMP_SGE,
    }
    if op not in range_ops:
        return None

    signed = op in {
        MediumLevelILOperation.MLIL_CMP_SLT,
        MediumLevelILOperation.MLIL_CMP_SLE,
        MediumLevelILOperation.MLIL_CMP_SGT,
        MediumLevelILOperation.MLIL_CMP_SGE,
    }
    width = state_var.type.width or 4
    if signed:
        keys = [(to_signed(k, width), i, value, env) for i, (k, value, env) in enumerate(keyed)]
    else:
        keys = [(k, i, value, env) for i, (k, value, env) in enumerate(keyed)]
    keys.sort(key=lambda t: (t[0], t[1]))
    sorted_keys = [t[0] for t in keys]
    c_cmp = to_signed(c, width) if signed else c

    if op in (MediumLevelILOperation.MLIL_CMP_SLE, MediumLevelILOperation.MLIL_CMP_ULE):
        idx = bisect_right(sorted_keys, c_cmp)
        true_part, false_part = keys[:idx], keys[idx:]
    elif op in (MediumLevelILOperation.MLIL_CMP_SLT, MediumLevelILOperation.MLIL_CMP_ULT):
        idx = bisect_left(sorted_keys, c_cmp)
        true_part, false_part = keys[:idx], keys[idx:]
    elif op in (MediumLevelILOperation.MLIL_CMP_SGT, MediumLevelILOperation.MLIL_CMP_UGT):
        idx = bisect_right(sorted_keys, c_cmp)
        true_part, false_part = keys[idx:], keys[:idx]
    else:  # SGE / UGE
        idx = bisect_left(sorted_keys, c_cmp)
        true_part, false_part = keys[idx:], keys[:idx]

    return (
        [(t[2], t[3]) for t in true_part],
        [(t[2], t[3]) for t in false_part],
    )


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
    - 直接 state 比较用 `_partition_by_state_compare`：
        * CMP_E/CMP_NE → hash 分裂，每块 O(m)；
        * signed/unsigned range → 排序 + bisect，每块 O(m log m)；
      flag / AND / OR 等复杂条件回退逐值求值；
    - 总步数 = Σ 每块活跃值数，且受 _MAX_BATCH_STEPS 预算限制；
      超预算/无法求值 → unresolved 走原树兜底。
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
                partition = _partition_by_state_compare(
                    instr.condition, entries, state_class.var_ids
                )
                if partition is None:
                    true_entries = []
                    false_entries = []
                    for value, env in entries:
                        branch = EnvEvaluator.eval_if(instr, env)
                        if branch is None:
                            continue
                        (true_entries if branch else false_entries).append(
                            (value, env)
                        )
                else:
                    true_entries, false_entries = partition
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


def _combine_state_classes(
    first: StateClass, second: StateClass
) -> StateClass:
    """把两个状态类合并为路由分类用的联合状态类。

    联合类只用于 dispatcher 决策块分类与比较常量收集；真实跳转映射仍按
    (v0, v1) 元组保存在 tuple resolver 中。
    """
    counts = dict(first.unique_counts)
    counts.update(second.unique_counts)
    return StateClass(
        primary=first.primary,
        vars=frozenset(first.vars | second.vars),
        var_ids=frozenset(first.var_ids | second.var_ids),
        assigned_values=frozenset(
            first.assigned_values | second.assigned_values
        ),
        unique_counts=counts,
    )


def _combine_state_classes_many(classes: List[StateClass]) -> StateClass:
    """把 N 个状态类合并为路由分类用的联合状态类。"""
    primary = classes[0].primary
    var_ids = set(classes[0].var_ids)
    vars_set = set(classes[0].vars)
    values = set(classes[0].assigned_values)
    counts = dict(classes[0].unique_counts)
    for cls in classes[1:]:
        var_ids.update(cls.var_ids)
        vars_set.update(cls.vars)
        values.update(cls.assigned_values)
        counts.update(cls.unique_counts)
    return StateClass(
        primary=primary,
        vars=frozenset(vars_set),
        var_ids=frozenset(var_ids),
        assigned_values=frozenset(values),
        unique_counts=counts,
    )


def _resolve_dispatch_map_ntuple(
    mlil: MediumLevelILFunction,
    classes: List[StateClass],
    combined: StateClass,
    route_starts: Set[int],
    dispatcher_entry_start: int,
    side_effect_ops: Set,
    deadline: float,
) -> Dict[Tuple, int]:
    """N 状态元组联合分发解析（N ≥ 2）。

    每个 entry 的 key 是 (v0, ..., v_{N-1})，env 同时装载所有状态类变量。
    dispatcher 决策条件引用任一类时由 partition/eval 处理，联合 flag /
    && / || 回退逐值求值。组合总数调用方保证 ≤ 4096。
    """
    transitions: Dict[Tuple, int] = {}
    initial = []
    for combo in product(*[sorted(c.assigned_values) for c in classes]):
        env: Dict = {}
        for cls, value in zip(classes, combo):
            for var in cls.vars:
                env[var] = value
        initial.append((combo, env))

    worklist: List[Tuple[int, List[Tuple[Tuple, Dict]]]] = [
        (dispatcher_entry_start, initial)
    ]
    visited_by_key: Dict[Tuple, Set[int]] = {}
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
            for key, _env in entries:
                transitions[key] = block_start
            continue

        fresh = []
        for key, env in entries:
            visited = visited_by_key.setdefault(key, set())
            if block_start in visited:
                continue
            visited.add(block_start)
            fresh.append((key, env))
        entries = fresh
        if not entries:
            continue

        next_groups: List = []
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
                partition = _partition_by_state_compare(
                    instr.condition, entries, combined.var_ids
                )
                if partition is None:
                    true_entries = []
                    false_entries = []
                    for key, env in entries:
                        branch = EnvEvaluator.eval_if(instr, env)
                        if branch is None:
                            continue
                        (true_entries if branch else false_entries).append(
                            (key, env)
                        )
                else:
                    true_entries, false_entries = partition
                if true_entries:
                    next_groups.append((instr.true, true_entries))
                if false_entries:
                    next_groups.append((instr.false, false_entries))
                break
            if isinstance(instr, MediumLevelILSetVar):
                for key, env in entries:
                    if instr.dest.identifier in combined.var_ids:
                        result = EnvEvaluator.eval(instr.src, env)
                    else:
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


def _resolve_dispatch_map_tuple(
    mlil: MediumLevelILFunction,
    first: StateClass,
    second: StateClass,
    combined: StateClass,
    route_starts: Set[int],
    dispatcher_entry_start: int,
    side_effect_ops: Set,
    deadline: float,
) -> Dict[Tuple[int, int], int]:
    """两状态兼容入口：委托给 N 状态 resolver。"""
    return _resolve_dispatch_map_ntuple(
        mlil,
        [first, second],
        combined,
        route_starts,
        dispatcher_entry_start,
        side_effect_ops,
        deadline,
    )


def _install_ntuple_guarded_jump_to(
    mlil: MediumLevelILFunction,
    classes: List[StateClass],
    transitions: Dict[Tuple, int],
    case_values: Set[int],
    dispatcher_entry_start: int,
    route_starts: Set[int],
) -> Optional[int]:
    """P3 N 状态版：为每个状态变量生成一层嵌套 jump_to guard。

    与 64-bit 编码合成 key 不同，这里无碰撞、支持任意宽度与 N≥2：
        guard0: preamble; jump_to(v0, {v0 → guard1(v0)})
        guard1: jump_to(v1, {v1 → guard2(v0,v1)})
        ...
        guardN-1: jump_to(v_{N-1}, {v_{N-1} → target})
    未解析 tuple 的目标填 dispatcher_entry，保留原 cmp-tree 兜底。
    """
    if len(classes) < 2 or len(transitions) < _MIN_TRANSITIONS:
        return None
    preamble = _collect_entry_preamble(mlil, dispatcher_entry_start)
    if preamble is None:
        return None

    all_keys = list(product(*[sorted(c.assigned_values) for c in classes]))
    if not all_keys:
        return None
    target_map: Dict[Tuple, int] = {
        key: transitions.get(key, dispatcher_entry_start) for key in all_keys
    }
    anchor = mlil[dispatcher_entry_start]
    loc = ILSourceLocation.from_instruction(anchor)

    def build_level(level: int, prefix: Tuple) -> int:
        cls = classes[level]
        # 收集该前缀下，当前层变量各取值的所有 tuple key
        groups: Dict[int, List[Tuple]] = {}
        for key in all_keys:
            if key[:level] != prefix:
                continue
            groups.setdefault(key[level], []).append(key)

        child_ops: Dict[int, int] = {}
        if level < len(classes) - 1:
            for value in sorted(groups.keys()):
                child_ops[value] = build_level(level + 1, prefix + (value,))

        guard_label = MediumLevelILLabel()
        mlil.mark_label(guard_label)
        if level == 0:
            for instr in preamble:
                mlil.append(mlil.copy_expr(instr), loc)

        label_map: Dict[int, MediumLevelILLabel] = {}
        for value in sorted(groups.keys()):
            lbl = MediumLevelILLabel()
            if level == len(classes) - 1:
                key = groups[value][0]
                lbl.operand = target_map[key]
            else:
                lbl.operand = child_ops[value]
            label_map[value] = lbl

        width = cls.primary.type.width if cls.primary.type else 4
        dest_expr = mlil.var(width, cls.primary, loc)
        mlil.append(mlil.jump_to(dest_expr, label_map, loc))
        return int(guard_label.operand)

    try:
        outer_label_op = build_level(0, ())
        outer_label = MediumLevelILLabel()
        outer_label.operand = outer_label_op
        redirected = _redirect_edges_to_dispatcher(
            mlil, dispatcher_entry_start, route_starts, outer_label,
            any_route=False,
        )
        if redirected == 0:
            return None
    except Exception:
        return None
    return outer_label_op


def _collect_entry_preamble(
    mlil: MediumLevelILFunction,
    dispatcher_entry_start: int,
) -> Optional[List[MediumLevelILInstruction]]:
    """收集 dispatcher 入口块内可安全重放的前导 SetVar。

    只允许 idempotent 拷贝/常量赋值；出现其它形式时返回 None，调用方
    必须放弃需要重放前导的变换。
    """
    entry_bb = mlil.get_basic_block_at(dispatcher_entry_start)
    if entry_bb is None or entry_bb.length == 0:
        return None
    preamble: List[MediumLevelILInstruction] = []
    for idx in range(entry_bb.start, entry_bb.end - 1):
        instr = mlil[idx]
        if not isinstance(instr, MediumLevelILSetVar):
            return None
        if not isinstance(
            instr.src,
            (MediumLevelILConst, MediumLevelILVar, MediumLevelILVarSsa),
        ):
            return None
        preamble.append(instr)
    return preamble


def _install_tuple_guarded_jump_to(
    mlil: MediumLevelILFunction,
    first: StateClass,
    second: StateClass,
    transitions: Dict[Tuple[int, int], int],
    case_values: Set[int],
    dispatcher_entry_start: int,
    route_starts: Set[int],
    fully_resolved: bool = False,
) -> Optional[int]:
    """P3 tuple 版：jump_to((v0 << 32) | v1, label_map)。

    仅支持两个 32-bit 状态类；编码无碰撞，未解析组合回退 dispatcher 入口。
    N > 2 时使用 _install_ntuple_guarded_jump_to 的嵌套 jump_to。
    """
    if len(transitions) < _MIN_TRANSITIONS:
        return None
    if (first.primary.type.width or 4) != 4 or (second.primary.type.width or 4) != 4:
        return None
    preamble = _collect_entry_preamble(mlil, dispatcher_entry_start)
    if preamble is None:
        return None

    anchor = mlil[dispatcher_entry_start]
    loc = ILSourceLocation.from_instruction(anchor)

    try:
        guard_label = MediumLevelILLabel()
        mlil.mark_label(guard_label)
        for instr in preamble:
            mlil.append(mlil.copy_expr(instr), loc)

        label_map: Dict[int, MediumLevelILLabel] = {}
        resolved_keys = set(transitions.keys())
        for (v0, v1), target_idx in transitions.items():
            encoded = ((v0 & 0xFFFFFFFF) << 32) | (v1 & 0xFFFFFFFF)
            lbl = MediumLevelILLabel()
            lbl.operand = target_idx
            label_map[encoded] = lbl
        if not fully_resolved:
            for v0 in sorted(first.assigned_values):
                for v1 in sorted(second.assigned_values):
                    if (v0, v1) in resolved_keys:
                        continue
                    encoded = ((v0 & 0xFFFFFFFF) << 32) | (v1 & 0xFFFFFFFF)
                    lbl = MediumLevelILLabel()
                    lbl.operand = dispatcher_entry_start
                    label_map[encoded] = lbl
        if not label_map:
            return None

        v0_expr = mlil.var(4, first.primary, loc)
        shift_expr = mlil.const(4, 32, loc)
        shifted = mlil.expr(
            MediumLevelILOperation.MLIL_LSL,
            v0_expr,
            shift_expr,
            0,
            0,
            0,
            8,
            loc,
        )
        v1_expr = mlil.var(4, second.primary, loc)
        dest_expr = mlil.expr(
            MediumLevelILOperation.MLIL_OR,
            shifted,
            v1_expr,
            0,
            0,
            0,
            8,
            loc,
        )
        mlil.append(mlil.jump_to(dest_expr, label_map, loc))

        redirected = _redirect_edges_to_dispatcher(
            mlil, dispatcher_entry_start, route_starts, guard_label,
            any_route=False,
        )
        if redirected == 0:
            return None
    except Exception:
        return None
    return int(guard_label.operand)


def _install_preamble_guarded_jump_to(
    mlil: MediumLevelILFunction,
    state_class: StateClass,
    transitions: Dict[int, int],
    case_values: Set[int],
    dispatcher_entry_start: int,
    route_starts: Set[int],
    fully_resolved: bool = False,
) -> Optional[int]:
    """P3：guard 内重放 dispatcher 入口前导，再 jump_to。

    成功条件：
    - 至少 _MIN_TRANSITIONS 个 resolved value；
    - dispatcher 入口前导全部可安全重放（idempotent SetVar）；
    - 至少重定向一条真实块回边。
    """
    if len(transitions) < _MIN_TRANSITIONS:
        return None
    preamble = _collect_entry_preamble(mlil, dispatcher_entry_start)
    if preamble is None:
        return None

    anchor = mlil[dispatcher_entry_start]
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
        if not fully_resolved:
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
            mlil, dispatcher_entry_start, route_starts, guard_label,
            any_route=False,
        )
        if redirected == 0:
            return None
    except Exception:
        return None
    return int(guard_label.operand)


def _redirect_edges_to_dispatcher(
    mlil: MediumLevelILFunction,
    dispatcher_entry_start: int,
    route_starts: Set[int],
    guard_label: MediumLevelILLabel,
    any_route: bool = False,
) -> int:
    """把真实块末尾回 dispatcher 的边重定向到 guard。

    any_route=False：只改 exact dispatcher_entry 的边（P3 guarded 兜底模式）。

    any_route=True：非 route 块中任何指向 route_starts 的边都改到 guard。
    仅用于 fully_resolved 且需要整体摘除 dispatcher 时；当前主流程仍以
    False 保守运行。
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
        allowed_targets = route_starts if any_route else {target_idx}
        try:
            if isinstance(last, MediumLevelILGoto):
                if last.dest not in allowed_targets:
                    continue
                new_label = MediumLevelILLabel()
                new_label.operand = guard_idx
                mlil.replace_expr(last.expr_index, mlil.goto(new_label, loc))
                redirected += 1
            elif isinstance(last, MediumLevelILIf):
                if last.true not in allowed_targets and last.false not in allowed_targets:
                    continue
                new_true = MediumLevelILLabel()
                new_true.operand = (
                    guard_idx if last.true in allowed_targets else last.true
                )
                new_false = MediumLevelILLabel()
                new_false.operand = (
                    guard_idx if last.false in allowed_targets else last.false
                )
                cond_copy = mlil.copy_expr(last.condition)
                new_if = mlil.if_expr(cond_copy, new_true, new_false, loc)
                mlil.replace_expr(last.expr_index, new_if)
                redirected += 1
        except Exception:
            continue
    return redirected


def _extract_state_set_chain(
    mlil: MediumLevelILFunction,
    start: int,
    dispatcher_entry_start: int,
    state_class: StateClass,
    side_effect_ops: Set,
    max_chain_blocks: int = 8,
) -> Optional[Tuple[int, List[MediumLevelILInstruction]]]:
    """沿无条件 goto 链收集从 start 到 dispatcher 入口的本地 SetVar 序列。

    返回 (最终 state 常量值, 需要重放的 SetVar 列表)，仅当：
    - 链上所有非终结指令都是无副作用 SetVar；
    - 每个块的终结都是 Goto，且最终回到 dispatcher_entry；
    - 链上至少出现一次 state class 的 const 赋值。

    这条链就是「条件状态赋值 + 返回 dispatcher 前数据搬运」的原文，之后会
    被完整复制到 mini-block，因此跳过链不会丢失任何本地数据更新。
    """
    replay: List[MediumLevelILInstruction] = []
    final_value: Optional[int] = None
    current = start
    visited: Set[int] = set()
    for _ in range(max_chain_blocks):
        if current in visited:
            return None
        visited.add(current)
        bb = mlil.get_basic_block_at(current)
        if bb is None or current != bb.start or bb.length == 0:
            return None

        for idx in range(bb.start, bb.end - 1):
            instr = mlil[idx]
            if _instruction_has_side_effect(instr, side_effect_ops):
                return None
            if not isinstance(instr, MediumLevelILSetVar):
                return None
            replay.append(instr)
            if (
                instr.dest.identifier in state_class.var_ids
                and isinstance(instr.src, MediumLevelILConst)
            ):
                final_value = instr.src.constant & mask(instr.size or 4)

        last = mlil[bb.end - 1]
        if _instruction_has_side_effect(last, side_effect_ops):
            return None
        if not isinstance(last, MediumLevelILGoto):
            # 条件状态赋值链出现分支，说明不是「单值确定」形态，保守拒绝
            return None
        if last.dest == dispatcher_entry_start:
            if final_value is None:
                return None
            return final_value, replay
        current = last.dest
    return None


def _rewrite_conditional_state_branches(
    mlil: MediumLevelILFunction,
    state_class: StateClass,
    transitions: Dict[int, int],
    dispatcher_entry_start: int,
    route_starts: Set[int],
    side_effect_ops: Set,
) -> int:
    """把 ``if (c) goto setA else goto setB`` 改写为直接的条件状态转移。

    模式：
        B: ...; if (c) goto A else goto C
        A: s = VA; ...; goto D; ...; goto dispatcher_entry
        C: s = VC; ...; goto dispatcher_entry

    改写为：
        B: ...; if (c) goto mini_A else goto mini_C
        mini_A: <A 链上 SetVar 副本...>; <dispatcher 前导副本...>; goto T(VA)

    安全保证：
    - A/C 链必须是无副作用 SetVar + 无条件 Goto，且最终回 dispatcher 入口；
    - VA/VC 必须已在 transitions 中完全解析；
    - A/C 链上的每个 SetVar 都被复制进 mini-block（顺序不变）；
    - dispatcher 入口前导也被复制，目标块不会缺少前导数据；
    - 只替换 B 中对应的 if 分支标签，B 的块体与条件原样保留。

    返回改写成功的分支数。
    """
    preamble = _collect_entry_preamble(mlil, dispatcher_entry_start)
    if preamble is None:
        return 0

    mini_cache: Dict[Tuple[Tuple[int, ...], int, int], MediumLevelILLabel] = {}
    rewritten = 0

    for b in list(mlil.basic_blocks):
        if b.start in route_starts or b.length == 0:
            continue
        last = mlil[b.end - 1]
        if not isinstance(last, MediumLevelILIf):
            continue

        branch_work = []
        for branch_target in (last.true, last.false):
            if branch_target == dispatcher_entry_start:
                continue
            extracted = _extract_state_set_chain(
                mlil,
                branch_target,
                dispatcher_entry_start,
                state_class,
                side_effect_ops,
            )
            if extracted is None:
                continue
            value, replay = extracted
            target_idx = transitions.get(value)
            if target_idx is None:
                continue
            branch_work.append((branch_target, value, replay, target_idx))

        if not branch_work:
            continue

        loc = ILSourceLocation.from_instruction(last)
        new_true = MediumLevelILLabel()
        new_false = MediumLevelILLabel()
        changed_true = False
        changed_false = False

        for branch_target, value, replay, target_idx in branch_work:
            key = (tuple(i.instr_index for i in replay), value, target_idx)
            cached_label = mini_cache.get(key)
            if cached_label is None:
                target_label = MediumLevelILLabel()
                target_label.operand = target_idx
                new_block_label = MediumLevelILLabel()
                mlil.mark_label(new_block_label)
                for instr in replay:
                    mlil.append(mlil.copy_expr(instr), loc)
                for instr in preamble:
                    mlil.append(mlil.copy_expr(instr), loc)
                mlil.append(mlil.goto(target_label, loc))
                cached_label = new_block_label
                mini_cache[key] = cached_label

            if branch_target == last.true:
                new_true.operand = cached_label.operand
                changed_true = True
            if branch_target == last.false:
                new_false.operand = cached_label.operand
                changed_false = True

        if not (changed_true or changed_false):
            continue

        # 未改写的分支保持原目标
        if not changed_true:
            new_true.operand = last.true
        if not changed_false:
            new_false.operand = last.false

        try:
            new_if = mlil.if_expr(
                mlil.copy_expr(last.condition),
                new_true,
                new_false,
                loc,
            )
            mlil.replace_expr(last.expr_index, new_if)
            rewritten += 1
        except Exception:
            continue

    return rewritten


def _shortcircuit_safe_state_defines(
    mlil: MediumLevelILFunction,
    state_class: StateClass,
    transitions: Dict[int, int],
    dispatcher_entry_start: int,
) -> Tuple[int, Set[int]]:
    """对「定义在块尾且块终结直接回 dispatcher 入口」的 state=const 做短路。

    只处理这一种形态：
        ...; primary = V; goto dispatcher_entry
    重写为：
        ...; goto mini;  mini: primary = V; <dispatcher 前导拷贝...>; goto T(V)

    安全性：
    - 原 state 写入保留在 mini-block；
    - dispatcher 入口前导被复制进 mini-block，目标块不会缺少 alias/result
      等前导值；
    - 只删除一条 goto dispatcher_entry，不跳过任何真实块指令；
    - 若 dispatcher 前导不可重放（非 idempotent SetVar），本函数直接放弃。

    返回 (patch 数, 新建 mini-block label operand 集合)。
    """
    if not transitions:
        return 0, set()
    preamble = _collect_entry_preamble(mlil, dispatcher_entry_start)
    if preamble is None:
        return 0, set()

    cache: Dict[Tuple[int, int, int], MediumLevelILLabel] = {}
    mini_label_ops: Set[int] = set()
    patched = 0

    for instr in list(mlil.instructions):
        if not isinstance(instr, MediumLevelILSetVar):
            continue
        if instr.dest.identifier not in state_class.var_ids:
            continue
        if not isinstance(instr.src, MediumLevelILConst):
            continue
        value = instr.src.constant & mask(instr.size or 4)
        target_idx = transitions.get(value)
        if target_idx is None:
            continue

        bb = mlil.get_basic_block_at(instr.instr_index)
        if bb is None:
            continue
        # 只接受「define 是块内最后一条非终结指令」的形态
        if instr.instr_index != bb.end - 2:
            continue
        last = mlil[bb.end - 1]
        if not isinstance(last, MediumLevelILGoto):
            continue
        if last.dest != dispatcher_entry_start:
            continue

        key = (instr.dest.identifier, value, target_idx)
        cached_label = cache.get(key)
        loc = ILSourceLocation.from_instruction(instr)
        try:
            if cached_label is None:
                target_label = MediumLevelILLabel()
                target_label.operand = target_idx
                new_block_label = MediumLevelILLabel()
                mlil.mark_label(new_block_label)
                # 原顺序：先 state 写入，再 dispatcher 入口前导，再路由
                mlil.append(mlil.copy_expr(instr), loc)
                for preamble_instr in preamble:
                    mlil.append(mlil.copy_expr(preamble_instr), loc)
                mlil.append(mlil.goto(target_label, loc))
                cached_label = new_block_label
                cache[key] = cached_label
                mini_label_ops.add(int(new_block_label.operand))
            mlil.replace_expr(
                instr.expr_index,
                mlil.goto(cached_label, loc),
            )
            patched += 1
        except Exception:
            continue
    return patched, mini_label_ops


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

    state_classes = find_state_classes(mlil, dispatcher_entry)
    if not state_classes:
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

    # 多候选策略：逐个状态类解析，选择 resolved 最多、target 分散的候选。
    # 多状态元组联合分发暂未合成，但至少不会再被「unique 数最多的单变量
    # 启发式」卡死在错误的 primary 上。
    chosen: Optional[Tuple[StateClass, Set[int], Dict[int, int]]] = None
    for state_class in state_classes:
        if time.time() > deadline:
            break
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
            continue
        if len(set(transitions.values())) < 2:
            continue
        quality = (len(transitions), len(set(transitions.values())))
        if chosen is None or quality > (len(chosen[2]), len(set(chosen[2].values()))):
            chosen = (state_class, route_starts, transitions)

    if chosen is None:
        log_info(
            f"[general] {fname}: no qualifying state class "
            f"(candidates={len(state_classes)})"
        )
        return False

    state_class, route_starts, transitions = chosen

    # N 状态元组尝试（N≥2）：仅当联合解析比单候选解析出更多组合时启用。
    # secondary 允许只有 2 个值，因此用宽松启发式补充候选。
    tuple_chosen: Optional[
        Tuple[List[StateClass], StateClass, Set[int], Dict[Tuple, int]]
    ] = None
    if time.time() <= deadline:
        extra_classes = list(state_classes)
        if len(extra_classes) < 2:
            extra_classes = find_state_classes(
                mlil, dispatcher_entry, require_cff_heuristic=False, limit=4
            )
        extra_pool = [
            c for c in extra_classes
            if c.primary.identifier not in state_class.var_ids
        ]
        # 尝试 [primary]+1 到 [primary]+3 个 secondary
        for width in range(1, min(3, len(extra_pool)) + 1):
            tuple_classes = [state_class] + extra_pool[:width]
            combo_count = 1
            for cls in tuple_classes:
                combo_count *= len(cls.assigned_values)
            if combo_count > 4096:
                continue
            combined = _combine_state_classes_many(tuple_classes)
            tuple_route = _classify_route_blocks(
                mlil,
                dispatcher_scc,
                dispatcher_entry.start,
                combined,
                _SIDE_EFFECT_OPS,
            )
            tuple_route.add(dispatcher_entry.start)
            tuple_trans = _resolve_dispatch_map_ntuple(
                mlil,
                tuple_classes,
                combined,
                tuple_route,
                dispatcher_entry.start,
                _SIDE_EFFECT_OPS,
                deadline,
            )
            if (
                len(tuple_trans) >= _MIN_TRANSITIONS
                and len(set(tuple_trans.values())) >= 2
                and len(tuple_trans) > len(transitions)
            ):
                quality = (
                    len(tuple_trans),
                    -combo_count,
                    len(set(tuple_trans.values())),
                )
                if tuple_chosen is None or quality > (
                    len(tuple_chosen[3]),
                    -sum(
                        len(c.assigned_values)
                        for c in tuple_chosen[0]
                    ),
                    len(set(tuple_chosen[3].values())),
                ):
                    tuple_chosen = (
                        tuple_classes, combined, tuple_route, tuple_trans
                    )

    # case_values 覆盖检查：dispatcher SCC 内全部状态比较常量
    if tuple_chosen is not None:
        classes_c, combined_c, route_c, trans_c = tuple_chosen
        case_values = collect_state_case_values(
            mlil, combined_c, dispatcher_scc
        )
    else:
        case_values = collect_state_case_values(mlil, state_class, dispatcher_scc)

    if tuple_chosen is not None:
        # tuple 模式：暂不做条件分支/短路改写，先保证联合分发的 switch 形态
        classes_c, combined_c, route_c, trans_c = tuple_chosen
        n_cond = 0
        n_short = 0
        mini_ops: Set[int] = set()
        total_combos = 1
        for cls in classes_c:
            total_combos *= len(cls.assigned_values)
        tuple_fully_resolved = len(trans_c) == total_combos
        if len(classes_c) == 2:
            guard_label_op = _install_tuple_guarded_jump_to(
                mlil,
                classes_c[0],
                classes_c[1],
                trans_c,
                case_values,
                dispatcher_entry.start,
                route_c,
                fully_resolved=tuple_fully_resolved,
            )
        else:
            guard_label_op = _install_ntuple_guarded_jump_to(
                mlil,
                classes_c,
                trans_c,
                case_values,
                dispatcher_entry.start,
                route_c,
            )
        log_tag = "tuple(" + ",".join(c.primary.name for c in classes_c) + ")"
        resolved_count = len(trans_c)
    else:
        # 条件状态赋值改写：if(c) s=A else s=B → if(c) goto mini_A else goto mini_B
        n_cond = _rewrite_conditional_state_branches(
            mlil,
            state_class,
            transitions,
            dispatcher_entry.start,
            route_starts,
            _SIDE_EFFECT_OPS,
        )

        # 再短路 tail state defines：必须在 redirect 之前做，否则真实块的
        # goto dispatcher 已经被改成 goto guard，形态检测不到
        n_short, mini_ops = _shortcircuit_safe_state_defines(
            mlil, state_class, transitions, dispatcher_entry.start
        )

        single_fully_resolved = set(state_class.assigned_values) <= set(
            transitions.keys()
        )
        guard_label_op = _install_preamble_guarded_jump_to(
            mlil,
            state_class,
            transitions,
            case_values,
            dispatcher_entry.start,
            route_starts,
            fully_resolved=single_fully_resolved,
        )
        log_tag = f"primary={state_class.primary.name}"
        resolved_count = len(transitions)
    if guard_label_op is None:
        log_info(f"[general] {fname}: P3 install failed")
        return False

    mlil.finalize()
    mlil.generate_ssa_form()

    side_effects_after = _collect_side_effect_signatures(mlil)
    _verify_no_side_effect_loss(side_effects_before, side_effects_after, fname)
    log_info(
        f"[general] {fname}: P3 installed guard=0x{guard_label_op:x} "
        f"mode={log_tag} transitions={resolved_count} "
        f"case_values={len(case_values)} "
        f"cond_rewritten={n_cond} shortcircuited={n_short} "
        f"miniblocks={len(mini_ops)}"
    )
    return True
