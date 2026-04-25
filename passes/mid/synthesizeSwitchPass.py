"""把 CFF dispatcher 重构为 MLIL JUMP_TO，让 BN 4.1+ 的 HLIL restructurer
显示成 switch-case 结构。

设计动机（参见 docs/pass_evaluation.md §2）：
  当前 deflate_hard 把每个 state SetVar=const 直接 patch 成 goto target，
  最终 HLIL 是一堆 goto 链，可读性中等。
  HLIL Restructurer (https://binary.ninja/2024/06/19/...) 已经能把 jump
  table 还原为 switch-case，但只针对编译器生成的合法 switch，不针对
  OLLVM cmp-tree dispatcher。

  本 pass 的思路：
  1. 用 deflate_hard 同样的 SCC + 副作用筛选识别 dispatcher 子图与 state
     变量
  2. 对每个 state SetVar=const，前向模拟到对应的真实块入口，建立
     {state_value → real_block_start} 映射
  3. 把 dispatcher_entry 块的第一条指令替换为
     `jump_to(state_var, {value: label})`，让 BN MLIL 把 dispatcher 看成
     带 N 个目标的 switch
  4. 同时 *保留* 真实块尾部的 `state = const; goto dispatcher` 不动，让
     state 值能正确流到 jump_to 的 dest

  这跟 deflate_hard 是 *互斥替代*：deflate 把 dispatcher 绕掉，本 pass 把
  dispatcher 重构成 switch。用户可在 mikuWorkflow.py 选其中一个。

形式化等价性：
  jump_to(state_var, {V → handler_V}) 在语义上等价于原 dispatcher 的
  if-tree 串联（已验证 _function_looks_like_cff 后我们知道每个 V 都对应
  唯一 handler，dispatcher 的 if-tree 也是把 state 路由到唯一 handler）。
  只要 forward-simulate 给出的 (V → handler) 映射正确，重构后的执行 trace
  与原 trace 在副作用层面等价。
"""

import time
from typing import Dict, Optional

from binaryninja import (
    AnalysisContext,
    ILSourceLocation,
    MediumLevelILBasicBlock,
    MediumLevelILConst,
    MediumLevelILFunction,
    MediumLevelILIf,
    MediumLevelILLabel,
    MediumLevelILSetVar,
    MediumLevelILVar,
)

from .deflatHardPass import (
    _collect_side_effect_signatures,
    _collect_state_vars,
    _detect_dispatcher_entry,
    _forward_resolve,
    _function_looks_like_cff,
    _identify_dispatcher_subgraph,
    _mask,
    _verify_no_side_effect_loss,
)

_TIME_BUDGET_SECONDS = 15.0
_MIN_TRANSITIONS = 2
_MAX_SWITCH_ITERS = 8  # 嵌套 dispatcher 最多重构 8 层（实测 sub_407368 有 3+ 层）


def _candidate_state_vars_ranked(
    mlil: MediumLevelILFunction,
    state_vars,
):
    """返回按 unique 常量赋值数排序的状态变量列表 (从多到少)。允许调用方
    依次尝试每一个，避免单一启发式失败时整个 pass 放弃。
    """
    if not state_vars:
        return []
    unique_vals: Dict = {var: set() for var in state_vars}
    for instr in mlil.instructions:
        if (
            isinstance(instr, MediumLevelILSetVar)
            and instr.dest in state_vars
            and isinstance(instr.src, MediumLevelILConst)
        ):
            unique_vals[instr.dest].add(
                instr.src.constant & _mask(instr.size or 4)
            )
    return sorted(
        [v for v, s in unique_vals.items() if len(s) >= 2],
        key=lambda v: -len(unique_vals[v]),
    )


def _collect_transitions_for_var(
    mlil: MediumLevelILFunction,
    primary,
    state_vars,
    dispatcher_blocks,
    dispatcher_entry_start: int,
    deadline: float,
) -> "Dict[int, int]":
    transitions: Dict[int, int] = {}
    for instr in mlil.instructions:
        if time.time() > deadline:
            break
        if (
            not isinstance(instr, MediumLevelILSetVar)
            or instr.dest != primary
            or not isinstance(instr.src, MediumLevelILConst)
        ):
            continue
        target = _forward_resolve(mlil, instr, state_vars, dispatcher_blocks)
        if target is None:
            continue
        if target == dispatcher_entry_start:
            continue
        target_bb = mlil.get_basic_block_at(target)
        if target_bb is None or target != target_bb.start:
            continue
        if target_bb.start in dispatcher_blocks:
            continue
        value = instr.src.constant & _mask(instr.size or 4)
        transitions.setdefault(value, target)
    return transitions


def _try_synthesize_one_dispatcher(
    mlil: MediumLevelILFunction,
    deadline: float,
    already_rewritten: set,
) -> bool:
    """识别一个 dispatcher 并把它重构为 jump_to。返回是否做了修改。

    通过 already_rewritten 集合跳过本次 pass 已经重构过的 dispatcher
    (按 dispatcher_entry.start 标识)，避免反复尝试同一个。

    multi-候选策略：依次尝试 unique 常量赋值数最多的 state var 作为 dispatch
    primary，第一个能给出 ≥_MIN_TRANSITIONS 个 distinct target 的就用它。
    """
    dispatcher_entry = _detect_dispatcher_entry(mlil, exclude=already_rewritten)
    if dispatcher_entry is None:
        return False
    state_vars = _collect_state_vars(mlil, dispatcher_entry)
    if not state_vars:
        return False
    if not _function_looks_like_cff(mlil, state_vars):
        return False
    dispatcher_blocks = _identify_dispatcher_subgraph(
        mlil, dispatcher_entry, state_vars
    )
    if not dispatcher_blocks:
        return False

    # 依次尝试每个候选 state var，选第一个能产出 ≥2 distinct target 的
    primary = None
    transitions: Dict[int, int] = {}
    for candidate in _candidate_state_vars_ranked(mlil, state_vars):
        if time.time() > deadline:
            break
        cand_trans = _collect_transitions_for_var(
            mlil, candidate, state_vars, dispatcher_blocks,
            dispatcher_entry.start, deadline,
        )
        if len(cand_trans) >= _MIN_TRANSITIONS and len(set(cand_trans.values())) >= 2:
            primary = candidate
            transitions = cand_trans
            break

    if primary is None:
        return False

    try:
        label_map: Dict[int, MediumLevelILLabel] = {}
        for value, target_idx in transitions.items():
            label = MediumLevelILLabel()
            label.operand = target_idx
            label_map[value] = label

        first_instr = mlil[dispatcher_entry.start]
        size = primary.type.width if primary.type else 4
        dest_expr = mlil.var(
            size,
            primary,
            ILSourceLocation.from_instruction(first_instr),
        )
        jump_to_expr = mlil.jump_to(
            dest_expr,
            label_map,
            ILSourceLocation.from_instruction(first_instr),
        )
        mlil.replace_expr(first_instr.expr_index, jump_to_expr)
    except Exception:
        return False

    already_rewritten.add(dispatcher_entry.start)
    mlil.finalize()
    mlil.generate_ssa_form()
    return True


def pass_synthesize_switch(analysis_context: AnalysisContext) -> None:
    """多迭代 synthesize_switch：每次重构一个 dispatcher。第一遍通常是最
    外层 dispatcher，重构后内层（嵌套）dispatcher 成为新的 detect 候选，
    第二遍处理内层，依此类推。最多 _MAX_SWITCH_ITERS 层。

    对应 sub_407368 这种"外层 switch x8, case 内含内层 switch i"的多层
    OLLVM CFF。
    """
    function = analysis_context.function
    mlil = function.mlil
    if mlil is None:
        return

    side_effects_before = _collect_side_effect_signatures(mlil)
    function_name = function.name

    deadline = time.time() + _TIME_BUDGET_SECONDS
    already_rewritten: set = set()

    for _ in range(_MAX_SWITCH_ITERS):
        if time.time() > deadline:
            break
        if not _try_synthesize_one_dispatcher(mlil, deadline, already_rewritten):
            break

    side_effects_after = _collect_side_effect_signatures(mlil)
    _verify_no_side_effect_loss(side_effects_before, side_effects_after, function_name)
