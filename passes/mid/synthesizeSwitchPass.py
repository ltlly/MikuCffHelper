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
_MIN_TRANSITIONS = 3


def _find_primary_state_var(
    mlil: MediumLevelILFunction,
    state_vars,
):
    """挑选被赋予最多 unique 常量值的状态变量作为 jump_to 的 dispatch 变量。

    sub_4075a0 上原本"取 dispatcher_entry 第一条 if 左操作数"会选到 fp
    (frame pointer)，因为 fp 也被 const-compare 了几次。改为按 unique 常量
    赋值数排序更可靠 —— 真正的 CFF 状态变量必然被赋值很多次。
    """
    if not state_vars:
        return None
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
    # 取 unique 值最多的
    best = max(unique_vals, key=lambda v: len(unique_vals[v]))
    if len(unique_vals[best]) < 3:
        return None
    return best


def pass_synthesize_switch(analysis_context: AnalysisContext) -> None:
    function = analysis_context.function
    mlil = function.mlil
    if mlil is None:
        return

    side_effects_before = _collect_side_effect_signatures(mlil)
    function_name = function.name

    deadline = time.time() + _TIME_BUDGET_SECONDS

    # 1. 检测 CFF
    dispatcher_entry = _detect_dispatcher_entry(mlil)
    if dispatcher_entry is None:
        return
    state_vars = _collect_state_vars(mlil, dispatcher_entry)
    if not state_vars:
        return
    if not _function_looks_like_cff(mlil, state_vars):
        return
    dispatcher_blocks = _identify_dispatcher_subgraph(
        mlil, dispatcher_entry, state_vars
    )
    if not dispatcher_blocks:
        return

    # 2. 选 primary state var (unique const 赋值数最多的)
    primary = _find_primary_state_var(mlil, state_vars)
    if primary is None:
        return

    # 3. 收集 (state_value → target instr_index) 映射
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
        # 必须是真实块入口
        target_bb = mlil.get_basic_block_at(target)
        if target_bb is None or target != target_bb.start:
            continue
        if target_bb.start in dispatcher_blocks:
            continue
        value = instr.src.constant & _mask(instr.size or 4)
        # 同 value 多次出现取第一个（应一致）
        transitions.setdefault(value, target)

    if len(transitions) < _MIN_TRANSITIONS:
        return

    # 4. 构造 jump_to(primary, label_map) 替换 dispatcher_entry 入口指令
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
        return

    mlil.finalize()
    mlil.generate_ssa_form()

    # 等价性验证
    side_effects_after = _collect_side_effect_signatures(mlil)
    _verify_no_side_effect_loss(side_effects_before, side_effects_after, function_name)
