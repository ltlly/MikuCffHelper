from typing import List
from binaryninja import (
    MediumLevelILCmpE,
    MediumLevelILFunction,
    MediumLevelILGoto,
    AnalysisContext,
    MediumLevelILLabel,
    MediumLevelILIf,
    MediumLevelILInstruction,
    MediumLevelILConst,
    MediumLevelILSetVar,
    MediumLevelILVar,
    ILSourceLocation,
)

from ...utils.state_machine import StateMachine
from ...utils import CFGAnalyzer
from ...utils.cfg_analyzer import CFGIndex
from ...utils import log_error


def pass_clear_const_if(analysis_context: AnalysisContext):
    """
    清除常量条件if语句的优化pass

    该pass用于优化MLIL将if(true) 与 if(false)语句替换为直接跳转。
    通过消除不必要的条件判断来简化控制流图。
    参数：
        analysis_context: 包含MLIL中间表示的分析上下文
    返回值：
        无
    """
    mlil = analysis_context.mlil
    any_updated = False
    for _ in range(len(mlil.basic_blocks)):
        updated = False
        for bb in mlil.basic_blocks:
            if_instr = bb[-1]
            if not isinstance(if_instr, MediumLevelILIf):
                continue
            condition = if_instr.condition
            if not isinstance(condition, MediumLevelILConst):
                continue
            const_val = condition.constant
            if const_val not in (0, 1):
                continue
            label = MediumLevelILLabel()
            label.operand = if_instr.true if const_val else if_instr.false
            goto_instr = mlil.goto(label, ILSourceLocation.from_instruction(if_instr))
            mlil.replace_expr(if_instr.expr_index, goto_instr)
            updated = True
        if updated:
            any_updated = True
            mlil.finalize()
            mlil.generate_ssa_form()
        else:
            break
    # 完全没改过就不再 finalize/generate_ssa_form，减少 pass_clear 链上的
    # 重复 SSA 重建（多个子 pass 常连续无更新）。
    if any_updated:
        mlil.finalize()
        mlil.generate_ssa_form()


def pass_clear_SSA_const_if(analysis_context: AnalysisContext):
    """
    清除可以通过SSA推断出是const的if

    >>> current_il_instruction
    <MediumLevelILIf: if (state-1#5 == 0xc176f739) then 61 @ 0x403bec else 62 @ 0x403bd0>
    >>> current_il_instruction.condition.left
    <MediumLevelILVarSsa: state-1#5>
    >>> current_mlil.get_ssa_var_definition(_)
    <MediumLevelILSetVar: state-1 = -0x3e8908c7>
    参数：
        analysis_context: 包含MLIL中间表示的分析上下文
    返回值：
        无
    """
    mlil = analysis_context.mlil
    function = analysis_context.function
    # state_vars 在多次外层迭代间不变，提到循环外避免每轮全函数扫描
    state_vars = StateMachine.find_state_var(function)
    any_updated = False
    for _ in range(len(mlil.basic_blocks)):
        updated = False
        for bb in mlil.basic_blocks:
            if_instr = bb[-1]
            if not isinstance(if_instr, MediumLevelILIf):
                continue
            condition = if_instr.condition
            if not isinstance(condition, MediumLevelILCmpE):
                continue
            if not hasattr(condition, "left"):
                continue
            left_il_var = condition.left
            if not isinstance(left_il_var, MediumLevelILVar):
                continue
            if left_il_var.var not in state_vars:
                continue
            right_const_il = condition.right
            if not isinstance(right_const_il, MediumLevelILConst):
                continue

            if_val = right_const_il.constant & 0xFFFFFFFF

            state_il_var = left_il_var
            state_il_var_ssa = state_il_var.ssa_form

            def_instr = mlil.get_ssa_var_definition(state_il_var_ssa)
            if not isinstance(def_instr, MediumLevelILSetVar):
                continue
            if not isinstance(def_instr.src, MediumLevelILConst):
                continue
            if def_instr.dest.type.width != 4:
                continue
            define_val = def_instr.src.constant & 0xFFFFFFFF
            const_val = if_val == define_val
            label = MediumLevelILLabel()
            label.operand = if_instr.true if const_val else if_instr.false
            goto_instr = mlil.goto(label, ILSourceLocation.from_instruction(if_instr))
            mlil.replace_expr(if_instr.expr_index, goto_instr)
            updated = True
        if updated:
            any_updated = True
            mlil.finalize()
            mlil.generate_ssa_form()
        else:
            break
    if any_updated:
        mlil.finalize()
        mlil.generate_ssa_form()


def pass_clear_goto(analysis_context: AnalysisContext):
    """
    优化连续goto结构的Pass

    该Pass用于优化MLIL中的连续goto结构：
    若goto的目标仍为goto，则将第一个goto的目标直接指向最终的非goto目标，
    递归处理直至目标不再是goto，确保所有连续goto被优化为单一跳转。

    参数：
        analysis_context: 包含MLIL中间表示的分析上下文
    返回值：
        无
    """
    mlil = analysis_context.mlil

    def optimize_goto(goto_instr):
        """
        递归优化goto指令
        """
        target_instr = mlil[goto_instr.dest]
        if not isinstance(target_instr, MediumLevelILGoto):
            return target_instr
        final_target = optimize_goto(target_instr)
        return final_target

    any_updated = False
    for _ in range(len(mlil.basic_blocks)):
        updated = False
        # 遍历所有基本块
        for bb in mlil.basic_blocks:
            goto_instr = bb[-1]
            if not isinstance(goto_instr, MediumLevelILGoto):
                continue
            final_target_instr = optimize_goto(goto_instr)
            if final_target_instr.instr_index == goto_instr.dest:
                continue
            # 创建新的goto指令指向最终目标
            label = MediumLevelILLabel()
            label.operand = final_target_instr.instr_index
            new_goto = mlil.goto(label, ILSourceLocation.from_instruction(goto_instr))
            updated = True
            mlil.replace_expr(goto_instr.expr_index, new_goto)
        if updated:
            # 更新MLIL
            any_updated = True
            mlil.finalize()
            mlil.generate_ssa_form()
        else:
            break
    if any_updated:
        mlil.finalize()
        mlil.generate_ssa_form()


def pass_clear_if(analysis_context: AnalysisContext):
    """
    优化if语句中指向goto的分支

    当if语句的then或else分支指向goto时，直接修改为指向goto的目标
    """
    mlil = analysis_context.mlil

    def get_final_target(instr) -> MediumLevelILInstruction:
        """
        获取指令的最终目标，处理连续goto
        """
        if isinstance(instr, MediumLevelILGoto):
            return get_final_target(mlil[instr.dest])
        return instr

    any_updated = False
    for _ in range(len(mlil.basic_blocks)):
        updated = False
        for bb in mlil.basic_blocks:
            if_instr = bb[-1]
            if not isinstance(if_instr, MediumLevelILIf):
                continue
            true_target = get_final_target(mlil[if_instr.true])
            false_target = get_final_target(mlil[if_instr.false])
            if (
                true_target.instr_index != if_instr.true
                or false_target.instr_index != if_instr.false
            ):
                true_label = MediumLevelILLabel()
                false_label = MediumLevelILLabel()
                true_label.operand = true_target.instr_index
                false_label.operand = false_target.instr_index
                new_if = mlil.if_expr(
                    mlil.copy_expr(if_instr.condition),
                    true_label,
                    false_label,
                    ILSourceLocation.from_instruction(if_instr),
                )
                mlil.replace_expr(if_instr.expr_index, new_if)
                updated = True
                break
        if updated:
            any_updated = True
            mlil.finalize()
            mlil.generate_ssa_form()
        else:
            break

    if any_updated:
        mlil.finalize()
        mlil.generate_ssa_form()


def merge_block(
    mlil: MediumLevelILFunction,
    instrs: List[MediumLevelILInstruction],
    pre_instrs: List[MediumLevelILInstruction],
) -> bool:
    # Validate pre_instrs types
    if pre_instrs and any(
        not isinstance(instr, (MediumLevelILGoto, MediumLevelILIf))
        for instr in pre_instrs
    ):
        log_error(f"Invalid predecessor instructions: {pre_instrs}")
        return False

    if not instrs:
        return False

    # Create label for merged block start
    merged_label = MediumLevelILLabel()
    mlil.mark_label(merged_label)
    merged_operand = merged_label.operand

    # Copy instructions to new block
    for instr in instrs:
        mlil.append(mlil.copy_expr(instr))

    # Redirect control flow from predecessors
    for pre_instr in pre_instrs:
        if isinstance(pre_instr, MediumLevelILGoto):
            # Replace Goto with jump to merged block
            new_goto = mlil.goto(
                merged_label, ILSourceLocation.from_instruction(pre_instr)
            )
            mlil.replace_expr(pre_instr.expr_index, new_goto)

        elif isinstance(pre_instr, MediumLevelILIf):
            target_index = instrs[0].instr_index
            true_idx, false_idx = pre_instr.true, pre_instr.false

            # Validate branch targets
            if target_index not in (true_idx, false_idx):
                raise ValueError("If statement branches don't target merged block")

            # Create labels with appropriate targets
            def create_label(original_idx: int) -> MediumLevelILLabel:
                label = MediumLevelILLabel()
                label.operand = (
                    merged_operand if original_idx == target_index else original_idx
                )
                return label

            true_label = create_label(true_idx)
            false_label = create_label(false_idx)

            # Create replacement If expression
            new_cond = mlil.copy_expr(pre_instr.condition)
            new_if = mlil.if_expr(
                new_cond,
                true_label,
                false_label,
                ILSourceLocation.from_instruction(pre_instr),
            )
            mlil.replace_expr(pre_instr.expr_index, new_if)

    return True


def pass_merge_block(analysis_context: AnalysisContext):
    "合并连续几个dirct block 为一个block"
    mlil = analysis_context.mlil
    if mlil is None:
        return
    any_updated = False
    for _ in range(len(mlil.basic_blocks)):
        index = CFGIndex(mlil)
        groups = CFGAnalyzer.find_cfg_groups(index.graph)
        updated = False
        for group in groups:
            # 因为函数必须从0开始, 如果要求合并的话 需要特殊处理0部分,因此不处理
            if group[0] == 0:
                group.pop(0)
            blocks = [mlil.get_basic_block_at(idx) for idx in group]
            block0 = blocks[0]
            pre_blocks = index.incoming_blocks(block0.start)
            pre_instrs = [x[-1] for x in pre_blocks]
            instrs = []
            for x in blocks[:-1]:
                instrs += list(x)[:-1]
            instrs += list(blocks[-1])
            if merge_block(mlil, instrs, pre_instrs):
                updated = True
        if updated:
            any_updated = True
            mlil.finalize()
            mlil.generate_ssa_form()
        else:
            break
    if any_updated:
        mlil.finalize()
        mlil.generate_ssa_form()


def handle_pre_last_instr(mlil: MediumLevelILFunction, pre_last_instr, bb, copy_label):
    if isinstance(pre_last_instr, MediumLevelILGoto):
        mlil.replace_expr(
            pre_last_instr.expr_index,
            mlil.goto(copy_label, ILSourceLocation.from_instruction(pre_last_instr)),
        )
    elif isinstance(pre_last_instr, MediumLevelILIf):
        true_target = pre_last_instr.true
        false_target = pre_last_instr.false
        if true_target == bb.start:
            fix_false_label = MediumLevelILLabel()
            fix_false_label.operand = false_target
            mlil.replace_expr(
                pre_last_instr.expr_index,
                mlil.if_expr(
                    mlil.copy_expr(
                        pre_last_instr.condition,
                    ),
                    copy_label,
                    fix_false_label,
                    ILSourceLocation.from_instruction(pre_last_instr),
                ),
            )
        elif false_target == bb.start:
            fix_true_label = MediumLevelILLabel()
            fix_true_label.operand = true_target
            mlil.replace_expr(
                pre_last_instr.expr_index,
                mlil.if_expr(
                    mlil.copy_expr(
                        pre_last_instr.condition,
                    ),
                    fix_true_label,
                    copy_label,
                    ILSourceLocation.from_instruction(pre_last_instr),
                ),
            )
        else:
            log_error("ERROR IF")
    else:
        log_error("ERROR")


def pass_clear(analysis_context: AnalysisContext):
    """当前 clear pipeline：
    - 不使用 pass_copy_common_block_mid（LLIL 已做过同样的事，MLIL 再做易膨胀）
    - pass_swap_if 已移除：39 函数 A/B 回归输出完全一致，且省一次全函数
      扫描 + 潜在 swap 重写（见 AGENTS.md）
    - pass_clear_SSA_const_if 保留：A/B 移除后 sub_4075a0 HLIL 4→19、
      sub_407994 26→39，对收敛仍必需
    """
    pass_clear_const_if(analysis_context)
    pass_clear_goto(analysis_context)
    pass_clear_if(analysis_context)
    pass_merge_block(analysis_context)
    pass_clear_SSA_const_if(analysis_context)
