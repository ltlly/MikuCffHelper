from binaryninja import (
    MediumLevelILFunction,
    MediumLevelILGoto,
    AnalysisContext,
    MediumLevelILLabel,
    MediumLevelILIf,
    MediumLevelILInstruction
)
from ...utils import log_info, ILSourceLocation


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

        # 递归处理连续goto
        final_target = optimize_goto(target_instr)
        log_info(
            f"Optimized goto {goto_instr.instr_index} to target {final_target.instr_index}")
        return final_target
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
            new_goto = mlil.goto(
                label, ILSourceLocation.from_instruction(goto_instr))
            updated = True
            mlil.replace_expr(goto_instr.expr_index, new_goto)
        if updated:
            # 更新MLIL
            mlil.finalize()
            mlil.generate_ssa_form()
        else:
            break
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

    for _ in range(len(mlil.basic_blocks)):
        updated = False
        for bb in mlil.basic_blocks:
            if_instr = bb[-1]

            if not isinstance(if_instr, MediumLevelILIf):
                continue
            true_target = get_final_target(mlil[if_instr.true])
            false_target = get_final_target(mlil[if_instr.false])

            if true_target.instr_index != if_instr.true or false_target.instr_index != if_instr.false:
                true_label = MediumLevelILLabel()
                false_label = MediumLevelILLabel()
                true_label.operand = true_target.instr_index
                false_label.operand = false_target.instr_index
                # 创建新的if指令
                new_if = mlil.if_expr(
                    mlil.copy_expr(if_instr.condition,ILSourceLocation.from_instruction(if_instr)),
                    true_label,
                    false_label,
                    ILSourceLocation.from_instruction(if_instr)
                )
                mlil.replace_expr(if_instr.expr_index, new_if)
                updated = True

        if updated:
            mlil.finalize()
            mlil.generate_ssa_form()
        else:
            break

    mlil.finalize()
    mlil.generate_ssa_form()


def pass_clear(analysis_context: AnalysisContext):
    pass_clear_goto(analysis_context)
    pass_clear_if(analysis_context)
