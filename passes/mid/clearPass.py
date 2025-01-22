from binaryninja import (
    MediumLevelILFunction,
    MediumLevelILGoto,
    AnalysisContext,
    MediumLevelILLabel,
    MediumLevelILIf,
    MediumLevelILInstruction,
    MediumLevelILConst,
    MediumLevelILBasicBlock,
    MediumLevelILRet,
)
from ...utils import log_info, ILSourceLocation, CFGAnalyzer
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
    for _ in range(len(mlil.basic_blocks)):
        updated = False
        for bb in mlil.basic_blocks:
            if not isinstance(bb[-1], MediumLevelILIf):
                continue
            if_instr = bb[-1]
            condition = if_instr.condition
            if not isinstance(condition, MediumLevelILConst):
                continue
            label = MediumLevelILLabel()
            if condition.constant == 1:
                label.operand = if_instr.true
            elif condition.constant == 0:
                label.operand = if_instr.false
            else:
                continue
            goto_instr = mlil.goto(label, ILSourceLocation.from_instruction(if_instr))
            mlil.replace_expr(if_instr.expr_index, goto_instr)
            updated = True
        if updated:
            mlil.finalize()
            mlil.generate_ssa_form()
        else:
            break
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

        # 递归处理连续goto
        final_target = optimize_goto(target_instr)
        log_info(
            f"Optimized goto {goto_instr.instr_index} to target {final_target.instr_index}"
        )
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
            new_goto = mlil.goto(label, ILSourceLocation.from_instruction(goto_instr))
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

            if (
                true_target.instr_index != if_instr.true
                or false_target.instr_index != if_instr.false
            ):
                true_label = MediumLevelILLabel()
                false_label = MediumLevelILLabel()
                true_label.operand = true_target.instr_index
                false_label.operand = false_target.instr_index
                # 创建新的if指令
                new_if = mlil.if_expr(
                    mlil.copy_expr(
                        if_instr.condition, ILSourceLocation.from_instruction(if_instr)
                    ),
                    true_label,
                    false_label,
                    ILSourceLocation.from_instruction(if_instr),
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


def pass_merge_block(analysis_context: AnalysisContext):
    mlil = analysis_context.mlil
    if mlil is None:
        return

    def merge_block(
        block: MediumLevelILBasicBlock, next_block: MediumLevelILBasicBlock
    ) -> bool:
        log_info("merrrrrrrrrrrrrrrrrr")
        pre_blocks = CFGAnalyzer.MLIL_get_incoming_blocks(mlil, block.start)
        pre_instrs = [prebb[-1] for prebb in pre_blocks]
        if not all(
            isinstance(instr, MediumLevelILGoto) or isinstance(instr, MediumLevelILIf)
            for instr in pre_instrs
        ):
            log_error(f"eeeee {pre_instrs}")
            return False

        label = MediumLevelILLabel()
        mlil.mark_label(label)
        for i in range(block.start, block.end - 1):
            instr = mlil[i]
            mlil.append(mlil.copy_expr(instr, ILSourceLocation.from_instruction(instr)))
        for i in range(next_block.start, next_block.end):
            instr = mlil[i]
            mlil.append(mlil.copy_expr(instr, ILSourceLocation.from_instruction(instr)))
        for pre_instr in pre_instrs:
            if isinstance(pre_instr, MediumLevelILGoto):
                mlil.replace_expr(
                    pre_instr.instr_index,
                    mlil.goto(label, ILSourceLocation.from_instruction(pre_instr)),
                )
            elif isinstance(pre_instr, MediumLevelILIf):
                true_idx = pre_instr.true
                false_idx = pre_instr.false
                true_label = MediumLevelILLabel()
                true_label.operand = true_idx
                false_label = MediumLevelILLabel()
                false_label.operand = false_idx
                if true_idx == block.start:
                    new_if = mlil.if_expr(
                        mlil.copy_expr(
                            pre_instr.condition,
                            ILSourceLocation.from_instruction(pre_instr),
                        ),
                        label,
                        false_label,
                        ILSourceLocation.from_instruction(pre_instr),
                    )
                    mlil.replace_expr(pre_instr.instr_index, new_if)
                elif false_idx == block.start:
                    new_if = mlil.if_expr(
                        mlil.copy_expr(
                            pre_instr.condition,
                            ILSourceLocation.from_instruction(pre_instr),
                        ),
                        true_label,
                        label,
                        ILSourceLocation.from_instruction(pre_instr),
                    )
                    mlil.replace_expr(pre_instr.instr_index, new_if)
                else:
                    raise Exception("Invalid if condition")
        return True

    for _ in range(len(mlil.basic_blocks) * 2):
        updated = False
        for block in mlil.basic_blocks:
            last_instr = block[-1]
            if not isinstance(last_instr, MediumLevelILGoto):
                continue
            next_block = mlil.get_basic_block_at(last_instr.dest)
            next_block_incoming = CFGAnalyzer.MLIL_get_incoming_blocks(
                mlil, next_block.start
            )
            if (
                next_block is not None
                and len(next_block_incoming) == 1
                and (
                    isinstance(next_block[-1], MediumLevelILGoto)
                    or isinstance(next_block[-1], MediumLevelILRet)
                )
            ):
                if merge_block(block, next_block):
                    updated = True
                    break
        if updated:
            log_info("mer ok!")
            mlil.finalize()
            mlil.generate_ssa_form()
        else:
            break
    mlil.finalize()
    mlil.generate_ssa_form()


def pass_clear(analysis_context: AnalysisContext):
    pass_clear_const_if(analysis_context)
    pass_clear_goto(analysis_context)
    pass_clear_if(analysis_context)
    pass_merge_block(analysis_context)
