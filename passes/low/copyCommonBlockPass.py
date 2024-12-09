from binaryninja import *

from ...fix_binaryninja_api.common import ILSourceLocation
from ...utils import LLIL_get_incoming_blocks, log_error


# sub_2e7a4
def pass_copy_common_block(analysis_context: AnalysisContext):
    llil = analysis_context.function.llil
    for _ in range(len(llil.basic_blocks)):
        updated = False
        for bb in llil.basic_blocks:
            lastInstr = llil[bb.end - 1]
            if lastInstr.operation == LowLevelILOperation.LLIL_IF:
                continue
            preBlocks = LLIL_get_incoming_blocks(llil, bb.start)
            if len(preBlocks) <= 1:
                continue
            is_cycle = False
            for frontier in bb.dominance_frontier:
                if frontier.start == bb.start:
                    is_cycle = True
                    break
            if is_cycle:
                continue
            for j in range(1, len(preBlocks)):
                updated = True
                preBlock = preBlocks[j]
                pre_lastInstr = llil[preBlock.end - 1]
                copyLabel = LowLevelILLabel()
                llil.mark_label(copyLabel)
                for l in range(bb.start, bb.end):
                    llil.append(llil.copy_expr(llil[l], ILSourceLocation.from_instruction(llil[l])))
                if isinstance(pre_lastInstr, LowLevelILGoto):
                    llil.replace_expr(pre_lastInstr.expr_index,
                                      llil.goto(copyLabel, ILSourceLocation.from_instruction(pre_lastInstr)))

                elif isinstance(pre_lastInstr, LowLevelILIf):
                    trueTarget = pre_lastInstr.true
                    falseTarget = pre_lastInstr.false
                    if trueTarget == bb.start:
                        fixFalseLabel = LowLevelILLabel()
                        fixFalseLabel.operand = falseTarget
                        llil.replace_expr(
                            pre_lastInstr.expr_index,
                            llil.if_expr(
                                llil.copy_expr(pre_lastInstr.condition,
                                               ILSourceLocation.from_instruction(pre_lastInstr)),
                                copyLabel,
                                fixFalseLabel,
                                ILSourceLocation.from_instruction(pre_lastInstr)
                            ),
                        )
                    elif falseTarget == bb.start:
                        fixTrueLabel = LowLevelILLabel()
                        fixTrueLabel.operand = trueTarget
                        llil.replace_expr(
                            pre_lastInstr.expr_index,
                            llil.if_expr(
                                llil.copy_expr(pre_lastInstr.condition,
                                               ILSourceLocation.from_instruction(pre_lastInstr)),
                                fixTrueLabel,
                                copyLabel,
                                ILSourceLocation.from_instruction(pre_lastInstr)
                            ),
                        )
                    else:
                        log_error("ERROR IF")
                else:
                    log_error("ERROR")
        if updated:
            llil.finalize()
            llil.generate_ssa_form()
        else:
            break
    llil.finalize()
    llil.generate_ssa_form()
