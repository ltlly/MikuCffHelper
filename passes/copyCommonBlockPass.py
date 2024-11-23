from binaryninja import *

from ..utils import LLIL_get_incoming_blocks, log_error
from ..utils import my_copy_expr


# sub_2e7a4
def pass_copy_common_block(llil: LowLevelILFunction):
    for _ in range(len(llil.basic_blocks)):
        update = False
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
                update = True
                preBlock = preBlocks[j]
                pre_lastInstr = llil[preBlock.end - 1]
                copyLabel = LowLevelILLabel()
                llil.mark_label(copyLabel)
                for l in range(bb.start, bb.end):
                    llil.append(my_copy_expr(llil, llil[l]))
                if isinstance(pre_lastInstr, LowLevelILGoto):
                    llil.replace_expr(pre_lastInstr.expr_index,
                                      llil.goto(copyLabel))
                elif isinstance(pre_lastInstr, LowLevelILIf):
                    trueTarget = pre_lastInstr.true
                    falseTarget = pre_lastInstr.false
                    if trueTarget == bb.start:
                        fixFalseLabel = LowLevelILLabel()
                        fixFalseLabel.operand = falseTarget
                        llil.replace_expr(pre_lastInstr.expr_index,
                                          llil.if_expr(my_copy_expr(llil, pre_lastInstr.condition), copyLabel,
                                                       fixFalseLabel))
                    elif falseTarget == bb.start:
                        fixTrueLabel = LowLevelILLabel()
                        fixTrueLabel.operand = trueTarget
                        llil.replace_expr(pre_lastInstr.expr_index,
                                          llil.if_expr(my_copy_expr(llil, pre_lastInstr.condition), fixTrueLabel,
                                                       copyLabel))
                    else:
                        log_error("ERROR IF")
                else:
                    log_error("ERROR")
        if update:
            llil.finalize()
            llil.generate_ssa_form()
    llil.finalize()
    llil.generate_ssa_form()
