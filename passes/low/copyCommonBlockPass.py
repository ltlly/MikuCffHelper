from binaryninja import *

from ...fix_binaryninja_api.common import ILSourceLocation
from ...utils import CFGAnalyzer, log_error


def handle_pre_last_instr(llil: LowLevelILFunction, pre_last_instr, bb, copy_label):
    if isinstance(pre_last_instr, LowLevelILGoto):
        llil.replace_expr(pre_last_instr.expr_index,
                          llil.goto(copy_label, ILSourceLocation.from_instruction(pre_last_instr)))
    elif isinstance(pre_last_instr, LowLevelILIf):
        true_target = pre_last_instr.true
        false_target = pre_last_instr.false
        if true_target == bb.start:
            fix_false_label = LowLevelILLabel()
            fix_false_label.operand = false_target
            llil.replace_expr(
                pre_last_instr.expr_index,
                llil.if_expr(
                    llil.copy_expr(pre_last_instr.condition, ILSourceLocation.from_instruction(pre_last_instr)),
                    copy_label,
                    fix_false_label,
                    ILSourceLocation.from_instruction(pre_last_instr)
                ),
            )
        elif false_target == bb.start:
            fix_true_label = LowLevelILLabel()
            fix_true_label.operand = true_target
            llil.replace_expr(
                pre_last_instr.expr_index,
                llil.if_expr(
                    llil.copy_expr(pre_last_instr.condition, ILSourceLocation.from_instruction(pre_last_instr)),
                    fix_true_label,
                    copy_label,
                    ILSourceLocation.from_instruction(pre_last_instr)
                ),
            )
        else:
            log_error("ERROR IF")
    else:
        log_error("ERROR")


def pass_copy_common_block(analysis_context: AnalysisContext):
    llil = analysis_context.function.llil
    for _ in range(len(llil.basic_blocks)):
        updated = False
        for bb in llil.basic_blocks:
            # last_instr = llil[bb.end - 1]
            # if last_instr.operation == LowLevelILOperation.LLIL_IF:
                # continue
            pre_blocks = CFGAnalyzer.LLIL_get_incoming_blocks(llil, bb.start)
            if len(pre_blocks) <= 1:
                continue
            if any(frontier.start == bb.start for frontier in bb.dominance_frontier):
                continue
            for j in range(1, len(pre_blocks)):
                updated = True
                pre_block = pre_blocks[j]
                pre_last_instr = llil[pre_block.end - 1]
                copy_label = LowLevelILLabel()
                llil.mark_label(copy_label)
                for l in range(bb.start, bb.end):
                    llil.append(llil.copy_expr(llil[l], ILSourceLocation.from_instruction(llil[l])))
                handle_pre_last_instr(llil, pre_last_instr, bb, copy_label)
        if updated:
            llil.finalize()
            llil.generate_ssa_form()
        else:
            break
    llil.finalize()
    llil.generate_ssa_form()
