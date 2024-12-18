from binaryninja import *

from ...utils import ILSourceLocation


def pass_inline_if_cond(analysis_context: AnalysisContext):
    llil = analysis_context.function.llil
    for bb in llil.ssa_form.basic_blocks:
        if not isinstance(bb[-1], LowLevelILIf):
            continue
        lastInstrSSA: LowLevelILInstruction = bb[-1]
        condition = lastInstrSSA.condition
        if not isinstance(condition, LowLevelILFlagSsa):
            continue
        define = llil.ssa_form.get_ssa_flag_definition(condition.src)
        if not bb.end > int(define.instr_index) >= bb.start:
            continue
        # todo: check can inline : use-define analysis

        use = llil.ssa_form.get_ssa_flag_uses(condition.src)
        log_info(f"use {use}")
        ifInstr: LowLevelILIf = lastInstrSSA.non_ssa_form
        defineInstr = define.non_ssa_form

        newTrueLabel = LowLevelILLabel()
        newTrueLabel.operand = ifInstr.true
        newFalseLabel = LowLevelILLabel()
        newFalseLabel.operand = ifInstr.false
        newIfinstr = llil.if_expr(llil.copy_expr(defineInstr.src,ILSourceLocation.from_instruction(ifInstr)), newTrueLabel, newFalseLabel,
                                  ILSourceLocation.from_instruction(ifInstr))
        # newIfinstr = llil.if_expr(my_copy_expr(llil,defineInstr.src), newTrueLabel, newFalseLabel)
        llil.replace_expr(ifInstr.expr_index, newIfinstr)
    llil.finalize()
    llil.generate_ssa_form()
