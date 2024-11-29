from binaryninja import *
from ..utils import get_basic_block_at,my_copy_expr


def pass_inline_if_cond(analysis_context: AnalysisContext):
    llil = analysis_context.function.llil
    for bb in llil.ssa_form.basic_blocks:
        if not isinstance(bb[-1], LowLevelILIf):
            continue
        lastInstrSSA:LowLevelILInstruction = bb[-1]
        condition = lastInstrSSA.condition
        if not isinstance(condition, LowLevelILFlagSsa):
            continue
        define = llil.ssa_form.get_ssa_flag_definition(condition.src)
        if not bb.end>int(define.instr_index) >= bb.start:
            continue
        # todo: check can inline : use-define analysis
        ifInstr = lastInstrSSA.non_ssa_form
        defineInstr = define.non_ssa_form
        newTrueLabel = LowLevelILLabel()
        newTrueLabel.operand = ifInstr.true
        newFalseLabel = LowLevelILLabel()
        newFalseLabel.operand = ifInstr.false

        newIfinstr = llil.if_expr(my_copy_expr(llil,defineInstr.src), newTrueLabel, newFalseLabel)
        llil.replace_expr(ifInstr.expr_index,newIfinstr)
    llil.finalize()
    llil.generate_ssa_form()
    