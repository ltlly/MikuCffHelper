from binaryninja import (
    AnalysisContext,
    LowLevelILIf,
    LowLevelILInstruction,
    LowLevelILFlagSsa,
    LowLevelILSetFlagSsa,
    LowLevelILFlagPhi,
    LowLevelILLabel,
    ILSourceLocation,
)


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
        if not isinstance(define, LowLevelILSetFlagSsa):
            continue
        if not bb.end > int(define.instr_index) >= bb.start:
            continue
        use = llil.ssa_form.get_ssa_flag_uses(condition.src)
        use = [x for x in use if not isinstance(x, LowLevelILFlagPhi)]
        if len(use) > 1:
            continue
        ifInstr: LowLevelILIf = lastInstrSSA.non_ssa_form
        defineInstr = define.non_ssa_form
        newTrueLabel = LowLevelILLabel()
        newTrueLabel.operand = ifInstr.true
        newFalseLabel = LowLevelILLabel()
        newFalseLabel.operand = ifInstr.false
        newIfinstr = llil.if_expr(
            llil.copy_expr(defineInstr.src),
            newTrueLabel,
            newFalseLabel,
            ILSourceLocation.from_instruction(ifInstr),
        )
        llil.replace_expr(ifInstr.expr_index, newIfinstr)
    llil.finalize()
    llil.generate_ssa_form()
