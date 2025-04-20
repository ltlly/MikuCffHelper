# Make sure ifInstr is a single block


from binaryninja import LowLevelILIf, LowLevelILLabel, AnalysisContext, ILSourceLocation


def pass_spilt_if_block(analysis_context: AnalysisContext):
    llil = analysis_context.function.llil
    updated = False
    for block in llil.basic_blocks:
        if block.length == 1:
            continue
        ifinstr = block[-1]
        if not isinstance(ifinstr, LowLevelILIf):
            continue
        goto_label = LowLevelILLabel()
        llil.mark_label(goto_label)
        llil.append(llil.copy_expr(ifinstr))
        llil.replace_expr(
            ifinstr.expr_index,
            llil.goto(goto_label, ILSourceLocation.from_instruction(ifinstr)),
        )
        updated = True
    llil.finalize()
    llil.generate_ssa_form()
    return updated
