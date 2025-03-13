# Make sure ifInstr is a single block


from binaryninja import LowLevelILIf, LowLevelILLabel, AnalysisContext, ILSourceLocation

from ...utils import log_info


def pass_spilt_if_block(analysis_context: AnalysisContext):
    llil = analysis_context.function.llil
    updated = False
    for ifbb in llil.basic_blocks:
        if ifbb.length == 1:
            continue
        ifinstr = ifbb[-1]
        if not isinstance(ifinstr, LowLevelILIf):
            continue
        goto_label = LowLevelILLabel()
        llil.mark_label(goto_label)
        llil.append(llil.copy_expr(ifinstr))
        llil.replace_expr(
            ifinstr.expr_index,
            llil.goto(goto_label, ILSourceLocation.from_instruction(ifinstr)),
        )  # type: ignore
        updated = True
    llil.finalize()
    llil.generate_ssa_form()
    return updated
