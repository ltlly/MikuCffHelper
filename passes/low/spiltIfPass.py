# Make sure ifInstr is a single block


from binaryninja import *

from ...utils import log_info, ILSourceLocation


def pass_spilt_if_block(analysis_context: AnalysisContext):
    llil = analysis_context.function.llil

    def traverse_if_bb(instr):
        if isinstance(instr, LowLevelILIf):
            block = llil.get_basic_block_at(instr.instr_index)
            if not block:
                return
            if block.instruction_count != 1:
                return block

    updated = False
    if_blocks = list(llil.traverse(traverse_if_bb))  # type: ignore
    for ifbb in if_blocks:
        ifinstr = ifbb[-1]
        if not isinstance(ifinstr, LowLevelILIf):
            continue
        goto_label = LowLevelILLabel()
        llil.mark_label(goto_label)
        llil.append(llil.copy_expr(ifinstr, ILSourceLocation.from_instruction(ifinstr)))  # type: ignore
        llil.replace_expr(
            ifinstr, llil.goto(goto_label, ILSourceLocation.from_instruction(ifinstr))
        )  # type: ignore
        updated = True
    llil.finalize()
    llil.generate_ssa_form()
    return updated
