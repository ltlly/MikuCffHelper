# Make sure ifInstr is a single block


from binaryninja import *

from ..utils import get_basic_block_at, my_copy_expr, log_info


def pass_spilt_if_block(analysis_context: AnalysisContext):
    llil = analysis_context.function.llil
    bbs = list(llil.basic_blocks)
    def traverse_if_bb(instr):
        if isinstance(instr, LowLevelILIf):
            block = get_basic_block_at(bbs, instr.instr_index)
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
        log_info(f"copying [::] {ifinstr}")
        goto_label = LowLevelILLabel()
        llil.mark_label(goto_label)
        llil.append(my_copy_expr(llil, ifinstr))
        llil.replace_expr(ifinstr, llil.goto(goto_label))
        updated = True
    llil.finalize()
    llil.generate_ssa_form()
    return updated
