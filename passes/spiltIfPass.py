# Make sure ifInstr is a single block


from binaryninja import *

from ..utils import get_basic_block_at


def pass_spilt_if_block(llil: LowLevelILFunction):
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

        #copy expr 的api设计有问题
        llil.append(llil.copy_expr(ifinstr))
        llil.replace_expr(ifinstr, llil.goto(goto_label))
        updated = True
    return updated
