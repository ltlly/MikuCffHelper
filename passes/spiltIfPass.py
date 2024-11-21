# Make sure ifInstr is a single block


from binaryninja import *

from ..utils import get_basic_block_at


def my_copy_expr(llil: LowLevelILFunction, instr: LowLevelILInstruction):
    # api: LowLevelILFunction.copy_expr
    # def copy_expr(self, original: LowLevelILInstruction) -> ExpressionIndex:
    #     """
    #     ``copy_expr`` adds an expression to the function which is equivalent to the given expression
    #
    #     :param LowLevelILInstruction original: the original IL Instruction you want to copy
    #     :return: The index of the newly copied expression
    #     """
    #     return self.expr(original.operation, original.raw_operands[0], original.raw_operands[1],
    #                      original.raw_operands[2], original.raw_operands[3], original.size, original.flags)

    flags = instr.flags if instr.flags != "" else None
    return llil.expr(instr.operation, instr.raw_operands[0], instr.raw_operands[1], instr.raw_operands[2],
                     instr.raw_operands[3], instr.size, flags)


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
        llil.append(my_copy_expr(llil, ifinstr))
        llil.replace_expr(ifinstr, llil.goto(goto_label))
        updated = True
    return updated
