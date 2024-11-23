from binaryninja import *

mikuLogger = Logger(0, "MikuCffHelper")


def log_info(msg):
    mikuLogger.log_info(msg)


def log_warn(msg):
    mikuLogger.log_warn(msg)


def log_error(msg):
    mikuLogger.log_error(msg)


def get_basic_block_at(basic_blocks, index):
    # because api:mlil.get_basic_block_at  sometimes is not correct
    bbs = sorted(list(basic_blocks), key=lambda bb: bb.start)
    low, high = 0, len(bbs) - 1
    while low <= high:
        mid = (low + high) // 2
        if bbs[mid].start <= index < bbs[mid].end:
            return bbs[mid]
        elif index < bbs[mid].start:
            high = mid - 1
        else:
            low = mid + 1
    return None


def LLIL_get_incoming_blocks(llil: LowLevelILFunction, bbIndex: int):
    bbs = []
    for bb in llil.basic_blocks:
        lastInstr = llil[bb.end - 1]
        if isinstance(lastInstr, LowLevelILGoto):
            if lastInstr.dest == bbIndex:
                bbs.append(bb)
        elif isinstance(lastInstr, LowLevelILIf):
            if lastInstr.true == bbIndex:
                bbs.append(bb)
            elif lastInstr.false == bbIndex:
                bbs.append(bb)
    bbs.sort(key=lambda bb: bb.start)
    return bbs


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
