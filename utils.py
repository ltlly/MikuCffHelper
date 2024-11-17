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


def replaceMlilInstr(mlil: MediumLevelILFunction, instrId: ExpressionIndex, newInstrId: ExpressionIndex):
    import binaryninja._binaryninjacore as core
    core.BNReplaceMediumLevelILInstruction(mlil.handle, instrId, newInstrId)
