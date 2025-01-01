from binaryninja import *

mikuLogger = Logger(0, "MikuCffHelper")

from  .fix_binaryninja_api.common import ILSourceLocation
def log_info(msg: str):
    mikuLogger.log_info(msg)


def log_warn(msg: str):
    mikuLogger.log_warn(msg)


def log_error(msg: str):
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
    log_error(f"can't find basic block at {index}")
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

def unsigned_to_signed_32bit(n):
    # 检查是否在无符号32位整数范围内
    if n < 0 or n > 0xFFFFFFFF:
        raise ValueError(
            "Input is out of range for a 32-bit unsigned integer")

    # 如果大于 0x7FFFFFFF，则减去 0x100000000
    if n > 0x7FFFFFFF:
        return n - 0x100000000
    else:
        return n

def collect_stateVar_info(func: Function, ret_int: bool = True):
    args = func.parameter_vars
    args_name = [var.name for var in args]
    mlil = func.medium_level_il
    if not mlil:
        return {}, {}
    ifTable: Dict[
        MediumLevelILVar|Any, List[MediumLevelILInstruction]|List[int]|Any
    ] = {}
    defineTable: Dict[
        MediumLevelILVar|Any, List[MediumLevelILInstruction]|List[int]|Any
    ] = {}
    def travse_if_const_compare(expr):
        if not isinstance(expr, MediumLevelILIf):
            return
        condition = expr.condition
        if isinstance(condition, MediumLevelILVar):
            log_error(f"if(cond) should not appear in {expr}")
            return
        if not hasattr(condition, "right"):
            return
        if isinstance(condition.right, MediumLevelILConst):
            left = condition.left
            for token in left.tokens:
                if token in args_name:
                    return
            if not isinstance(left, MediumLevelILVar):
                return
            if left.src not in ifTable:
                ifTable[left.src] = []
            if ret_int:
                ifTable[left.src].append(condition.right.value.value)
            else:
                # sometimes condition.instr_index != expr.instr_index 
                ifTable[left.src].append(expr)
    def travse_define(expr):
        if not isinstance(expr, MediumLevelILSetVar):
            return
        if not isinstance(expr.src, MediumLevelILConst):
            return
        for token in expr.tokens:
            if token in args_name:
                return
        if expr.dest not in defineTable:
            defineTable[expr.dest] = []
        if ret_int:
            defineTable[expr.dest].append(expr.src.value.value)
        else:
            defineTable[expr.dest].append(expr)
    list(mlil.traverse(travse_if_const_compare))
    list(mlil.traverse(travse_define))
    if not ret_int:
        for x in ifTable:
            ifTable[x] = [instr for instr in ifTable[x] if instr.instr_index < len(mlil)]
        for x in defineTable:
            defineTable[x] = [
                instr for instr in defineTable[x] if instr.instr_index < len(mlil)
            ]
    return ifTable, defineTable
