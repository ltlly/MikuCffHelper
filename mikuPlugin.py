from binaryninja import *
from binaryninjaui import UIContext

funDict = {}


def make_stateVar(bv: BinaryView, func: Function, var: Variable):
    if func.start not in funDict:
        funDict[func.start] = {}
    varNameList = [var.name for var in func.vars]
    i = 0
    while f"state-{i}" in varNameList or f"state-{i}" in funDict[func.start]:
        i += 1
    name = f"state-{i}"
    var.set_name_async(name)
    funDict[func.start][name] = var


def set_stateVar(bv: BinaryView, func: Function):
    ctx = UIContext.activeContext()
    h = ctx.contentActionHandler()
    a = h.actionContext()
    token_state = a.token
    var = Variable.from_identifier(func, token_state.token.value)
    make_stateVar(bv, func, var)


def suggest_stateVar(bv: BinaryView, func: Function):
    mlil = func.medium_level_il
    if not mlil:
        return
    from .utils import collect_stateVar_info
    # 找到所有比较var const 的if
    ifTable,defineTable = collect_stateVar_info(func)

    for var, values in defineTable.items():
        if var in ifTable and len(values) == len(ifTable[var]) and len(values) >= 3:
            make_stateVar(bv, func, var)
            continue
        if len(values) >= 3 and sum(values) // len(values) > 0x10000000:
            make_stateVar(bv, func, var)
            continue
    for var, values in ifTable.items():
        if var.name.startswith("state-") and "_" not in var.name:
            continue
        if var in defineTable and len(values) == len(defineTable[var]) and len(values) >= 3:
            make_stateVar(bv, func, var)
            continue
        if len(values) >= 3 and sum(values) // len(values) > 0x10000000:
            make_stateVar(bv, func, var)
            continue
    funDict[func.start] = {}


def isV(bv: BinaryView, inst):
    return True
