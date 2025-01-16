from binaryninja import *
from typing import Dict, List

# Initialize logger
mikuLogger = Logger(0, "MikuCffHelper")

def log_info(msg: str):
    mikuLogger.log_info(msg)

def log_warn(msg: str):
    mikuLogger.log_warn(msg)

def log_error(msg: str):
    mikuLogger.log_error(msg)

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
    from binaryninjaui import UIContext
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
    from .state_machine import collect_stateVar_info
    # 找到所有比较var const 的if
    ifTable: Dict[MediumLevelILVar, List[int]]
    defineTable: Dict[MediumLevelILVar,List[int]]
    ifTable, defineTable = collect_stateVar_info(func)
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
