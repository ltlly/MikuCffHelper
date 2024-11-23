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
    potential_states = set()
    args = func.parameter_vars
    args_name = [var.name for var in args]
    mlil = func.medium_level_il
    if not mlil:
        return
    # 找到所有比较var const 的if
    ifTable = {}
    def travse_if_const_compare(expr):
        if expr.operation == MediumLevelILOperation.MLIL_IF:
            condition = expr.condition
            if condition.operation == MediumLevelILOperation.MLIL_VAR:
                boolvar = condition.src
                tDefine = mlil.get_var_definitions(boolvar)
                if len(tDefine) != 1:
                    return
                condition = tDefine[0].src
            if not hasattr(condition, "right"):
                return
            if condition.right.operation == MediumLevelILOperation.MLIL_CONST:
                left = condition.left
                for token in left.tokens:
                    if token in args_name:
                        return
                if left.operation != MediumLevelILOperation.MLIL_VAR:
                    return
                if left.src not in ifTable:
                    ifTable[left.src] = []
                ifTable[left.src].append(condition.right.value.value)
    list(mlil.traverse(travse_if_const_compare))
    defineTable = {}
    def travse_define(expr):
        if expr.operation == MediumLevelILOperation.MLIL_SET_VAR:
            if expr.src.operation == MediumLevelILOperation.MLIL_CONST:
                for token in expr.tokens:
                    if token in args_name:
                        return
                if expr.dest not in defineTable:
                    defineTable[expr.dest] = []
                defineTable[expr.dest].append(expr.src.value.value)
    list(mlil.traverse(travse_define))
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
