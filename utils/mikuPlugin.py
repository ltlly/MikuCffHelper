from binaryninja import *
from typing import Dict, List

# Initialize logger
mikuLogger = Logger(0, "MikuCffHelper")


def log_info(msg: str):
    """记录信息日志
    Args:
        msg (str): 要记录的信息
    """
    mikuLogger.log_info(msg)


def log_warn(msg: str):
    """记录警告日志
    Args:
        msg (str): 要记录的警告信息
    """
    mikuLogger.log_warn(msg)


def log_error(msg: str):
    """记录错误日志
    Args:
        msg (str): 要记录的错误信息
    """
    mikuLogger.log_error(msg)


funDict = {}


def make_stateVar(bv: BinaryView, func: Function, var: Variable):
    """创建状态变量
    Args:
        bv (BinaryView): 二进制视图
        func (Function): 目标函数
        var (Variable): 要标记为状态变量的变量
    """
    global state_counter
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
    """设置状态变量
    Args:
        bv (BinaryView): 二进制视图
        func (Function): 目标函数
    """
    from binaryninjaui import UIContext

    ctx = UIContext.activeContext()
    h = ctx.contentActionHandler()
    a = h.actionContext()
    token_state = a.token
    var = Variable.from_identifier(func, token_state.token.value)
    make_stateVar(bv, func, var)


def suggest_stateVar(bv: BinaryView, func: Function):
    """建议可能的状态变量
    Args:
        bv (BinaryView): 二进制视图
        func (Function): 目标函数
    """
    mlil = func.medium_level_il
    if not mlil:
        return
    from .state_machine import collect_stateVar_info

    # State variable recognition rules
    state_var_rules = [
        # Rule 1: Variable appears in both ifTable and defineTable with same value count >= 3
        lambda var, ifTable, defineTable: (
            var in ifTable
            and var in defineTable
            and len(defineTable[var]) == len(ifTable[var])
            and len(defineTable[var]) >= 3
        ),
        # Rule 2: Variable in defineTable with value count >= 3 and average > 0x10000000
        lambda var, ifTable, defineTable: (
            var in defineTable
            and len(defineTable[var]) >= 3
            and sum(defineTable[var]) // len(defineTable[var]) > 0x10000000
        ),
        # Rule 3: Variable in ifTable with value count >= 3 and average > 0x10000000
        lambda var, ifTable, defineTable: (
            var in ifTable
            and len(ifTable[var]) >= 3
            and sum(ifTable[var]) // len(ifTable[var]) > 0x10000000
        ),
        lambda var, ifTable, defineTable: (
            var.name.startswith("state-") and "_" in var.name
        ),
    ]
    ifTable, defineTable = collect_stateVar_info(func)
    # Check all variables
    for var in set(list(ifTable.keys()) + list(defineTable.keys())):
        # Skip already marked state variables
        if var.name.startswith("state-") and "_" not in var.name:
            continue
        # Check all rules
        for rule in state_var_rules:
            if rule(var, ifTable, defineTable):
                make_stateVar(bv, func, var)
                break
    funDict[func.start] = {}


def isV(bv: BinaryView, inst):
    """验证指令是否有效
    Args:
        bv (BinaryView): 二进制视图
        inst: 要验证的指令
    Returns:
        bool: 如果指令有效返回True
    """
    return True
