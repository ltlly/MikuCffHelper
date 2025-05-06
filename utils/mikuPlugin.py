from binaryninja import Logger, BinaryView, Function, Variable

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


func_dict = {}


def make_stateVar(func: Function, var: Variable):
    """创建状态变量
    Args:
        func (Function): 目标函数
        var (Variable): 要标记为状态变量的变量
    """
    if func.start not in func_dict:
        func_dict[func.start] = {}
    var_name_list = [var.name for var in func.vars]
    i = 0
    while f"state-{i}" in var_name_list or f"state-{i}" in func_dict[func.start]:
        i += 1
    name = f"state-{i}"
    var.set_name_async(name)
    func_dict[func.start][name] = var


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
    make_stateVar(func, var)


def suggest_stateVar(bv: BinaryView, func: Function):
    from .state_machine import StateMachine

    state_vars = StateMachine.find_state_var(func)
    for var in state_vars:
        if var.name.startswith("state-"):
            continue
        make_stateVar(func, var)
    func_dict[func.start] = {}


def isV(bv: BinaryView, inst):
    """验证指令是否有效
    Args:
        bv (BinaryView): 二进制视图
        inst: 要验证的指令
    Returns:
        bool: 如果指令有效返回True
    """
    return True
