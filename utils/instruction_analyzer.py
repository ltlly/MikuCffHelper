from typing import List, Dict, Any
from pprint import pformat
from binaryninja import (
    MediumLevelILFunction,
    MediumLevelILIf,
    MediumLevelILInstruction,
    MediumLevelILSetVar,
    MediumLevelILOperation,
    Variable,
)
from .mikuPlugin import log_info, log_error
from .instr_vistor import SimpleVisitor


def unsigned_to_signed_32bit(n):
    """将32位无符号整数转换为有符号整数"""
    # 检查是否在无符号32位整数范围内
    if n < 0 or n > 0xFFFFFFFF:
        raise ValueError("Input is out of range for a 32-bit unsigned integer")

    # 如果大于 0x7FFFFFFF，则减去 0x100000000
    if n > 0x7FFFFFFF:
        return n - 0x100000000
    else:
        return n


def get_mask(width: int) -> int:
    """根据宽度生成掩码
    Args:
        width (int): 掩码宽度（字节数）
    Returns:
        int: 对应的位掩码值
    """
    match width:
        case 1:
            return 0xFF
        case 2:
            return 0xFFFF
        case 4:
            return 0xFFFFFFFF
        case 8:
            return 0xFFFFFFFFFFFFFFFF
        case _:
            return int(f"0x{'ff' * width}", 16)


class InstructionAnalyzer:
    """指令分析器，负责处理指令分析和状态转换检测"""

    @staticmethod
    def find_state_transition_instructions(
        local_if_table: List[MediumLevelILIf],
        local_define_table: List[MediumLevelILSetVar],
    ) -> List[Dict[str, Any]]:
        """查找状态转换指令
        Args:
            local_if_table (List[MediumLevelILIf]): 本地if指令表
            local_define_table (List[MediumLevelILSetVar]): 本地定义指令表
        Returns:
            List[Dict[str, Any]]: 匹配的状态转换指令对列表
        """
        paired_instructions = []

        # 使用字典存储if_instr的key_if值
        if_dict = {}
        for if_instr in local_if_table:
            if_const = if_instr.condition.right
            if_const_width = if_instr.condition.left.size
            key_if = if_const.value.value & get_mask(if_const_width)
            if key_if not in if_dict:
                if_dict[key_if] = []
            if_dict[key_if].append(if_instr)

        for def_instr in local_define_table:
            t_def_const = def_instr.src
            t_def_const_width = def_instr.size
            key_define = t_def_const.value.value & get_mask(t_def_const_width)
            if key_define in if_dict:
                for if_instr in if_dict[key_define]:
                    paired_instructions.append(
                        {
                            "if_instr": if_instr,
                            "def_instr": def_instr,
                            "def_const": def_instr.src,
                            "if_const": if_instr.condition.right,
                        }
                    )
        return paired_instructions

    @staticmethod
    def find_white_instructions(
        mlil: MediumLevelILFunction, possible_state_vars: List[Variable]
    ):
        """查找白名单指令
        Args:
            mlil (MediumLevelILFunction): 中间语言函数
            possible_state_vars (List[Variable]): 可能的状态变量列表
        Returns:
            List[MediumLevelILInstruction]: 符合条件的白名单指令列表
        """
        white_instructions = []
        for instr in mlil.instructions:
            if instr.operation not in [
                MediumLevelILOperation.MLIL_GOTO,
                MediumLevelILOperation.MLIL_IF,
                MediumLevelILOperation.MLIL_SET_VAR,
            ]:
                continue
            vars = instr.vars_written + instr.vars_read
            if not all([var in possible_state_vars for var in vars]):
                continue
            white_instructions.append(instr)
        return white_instructions

    @staticmethod
    def check_state_if_instr(instr: MediumLevelILInstruction):
        """检查指令是否为状态相关的if指令
        Args:
            instr (MediumLevelILInstruction): 待检查的指令
        Returns:
            bool: 如果是状态相关的if指令返回True，否则返回False
        """
        if not isinstance(instr, MediumLevelILIf):
            return False
        condition = instr.condition
        if (not hasattr(condition, "left")) or (not hasattr(condition, "right")):
            return False
        if condition.right.operation != MediumLevelILOperation.MLIL_CONST:
            return False
        return True

    @staticmethod
    def emu_if(left_const: int, if_symbol: MediumLevelILOperation, right_const: int):
        """模拟if条件判断
        Args:
            left_const (int): 左操作数
            if_symbol (MediumLevelILOperation): 比较操作符
            right_const (int): 右操作数
        Returns:
            bool: 比较结果
        """

        def cmp_e(a, b):
            return a == b

        def cmp_ne(a, b):
            return a != b

        def cmp_ult(a, b):
            return a < b

        def cmp_ule(a, b):
            return a <= b

        def cmp_ugt(a, b):
            return a > b

        def cmp_uge(a, b):
            return a >= b

        def cmp_slt(a, b):
            return unsigned_to_signed_32bit(a) < unsigned_to_signed_32bit(b)

        def cmp_sle(a, b):
            return unsigned_to_signed_32bit(a) <= unsigned_to_signed_32bit(b)

        def cmp_sgt(a, b):
            return unsigned_to_signed_32bit(a) > unsigned_to_signed_32bit(b)

        def cmp_sge(a, b):
            return unsigned_to_signed_32bit(a) >= unsigned_to_signed_32bit(b)

        cmp_funcs = {
            MediumLevelILOperation.MLIL_CMP_E: cmp_e,
            MediumLevelILOperation.MLIL_CMP_NE: cmp_ne,
            MediumLevelILOperation.MLIL_CMP_ULT: cmp_ult,
            MediumLevelILOperation.MLIL_CMP_ULE: cmp_ule,
            MediumLevelILOperation.MLIL_CMP_UGT: cmp_ugt,
            MediumLevelILOperation.MLIL_CMP_UGE: cmp_uge,
            MediumLevelILOperation.MLIL_CMP_SLT: cmp_slt,
            MediumLevelILOperation.MLIL_CMP_SLE: cmp_sle,
            MediumLevelILOperation.MLIL_CMP_SGT: cmp_sgt,
            MediumLevelILOperation.MLIL_CMP_SGE: cmp_sge,
        }
        return cmp_funcs[if_symbol](left_const, right_const)

    @staticmethod
    def emu_instrs_simple(
        instrs: List[MediumLevelILInstruction],
        mlil: MediumLevelILFunction,
    ):
        """
        只check  store load , if 转移
        """
        v = SimpleVisitor(mlil.source_function.view, mlil.source_function)
        try:
            for i in range(len(instrs)):
                instr = instrs[i]
                if instr.operation == MediumLevelILOperation.MLIL_IF:
                    _, nextip = v.visit(instr)
                    if i + 1 < len(instrs) and nextip != instrs[i + 1].instr_index:
                        return (False, None)
                    elif i == len(instrs) - 1:
                        return (True, nextip)
                else:
                    v.visit(instr)
        except:
            return (False, None)
        raise Exception("理论上 不应该到达这里")

    @staticmethod
    def check_path(
        mlil: MediumLevelILFunction,
        path: List[int],
        white_instructions: List[MediumLevelILInstruction],
    ):
        """检查路径是否有效
        Args:
            mlil (MediumLevelILFunction): 中间语言函数
            path (List[int]): 指令路径
            state_vars (List[Variable]): 状态变量列表
            white_instructions (List[MediumLevelILInstruction]): 白名单指令列表
        Returns:
            bool: 如果路径有效返回True，否则返回False
        """
        instrs = []
        for x in path:
            instrs.append(mlil[x])
        if not all([instr in white_instructions for instr in instrs]):
            # log_info(
            #     f"not in white instructions::{pformat([instr for instr in instrs if instr not in white_instructions])}")
            return (False, None)
        res = InstructionAnalyzer.emu_instrs_simple(instrs, mlil)
        return res
