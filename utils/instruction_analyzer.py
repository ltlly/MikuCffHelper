from typing import List, Dict, Any
from pprint import pformat
from binaryninja import (
    MediumLevelILFunction,
    MediumLevelILIf,
    MediumLevelILInstruction,
    MediumLevelILSetVar,
    MediumLevelILOperation,
    Variable
)
from .mikuPlugin import log_info

def unsigned_to_signed_32bit(n):
    """Convert 32-bit unsigned integer to signed integer"""
    # 检查是否在无符号32位整数范围内
    if n < 0 or n > 0xFFFFFFFF:
        raise ValueError(
            "Input is out of range for a 32-bit unsigned integer")

    # 如果大于 0x7FFFFFFF，则减去 0x100000000
    if n > 0x7FFFFFFF:
        return n - 0x100000000
    else:
        return n

class InstructionAnalyzer:
    """Handles instruction analysis and state transition detection"""
    
    @staticmethod
    def find_state_transition_instructions(
            local_if_table: List[MediumLevelILIf],
            local_define_table: List[MediumLevelILSetVar]
        ) -> List[Dict[str, Any]]:
        paired_instructions = []

        for def_instr in local_define_table:
            t_def_const = def_instr.src
            t_def_const_width = def_instr.size
            key_define = t_def_const.value.value & int(f"0x{'ff' * t_def_const_width}", 16)
            for if_instr in local_if_table:
                if_const = if_instr.condition.right
                if_const_width = if_instr.condition.left.size
                key_if = if_const.value.value & int(f"0x{'ff' * if_const_width}", 16)
                if key_if == key_define:
                    paired_instructions.append({
                        "if_instr": if_instr,
                        "def_instr": def_instr,
                        "def_const": def_instr.src,
                        "if_const": if_const,
                    })
        return paired_instructions

    @staticmethod
    def find_white_instructions(mlil: MediumLevelILFunction, possible_state_vars: List[Variable]):
        white_instructions = []
        for instr in mlil.instructions:
            if instr.operation not in [MediumLevelILOperation.MLIL_GOTO, MediumLevelILOperation.MLIL_IF,
                                    MediumLevelILOperation.MLIL_SET_VAR]:
                continue
            vars = instr.vars_written + instr.vars_read
            if not all([var in possible_state_vars for var in vars]):
                continue
            white_instructions.append(instr)
        return white_instructions

    @staticmethod
    def check_state_if_instr(instr: MediumLevelILInstruction):
        if not isinstance(instr, MediumLevelILIf):
            return False
        condition = instr.condition
        if "left" not in dir(condition) and "right" not in dir(condition):
            return False
        if condition.right.operation != MediumLevelILOperation.MLIL_CONST:
            return False
        return True

    @staticmethod
    def emu_if(left_const: int, if_symbol: MediumLevelILOperation, right_const: int):
        def cmp_e(a, b): return a == b
        def cmp_ne(a, b): return a != b
        def cmp_ult(a, b): return a < b
        def cmp_ule(a, b): return a <= b
        def cmp_ugt(a, b): return a > b
        def cmp_uge(a, b): return a >= b
        def cmp_slt(a, b): return unsigned_to_signed_32bit(a) < unsigned_to_signed_32bit(b)
        def cmp_sle(a, b): return unsigned_to_signed_32bit(a) <= unsigned_to_signed_32bit(b)
        def cmp_sgt(a, b): return unsigned_to_signed_32bit(a) > unsigned_to_signed_32bit(b)
        def cmp_sge(a, b): return unsigned_to_signed_32bit(a) >= unsigned_to_signed_32bit(b)

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
    def check_path(
            mlil: MediumLevelILFunction,
            path: List[int],
            state_vars: List[Variable],
            white_instructions: List[MediumLevelILInstruction]
    ):
        instrs = []
        for x in path:
            instrs.append(mlil[x])
        if not all([instr in white_instructions for instr in instrs]):
            log_info(
                f"not in white instructions::{pformat([instr for instr in instrs if instr not in white_instructions])}")
            return False
        log_info(f"[path] instructions::{pformat(instrs)}")
        log_info(f"[path] paths::{pformat(path)}")
        return True