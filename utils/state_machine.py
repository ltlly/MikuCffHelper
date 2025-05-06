from typing import Callable, List, Dict, Tuple
from binaryninja import (
    Function,
    Variable,
    MediumLevelILFunction,
    MediumLevelILSetVar,
    MediumLevelILVar,
    MediumLevelILIf,
    MediumLevelILConst,
    MediumLevelILInstruction,
)


class StateMachine:
    """状态机分析器，负责状态机分析和状态变量检测"""

    @staticmethod
    def collect_stateVar_info(
        func: Function, ret_int: bool = True
    ) -> Tuple[
        Dict[Variable, List[MediumLevelILInstruction] | List[int]],
        Dict[Variable, List[MediumLevelILInstruction] | List[int]],
    ]:
        """收集函数中的状态变量信息
        Args:
            func (Function): 目标函数
            ret_int (bool): 是否返回整数值
        Returns:
            Tuple[Dict[Variable, List[MediumLevelILInstruction] | List[int]],
                  Dict[Variable, List[MediumLevelILInstruction] | List[int]]]
            : 返回的字典包含变量和对应的指令列表或整数值列表
        """
        args = func.parameter_vars
        args_name = [var.name for var in args]
        mlil = func.medium_level_il
        if not mlil:
            return {}, {}

        def find_if_const_compare(
            mlil: MediumLevelILFunction,
        ) -> Dict[Variable, List[MediumLevelILInstruction] | List[int]]:
            ifTable: Dict[Variable, List[MediumLevelILInstruction] | List[int]] = {}
            for bb in mlil.basic_blocks:
                expr = bb[-1]
                if not isinstance(expr, MediumLevelILIf):
                    continue
                condition = expr.condition
                if isinstance(condition, MediumLevelILVar):
                    continue
                if not hasattr(condition, "right"):
                    continue
                if isinstance(condition.right, MediumLevelILConst):
                    left = condition.left
                    for token in left.tokens:
                        if token in args_name:
                            continue
                    if not isinstance(left, MediumLevelILVar):
                        continue
                    if left.src not in ifTable:
                        ifTable[left.src] = []
                    if ret_int:
                        ifTable[left.src].append(condition.right.value.value)
                    else:
                        ifTable[left.src].append(expr)
            return ifTable

        def find_define(
            mlil: MediumLevelILFunction,
        ) -> Dict[Variable, List[MediumLevelILInstruction] | List[int]]:
            defineTable: Dict[Variable, List[MediumLevelILInstruction] | List[int]] = {}
            for expr in mlil.instructions:
                if not isinstance(expr, MediumLevelILSetVar):
                    continue
                if not isinstance(expr.src, MediumLevelILConst):
                    continue
                for token in expr.tokens:
                    if token in args_name:
                        continue
                if expr.dest not in defineTable:
                    defineTable[expr.dest] = []
                if ret_int:
                    defineTable[expr.dest].append(expr.src.value.value)
                else:
                    defineTable[expr.dest].append(expr)
            return defineTable

        ifTable = find_if_const_compare(mlil)
        defineTable = find_define(mlil)
        if not ret_int:
            for x in ifTable:
                ifTable[x] = [
                    instr for instr in ifTable[x] if instr.instr_index < len(mlil)
                ]
            for x in defineTable:
                defineTable[x] = [
                    instr for instr in defineTable[x] if instr.instr_index < len(mlil)
                ]
        return ifTable, defineTable

    @staticmethod
    def find_state_var(func: Function) -> List[Variable]:
        """查找函数中的状态变量
        Args:
            func (Function): 目标函数
        """
        mlil = func.medium_level_il
        if not mlil:
            return []
        from .state_machine import StateMachine

        # State variable recognition rules
        state_var_rules: List[
            Callable[
                [
                    Variable,
                    Dict[Variable, List[MediumLevelILInstruction] | List[int]],
                    Dict[Variable, List[MediumLevelILInstruction] | List[int]],
                ],
                bool,
            ]
        ] = [
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
        state_vars: List[Variable] = []
        ifTable, defineTable = StateMachine.collect_stateVar_info(func)
        # Check all variables
        for mlil_var in set(list(ifTable.keys()) + list(defineTable.keys())):
            for rule in state_var_rules:
                if rule(mlil_var, ifTable, defineTable):
                    state_vars.append(mlil_var)
                    break
        return state_vars
