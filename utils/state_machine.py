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

        # 注意：CFF 状态变量的关键特征是 *被赋予多个不同的常量*，否则就是
        # 普通的常量传播变量（同一个常量被 SSA 拆出来赋了 N 次仍然是同一个值）。
        # 因此识别规则全部用 *unique 值数* 而不是出现次数。
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
            # Rule 1: 同时出现在 const 赋值与 if 常量比较中，且各自 unique 常量数 ≥ 2
            lambda var, ifTable, defineTable: (
                var in ifTable
                and var in defineTable
                and len(set(defineTable[var])) >= 2
                and len(set(ifTable[var])) >= 2
            ),
            # Rule 2: 在 const 赋值中 unique 值 ≥ 3 且平均值较大（典型 CFF 状态值）
            lambda var, ifTable, defineTable: (
                var in defineTable
                and len(set(defineTable[var])) >= 3
                and sum(defineTable[var]) // len(defineTable[var]) > 0x10000000
            ),
            # Rule 3: 在 if 常量比较中 unique 值 ≥ 3 且平均值较大
            lambda var, ifTable, defineTable: (
                var in ifTable
                and len(set(ifTable[var])) >= 3
                and sum(ifTable[var]) // len(ifTable[var]) > 0x10000000
            ),
            # Rule 4: 已被用户标记为 state-X 的变量
            lambda var, ifTable, defineTable: (
                var.name.startswith("state-")
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
