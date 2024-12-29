from pprint import pformat

import networkx as nx
from binaryninja import (
    MediumLevelILFunction,
    MediumLevelILIf,
    MediumLevelILGoto,
    Function,
    Variable,
    AnalysisContext,
    MediumLevelILOperation,
    MediumLevelILSetVar,
    MediumLevelILVar, MediumLevelILInstruction,
)

from ...utils import log_error, collect_stateVar_info, log_info, unsigned_to_signed_32bit


def create_cfg_graph(mlil: MediumLevelILFunction):
    G = nx.DiGraph()
    for block in mlil.basic_blocks:
        G.add_node(block.start)
        if isinstance(block[-1], MediumLevelILIf):
            G.add_edge(block.start, block[-1].true, edge_label="true")
            G.add_edge(block.start, block[-1].false, edge_label="false")
        elif isinstance(block[-1], MediumLevelILGoto):
            G.add_edge(block.start, block[-1].dest, edge_label="goto")
        else:
            for edge in block.outgoing_edges:
                G.add_edge(block.start, edge.target.start, edge_label="unknown")
    return G


def create_full_cfg_graph(mlil: MediumLevelILFunction):
    G = nx.DiGraph()
    for block in mlil.basic_blocks:
        for i in range(block.start, block.end):
            G.add_node(i)
        for i in range(block.start, block.end - 1):
            G.add_edge(i, i + 1)
    for block in mlil.basic_blocks:
        lastInstr = block[-1]
        if isinstance(lastInstr, MediumLevelILIf):
            G.add_edge(lastInstr.instr_index, lastInstr.true, edge_label="true")
            G.add_edge(lastInstr.instr_index, lastInstr.false, edge_label="false")
        elif isinstance(lastInstr, MediumLevelILGoto):
            G.add_edge(lastInstr.instr_index, lastInstr.dest, edge_label="goto")
        else:
            for edge in block.outgoing_edges:
                G.add_edge(lastInstr.instr_index, edge.target.start, edge_label="unknown")
    return G


def find_state_var(func: Function):
    vars = func.vars
    vars_name = [var.name for var in vars]
    if all([not var.startswith("state-") for var in vars_name]):
        from ...mikuPlugin import suggest_stateVar
        suggest_stateVar(func.view, func)
    state_vars = [var for var in vars if var.name.startswith("state-")]
    return state_vars


def find_paired_state_var(state_var: Variable, mlil: MediumLevelILFunction):
    if not state_var.name.startswith("state-"):
        return None
    defines = mlil.get_var_definitions(state_var)
    if all(
            [defi.src.operation == MediumLevelILOperation.MLIL_CONST for defi in defines]
    ):
        return None
    for define in defines:
        if not isinstance(define, MediumLevelILSetVar):
            continue
        var = define.src
        if (
                isinstance(var, MediumLevelILVar)
                and var.src.name.startswith("state-")
                and var.src != state_var
        ):
            return var.src


from typing import List, Dict, Any


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


def pass_deflate_hard(analysis_context: AnalysisContext):
    function: Function = analysis_context.function
    mlil: MediumLevelILFunction = function.mlil
    if mlil is None:
        log_error(f"Function {function.name} has no MLIL")
        return
    # G = create_cfg_graph(mlil)
    G_full = create_full_cfg_graph(mlil)
    state_vars = find_state_var(function)
    if_table, define_table = collect_stateVar_info(function, False)
    for state_var in state_vars:
        paired_state_var = find_paired_state_var(state_var, mlil)
        possible_state_vars = [state_var]
        if paired_state_var is not None:
            state_vars.remove(paired_state_var)
            state_vars.remove(state_var)
            possible_state_vars.append(paired_state_var)
            log_info(f"{paired_state_var},{state_var}")
            local_if_table = if_table.get(paired_state_var, []) + if_table.get(state_var, [])
            local_define_table = define_table.get(paired_state_var, []) + define_table.get(state_var, [])
        else:
            log_info(f"{paired_state_var},{state_var}")
            local_if_table = if_table.get(state_var, [])
            local_define_table = define_table.get(state_var, [])
        # filter if and define
        # log_info(f"{local_if_table},{local_define_table}")
        trans_dict = find_state_transition_instructions(local_if_table, local_define_table)
        log_info(f"{pformat(trans_dict)}")

        white_instructions = find_white_instructions(mlil, possible_state_vars)
        # log_info(f"white_instructions::{pformat(white_instructions)}")

        for trans in trans_dict:
            def_instr = trans["def_instr"]
            if_instr = trans["if_instr"]
            if_const = trans["if_const"]
            def_const = trans["def_const"]

            # path = nx.shortest_path(G, start_search, end_search)
            path_full = nx.shortest_path(G_full, def_instr.instr_index, if_instr.instr_index)

            cond = check_path(mlil, path_full, possible_state_vars, white_instructions)
            if not cond:
                continue


def check_state_if_instr(instr: MediumLevelILInstruction):
    if not isinstance(instr, MediumLevelILIf):
        return False
    condition = instr.condition
    if "left" not in dir(condition) and "right" not in dir(condition):
        return False
    if condition.right.operation != MediumLevelILOperation.MLIL_CONST:
        return False
    return True


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
        # 打印不在白名单的指令
        # todo 这里应该收集
        log_info(
            f"not in white instructions::{pformat([instr for instr in instrs if instr not in white_instructions])}")
        return False
    log_info(f"[path] instructions::{pformat(instrs)}")
    log_info(f"[path] paths::{pformat(path)}")
    return True
