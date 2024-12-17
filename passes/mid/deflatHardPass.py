from typing import List

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

from ...utils import log_error, collect_stateVar_info


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
    else:
        for defi in defines:
            if not isinstance(defi, MediumLevelILSetVar):
                continue
            var = defi.src
            if (
                    isinstance(var, MediumLevelILVar)
                    and var.src.name.startswith("state-")
                    and var.src != state_var
            ):
                return var.src


def pass_deflate_hard(analysis_context: AnalysisContext):
    function = analysis_context.function
    mlil = function.mlil
    if mlil is None:
        log_error(f"Function {function.name} has no MLIL")
        return
    G = create_cfg_graph(mlil)
    state_vars = find_state_var(function)
    if_table, define_table = collect_stateVar_info(function, False)
    for state_var in state_vars:
        paired_state_var = find_paired_state_var(state_var, mlil)
        possible_state_vars = [state_var]
        if paired_state_var is not None:
            state_vars.remove(paired_state_var)
            state_vars.remove(state_var)
            possible_state_vars.append(paired_state_var)
        log_error(f"{paired_state_var},{state_var}")

        if paired_state_var:
            local_if_table = if_table.get(paired_state_var, []) + if_table.get(
                state_var, []
            )
            local_define_table = define_table.get(
                paired_state_var, []
            ) + define_table.get(state_var, [])
        else:
            local_if_table = if_table.get(state_var, [])
            local_define_table = define_table.get(state_var, [])

        # filter if and define

        log_error(f"{local_if_table},{local_define_table}")
        for if_instr in local_if_table:
            if_const = if_instr.condition.right
            if_const_width = if_instr.condition.left.size
            def_const = None
            def_instr = None

            for define_instr in local_define_table:
                t_def_const = define_instr.src
                t_def_const_width = define_instr.size

                if (if_const.value.value & int(f"0x{'ff' * if_const_width}", 16)) == (
                        t_def_const.value.value & int(f"0x{'ff' * t_def_const_width}", 16)
                ):
                    def_const = t_def_const
                    def_instr = define_instr
                    break

            if def_const is None:
                continue

            start_search = mlil.get_basic_block_at(def_instr.instr_index).start
            end_search = mlil.get_basic_block_at(if_instr.instr_index).start

            path = nx.shortest_path(G, start_search, end_search)

            log_error(f"{def_instr}, {if_instr}")
            log_error(f"{start_search}, {end_search}")
            log_error(f"{path}")

            check_path(mlil, path, possible_state_vars, start_search, end_search)


def check_state_if_instr(instr: MediumLevelILInstruction):
    if not isinstance(instr, MediumLevelILIf):
        return False
    condition = instr.condition
    #        todo


def check_path(
        mlil: MediumLevelILFunction,
        path: List[int],
        state_vars: List[Variable],
        start_search: int,
        end_search: int,
):
    instrs = []
    for i in range(start_search, mlil.get_basic_block_at(path[0]).end):
        instrs.append(mlil[i])
    for block in path[1:]:
        for instr in mlil.get_basic_block_at(block):
            instrs.append(instr)
    log_error(f"{instrs}")
    check = True
    vars = []
    for instr in instrs:
        vars += instr.vars_written
        vars += instr.vars_read
    if not all([var in state_vars for var in vars]):
        check = False
    if not check:
        return False
