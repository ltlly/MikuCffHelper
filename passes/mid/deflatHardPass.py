from pprint import pformat
from typing import List, Dict, Any
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

from ...utils import (
    log_error,
    collect_stateVar_info,
    log_info,
    unsigned_to_signed_32bit,
    CFGAnalyzer,
    StateMachine,
    InstructionAnalyzer
)


def pass_deflate_hard(analysis_context: AnalysisContext):
    function: Function = analysis_context.function
    mlil: MediumLevelILFunction | None = function.mlil
    if mlil is None:
        log_error(f"Function {function.name} has no MLIL")
        return
    G_full = CFGAnalyzer.create_full_cfg_graph(mlil)
    state_vars = StateMachine.find_state_var(function)
    if_table, define_table = collect_stateVar_info(function, False)
    
    for state_var in state_vars:
        paired_state_var = StateMachine.find_paired_state_var(state_var, mlil)
        possible_state_vars = [state_var]
        
        if paired_state_var is not None:
            possible_state_vars.append(paired_state_var)
            log_info(f"{paired_state_var},{state_var}")
            local_if_table = if_table.get(paired_state_var, []) + if_table.get(state_var, [])
            local_define_table = define_table.get(paired_state_var, []) + define_table.get(state_var, [])
        else:
            log_info(f"{paired_state_var},{state_var}")
            local_if_table = if_table.get(state_var, [])
            local_define_table = define_table.get(state_var, [])
            
        trans_dict = InstructionAnalyzer.find_state_transition_instructions(local_if_table, local_define_table)
        log_info(f"{pformat(trans_dict)}")

        white_instructions = InstructionAnalyzer.find_white_instructions(mlil, possible_state_vars)

        for trans in trans_dict:
            def_instr: MediumLevelILInstruction | MediumLevelILSetVar = trans["def_instr"]
            if_instr: MediumLevelILInstruction | MediumLevelILIf = trans["if_instr"]
            
            path_full = nx.shortest_path(G_full, def_instr.instr_index, if_instr.instr_index)
            cond = InstructionAnalyzer.check_path(mlil, path_full, possible_state_vars, white_instructions)
            if not cond:
                continue
