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
    log_error(pformat(if_table))
    log_error(pformat(define_table))
    possible_state_vars = state_vars
    l_if_table = []
    for k,v in if_table.items():
        l_if_table+=v
    l_define_table =[]
    for k,v in define_table.items():
        l_define_table+=v

    trans_dict = InstructionAnalyzer.find_state_transition_instructions(l_if_table, l_define_table)
    white_instructions = InstructionAnalyzer.find_white_instructions(mlil, possible_state_vars)
    for trans in trans_dict:
        def_instr: MediumLevelILInstruction | MediumLevelILSetVar = trans["def_instr"]
        if_instr: MediumLevelILInstruction | MediumLevelILIf = trans["if_instr"]
        try:
            path_full = nx.shortest_path(G_full, def_instr.instr_index, if_instr.instr_index)
        except nx.NetworkXNoPath:
            continue
        cond = InstructionAnalyzer.check_path(mlil, path_full, possible_state_vars, white_instructions)
        if not cond:
            continue
