import networkx as nx
from binaryninja import *


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
                G.add_edge(block.start, edge.target.start,
                           edge_label="unknown")
    return G


def find_state_var(func: Function):
    vars = func.vars
    vars_name = [var.name for var in vars]
    if all([not var.startswith("state-") for var in vars_name]):
        from ..mikuPlugin import suggest_stateVar
        suggest_stateVar(func.view, func)
    state_vars = [var for var in vars if var.name.startswith("state-")]
    return state_vars


def find_paired_stateVar(stateVar: Variable, mlil: MediumLevelILFunction):
    if not stateVar.name.startswith("state-"):
        return None
    defines = mlil.get_var_definitions(stateVar)
    if all([defi.src.operation == MediumLevelILOperation.MLIL_CONST for defi in defines]):
        return None
    else:
        for defi in defines:
            if not isinstance(defi, MediumLevelILSetVar):
                continue
            var = defi.src
            if isinstance(var, MediumLevelILVar) and var.src.name.startswith("state-") and var.src != stateVar:
                return var.src




def pass_deflat_hard(analysys_context: AnalysisContext):
    function = analysys_context.function
    mlil = function.mlil
    if mlil is None:
        log_error(f"Function {function.name} has no MLIL")
        return
    G = create_cfg_graph(mlil)
    state_vars = find_state_var(function)
    print(state_vars)
