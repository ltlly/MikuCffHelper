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
    MediumLevelILVar,
)
from ...utils import log_error, collect_stateVar_info, get_basic_block_at


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
        from ..mikuPlugin import suggest_stateVar

        suggest_stateVar(func.view, func)
    state_vars = [var for var in vars if var.name.startswith("state-")]
    return state_vars


def find_paired_stateVar(stateVar: Variable, mlil: MediumLevelILFunction):
    if not stateVar.name.startswith("state-"):
        return None
    defines = mlil.get_var_definitions(stateVar)
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
                and var.src != stateVar
            ):
                return var.src


def pass_deflat_hard(analysis_context: AnalysisContext):
    function = analysis_context.function
    mlil = function.mlil
    if mlil is None:
        log_error(f"Function {function.name} has no MLIL")
        return
    G = create_cfg_graph(mlil)
    state_vars = find_state_var(function)
    print(state_vars)
    ifTable, defineTable = collect_stateVar_info(function, False)
    for state_var in state_vars:
        paired_state_var = find_paired_stateVar(state_var, mlil)
        possable_state_vars = [state_var]
        if paired_state_var is not None:
            state_vars.remove(paired_state_var)
            state_vars.remove(state_var)
            possable_state_vars.append(paired_state_var)
        # print(paired_state_var,state_var)
        log_error(f"{paired_state_var},{state_var}")

        local_ifTable = []
        local_defineTable = []
        if paired_state_var is not None:
            if1 = ifTable[paired_state_var] if paired_state_var in ifTable else []
            if2 = ifTable[state_var] if state_var in ifTable else []
            local_ifTable = if1 + if2
            define1 = (
                defineTable[paired_state_var] if paired_state_var in defineTable else []
            )
            define2 = defineTable[state_var] if state_var in defineTable else []
            local_defineTable = define1 + define2
        else:
            local_ifTable = ifTable[state_var]
            local_defineTable = defineTable[state_var]
        # filter if and define


        log_error(f"{local_ifTable},{local_defineTable}")
        for ifInstr in local_ifTable:
            ifConst = ifInstr.condition.right
            defConst = None
            defInstr =None
            for t2 in local_defineTable:
                t_defConst = t2.src
                # todo fix 0xFFFFFFFF
                if (ifConst.value.value) & 0xFFFFFFFF == (t_defConst.value.value) & 0xFFFFFFFF:
                    defConst = t_defConst
                    defInstr = t2
                    break
            if defConst is None:
                continue
                
            start_search: int = get_basic_block_at(mlil, defInstr.instr_index).start
            end_search: int = get_basic_block_at(mlil, ifInstr.instr_index).start
            log_error(f"{defInstr},{ifInstr}")
            log_error(f"{start_search},{end_search}")
            log_error(f"{nx.shortest_path(G,start_search,end_search)}")
