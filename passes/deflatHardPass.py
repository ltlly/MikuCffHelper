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

def pass_deflat_hard(analysys_context: AnalysisContext):
    function = analysys_context.function
    mlil = function.mlil
    if mlil is None:
        log_error(f"Function {function.name} has no MLIL")
        return
    G = create_cfg_graph(mlil)
    #todo
