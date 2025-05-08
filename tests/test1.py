from binaryninja import *
import networkx as nx
import json


def create_cfg_graph(il: MediumLevelILFunction | LowLevelILFunction):
    """创建基本块级别的控制流图
    Args:
        mlil (MediumLevelILFunction): 中间语言函数
    Returns:
        networkx.DiGraph: 生成的控制流图
    """
    if isinstance(il, MediumLevelILFunction):
        ifInstrInstance = MediumLevelILIf
        gotoInstrInstance = MediumLevelILGoto
    elif isinstance(il, LowLevelILFunction):
        ifInstrInstance = LowLevelILIf
        gotoInstrInstance = LowLevelILGoto
    else:
        raise TypeError("il must be MediumLevelILFunction or LowLevelILFunction")
    G = nx.DiGraph()
    for block in il.basic_blocks:
        G.add_node(block.start)
        if isinstance(block[-1], ifInstrInstance):
            G.add_edge(block.start, block[-1].true, edge_label="true")
            G.add_edge(block.start, block[-1].false, edge_label="false")
        elif isinstance(block[-1], gotoInstrInstance):
            G.add_edge(block.start, block[-1].dest, edge_label="goto")
        else:
            for edge in block.outgoing_edges:
                G.add_edge(block.start, edge.target.start, edge_label="unknown")
    return G


def process_func(func):
    try:
        mlil = func.mlil
        if mlil is None:
            return
        data = {}
        data["name"] = func.name
        data["mlil_blocks_len"] = len(mlil.basic_blocks)
        data["mlil_instructions_len"] = len(list(mlil.instructions))
        G = create_cfg_graph(mlil)
        data["cfg_nodes_len"] = len(G.nodes)
        data["cfg_edges_len"] = len(G.edges)
        if_instr_len = 0
        for instr in mlil.instructions:
            if isinstance(instr, MediumLevelILIf):
                if_instr_len += 1
        data["if_instr_len"] = if_instr_len
        # 圈复杂度
        data["cyclomatic_complexity"] = len(G.edges) - len(G.nodes) + 2
        # 分支复杂度
        data["branch_complexity"] = len(G.edges) - len(G.nodes) + 1
        out_degrees = [G.out_degree(node) for node in G.nodes]
        data["avg_out_degree"] = (
            sum(out_degrees) / len(out_degrees) if out_degrees else 0
        )
        return json.dumps(data, indent=4)
    except Exception as e:
        print(f"Error processing function {func.name}: {e}")
result = []
for func in bv.functions:
    data = process_func(func)
    if data:
        result.append(data)

with open(
    r"C:\\Users\\ltlly\AppData\\Roaming\\Binary Ninja\\plugins\\cfg_analysis_deflat.json",
    "w",
) as f:
    json.dump(result, f, indent=4)
print("cfg_analysis.json created")
