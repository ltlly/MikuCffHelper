from typing import Dict, Any
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
    LowLevelILFunction, LowLevelILGoto, LowLevelILIf,
    Logger
)

mikuLogger = Logger(0, "MikuCffHelper")

def log_error(msg: str):
    mikuLogger.log_error(msg)

class CFGAnalyzer:
    """控制流图分析器，负责控制流图的分析和操作"""
    
    @staticmethod
    def create_cfg_graph(mlil: MediumLevelILFunction):
        """创建基本块级别的控制流图
        Args:
            mlil (MediumLevelILFunction): 中间语言函数
        Returns:
            networkx.DiGraph: 生成的控制流图
        """
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

    @staticmethod
    def create_full_cfg_graph(mlil: MediumLevelILFunction):
        """创建指令级别的完整控制流图
        Args:
            mlil (MediumLevelILFunction): 中间语言函数
        Returns:
            networkx.DiGraph: 生成的完整控制流图
        """
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

    @staticmethod
    def get_basic_block_at(basic_blocks, index):
        """获取指定索引处的基本块
        Args:
            basic_blocks: 基本块列表
            index: 目标索引
        Returns:
            包含指定索引的基本块，如果找不到返回None
        """
        bbs = sorted(list(basic_blocks), key=lambda bb: bb.start)
        low, high = 0, len(bbs) - 1
        while low <= high:
            mid = (low + high) // 2
            if bbs[mid].start <= index < bbs[mid].end:
                return bbs[mid]
            elif index < bbs[mid].start:
                high = mid - 1
            else:
                low = mid + 1
        log_error(f"can't find basic block at {index}")
        return None

    @staticmethod
    def LLIL_get_incoming_blocks(llil: LowLevelILFunction, bbIndex: int):
        """获取基本块的所有前驱块
        Args:
            llil (LowLevelILFunction): 低级中间语言函数
            bbIndex (int): 目标基本块索引
        Returns:
            List: 所有前驱基本块列表
        """
        bbs = []
        for bb in llil.basic_blocks:
            lastInstr = llil[bb.end - 1]
            if isinstance(lastInstr, LowLevelILGoto):
                if lastInstr.dest == bbIndex:
                    bbs.append(bb)
            elif isinstance(lastInstr, LowLevelILIf):
                if lastInstr.true == bbIndex:
                    bbs.append(bb)
                elif lastInstr.false == bbIndex:
                    bbs.append(bb)
        bbs.sort(key=lambda bb: bb.start)
        return bbs