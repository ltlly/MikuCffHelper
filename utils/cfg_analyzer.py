from typing import Dict, Any, List
import networkx as nx
from binaryninja import (
    MediumLevelILBasicBlock,
    MediumLevelILFunction,
    MediumLevelILIf,
    MediumLevelILGoto,
    LowLevelILFunction,
    LowLevelILGoto,
    LowLevelILIf,
    Logger,
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
                    G.add_edge(
                        lastInstr.instr_index, edge.target.start, edge_label="unknown"
                    )
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

    @staticmethod
    def MLIL_get_incoming_blocks(
        mlil: MediumLevelILFunction, bbIndex: int
    ) -> List[MediumLevelILBasicBlock]:
        """获取目标基本块的所有前驱基本块
        Args:
            mlil (MediumLevelILFunction): 中级中间语言函数
            bbIndex (int): 目标基本块索引
        Returns:
            List: 所有前驱基本块列表
        """
        bbs = []
        for bb in mlil.basic_blocks:
            lastInstr = mlil[bb.end - 1]
            if isinstance(lastInstr, MediumLevelILGoto):
                if lastInstr.dest == bbIndex:
                    bbs.append(bb)
            elif isinstance(lastInstr, MediumLevelILIf):
                if lastInstr.true == bbIndex:
                    bbs.append(bb)
                elif lastInstr.false == bbIndex:
                    bbs.append(bb)
        bbs.sort(key=lambda bb: bb.start)
        return bbs

    @staticmethod
    def find_cfg_groups(block_cfg: nx.Graph) -> List[List[int]]:
        """
        查找CFG中的线性组
        线性组是指由出度为1的节点组成的链
        Args:
            block_cfg (nx.Graph): 基本块控制流图
        Returns:
            List[List[int]]: 线性组列表,返回[[block1.start,block2.start],[block3.start,block4.start]]
        """
        visited = set()
        groups = []
        for node in block_cfg.nodes():
            if node in visited:
                continue  # 跳过已访问节点

            # 只允许出度为1的节点作为组的起点
            if block_cfg.out_degree(node) != 1:
                continue

            current_group = []
            current_node = node
            current_group.append(current_node)
            visited.add(current_node)

            while True:
                # 获取当前节点的唯一后继
                successors = list(block_cfg.successors(current_node))
                if len(successors) != 1:
                    break  # 出度不为1时终止
                next_node = successors[0]

                # 检查后继节点的入度和出度
                if block_cfg.in_degree(next_node) != 1 or block_cfg.out_degree(
                    next_node
                ) not in {0, 1}:
                    break  # 不满足条件时终止

                # 检查后继节点是否已访问
                if next_node in visited:
                    break

                # 将后继节点加入组
                current_group.append(next_node)
                visited.add(next_node)
                current_node = next_node

                # 如果出度为0，终止扩展
                if block_cfg.out_degree(current_node) == 0:
                    break

            # 仅保留有效组（长度≥2）
            if len(current_group) >= 2:
                groups.append(current_group)

        return groups
