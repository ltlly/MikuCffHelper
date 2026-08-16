"""多维可读性指标。

去混淆效果不能只看 basic block 数量：把 dispatcher 换成等量的 mini-block
也可能让块数不变但结构更差。这里同时测量：

- MLIL：块数、边数、圈复杂度 (E-N+2P)、显式分支数；
- HLIL：指令行数、if / loop / goto / jump / switch / case / call 数量；
- 表达式最大嵌套深度。

指标纯计算、无副作用，供模式评估和未来 trial-select 使用。
"""

from dataclasses import dataclass
from typing import List, Optional

from binaryninja import (
    HighLevelILInstruction,
    HighLevelILOperation,
    MediumLevelILFunction,
    MediumLevelILIf,
)


@dataclass
class ReadabilityMetrics:
    mlil_blocks: int = 0
    mlil_edges: int = 0
    mlil_cyclomatic: int = 0
    mlil_branches: int = 0
    hlil_lines: int = 0
    hlil_if: int = 0
    hlil_loops: int = 0
    hlil_goto: int = 0
    hlil_jump: int = 0
    hlil_switch: int = 0
    hlil_cases: int = 0
    hlil_calls: int = 0
    max_expr_depth: int = 0

    def as_dict(self):
        return self.__dict__.copy()

    def penalty(
        self,
        w_cyclomatic: float = 1.0,
        w_lines: float = 1.0,
        w_goto_jump: float = 2.0,
        w_depth: float = 1.0,
        w_blocks: float = 0.5,
    ) -> float:
        """可读性惩罚分，越小越好。

        权重保持可解释：圈复杂度、HLIL 行数、goto/jump、嵌套深度为主，
        block 数只占 0.5（避免过去只看 block 数的偏差）。
        """
        return (
            w_cyclomatic * self.mlil_cyclomatic
            + w_lines * self.hlil_lines
            + w_goto_jump * (self.hlil_goto + self.hlil_jump)
            + w_depth * self.max_expr_depth
            + w_blocks * self.mlil_blocks
        )


def _max_depth(expr, depth: int = 1) -> int:
    """递归计算 HLIL 表达式的最大嵌套深度。"""
    best = depth
    try:
        operands = expr.operands
    except Exception:
        operands = []
    for operand in operands:
        if isinstance(operand, HighLevelILInstruction):
            best = max(best, _max_depth(operand, depth + 1))
        elif isinstance(operand, (list, tuple)):
            for item in operand:
                if isinstance(item, HighLevelILInstruction):
                    best = max(best, _max_depth(item, depth + 1))
    return best


def metrics_mlil(mlil: MediumLevelILFunction) -> ReadabilityMetrics:
    m = ReadabilityMetrics()
    if mlil is None:
        return m
    bbs = list(mlil.basic_blocks)
    m.mlil_blocks = len(bbs)
    seen_edges = set()
    for bb in bbs:
        for edge in bb.outgoing_edges:
            pair = (bb.start, edge.target.start)
            if pair not in seen_edges:
                seen_edges.add(pair)
        last = mlil[bb.end - 1] if bb.length else None
        if isinstance(last, MediumLevelILIf):
            m.mlil_branches += 1
    m.mlil_edges = len(seen_edges)
    # 单入口函数：P=1；防御 P=0
    m.mlil_cyclomatic = max(0, m.mlil_edges - m.mlil_blocks + 2)
    return m


def metrics_hlil(func) -> ReadabilityMetrics:
    m = metrics_mlil(func.mlil) if getattr(func, "mlil", None) is not None else ReadabilityMetrics()
    if func is None or func.hlil is None:
        return m
    m.hlil_lines = len(list(func.hlil.instructions))
    counts = {
        HighLevelILOperation.HLIL_IF: "hlil_if",
        HighLevelILOperation.HLIL_GOTO: "hlil_goto",
        HighLevelILOperation.HLIL_JUMP: "hlil_jump",
        HighLevelILOperation.HLIL_SWITCH: "hlil_switch",
        HighLevelILOperation.HLIL_CASE: "hlil_cases",
        HighLevelILOperation.HLIL_CALL: "hlil_calls",
        HighLevelILOperation.HLIL_CALL_SSA: "hlil_calls",
        HighLevelILOperation.HLIL_TAILCALL: "hlil_calls",
        HighLevelILOperation.HLIL_WHILE: "hlil_loops",
        HighLevelILOperation.HLIL_WHILE_SSA: "hlil_loops",
        HighLevelILOperation.HLIL_DO_WHILE: "hlil_loops",
        HighLevelILOperation.HLIL_DO_WHILE_SSA: "hlil_loops",
        HighLevelILOperation.HLIL_FOR: "hlil_loops",
        HighLevelILOperation.HLIL_FOR_SSA: "hlil_loops",
    }

    def visitor(expr):
        if not isinstance(expr, HighLevelILInstruction):
            return
        attr = counts.get(expr.operation)
        if attr is not None:
            setattr(m, attr, getattr(m, attr) + 1)
        m.max_expr_depth = max(m.max_expr_depth, _max_depth(expr))

    for top in func.hlil.instructions:
        try:
            list(top.traverse(visitor))
        except Exception:
            continue
        m.max_expr_depth = max(m.max_expr_depth, _max_depth(top))
    return m


def readability_for_function(func) -> ReadabilityMetrics:
    """综合 MLIL + HLIL 指标。"""
    return metrics_hlil(func)

BAD_METRIC_KEYS = (
    "mlil_blocks",
    "mlil_cyclomatic",
    "hlil_lines",
    "hlil_goto",
    "hlil_jump",
    "max_expr_depth",
)


def dominates(a: ReadabilityMetrics, b: ReadabilityMetrics) -> bool:
    """a 在所有坏指标上不劣于 b，且至少一个严格更优。"""
    a_d, b_d = a.as_dict(), b.as_dict()
    le_all = all(a_d[k] <= b_d[k] for k in BAD_METRIC_KEYS)
    lt_one = any(a_d[k] < b_d[k] for k in BAD_METRIC_KEYS)
    return le_all and lt_one


def default_penalty(
    m: ReadabilityMetrics,
    w_blocks: float = 0.5,
    w_cyclomatic: float = 1.0,
    w_lines: float = 1.0,
    w_goto_jump: float = 3.0,
    w_depth: float = 1.0,
) -> float:
    """默认可读性惩罚分。权重集中在上层结构复杂度，block 只占 0.5。"""
    d = m.as_dict()
    return (
        w_blocks * d["mlil_blocks"]
        + w_cyclomatic * d["mlil_cyclomatic"]
        + w_lines * d["hlil_lines"]
        + w_goto_jump * (d["hlil_goto"] + d["hlil_jump"])
        + w_depth * d["max_expr_depth"]
    )
