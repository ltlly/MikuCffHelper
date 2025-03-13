from binaryninja import *

from ..utils import log_error


def get_basic_block_at(self, index: int) -> Optional["basicblock.BasicBlock"]:
    basic_blocks = self.basic_blocks
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


def if_expr(
    self,
    operand: ExpressionIndex,
    t: MediumLevelILLabel,
    f: MediumLevelILLabel,
    loc: ILSourceLocation = None,
) -> ExpressionIndex:
    if loc:
        return ExpressionIndex(
            core.BNMediumLevelILIfWithLocation(
                self.handle, operand, t.handle, f.handle, loc.address, loc.source_operand
            )
        )
    return ExpressionIndex(
        core.BNMediumLevelILIf(self.handle, operand, t.handle, f.handle)
    )


def goto(
    self, label: MediumLevelILLabel, loc: ILSourceLocation = None
) -> ExpressionIndex:
    if loc:
        return ExpressionIndex(
            core.BNMediumLevelILGotoWithLocation(
                self.handle, label.handle, loc.address,  loc.source_operand
            )
        )
    return ExpressionIndex(core.BNMediumLevelILGoto(self.handle, label.handle))


MediumLevelILFunction.get_basic_block_at = get_basic_block_at
MediumLevelILFunction.if_expr = if_expr
MediumLevelILFunction.goto = goto
