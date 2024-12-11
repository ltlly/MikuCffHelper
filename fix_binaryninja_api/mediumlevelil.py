from binaryninja import *

from .common import ILSourceLocation
from ..utils import log_error

def copy_expr(self, original: MediumLevelILInstruction,loc: ILSourceLocation = None) -> ExpressionIndex:
    return self.expr(original.operation, original.raw_operands[0], original.raw_operands[1], original.raw_operands[2], original.raw_operands[3], original.raw_operands[4], original.size,loc)

def if_expr(self, operand: ExpressionIndex, t: MediumLevelILLabel, f: MediumLevelILLabel,loc: ILSourceLocation = None) -> ExpressionIndex:
    if loc is not None and loc.valid:
        return ExpressionIndex(core.BNMediumLevelILIfWithLocation(self.handle, operand, t.handle, f.handle, loc.address, loc.sourceOperand))
    return ExpressionIndex(core.BNMediumLevelILIf(self.handle, operand, t.handle, f.handle))


def goto(self, label: MediumLevelILLabel,loc: ILSourceLocation = None) -> ExpressionIndex:
    if loc is not None and loc.valid:
        return ExpressionIndex(core.BNMediumLevelILGotoWithLocation(self.handle, label.handle, loc.address, loc.sourceOperand))
    return ExpressionIndex(core.BNMediumLevelILGoto(self.handle, label.handle))

def expr(
    self, operation: MediumLevelILOperation, a: int = 0, b: int = 0, c: int = 0, d: int = 0, e: int = 0,
    size: int = 0,loc: ILSourceLocation = None
) -> ExpressionIndex:
    _operation = operation
    if isinstance(operation, str):
        _operation = MediumLevelILOperation[operation]
    elif isinstance(operation, MediumLevelILOperation):
        _operation = operation.value
    if loc is not None and loc.valid:
        return ExpressionIndex(core.BNMediumLevelILAddExprWithLocation(self.handle, _operation,loc.address, loc.sourceOperand, size, a, b, c, d, e, ))
    return ExpressionIndex(core.BNMediumLevelILAddExpr(self.handle, _operation, size, a, b, c, d, e))

def get_basic_block_at(self, index: int) -> Optional['basicblock.BasicBlock']:
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


MediumLevelILFunction.get_basic_block_at = get_basic_block_at

MediumLevelILFunction.expr = expr
MediumLevelILFunction.copy_expr = copy_expr
MediumLevelILFunction.if_expr = if_expr
MediumLevelILFunction.goto = goto
