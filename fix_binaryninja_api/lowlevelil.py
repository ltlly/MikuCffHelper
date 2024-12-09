from binaryninja import *

from .common import ILSourceLocation


def copy_expr(
        self, instr: LowLevelILInstruction, loc: ILSourceLocation = None
):
    flags = instr.flags if instr.flags != "" else None
    return self.expr(
        instr.operation,
        instr.raw_operands[0],
        instr.raw_operands[1],
        instr.raw_operands[2],
        instr.raw_operands[3],
        instr.size,
        flags,
        loc,
    )


def if_expr(self, operand: ExpressionIndex, t: LowLevelILLabel, f: LowLevelILLabel,
            loc: ILSourceLocation = None) -> ExpressionIndex:
    log_error(f"using my if_expr")
    if loc is not None and loc.valid:
        log_error(f"using my if_expr loc {loc.address}")
        return ExpressionIndex(
            core.BNLowLevelILIfWithLocation(self.handle, operand, t.handle, f.handle, loc.address, loc.sourceOperand))
    return ExpressionIndex(core.BNLowLevelILIf(self.handle, operand, t.handle, f.handle))


def goto(self, label: LowLevelILLabel, loc: ILSourceLocation = None) -> ExpressionIndex:
    if loc is not None and loc.valid:
        return ExpressionIndex(
            core.BNLowLevelILGotoWithLocation(self.handle, label.handle, loc.address, loc.sourceOperand))
    return ExpressionIndex(core.BNLowLevelILGoto(self.handle, label.handle))


def expr(
        self,
        operation,
        a: ExpressionIndex = 0,
        b: ExpressionIndex = 0,
        c: ExpressionIndex = 0,
        d: ExpressionIndex = 0,
        size: int = 0,
        flags: Optional[
            Union[
                "architecture.FlagWriteTypeName",
                "architecture.FlagType",
                "architecture.FlagIndex",
            ]
        ] = None,
        loc: ILSourceLocation = None,
):
    _flags = architecture.FlagIndex(0)
    if isinstance(operation, str):
        operation = LowLevelILOperation[operation]
    elif isinstance(operation, LowLevelILOperation):
        operation = operation.value
    if isinstance(flags, str):
        _flags = self.arch.get_flag_write_type_by_name(
            architecture.FlagWriteTypeName(flags)
        )
    elif isinstance(flags, ILFlag):
        _flags = flags.index
    elif isinstance(flags, int):
        _flags = architecture.FlagIndex(flags)
    elif flags is None:
        _flags = architecture.FlagIndex(0)
    else:
        assert False, "flags type unsupported"
    if loc is not None and loc.valid:
        return ExpressionIndex(
            core.BNLowLevelILAddExprWithLocation(
                self.handle,
                loc.address,
                loc.sourceOperand,
                operation,
                size,
                _flags,
                a,
                b,
                c,
                d,
            )
        )
    else:
        return ExpressionIndex(
            core.BNLowLevelILAddExpr(self.handle, operation, size, _flags, a, b, c, d)
        )


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


LowLevelILFunction.get_basic_block_at = get_basic_block_at
LowLevelILFunction.expr = expr
LowLevelILFunction.copy_expr = copy_expr
LowLevelILFunction.if_expr = if_expr
LowLevelILFunction.goto = goto
