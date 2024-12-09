from binaryninja import *

from .common import ILSourceLocation


def copy_expr(llil: LowLevelILFunction, instr: LowLevelILInstruction, ILSourceLocation: ILSourceLocation = None):
    flags = instr.flags if instr.flags != "" else None
    return expr(llil,
                instr.operation,
                instr.raw_operands[0],
                instr.raw_operands[1],
                instr.raw_operands[2],
                instr.raw_operands[3],
                instr.size,
                flags,
                ILSourceLocation)


def expr(llil, operation, a: ExpressionIndex = 0, b: ExpressionIndex = 0, c: ExpressionIndex = 0,
         d: ExpressionIndex = 0, size: int = 0,
         flags: Optional[
             Union['architecture.FlagWriteTypeName', 'architecture.FlagType', 'architecture.FlagIndex']] = None,
         ILSourceLocation: ILSourceLocation = None):
    _flags = architecture.FlagIndex(0)
    if isinstance(operation, str):
        operation = LowLevelILOperation[operation]
    elif isinstance(operation, LowLevelILOperation):
        operation = operation.value
    if isinstance(flags, str):
        _flags = llil.arch.get_flag_write_type_by_name(architecture.FlagWriteTypeName(flags))
    elif isinstance(flags, ILFlag):
        _flags = flags.index
    elif isinstance(flags, int):
        _flags = architecture.FlagIndex(flags)
    elif flags is None:
        _flags = architecture.FlagIndex(0)
    else:
        assert False, "flags type unsupported"

    if ILSourceLocation is not None and ILSourceLocation.valid:
        return ExpressionIndex(
            core.BNLowLevelILAddExprWithLocation(llil.handle, ILSourceLocation.address, ILSourceLocation.sourceOperand,
                                                 operation, size, _flags, a, b, c, d))
    else:
        return ExpressionIndex(core.BNLowLevelILAddExpr(llil.handle, operation, size, _flags, a, b, c, d))
