from binaryninja import (
    MediumLevelILIf,
    MediumLevelILCmpNe,
    MediumLevelILOperation,
    AnalysisContext,
    MediumLevelILLabel,
    ILSourceLocation,
)


def pass_reverse_if(analysis_context: AnalysisContext):
    """
    把所有的if (a!=123)then 1 else 2 反转为 if a==123 then 2 else 1
    """
    mlil = analysis_context.function.mlil

    updated = False
    ifInstrs = []
    for block in mlil.basic_blocks:
        instr = block[-1]
        if isinstance(instr, MediumLevelILIf) and isinstance(
            instr.condition, MediumLevelILCmpNe
        ):
            ifInstrs.append(instr)
    for instr in ifInstrs:
        condition = instr.condition
        trueLabel = MediumLevelILLabel()
        falseLabel = MediumLevelILLabel()
        trueLabel.operand = instr.false
        falseLabel.operand = instr.true
        new_condition = mlil.expr(
            MediumLevelILOperation.MLIL_CMP_E,
            mlil.copy_expr(condition.operands[0]),
            mlil.copy_expr(condition.operands[1]),
        )
        mlil.replace_expr(
            instr,
            mlil.if_expr(
                new_condition,
                trueLabel,
                falseLabel,
                ILSourceLocation.from_instruction(instr),
            ),
        )
        updated = True
    if updated:
        mlil.finalize()
        mlil.generate_ssa_form()
