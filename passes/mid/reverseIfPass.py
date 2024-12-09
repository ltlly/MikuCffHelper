from binaryninja import MediumLevelILIf, MediumLevelILCmpNe, MediumLevelILOperation, \
    AnalysisContext, MediumLevelILLabel


def pass_reverse_if(analysis_context: AnalysisContext):
    """
    把所有的if (a!=123)全部反转
    """
    mlil = analysis_context.function.mlil
    def traverse_find_if(instr):
        if isinstance(instr, MediumLevelILIf) and isinstance(
                instr.condition, MediumLevelILCmpNe
        ):
            return instr
        return
    updated = False
    ifInstrs = mlil.traverse(traverse_find_if)
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
        mlil.replace_expr(instr, mlil.if_expr(
            new_condition, falseLabel, trueLabel))
        updated = True
    if updated:
        mlil.finalize()
        mlil.generate_ssa_form()
