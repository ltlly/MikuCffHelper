"""把 MLIL_JUMP_TO 的 case 表按键值排序。

BN 的 jump_to targets 是 dict，插入顺序会影响 HLIL switch 的 case 展示
顺序。general pass 生成 label_map 时 key 来自 set 迭代，顺序不稳定；
排序后 case 从负到正单调，人工阅读更接近编译器生成的 switch。

该 pass 只调整 targets 的遍历顺序，不改变 dest 表达式与映射关系，
因此不改变语义。
"""

from binaryninja import (
    AnalysisContext,
    ILSourceLocation,
    MediumLevelILJumpTo,
    MediumLevelILLabel,
)


def pass_order_jump_tables(analysis_context: AnalysisContext) -> bool:
    mlil = analysis_context.function.mlil
    if mlil is None:
        return False
    updated = False
    for instr in list(mlil.instructions):
        if not isinstance(instr, MediumLevelILJumpTo):
            continue
        targets = instr.targets
        ordered_keys = sorted(targets)
        if list(targets.keys()) == ordered_keys:
            continue
        label_map = {}
        for value in ordered_keys:
            label = MediumLevelILLabel()
            label.operand = targets[value]
            label_map[value] = label
        try:
            dest_index = instr.raw_operands[0]
            new_expr = mlil.jump_to(
                dest_index,
                label_map,
                ILSourceLocation.from_instruction(instr),
            )
            mlil.replace_expr(instr.expr_index, new_expr)
            updated = True
        except Exception:
            continue
    if updated:
        mlil.finalize()
        mlil.generate_ssa_form()
    return updated
