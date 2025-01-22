from binaryninja import (
    MediumLevelILIf,
    MediumLevelILCmpNe,
    MediumLevelILOperation,
    AnalysisContext,
    MediumLevelILLabel,
    MediumLevelILSetVar,
    MediumLevelILInstruction,
)

from ...utils import StateMachine, collect_stateVar_info
from ...utils import log_error, log_info, log_warn


def pass_mov_state_define(analysis_context: AnalysisContext):
    func = analysis_context.function
    mlil = func.mlil
    if mlil is None:
        log_error(f"Function {func.name} has no MLIL")
        return
    updated = False
    _, define_table = collect_stateVar_info(func, False)
    for define in define_table:
        if not isinstance(define, MediumLevelILSetVar):
            continue
        define_block = mlil.get_basic_block_at(define.instr_index)
        if len(define_block) == 2:
            continue
        if define.instr_index == define_block.end - 2:
            continue
        # 对于define 不是 倒数第二句的
        will_check_instr: list[MediumLevelILInstruction] = []
        for i in range(define.instr_index + 1, define_block.end - 1):
            will_check_instr.append(mlil[i])
        can_move = True
        vars = define.vars_read + define.vars_written
        for instr in will_check_instr:
            for x in instr.vars_read + instr.vars_written:
                if x in vars:
                    can_move = False
                    break
            if not can_move:
                break
        if not can_move:
            continue
        new_define = mlil.copy_expr(define)
        for instr in will_check_instr:
            mlil.replace_expr(instr.instr_index - 1, instr)
        mlil.replace_expr(define_block.end - 2, new_define)
        log_info("movvvvvvvvvvvvvv!")
        updated = True
    if updated:
        mlil.finalize()
        mlil.generate_ssa_form()
