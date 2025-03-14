from binaryninja import (
    AnalysisContext,
    MediumLevelILSetVar,
    MediumLevelILInstruction,
    MediumLevelILBasicBlock,
    ILSourceLocation,
)

from ...utils import collect_stateVar_info, StateMachine
from ...utils import log_error, log_info


def pass_mov_state_define(analysis_context: AnalysisContext):
    func = analysis_context.function
    mlil = func.mlil
    if mlil is None:
        log_error(f"Function {func.name} has no MLIL")
        return

    updated = False
    state_vars = StateMachine.find_state_var(func)
    _, define_table = collect_stateVar_info(func, False)
    l_define_table = []
    for k, v in define_table.items():
        l_define_table += v

    # 按block分组收集statevar定义
    block_defines = {}
    for define in l_define_table:
        if not isinstance(define, MediumLevelILSetVar):
            continue
        define_block = mlil.get_basic_block_at(define.instr_index)
        if len(define_block) == 2:
            continue
        if define_block not in block_defines:
            block_defines[define_block] = []
        block_defines[define_block].append(define)
    # 处理每个block
    for block, defines in block_defines.items():
        block: MediumLevelILBasicBlock
        defines: list[MediumLevelILSetVar]
        if len(defines) == block.length - 1:
            continue
        # 保持相对顺序
        defines.sort(key=lambda d: d.instr_index)
        # 收集所有待移动语句的读写变量
        all_vars = set()
        for define in defines:
            all_vars.update(define.vars_read)
            all_vars.update(define.vars_written)
        # 检查冲突
        can_move = True
        check_index = list(range(defines[0].instr_index, block.end - 1))
        check_index = [
            x for x in check_index if x not in [d.instr_index for d in defines]
        ]
        # log_info(f"check_index::{check_index}")
        for i in check_index:
            instr = mlil[i]
            v = instr.vars_read + instr.vars_written
            if any(var in all_vars for var in v):
                can_move = False
                break
        # log_info(f"can_move::{can_move}")
        if not can_move:
            continue
        # 移动语句
        defines_copy = [mlil.copy_expr(define) for define in defines]
        not_defines_copy = list(range(block.start, block.end - 1))
        # 最后一句不copy
        not_defines_copy = [
            x for x in not_defines_copy if x not in [d.instr_index for d in defines]
        ]
        not_defines_copy = [mlil.copy_expr(mlil[x]) for x in not_defines_copy]
        will_copy = not_defines_copy + defines_copy
        for i in range(block.start, block.end - 1):
            mlil.replace_expr(mlil[i].expr_index, will_copy[i - block.start])
        updated = True
    if updated:
        mlil.finalize()
        mlil.generate_ssa_form()
