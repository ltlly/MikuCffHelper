import networkx as nx
from binaryninja import (
    MediumLevelILFunction,
    MediumLevelILIf,
    MediumLevelILGoto,
    Function,
    AnalysisContext,
    MediumLevelILSetVar,
    MediumLevelILInstruction,
    MediumLevelILLabel,
    Variable,
    MediumLevelILConst,
    MediumLevelILVar,
    ILSourceLocation,
)

from ...utils import (
    log_error,
    collect_stateVar_info,
    CFGAnalyzer,
    StateMachine,
    InstructionAnalyzer,
    SimpleVisitor,
)


# todo sub_1f310
def emu_hard(instrs: list[MediumLevelILInstruction], white_vars: list[Variable]):
    func = instrs[0].function.source_function
    v = SimpleVisitor(func.view, func)
    walked_instrs = []
    for i, instr in enumerate(instrs):
        try:
            match instr:
                case MediumLevelILGoto():
                    continue
                case MediumLevelILSetVar():
                    left = instr.dest
                    if left in white_vars:
                        v.visit(instr)
                    walked_instrs.append(instr)
                case MediumLevelILIf():
                    # if any(var not in white_vars for var in instr.vars_read):
                    # log_error(f"ck var {instr}")
                    # return (False, None, [])
                    _, nextip = v.visit(instr)
                    if i + 1 < len(instrs) and nextip != instrs[i + 1].instr_index:
                        # log_error(
                        #     f"path not eq! want{instrs[i + 1].instr_index} but {nextip}"
                        # )
                        return (False, None, [])
                    elif i == len(instrs) - 1:
                        return (True, nextip, walked_instrs)
                case _:
                    if any(var in white_vars for var in instr.vars_read) or any(
                        var in white_vars for var in instr.vars_written
                    ):
                        log_error(f"ck _ {instr.instr_index}::{instr}")
                        return (False, None, [])
                    walked_instrs.append(instr)
        except Exception as e:
            # log_error(f"error:: {instr.instr_index}::{instr}")
            from pprint import pformat

            # log_error(pformat(instrs))
            # log_error(pformat(v.vars))
            # log_error(f"{e}")
            return (False, None, [])
    raise  # never reach here


def quick_check(
    instrs: list[MediumLevelILInstruction],
    mlil: MediumLevelILFunction,
):
    define_var: Variable = instrs[0].dest
    for instr in instrs[1:]:
        if not isinstance(instr, MediumLevelILSetVar):
            continue
        if instr.dest == define_var and isinstance(instr.src, MediumLevelILConst):
            return False
    return True


def pass_deflate_hard(analysis_context: AnalysisContext):
    function: Function = analysis_context.function
    mlil: MediumLevelILFunction | None = function.mlil
    if mlil is None:
        log_error(f"Function {function.name} has no MLIL")
        return

    # 保存已处理的 define 与 if 指令，避免重复处理
    worked_define = []
    worked_if = []
    # 最多遍历基本块数量的两倍次，若无更新则提前退出
    for _ in range(len(mlil.basic_blocks) * 2):
        updated = False
        # 构建完整的控制流图
        G_full = CFGAnalyzer.create_full_cfg_graph(mlil)
        state_vars = StateMachine.find_state_var(function)
        if_table, define_table = collect_stateVar_info(function, False)
        # 整理所有 if 指令和 define 指令，并过滤掉已处理项
        l_if_table = [
            instr for v in if_table.values() for instr in v if instr not in worked_if
        ]
        l_define_table = [
            instr
            for v in define_table.values()
            for instr in v
            if instr not in worked_define
        ]

        # 查找状态转换指令对
        trans_dict = InstructionAnalyzer.find_state_transition_instructions(
            l_if_table, l_define_table
        )
        for trans in trans_dict:
            def_instr: MediumLevelILInstruction | MediumLevelILSetVar = trans[
                "def_instr"
            ]
            if_instr: MediumLevelILInstruction | MediumLevelILIf = trans["if_instr"]
            # 尝试找到从 def_instr 到 if_instr 的最短路径
            try:
                path_full = nx.shortest_path(
                    G_full, def_instr.instr_index, if_instr.instr_index
                )
            except nx.NetworkXNoPath:
                continue

            define_state_var = def_instr.vars_written[0]
            if_state_var = if_instr.vars_read[0]
            instrs = [mlil[i] for i in path_full]
            r = quick_check(instrs, mlil)
            if not r:
                continue
            r, target_idx, unused_instrs = emu_hard(instrs, state_vars)
            if not r:
                continue
            # log_error(f"r: {r}, target_idx: {target_idx}, unused_instrs: {unused_instrs}")
            # for i in path_full:
            #     instr = mlil[i]
            #     log_error(f"{i}::{instr}")
            target_label = MediumLevelILLabel()
            target_label.operand = target_idx
            will_patch_instr = mlil[path_full[0]]

            new_block_label = MediumLevelILLabel()
            mlil.mark_label(new_block_label)
            for instr in unused_instrs:
                mlil.append(mlil.copy_expr(instr))
            mlil.append(mlil.goto(target_label))

            mlil.replace_expr(
                will_patch_instr.expr_index,
                mlil.goto(
                    new_block_label, ILSourceLocation.from_instruction(will_patch_instr)
                ),
            )
            updated = True

        # 若本轮有更新，则重新生成 MLIL SSA 形式，否则退出循环
        if updated:
            mlil.finalize()
            mlil.generate_ssa_form()
        else:
            break

    # 最后再次 finalize 与生成 SSA
    mlil.finalize()
    mlil.generate_ssa_form()
