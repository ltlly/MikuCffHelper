import networkx as nx
from binaryninja import (
    MediumLevelILFunction,
    MediumLevelILIf,
    MediumLevelILGoto,
    Function,
    AnalysisContext,
    MediumLevelILSetVar,
    ILSourceLocation,
    MediumLevelILInstruction,
    MediumLevelILLabel,
)

from ...utils import (
    log_error,
    collect_stateVar_info,
    CFGAnalyzer,
    StateMachine,
    InstructionAnalyzer,
)

# todo sub_1f310


def pass_deflate_simple(analysis_context: AnalysisContext):
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
            white_instructions = InstructionAnalyzer.find_white_instructions(
                mlil, [define_state_var, if_state_var]
            )

            cond, target_idx = InstructionAnalyzer.check_path(
                mlil, path_full, white_instructions
            )
            if not cond:
                continue

            # 创建用于跳转的新标签
            label = MediumLevelILLabel()
            label.operand = target_idx

            # 在路径中寻找第一个 Goto 指令进行替换
            will_patch_instr = None
            i = 0
            while i < len(path_full):
                candidate = mlil[path_full[i]]
                if isinstance(candidate, MediumLevelILGoto):
                    will_patch_instr = candidate
                    break
                i += 1

            # 如果未找到合适的跳转指令则跳过此次处理
            if will_patch_instr is None:
                continue

            # 生成新的 goto 指令并替换原有表达式
            new_goto = mlil.goto(
                label, ILSourceLocation.from_instruction(will_patch_instr)
            )
            mlil.replace_expr(will_patch_instr.expr_index, new_goto)

            # 记录已处理的指令
            worked_define.append(def_instr)
            worked_if.append(if_instr)
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
