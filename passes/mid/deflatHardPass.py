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
)

from ...utils import (
    log_error,
    collect_stateVar_info,
    CFGAnalyzer,
    StateMachine,
    InstructionAnalyzer,
    ILSourceLocation,
)

# todo sub_1f310


def pass_deflate_hard(analysis_context: AnalysisContext):
    function: Function = analysis_context.function
    mlil: MediumLevelILFunction | None = function.mlil
    if mlil is None:
        log_error(f"Function {function.name} has no MLIL")
        return
    worked_define = []
    worked_if = []
    for _ in range(len(mlil.basic_blocks) * 2):
        updated = False
        G_full = CFGAnalyzer.create_full_cfg_graph(mlil)
        state_vars = StateMachine.find_state_var(function)
        if_table, define_table = collect_stateVar_info(function, False)
        possible_state_vars = state_vars
        l_if_table = []
        for k, v in if_table.items():
            l_if_table += v
        l_define_table = []
        for k, v in define_table.items():
            l_define_table += v
        l_if_table = [x for x in l_if_table if x not in worked_if]
        l_define_table = [x for x in l_define_table if x not in worked_define]
        trans_dict = InstructionAnalyzer.find_state_transition_instructions(
            l_if_table, l_define_table
        )

        for trans in trans_dict:
            def_instr: MediumLevelILInstruction | MediumLevelILSetVar = trans[
                "def_instr"
            ]
            if_instr: MediumLevelILInstruction | MediumLevelILIf = trans["if_instr"]

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
            label = MediumLevelILLabel()
            label.operand = target_idx
            will_patch_instr = None
            i = 0
            while not isinstance(will_patch_instr, MediumLevelILGoto):
                will_patch_instr = mlil[path_full[i]]
                i += 1
            # 不会命中
            # if not isinstance(will_patch_instr,MediumLevelILGoto):
            #     log_error(f"what can i say!")
            #     log_error(f"path {path_full}")
            #     log_error(f"will_patch_instr {will_patch_instr} {will_patch_instr.instr_index}")
            #     for x in path_full:
            #         log_error(f"{mlil[x].instr_index} :: {mlil[x]}")
            #     continue

            # log_error(f"==================================")
            # log_error(f"working {def_instr} to {if_instr}")
            # log_error(f"path {path_full}")
            # log_error(
            #     f"will_patch_instr {will_patch_instr} {will_patch_instr.instr_index}")
            # for x in path_full:
            #     log_error(f"{mlil[x].instr_index} :: {mlil[x]}")

            new_goto = mlil.goto(
                label, ILSourceLocation.from_instruction(will_patch_instr)
            )
            mlil.replace_expr(will_patch_instr.expr_index, new_goto)
            worked_define.append(def_instr)
            worked_if.append(if_instr)
            updated = True
        if updated:
            mlil.finalize()
            mlil.generate_ssa_form()
            continue
        else:
            break
    mlil.finalize()
    mlil.generate_ssa_form()
