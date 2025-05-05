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
import z3


from ...utils.instr_vistor import IfResult

from ...utils import (
    log_info,
    log_error,
    CFGAnalyzer,
    StateMachine,
    InstructionAnalyzer,
    SimpleVisitor,
)
# todo sub_407d8c
# [MikuCffHelper] emu_hard: False,[<MediumLevelILSetVar: x12_92 = 0x26bd6ae0>, <MediumLevelILSetVar: state-1 = 0x160d5cc>, <MediumLevelILGoto: goto 11 @ 0x407e18>, <MediumLevelILSetVar: state-0 = state-1>, <MediumLevelILGoto: goto 13>, <MediumLevelILIf: if (state-1 s> 0x26bd6adf) then 14 @ 0x407e58 else 15 @ 0x407e28>, <MediumLevelILIf: if (state-0 s<= 0x47691216) then 16 @ 0x407eb4 else 18 @ 0x407e64>, <MediumLevelILSetVar: state-1 = -0x7a8eb0b7>, <MediumLevelILGoto: goto 23>, <MediumLevelILIf: if (state-0 == 0x26bd6ae0) then 11 @ 0x407e18 else 29 @ 0x407ebc>]
# [MikuCffHelper] emu_hard: False,[<MediumLevelILSetVar: x12_92 = 0x47691217>, <MediumLevelILSetVar: state-1 = 0x160d5cc>, <MediumLevelILGoto: goto 11 @ 0x407e18>, <MediumLevelILSetVar: state-0 = state-1>, <MediumLevelILGoto: goto 13>, <MediumLevelILIf: if (state-1 s> 0x26bd6adf) then 14 @ 0x407e58 else 15 @ 0x407e28>, <MediumLevelILIf: if (state-0 s<= 0x47691216) then 16 @ 0x407eb4 else 18 @ 0x407e64>, <MediumLevelILSetVar: state-1 = -0x125b9f00>, <MediumLevelILGoto: goto 24>, <MediumLevelILIf: if (state-0 == 0x47691217) then 11 @ 0x407e18 else 31 @ 0x407e70>]
# [MikuCffHelper] emu_hard: False,[<MediumLevelILSetVar: state-1 = -0x7a8eb0b7>, <MediumLevelILGoto: goto 23>, <MediumLevelILIf: if (state-0 == 0x26bd6ae0) then 11 @ 0x407e18 else 29 @ 0x407ebc>, <MediumLevelILSetVar: state-0 = state-1>, <MediumLevelILGoto: goto 13>, <MediumLevelILIf: if (state-1 s> 0x26bd6adf) then 14 @ 0x407e58 else 15 @ 0x407e28>, <MediumLevelILIf: if (state-0 s> 0xfe4c27a1) then 20 @ 0x407e90 else 22 @ 0x407e30>, <MediumLevelILIf: if (state-0 == 0x85714f49) then 26 @ 0x407ed8 else 28 @ 0x407e38>]
# [MikuCffHelper] emu_hard: True,[<MediumLevelILSetVar: state-1 = -0x32ed9066>, <MediumLevelILGoto: goto 11 @ 0x407e18>, <MediumLevelILSetVar: state-0 = state-1>, <MediumLevelILGoto: goto 13>, <MediumLevelILIf: if (state-1 s> 0x26bd6adf) then 14 @ 0x407e58 else 15 @ 0x407e28>, <MediumLevelILIf: if (state-0 s> 0xfe4c27a1) then 20 @ 0x407e90 else 22 @ 0x407e30>, <MediumLevelILIf: if (state-0 == 0x85714f49) then 26 @ 0x407ed8 else 28 @ 0x407e38>, <MediumLevelILIf: if (state-0 == 0xcd126f9a) then 33 @ 0x407ee0 else 41 @ 0x407e3c>]
# [MikuCffHelper] emu_hard: False,[<MediumLevelILSetVar: x12_92 = 0x26bd6ae0>, <MediumLevelILSetVar: state-1 = 0x160d5cc>, <MediumLevelILGoto: goto 11 @ 0x407e18>, <MediumLevelILSetVar: state-0 = state-1>, <MediumLevelILGoto: goto 13>, <MediumLevelILIf: if (state-1 s> 0x26bd6adf) then 14 @ 0x407e58 else 15 @ 0x407e28>, <MediumLevelILIf: if (state-0 s<= 0x47691216) then 16 @ 0x407eb4 else 18 @ 0x407e64>, <MediumLevelILSetVar: state-1 = -0x7a8eb0b7>, <MediumLevelILGoto: goto 23>, <MediumLevelILIf: if (state-0 == 0x26bd6ae0) then 11 @ 0x407e18 else 29 @ 0x407ebc>]
# [MikuCffHelper] emu_hard: False,[<MediumLevelILSetVar: x12_92 = 0x47691217>, <MediumLevelILSetVar: state-1 = 0x160d5cc>, <MediumLevelILGoto: goto 11 @ 0x407e18>, <MediumLevelILSetVar: state-0 = state-1>, <MediumLevelILGoto: goto 13>, <MediumLevelILIf: if (state-1 s> 0x26bd6adf) then 14 @ 0x407e58 else 15 @ 0x407e28>, <MediumLevelILIf: if (state-0 s<= 0x47691216) then 16 @ 0x407eb4 else 18 @ 0x407e64>, <MediumLevelILSetVar: state-1 = -0x125b9f00>, <MediumLevelILGoto: goto 24>, <MediumLevelILIf: if (state-0 == 0x47691217) then 11 @ 0x407e18 else 31 @ 0x407e70>]
# [MikuCffHelper] emu_hard: False,[<MediumLevelILSetVar: state-1 = -0x7a8eb0b7>, <MediumLevelILGoto: goto 23>, <MediumLevelILIf: if (state-0 == 0x26bd6ae0) then 11 @ 0x407e18 else 29 @ 0x407ebc>, <MediumLevelILSetVar: state-0 = state-1>, <MediumLevelILGoto: goto 13>, <MediumLevelILIf: if (state-1 s> 0x26bd6adf) then 14 @ 0x407e58 else 15 @ 0x407e28>, <MediumLevelILIf: if (state-0 s> 0xfe4c27a1) then 20 @ 0x407e90 else 22 @ 0x407e30>, <MediumLevelILIf: if (state-0 == 0x85714f49) then 26 @ 0x407ed8 else 28 @ 0x407e38>]
# [MikuCffHelper] emu_hard: True,[<MediumLevelILSetVar: state-1 = -0x7a8eb0b7>, <MediumLevelILGoto: goto 11 @ 0x407e18>, <MediumLevelILSetVar: state-0 = state-1>, <MediumLevelILGoto: goto 13>, <MediumLevelILIf: if (state-1 s> 0x26bd6adf) then 14 @ 0x407e58 else 15 @ 0x407e28>, <MediumLevelILIf: if (state-0 s> 0xfe4c27a1) then 20 @ 0x407e90 else 22 @ 0x407e30>, <MediumLevelILIf: if (state-0 == 0x85714f49) then 26 @ 0x407ed8 else 28 @ 0x407e38>]
# [MikuCffHelper] emu_hard: False,[<MediumLevelILSetVar: x12_92 = 0x26bd6ae0>, <MediumLevelILSetVar: state-1 = 0x160d5cc>, <MediumLevelILGoto: goto 11 @ 0x407e18>, <MediumLevelILSetVar: state-0 = state-1>, <MediumLevelILGoto: goto 13>, <MediumLevelILIf: if (state-1 s> 0x26bd6adf) then 14 @ 0x407e58 else 15 @ 0x407e28>, <MediumLevelILIf: if (state-0 s<= 0x47691216) then 16 @ 0x407eb4 else 18 @ 0x407e64>, <MediumLevelILSetVar: state-1 = -0x7a8eb0b7>, <MediumLevelILGoto: goto 23>, <MediumLevelILIf: if (state-0 == 0x26bd6ae0) then 11 @ 0x407e18 else 29 @ 0x407ebc>]
# [MikuCffHelper] emu_hard: False,[<MediumLevelILSetVar: x12_92 = 0x47691217>, <MediumLevelILSetVar: state-1 = 0x160d5cc>, <MediumLevelILGoto: goto 11 @ 0x407e18>, <MediumLevelILSetVar: state-0 = state-1>, <MediumLevelILGoto: goto 13>, <MediumLevelILIf: if (state-1 s> 0x26bd6adf) then 14 @ 0x407e58 else 15 @ 0x407e28>, <MediumLevelILIf: if (state-0 s<= 0x47691216) then 16 @ 0x407eb4 else 18 @ 0x407e64>, <MediumLevelILSetVar: state-1 = -0x125b9f00>, <MediumLevelILGoto: goto 24>, <MediumLevelILIf: if (state-0 == 0x47691217) then 11 @ 0x407e18 else 31 @ 0x407e70>]
# [MikuCffHelper] emu_hard: False,[<MediumLevelILSetVar: state-1 = -0x7a8eb0b7>, <MediumLevelILGoto: goto 23>, <MediumLevelILIf: if (state-0 == 0x26bd6ae0) then 11 @ 0x407e18 else 29 @ 0x407ebc>, <MediumLevelILSetVar: state-0 = state-1>, <MediumLevelILGoto: goto 13>, <MediumLevelILIf: if (state-1 s> 0x26bd6adf) then 14 @ 0x407e58 else 15 @ 0x407e28>, <MediumLevelILIf: if (state-0 s> 0xfe4c27a1) then 20 @ 0x407e90 else 22 @ 0x407e30>, <MediumLevelILIf: if (state-0 == 0x85714f49) then 26 @ 0x407ed8 else 28 @ 0x407e38>]
# [MikuCffHelper] emu_hard: False,[<MediumLevelILSetVar: x12_92 = 0x26bd6ae0>, <MediumLevelILSetVar: state-1 = 0x160d5cc>, <MediumLevelILGoto: goto 11 @ 0x407e18>, <MediumLevelILSetVar: state-0 = state-1>, <MediumLevelILGoto: goto 13>, <MediumLevelILIf: if (state-1 s> 0x26bd6adf) then 14 @ 0x407e58 else 15 @ 0x407e28>, <MediumLevelILIf: if (state-0 s<= 0x47691216) then 16 @ 0x407eb4 else 18 @ 0x407e64>, <MediumLevelILSetVar: state-1 = -0x7a8eb0b7>, <MediumLevelILGoto: goto 23>, <MediumLevelILIf: if (state-0 == 0x26bd6ae0) then 11 @ 0x407e18 else 29 @ 0x407ebc>]
# [MikuCffHelper] emu_hard: False,[<MediumLevelILSetVar: x12_92 = 0x47691217>, <MediumLevelILSetVar: state-1 = 0x160d5cc>, <MediumLevelILGoto: goto 11 @ 0x407e18>, <MediumLevelILSetVar: state-0 = state-1>, <MediumLevelILGoto: goto 13>, <MediumLevelILIf: if (state-1 s> 0x26bd6adf) then 14 @ 0x407e58 else 15 @ 0x407e28>, <MediumLevelILIf: if (state-0 s<= 0x47691216) then 16 @ 0x407eb4 else 18 @ 0x407e64>, <MediumLevelILSetVar: state-1 = -0x125b9f00>, <MediumLevelILGoto: goto 24>, <MediumLevelILIf: if (state-0 == 0x47691217) then 11 @ 0x407e18 else 31 @ 0x407e70>]
# [MikuCffHelper] emu_hard: False,[<MediumLevelILSetVar: state-1 = -0x7a8eb0b7>, <MediumLevelILGoto: goto 23>, <MediumLevelILIf: if (state-0 == 0x26bd6ae0) then 11 @ 0x407e18 else 29 @ 0x407ebc>, <MediumLevelILSetVar: state-0 = state-1>, <MediumLevelILGoto: goto 13>, <MediumLevelILIf: if (state-1 s> 0x26bd6adf) then 14 @ 0x407e58 else 15 @ 0x407e28>, <MediumLevelILIf: if (state-0 s> 0xfe4c27a1) then 20 @ 0x407e90 else 22 @ 0x407e30>, <MediumLevelILIf: if (state-0 == 0x85714f49) then 26 @ 0x407ed8 else 28 @ 0x407e38>]


def emu_hard(instrs: list[MediumLevelILInstruction], state_vars: list[Variable]):
    """
    处理状态机的指令，判断是否存在有效路径

    Returns:
        (是否存在有效路径, 目标指令索引, 遍历到的指令列表)
    Args:
        instrs: 指令列表
        state_vars: 状态变量列表
    """
    func = instrs[0].function.source_function
    v = SimpleVisitor(func.view, func)
    walked_instrs = []
    s = z3.Solver()
    conditions = []
    false_ret = (False, -1, [], v)
    for i, instr in enumerate(instrs):
        log_info(f"visit {instr} {v.vars}")
        try:
            match instr:
                case MediumLevelILGoto():
                    continue
                case MediumLevelILSetVar():
                    left = instr.dest
                    if left in state_vars:
                        v.visit(instr)
                    walked_instrs.append(instr)
                case MediumLevelILIf():
                    res: IfResult = v.visit(instr)
                    if res.is_boolean:
                        nextip = res.target_index
                        if i + 1 < len(instrs) and nextip != instrs[i + 1].instr_index:
                            log_error(
                                f"emu_hard false at i={i}, instr={instr} {nextip} != {instrs[i + 1].instr_index}"
                            )
                            return (False, i, walked_instrs, v)
                        elif i == len(instrs) - 1 and len(conditions) == 0:
                            return (True, nextip, walked_instrs, v)
                    else:
                        vars = instr.vars_written + instr.vars_read
                        if not all([var in state_vars for var in vars]):
                            log_error(
                                f"emu_hard false at i={i}, instr={instr} not state_vars"
                            )
                            return (False, i, walked_instrs, v)
                        if instrs[i + 1].instr_index == res.true_target_index:
                            conditions.append(res.condition)
                            log_error(f"add {res.condition}")
                        else:
                            conditions.append(z3.Not(res.condition))
                            log_error(f"add not {res.condition}")
                case _:
                    vars_read = instr.vars_read
                    vars_written = instr.vars_written
                    if any(var in state_vars for var in vars_read) or any(
                        var in state_vars for var in vars_written
                    ):
                        log_error(
                            f"emu_hard false at i={i}, instr={instr} state var usage"
                        )
                        return (False, i, walked_instrs, v)
                    walked_instrs.append(instr)
        except Exception as e:
            if not isinstance(e, NotImplementedError):
                log_text = ""
                log_text += f"Exception in emu_hard: {e}\n"
                for instr in instrs:
                    log_text += f"{instr.instr_index}::{instr}\n"
                log_error(log_text)
            log_error(f"emu_hard false in exception at i={i}, instr={instr}")
            return (False, i, walked_instrs, v)
    s.add(*conditions)
    log_error(f"期望成立 {s.check()} {s.model()}")
    return false_ret


def quick_check(
    instrs: list[MediumLevelILInstruction],
    const_val: int,
):
    define_var: Variable = instrs[0].dest
    for instr in instrs[1:]:
        if not isinstance(instr, MediumLevelILSetVar):
            continue
        if (
            instr.dest == define_var
            and isinstance(instr.src, MediumLevelILConst)
            and instr.src.constant != const_val
        ):
            return False
    return True


def find_valid_paths(G, source, target, mlil, state_vars, max_paths=10):
    """
    自定义路径搜索算法，在搜索过程中应用剪枝策略

    Args:
        G: 控制流图
        source: 起始节点
        target: 目标节点
        mlil: MediumLevelILFunction
        state_vars: 状态变量列表
        max_paths: 最大返回路径数

    Returns:
        有效路径列表
    """
    # 使用广度优先搜索，同时记录历史路径
    queue = [(source, [source])]
    valid_paths = []
    visited_prefixes = set()  # 记录已经访问过的无效路径前缀
    define_instr = mlil[source]
    define_il_var = define_instr.dest
    define_const_val = define_instr.src.constant
    while queue and len(valid_paths) < max_paths:
        node, path = queue.pop(0)
        if node == target:
            instrs = [mlil[i] for i in path]
            if quick_check(instrs, define_const_val):
                r, target_idx, unused_instrs, v = emu_hard(instrs, state_vars)
                import pprint

                text = pprint.pformat(f"{r}::{path}::{instrs}\n{v.vars} \n{'=' * 20}")
                log_info(text)
                if r:
                    valid_paths.append((path, target_idx, unused_instrs))
            continue
        neighbors = list(G.neighbors(node))
        path_prefix = tuple(path)
        if path_prefix in visited_prefixes:
            continue
        valid_extension = False
        for neighbor in neighbors:
            if neighbor in path:
                continue
            extended_path = path + [neighbor]
            if isinstance(mlil[neighbor], MediumLevelILSetVar):
                n_instr = mlil[neighbor]
                if (
                    isinstance(n_instr, MediumLevelILSetVar)
                    and n_instr.dest == define_il_var
                ):
                    if (
                        isinstance(n_instr.src, MediumLevelILConst)
                        and n_instr.src.constant != define_const_val
                    ):
                        continue
                    if isinstance(n_instr.src, MediumLevelILVar):
                        continue
            queue.append((neighbor, extended_path))
            valid_extension = True
        if not valid_extension:
            visited_prefixes.add(path_prefix)
    return valid_paths


def pass_deflate_hard(analysis_context: AnalysisContext):
    function: Function = analysis_context.function
    mlil: MediumLevelILFunction | None = function.mlil
    if mlil is None:
        log_error(f"Function {function.name} has no MLIL")
        return
    # 保存已处理的 define 与 if 指令，避免重复处理
    worked_define = set()
    worked_if = set()
    # 最多遍历基本块数量的两倍次，若无更新则提前退出
    for _ in range(len(mlil.basic_blocks) * 2):
        updated = False
        # 构建完整的控制流图
        G_full = CFGAnalyzer.create_full_cfg_graph(mlil)
        state_vars = StateMachine.find_state_var(function)
        if_table, define_table = StateMachine.collect_stateVar_info(function, False)
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
            try:
                valid_paths = find_valid_paths(
                    G_full,
                    def_instr.instr_index,
                    if_instr.instr_index,
                    mlil,
                    state_vars,
                )
                assert len(valid_paths) <= 1, "too many paths"
                for path_data in valid_paths:
                    path_full, target_idx, unused_instrs = path_data
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
                            new_block_label,
                            ILSourceLocation.from_instruction(will_patch_instr),
                        ),
                    )
                    updated = True
                    break
            except nx.NetworkXNoPath:
                continue
            if updated:
                mlil.finalize()
                mlil.generate_ssa_form()
                break
        if not updated:
            break
    mlil.finalize()
    mlil.generate_ssa_form()
