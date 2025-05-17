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
from dataclasses import dataclass

from ...utils.instr_vistor import IfResult

from ...utils import (
    log_info,
    log_error,
    CFGAnalyzer,
    StateMachine,
    InstructionAnalyzer,
    SimpleVisitor,
)


# todo 407d8c
@dataclass
class PatchInfo:
    """
    用于存储补丁信息的类
    """

    instr: MediumLevelILInstruction
    target: MediumLevelILInstruction
    type: str  # 补丁类型 goto 或 if
    branch: bool  # 修补if的true分支还是false分支


@dataclass
class EmuHardResult:
    """
    emu_hard 函数的返回值类型
    """

    success: bool  # 是否存在有效路径
    unused_instrs: list[MediumLevelILInstruction]  # 无关指令列表
    patchInfo: PatchInfo  # 补丁信息
    visitor: SimpleVisitor  # 访问器


def emu_hard(
    instrs: list[MediumLevelILInstruction], state_vars: list[Variable]
) -> EmuHardResult:
    """
    处理状态机的指令，判断是否存在有效路径

    Returns:
        (是否存在有效路径, 目标指令索引, 遍历到的指令列表)
    Args:
        instrs: 指令列表
        state_vars: 状态变量列表
    """
    func = instrs[0].function.source_function
    mlil = func.mlil
    v = SimpleVisitor(func.view, func)
    walked_instrs = []
    s = z3.Solver()
    conditions = []
    false_ret = EmuHardResult(False, [], PatchInfo(None, None, "", False), v)
    true_ret = false_ret
    last_if = [None, False]
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
                            return false_ret
                        elif i == len(instrs) - 1:
                            true_ret = EmuHardResult(
                                True,
                                walked_instrs,
                                PatchInfo(instrs[0], mlil[nextip], "goto", False),
                                v,
                            )
                    else:
                        vars = instr.vars_written + instr.vars_read
                        if not all([var in state_vars for var in vars]):
                            return false_ret
                        if instrs[i + 1].instr_index == res.true_target_index:
                            conditions.append(res.condition)
                            last_if = [instr, True]
                        else:
                            conditions.append(z3.Not(res.condition))
                            last_if = [instr, False]
                case _:
                    vars_read = instr.vars_read
                    vars_written = instr.vars_written
                    if any(var in state_vars for var in vars_read) or any(
                        var in state_vars for var in vars_written
                    ):
                        return false_ret
                    walked_instrs.append(instr)
        except Exception as e:
            if not isinstance(e, NotImplementedError):
                log_text = ""
                log_text += f"Exception in emu_hard: {e}\n"
                for instr in instrs:
                    log_text += f"{instr.instr_index}::{instr}\n"
            return false_ret
    if len(conditions) == 0:
        return true_ret
    s.add(*conditions)
    log_error(f"期望成立 {s.check()} {s.model()}")
    last_if_index = instrs.index(last_if[0])
    new_instrs = instrs[last_if_index:]
    new_walked_instrs = []
    for instr in walked_instrs:
        if instr in new_instrs:
            new_walked_instrs.append(instr)
    # return false_ret
    return EmuHardResult(
        True,
        new_walked_instrs,
        PatchInfo(last_if[0], true_ret.patchInfo.target, "if", last_if[1]),
        v,
    )


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


def find_valid_paths(
    G, source, target, mlil, state_vars, max_paths=10
) -> list[EmuHardResult]:
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
    407994
    """
    # 使用广度优先搜索，同时记录历史路径
    queue = [(source, [source])]
    valid_paths = []
    visited_prefixes = set()  # 记录已经访问过的无效路径前缀
    define_instr: MediumLevelILSetVar = mlil[source]
    define_il_var: Variable = define_instr.dest
    define_const_val = define_instr.src.constant
    if_instr: MediumLevelILIf = mlil[target]
    if_il_var: Variable = if_instr.condition.left.var
    should_quick_check = False
    if define_il_var == if_il_var:
        should_quick_check = True
    log_error(
        f"finding::::: {source} {target} {define_instr} {define_il_var} {define_const_val}"
    )
    while queue and len(valid_paths) < max_paths:
        node, path = queue.pop(0)
        if node == target:
            instrs = [mlil[i] for i in path]
            if should_quick_check and not quick_check(instrs, define_const_val):
                continue
            ret = emu_hard(instrs, state_vars)
            import pprint

            text = pprint.pformat(
                f"{ret.success}::{path}::{instrs}\n{ret.unused_instrs} \n{'=' * 20}"
            )
            log_info(text)
            if ret.success:
                valid_paths.append(ret)
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
            instrs = [mlil[i] for i in extended_path]
            if should_quick_check and not quick_check(instrs, define_const_val):
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
    worked_define = set()
    worked_if = set()
    max_iterations = len(mlil.basic_blocks) * 33
    for _ in range(max_iterations):
        updated = False
        G_full = CFGAnalyzer.create_full_cfg_graph(mlil)
        state_vars = StateMachine.find_state_var(function)
        if_table, define_table = StateMachine.collect_stateVar_info(function, False)
        l_if_table = [
            instr for v in if_table.values() for instr in v if instr not in worked_if
        ]
        l_define_table = [
            instr
            for v in define_table.values()
            for instr in v
            if instr not in worked_define
        ]
        trans_dict = InstructionAnalyzer.find_state_transition_instructions(
            l_if_table, l_define_table
        )
        for trans in trans_dict:
            def_instr: MediumLevelILSetVar = trans["def_instr"]
            if_instr: MediumLevelILIf = trans["if_instr"]
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
                    worked_if.add(trans["if_instr"])
                    worked_define.add(trans["def_instr"])
                    if path_data.patchInfo.type == "goto":
                        target_label = MediumLevelILLabel()
                        target_label.operand = path_data.patchInfo.target.instr_index
                        will_patch_instr = path_data.patchInfo.instr
                        new_block_label = MediumLevelILLabel()
                        mlil.mark_label(new_block_label)
                        for instr in path_data.unused_instrs:
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
                    elif path_data.patchInfo.type == "if":
                        target_label = MediumLevelILLabel()
                        target_label.operand = path_data.patchInfo.target.instr_index
                        will_patch_instr: MediumLevelILIf = path_data.patchInfo.instr
                        new_block_label = MediumLevelILLabel()
                        mlil.mark_label(new_block_label)
                        for instr in path_data.unused_instrs:
                            mlil.append(mlil.copy_expr(instr))
                        mlil.append(mlil.goto(target_label))
                        if path_data.patchInfo.branch:
                            false_label = MediumLevelILLabel()
                            false_label.operand = will_patch_instr.false
                            new_if_instr = mlil.if_expr(
                                mlil.copy_expr(will_patch_instr.condition),
                                new_block_label,
                                false_label,
                                ILSourceLocation.from_instruction(will_patch_instr),
                            )
                        else:
                            true_label = MediumLevelILLabel()
                            true_label.operand = will_patch_instr.true
                            new_if_instr = mlil.if_expr(
                                mlil.copy_expr(will_patch_instr.condition),
                                true_label,
                                new_block_label,
                                ILSourceLocation.from_instruction(will_patch_instr),
                            )
                        mlil.replace_expr(def_instr.expr_index, mlil.nop())
                        mlil.replace_expr(
                            will_patch_instr.expr_index,
                            new_if_instr,
                        )
                        updated = True
                        break

            except nx.NetworkXNoPath:
                continue
            except Exception as e:
                log_error(f"Error in find_valid_paths: {e}")
                continue
            if updated:
                mlil.finalize()
                mlil.generate_ssa_form()
                break
        if not updated:
            break
        # mlil.finalize()
        # mlil.generate_ssa_form()
    mlil.finalize()
    mlil.generate_ssa_form()
