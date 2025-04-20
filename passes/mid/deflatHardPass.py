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
                    _, nextip = v.visit(instr)
                    if i + 1 < len(instrs) and nextip != instrs[i + 1].instr_index:
                        return (False, None, [])
                    elif i == len(instrs) - 1:
                        return (True, nextip, walked_instrs)
                case _:
                    vars_read = instr.vars_read
                    vars_written = instr.vars_written
                    if any(var in white_vars for var in vars_read) or any(
                        var in white_vars for var in vars_written
                    ):
                        log_error(f"ck _ {instr.instr_index}::{instr}")
                        return (False, None, [])
                    walked_instrs.append(instr)
        except Exception as e:
            log_text = ""
            log_text+= f"Exception in emu_hard: {e}\n"
            for instr in instrs:
                log_text += f"{instr.instr_index}::{instr}\n"
            log_error(log_text)
            return (False, None, [])
    raise 


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
            if quick_check(instrs, mlil):
                try:
                    r, target_idx, unused_instrs = emu_hard(instrs, state_vars)
                    log_error(
                        f"emu_hard: {r},{instrs}"
                    )
                    if r:
                        valid_paths.append((path, target_idx, unused_instrs))
                except Exception:
                    pass
            continue
        neighbors = list(G.neighbors(node))
        path_prefix = tuple(path)
        if path_prefix in visited_prefixes:
            continue
        valid_extension = False
        for neighbor in neighbors:
            # 避免环路
            if neighbor in path:
                continue
            extended_path = path + [neighbor]
            if isinstance(mlil[neighbor], MediumLevelILSetVar):
                n_instr = mlil[neighbor]
                if isinstance(n_instr, MediumLevelILSetVar) and n_instr.dest == define_il_var:
                    if isinstance(n_instr.src, MediumLevelILConst) and n_instr.src.constant != define_const_val:
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
            try:
                # 使用自定义路径搜索算法替代 NetworkX 的 shortest_simple_paths
                valid_paths = find_valid_paths(
                    G_full, def_instr.instr_index, if_instr.instr_index, mlil, state_vars
                )
                assert len(valid_paths)  <= 1, "too many paths"
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
                            new_block_label, ILSourceLocation.from_instruction(will_patch_instr)
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
