from binaryninja import (
    LowLevelILFunction,
    LowLevelILGoto,
    LowLevelILIf,
    LowLevelILLabel,
    LowLevelILInstruction,
    LowLevelILBasicBlock,
    AnalysisContext,
    ILSourceLocation,
)

from ...utils import CFGAnalyzer, log_error


def _llil_function_likely_cff(llil: LowLevelILFunction) -> bool:
    """LLIL 层的 Blazytko 支配树式 CFF 嗅探。

    防止对正常函数（Rust match / C++ stdlib）做 copy_common_block 把它们
    炸大。判据：存在某个块支配 ≥ 30% 函数块且有 back-edge from dominated。
    """
    bbs = list(llil.basic_blocks)
    n = len(bbs)
    if n < 8:
        return False
    bb_by_start = {b.start: b for b in bbs}
    for d in bbs:
        # 估算被 d 支配的子树大小
        subtree = {d.start}
        stack = [d]
        while stack:
            x = stack.pop()
            for c in x.dominator_tree_children:
                if c.start not in subtree:
                    subtree.add(c.start)
                    stack.append(c)
        if len(subtree) / n < 0.3:
            continue
        # 检查 back-edge：被 d 支配的某个块跳回 d
        has_back_edge = False
        for src_start in subtree:
            src = bb_by_start.get(src_start)
            if src is None:
                continue
            for edge in src.outgoing_edges:
                if edge.target.start == d.start and src.start != d.start:
                    has_back_edge = True
                    break
            if has_back_edge:
                break
        if has_back_edge:
            return True
    return False


def fix_pre_bb(
    llil: LowLevelILFunction,
    pre_last_instr: LowLevelILInstruction,
    bb: LowLevelILBasicBlock,
    copy_label: LowLevelILLabel,
):
    if isinstance(pre_last_instr, LowLevelILGoto):
        llil.replace_expr(
            pre_last_instr.expr_index,
            llil.goto(copy_label, ILSourceLocation.from_instruction(pre_last_instr)),
        )
    elif isinstance(pre_last_instr, LowLevelILIf):
        true_target = pre_last_instr.true
        false_target = pre_last_instr.false
        if true_target == bb.start:
            fix_false_label = LowLevelILLabel()
            fix_false_label.operand = false_target
            llil.replace_expr(
                pre_last_instr.expr_index,
                llil.if_expr(
                    llil.copy_expr(
                        pre_last_instr.condition,
                    ),
                    copy_label,
                    fix_false_label,
                    ILSourceLocation.from_instruction(pre_last_instr),
                ),
            )
        elif false_target == bb.start:
            fix_true_label = LowLevelILLabel()
            fix_true_label.operand = true_target
            llil.replace_expr(
                pre_last_instr.expr_index,
                llil.if_expr(
                    llil.copy_expr(
                        pre_last_instr.condition,
                    ),
                    fix_true_label,
                    copy_label,
                    ILSourceLocation.from_instruction(pre_last_instr),
                ),
            )
        else:
            log_error("ERROR IF")
    else:
        log_error("ERROR")


def pass_copy_common_block(analysis_context: AnalysisContext):
    """复制有多前驱的小块，使每条 dispatcher 路径独占一份。

    爆炸控制：
    - 总块数硬上限 (>500 直接跳过)
    - 单块大小上限 (>8 跳过；之前 16 太宽松导致 sub_428b68 这种从 106
      炸到 405)
    - 总复制额度上限 (initial_blocks × 1.5)，超出立即停止本 pass
    """
    llil = analysis_context.function.llil
    if llil is None:
        return
    initial_count = len(llil.basic_blocks)
    if initial_count > 500:
        return
    # task #16: 只对 *看起来是 CFF 的* 函数复制块，否则白白把 Rust/C++ 正常
    # 函数炸大（libsafexEx 的 __cxa_guard_acquire 20→28，sub_492b20 19→42）
    if not _llil_function_likely_cff(llil):
        return
    max_total_blocks = int(initial_count * 1.5) + 16  # 复制额度
    max_iterations = min(initial_count, 64)
    for _ in range(max_iterations):
        if len(llil.basic_blocks) > max_total_blocks:
            break
        updated = False
        g = CFGAnalyzer.create_cfg_graph(llil)
        for bb in llil.basic_blocks:
            if bb.length > 8:
                continue
            pre_blocks = CFGAnalyzer.LLIL_get_incoming_blocks(llil, bb.start)
            if len(pre_blocks) <= 1:
                continue
            pre_instrs = [prebb[-1] for prebb in pre_blocks]
            if not all(
                isinstance(instr, LowLevelILGoto) or isinstance(instr, LowLevelILIf)
                for instr in pre_instrs
            ):
                continue
            if CFGAnalyzer.is_node_in_loop(g, bb.start):
                continue
            for j in range(1, len(pre_blocks)):
                if len(llil.basic_blocks) > max_total_blocks:
                    break
                updated = True
                pre_block = pre_blocks[j]
                pre_last_instr = llil[pre_block.end - 1]
                copy_label = LowLevelILLabel()
                llil.mark_label(copy_label)
                for instr_index in range(bb.start, bb.end):
                    llil.append(llil.copy_expr(llil[instr_index]))
                fix_pre_bb(llil, pre_last_instr, bb, copy_label)
        if updated:
            llil.finalize()
            llil.generate_ssa_form()
        else:
            break
    llil.finalize()
    llil.generate_ssa_form()
