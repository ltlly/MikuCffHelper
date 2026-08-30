from binaryninja import AnalysisContext

from .passes.mid.deflatHardPass import (
    _commit_detached_candidate,
    build_verified_deflate_candidate,
    pass_deflate_hard,
)
from .passes.mid.synthesizeSwitchPass import (
    build_verified_switch_candidate,
    pass_synthesize_switch,
)
from .utils import log_info, log_warn


def _reachable_complexity(mlil):
    """Parameter-free structural cost of the candidate's reachable CFG.

    Lexicographic order avoids arbitrary weights: first minimize decision points,
    then reachable blocks, then reachable instructions. Detached unreachable copies
    do not influence the choice because BN's later structurer follows the entry CFG.
    """

    blocks = list(mlil.basic_blocks)
    if not blocks:
        raise ValueError("candidate contains no basic blocks")
    by_start = {block.start: block for block in blocks}
    entry = mlil.get_basic_block_at(0)
    if entry is None:
        entry = blocks[0]
    reachable = set()
    pending = [entry.start]
    while pending:
        start = pending.pop()
        if start in reachable:
            continue
        block = by_start.get(start)
        if block is None:
            raise ValueError(f"candidate edge targets missing block {start}")
        reachable.add(start)
        pending.extend(edge.target.start for edge in block.outgoing_edges)
    decisions = sum(
        len(by_start[start].outgoing_edges) > 1 for start in reachable
    )
    instructions = sum(by_start[start].length for start in reachable)
    return decisions, len(reachable), instructions


def workflow_patch_llil(analysis_context: AnalysisContext):
    """Legacy LLIL normalizers.

    The verified MLIL pipeline does not depend on block copying or condition
    normalization.  This activity remains available for manual experiments, but is
    disabled by default at registration time because it has no local equivalence
    certificate.
    """
    if analysis_context.llil is None:
        return
    # Keep optional NetworkX-based legacy tooling out of the verified default
    # pipeline and its import-time dependency surface.
    from .passes.low.copyCommonBlockPass import pass_copy_common_block
    from .passes.low.inlineIfCondPass import pass_inline_if_cond
    from .passes.low.spiltIfPass import pass_spilt_if_block

    pass_copy_common_block(analysis_context)
    pass_inline_if_cond(analysis_context)
    pass_spilt_if_block(analysis_context)


def workflow_patch_mlil(analysis_context: AnalysisContext):
    if analysis_context.mlil is None:
        return
    # The certificate planner reads state writes in their original order, so unsafe
    # pre-normalization and a fixed number of repeated passes are unnecessary.
    pass_deflate_hard(analysis_context)


def workflow_patch_mlil_switch(analysis_context: AnalysisContext):
    """互斥的 deflate 替代路径：把 dispatcher 重构为 MLIL JUMP_TO，让 BN
    HLIL restructurer 显示成 switch-case 结构。

    与 workflow_patch_mlil 互斥：用户只应启用其中一个 (UI 里的 eligibility
    切换)。
    """
    if analysis_context.mlil is None:
        return
    pass_synthesize_switch(analysis_context)


def workflow_patch_mlil_auto(analysis_context: AnalysisContext):
    """Build both verified paths and commit the structurally simplest candidate."""
    if analysis_context.mlil is None:
        return

    fname = analysis_context.function.name
    original = analysis_context.mlil
    choices = []
    for kind, builder in (
        ("switch", build_verified_switch_candidate),
        ("deflate", build_verified_deflate_candidate),
    ):
        try:
            planned = builder(original)
            if planned is None:
                continue
            candidate, certified_edges = planned
            choices.append(
                (
                    _reachable_complexity(candidate),
                    kind,
                    candidate,
                    certified_edges,
                )
            )
        except Exception as error:
            log_warn(f"[auto] {fname}: {kind} candidate rejected: {error}")
    if not choices:
        log_info(f"[auto] {fname}: no certificate-backed candidate")
        return

    # Exact ties prefer switch only as a presentation choice; no numeric weight or
    # empirical threshold participates in the ordering.
    complexity, kind, candidate, certified_edges = min(
        choices,
        key=lambda choice: (choice[0], choice[1] != "switch"),
    )
    if _commit_detached_candidate(analysis_context, candidate):
        log_info(
            f"[auto] {fname}: committed {kind}, reachable complexity="
            f"{complexity}, certified_edges={certified_edges}"
        )


def workflow_patch_hlil(analysis_context: AnalysisContext):
    from .utils import suggest_stateVar

    suggest_stateVar(analysis_context.view, analysis_context.function)
