"""Certificate-backed MLIL ``JUMP_TO`` synthesis.

Unlike the legacy whole-dispatcher replacement, this pass never assumes that a set
of observed constants is the complete runtime domain. It appends a fast-path switch
and redirects only incoming edges whose exact state and dispatcher macro-step have
already been certified. Unknown/default/conflicting edges still execute the original
comparison tree, which is the semantic fallback.

The generated ``jump_to`` has no default because an unlisted value cannot reach it:
only certificate-backed edges with a listed singleton value are redirected. Skipped
dispatcher ``SetVar`` instructions are replayed before the handler target.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Set, Tuple

from binaryninja import (
    AnalysisContext,
    ILSourceLocation,
    MediumLevelILFunction,
    MediumLevelILGoto,
    MediumLevelILIf,
    MediumLevelILLabel,
    MediumLevelILSetVar,
    Variable,
)

from .deflatHardPass import (
    CertifiedEdge,
    _base_variable,
    _certify_dispatcher_edges,
    _collect_side_effect_signatures,
    _copy_replay_expression,
    _collect_state_vars,
    _current_mlil,
    _cyclic_component_index,
    _commit_detached_candidate,
    _deduplicate_certificates,
    _detect_dispatcher_entries,
    _identify_dispatcher_subgraph,
    _indirect_location,
    _validate_detached_candidate,
    _mask,
    _preserve_replacement_attributes,
    _set_builder_address,
    _validate_certified_edge,
    _verify_no_side_effect_loss,
    _width,
)
from ...utils import log_info, log_warn


ReplayKey = Tuple[Tuple[int, ...], int]


@dataclass
class SwitchPlan:
    dispatcher_start: int
    primary: Variable
    width: int
    value_to_replay: Dict[int, ReplayKey]
    certificates: List[CertifiedEdge]


def _variable_width(
    mlil: MediumLevelILFunction,
    variable: Variable,
) -> Optional[int]:
    """Obtain width from BN type/IL facts; never assume 32 or 64 bits."""

    var_type = getattr(variable, "type", None)
    width = getattr(var_type, "width", 0)
    if isinstance(width, int) and width > 0:
        return width
    for instruction in mlil.instructions:
        if not isinstance(instruction, MediumLevelILSetVar):
            continue
        if _base_variable(instruction.dest) != variable:
            continue
        width = _width(instruction)
        if width is not None:
            return width
    return None


def _plan_for_primary(
    mlil: MediumLevelILFunction,
    dispatcher_start: int,
    primary: Variable,
    certificates: Sequence[CertifiedEdge],
) -> Optional[SwitchPlan]:
    width = _variable_width(mlil, primary)
    if width is None:
        return None
    mask = _mask(width)
    relation: Dict[int, Set[ReplayKey]] = defaultdict(set)
    for certificate in certificates:
        value = certificate.value_for(primary)
        if value is not None:
            relation[value & mask].add(certificate.replay_key)

    # A value is eligible only when the collected relation is a mathematical
    # function. Conflicts are not resolved by first/last-wins ordering.
    value_to_replay = {
        value: next(iter(outcomes))
        for value, outcomes in relation.items()
        if len(outcomes) == 1
    }
    selected = [
        certificate
        for certificate in certificates
        if (
            (value := certificate.value_for(primary)) is not None
            and value_to_replay.get(value & mask) == certificate.replay_key
        )
    ]

    # ``jump_to`` is useful only for an actual branch relation. These are structural
    # arity requirements, not empirical coverage thresholds.
    if len(value_to_replay) <= 1:
        return None
    if len(set(value_to_replay.values())) <= 1:
        return None
    return SwitchPlan(
        dispatcher_start=dispatcher_start,
        primary=primary,
        width=width,
        value_to_replay=value_to_replay,
        certificates=selected,
    )


def _choose_switch_plan(
    mlil: MediumLevelILFunction,
    dispatcher_start: int,
    state_vars: Set[Variable],
    certificates: Sequence[CertifiedEdge],
) -> Optional[SwitchPlan]:
    """Choose by program-derived coverage; the choice cannot affect soundness."""

    plans = [
        plan
        for variable in state_vars
        if (
            plan := _plan_for_primary(
                mlil, dispatcher_start, variable, certificates
            )
        )
        is not None
    ]
    if not plans:
        return None
    return max(
        plans,
        key=lambda plan: (
            len(plan.certificates),
            len(plan.value_to_replay),
            len(set(plan.value_to_replay.values())),
            -plan.primary.identifier,
        ),
    )


def _select_nonoverlapping_plans(
    mlil: MediumLevelILFunction,
    initial_plans: Sequence[SwitchPlan],
) -> List[SwitchPlan]:
    selected: List[SwitchPlan] = []
    used_edges: Set[Tuple[int, str, int]] = set()
    for initial in initial_plans:
        remaining = [
            certificate
            for certificate in initial.certificates
            if certificate.edge_key not in used_edges
        ]
        plan = _plan_for_primary(
            mlil,
            initial.dispatcher_start,
            initial.primary,
            remaining,
        )
        if plan is None:
            continue
        selected.append(plan)
        used_edges.update(
            certificate.edge_key for certificate in plan.certificates
        )
    return selected


def _build_detached_switch_candidate(
    original: MediumLevelILFunction,
    plans: Sequence[SwitchPlan],
) -> Optional[MediumLevelILFunction]:
    """Build every replay/guard/edit on an isolated copy, then validate it."""

    if not plans or not hasattr(original, "translate"):
        return None
    guard_labels = {
        plan.dispatcher_start: MediumLevelILLabel() for plan in plans
    }
    replay_labels = {
        certificate.replay_key: MediumLevelILLabel()
        for plan in plans
        for certificate in plan.certificates
        if certificate.replay_exprs
    }
    by_expr: Dict[int, List[Tuple[CertifiedEdge, MediumLevelILLabel]]] = defaultdict(list)
    for plan in plans:
        guard = guard_labels[plan.dispatcher_start]
        for certificate in plan.certificates:
            by_expr[certificate.terminator_expr].append((certificate, guard))

    def transform(new_function, _old_block, old_instruction):
        replacements = by_expr.get(old_instruction.expr_index)
        if not replacements:
            return old_instruction.copy_to(new_function)
        location = ILSourceLocation.from_instruction(old_instruction)
        if isinstance(old_instruction, MediumLevelILGoto):
            certificate, guard = replacements[0]
            if certificate.arm != "goto":
                raise ValueError("goto certificate arm mismatch")
            replacement = new_function.goto(guard, location)
            return _preserve_replacement_attributes(
                new_function, replacement, old_instruction
            )
        if not isinstance(old_instruction, MediumLevelILIf):
            raise ValueError("certificate does not point at a branch terminator")
        true_label = new_function.get_label_for_source_instruction(
            old_instruction.true
        )
        false_label = new_function.get_label_for_source_instruction(
            old_instruction.false
        )
        if true_label is None or false_label is None:
            raise ValueError("original if target has no copied label")
        for certificate, guard in replacements:
            if certificate.arm == "true":
                true_label = guard
            elif certificate.arm == "false":
                false_label = guard
        replacement = new_function.if_expr(
            old_instruction.condition.copy_to(new_function),
            true_label,
            false_label,
            location,
        )
        return _preserve_replacement_attributes(
            new_function, replacement, old_instruction
        )

    try:
        candidate = original.translate(transform)

        # Replay every skipped state write in original order before its handler.
        for replay_key, label in replay_labels.items():
            replay_exprs, handler = replay_key
            originals = [original.get_expr(index) for index in replay_exprs]
            if not originals or not all(
                isinstance(item, MediumLevelILSetVar) for item in originals
            ):
                return None
            candidate.mark_label(label)
            for item in originals:
                _set_builder_address(candidate, item)
                location = _indirect_location(item)
                candidate.append(
                    _copy_replay_expression(candidate, item),
                    location,
                )
            target = candidate.get_label_for_source_instruction(handler)
            if target is None:
                return None
            tail = originals[-1]
            _set_builder_address(candidate, tail)
            location = _indirect_location(tail)
            candidate.append(candidate.goto(target, location), location)

        # Each guard lists exactly the singleton values of its redirected edges.
        for plan in plans:
            guard = guard_labels[plan.dispatcher_start]
            candidate.mark_label(guard)
            labels: Dict[int, MediumLevelILLabel] = {}
            for value, replay_key in plan.value_to_replay.items():
                destination = replay_labels.get(replay_key)
                if destination is None:
                    destination = candidate.get_label_for_source_instruction(
                        replay_key[1]
                    )
                if destination is None:
                    return None
                labels[value] = destination
            if len(labels) <= 1:
                return None
            anchor = original.get_expr(plan.certificates[0].terminator_expr)
            _set_builder_address(candidate, anchor)
            location = _indirect_location(anchor)
            candidate.append(
                candidate.jump_to(
                    candidate.var(plan.width, plan.primary, location),
                    labels,
                    location,
                ),
                location,
            )
        candidate.finalize()
        candidate.generate_ssa_form()
    except Exception as error:
        log_warn(f"[verified-switch] detached copy failed: {error}")
        return None
    return candidate if _validate_detached_candidate(original, candidate) else None


def _collect_plans(mlil: MediumLevelILFunction) -> List[SwitchPlan]:
    plans: List[SwitchPlan] = []
    components = _cyclic_component_index(mlil)
    for entry in _detect_dispatcher_entries(mlil):
        component = set(components.get(entry.start, ()))
        state_vars = _collect_state_vars(mlil, entry, component)
        if not state_vars:
            continue
        dispatcher_blocks = _identify_dispatcher_subgraph(
            mlil,
            entry,
            state_vars,
            component,
        )
        if not dispatcher_blocks:
            continue
        certificates = _deduplicate_certificates(
            _certify_dispatcher_edges(
                mlil, entry, state_vars, dispatcher_blocks
            )
        )
        certificates = [
            certificate
            for certificate in certificates
            if _validate_certified_edge(mlil, certificate)
        ]
        plan = _choose_switch_plan(
            mlil, entry.start, state_vars, certificates
        )
        if plan is not None:
            plans.append(plan)
    return plans


def build_verified_switch_candidate(
    mlil: MediumLevelILFunction,
) -> Optional[Tuple[MediumLevelILFunction, int]]:
    """Return a validated detached switch candidate and certified edge count."""

    plans = _select_nonoverlapping_plans(mlil, _collect_plans(mlil))
    candidate = _build_detached_switch_candidate(mlil, plans)
    if candidate is None:
        return None
    return candidate, sum(len(plan.certificates) for plan in plans)


def pass_synthesize_switch(analysis_context: AnalysisContext) -> bool:
    """Install partial, certificate-backed switch fast paths."""

    mlil = _current_mlil(analysis_context)
    function = getattr(analysis_context, "function", None)
    if mlil is None:
        return False
    function_name = getattr(function, "name", "<unknown>")
    effects_before = _collect_side_effect_signatures(mlil)

    plans = _select_nonoverlapping_plans(mlil, _collect_plans(mlil))
    candidate = _build_detached_switch_candidate(mlil, plans)
    if candidate is None or not _commit_detached_candidate(
        analysis_context, candidate
    ):
        _verify_no_side_effect_loss(effects_before, effects_before, function_name)
        return False

    transformed_edges = sum(len(plan.certificates) for plan in plans)
    for plan in plans:
        log_info(
            f"[verified-switch] {function_name}: dispatcher "
            f"0x{plan.dispatcher_start:x}, {len(plan.value_to_replay)} "
            f"singleton value(s), {len(plan.certificates)} certified edge(s)"
        )
    return transformed_edges > 0
