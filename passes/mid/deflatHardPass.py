"""Proof-carrying control-flow deflattening for Binary Ninja MLIL.

Candidate discovery is broad and parameter-free. A CFG edge is changed only when a
local certificate shows that the original dispatcher macro-step follows one unique
path, executes only supported non-trapping bit-vector expressions and replayable
``SetVar`` writes, and reaches a real basic-block entry. Unknown values, conflicts,
unsupported IL and cycles leave the original CFG untouched.

Correctness is therefore sound-but-incomplete: each accepted rewrite is a local
weak/stuttering simulation step, while rejected edges retain the exact dispatcher as
fallback. No sample-derived score, random-constant range, step limit, pass count or
timeout participates in rewrite authorization.
"""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from typing import (
    Dict,
    FrozenSet,
    Iterable,
    Iterator,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Set,
    Tuple,
)

from binaryninja import (
    AnalysisContext,
    ILSourceLocation,
    MediumLevelILBasicBlock,
    MediumLevelILConst,
    MediumLevelILFunction,
    MediumLevelILGoto,
    MediumLevelILIf,
    MediumLevelILInstruction,
    MediumLevelILLabel,
    MediumLevelILOperation,
    MediumLevelILSetVar,
    Variable,
)

from ...utils import log_error, log_info, log_warn


# ---------------------------------------------------------------------------
# Width-exact finite bit-vector evaluation
# ---------------------------------------------------------------------------


def _mask(width: int) -> int:
    """Return the mask for an IR-provided byte width; never guess a width."""

    if not isinstance(width, int) or width <= 0:
        raise ValueError(f"invalid MLIL width: {width!r}")
    return (1 << (width * 8)) - 1


def _width(expr: MediumLevelILInstruction) -> Optional[int]:
    width = getattr(expr, "size", 0)
    return width if isinstance(width, int) and width > 0 else None


def _to_signed(value: int, width: int) -> int:
    bits = width * 8
    value &= _mask(width)
    sign = 1 << (bits - 1)
    return value - (1 << bits) if value & sign else value


def _base_variable(value):
    """Normalize SSA variables if a BN build exposes them in ``vars_read``."""

    candidate = getattr(value, "var", value)
    return candidate if isinstance(candidate, Variable) else None


def _eval(
    expr: MediumLevelILInstruction,
    env: Mapping[Variable, int],
) -> Optional[int]:
    """Evaluate the supported MLIL bit-vector subset, or return ``Unknown``."""

    op = expr.operation
    width = _width(expr)

    if op in {
        MediumLevelILOperation.MLIL_CONST,
        MediumLevelILOperation.MLIL_CONST_PTR,
    }:
        if width is None:
            return None
        return expr.constant & _mask(width)

    if op == MediumLevelILOperation.MLIL_VAR:
        if width is None:
            return None
        var = _base_variable(getattr(expr, "src", None))
        value = env.get(var) if var is not None else None
        return None if value is None else value & _mask(width)

    if op == MediumLevelILOperation.MLIL_VAR_FIELD:
        # A zero-offset field is a width truncation. Other offsets need the full
        # source layout and remain Unknown.
        if width is None or getattr(expr, "offset", None) != 0:
            return None
        var = _base_variable(getattr(expr, "src", None))
        value = env.get(var) if var is not None else None
        return None if value is None else value & _mask(width)

    unary = {
        MediumLevelILOperation.MLIL_ZX,
        MediumLevelILOperation.MLIL_SX,
        MediumLevelILOperation.MLIL_LOW_PART,
        MediumLevelILOperation.MLIL_NEG,
        MediumLevelILOperation.MLIL_NOT,
    }
    bool_to_int = getattr(MediumLevelILOperation, "MLIL_BOOL_TO_INT", None)
    if op in unary or (bool_to_int is not None and op == bool_to_int):
        if width is None or not hasattr(expr, "src"):
            return None
        value = _eval(expr.src, env)
        if value is None:
            return None
        if op == MediumLevelILOperation.MLIL_SX:
            src_width = _width(expr.src)
            if src_width is None:
                return None
            return _to_signed(value, src_width) & _mask(width)
        if op == MediumLevelILOperation.MLIL_NEG:
            return (-value) & _mask(width)
        if op == MediumLevelILOperation.MLIL_NOT:
            return (~value) & _mask(width)
        if bool_to_int is not None and op == bool_to_int:
            return int(value != 0) & _mask(width)
        return value & _mask(width)

    if not (hasattr(expr, "left") and hasattr(expr, "right")) or width is None:
        return None
    left = _eval(expr.left, env)
    right = _eval(expr.right, env)
    if left is None or right is None:
        return None

    mask = _mask(width)
    bits = width * 8
    left &= mask
    right &= mask

    if op == MediumLevelILOperation.MLIL_ADD:
        return (left + right) & mask
    if op == MediumLevelILOperation.MLIL_SUB:
        return (left - right) & mask
    if op == MediumLevelILOperation.MLIL_MUL:
        return (left * right) & mask
    if op == MediumLevelILOperation.MLIL_AND:
        return left & right
    if op == MediumLevelILOperation.MLIL_OR:
        return left | right
    if op == MediumLevelILOperation.MLIL_XOR:
        return left ^ right
    if op in {
        MediumLevelILOperation.MLIL_LSL,
        MediumLevelILOperation.MLIL_LSR,
        MediumLevelILOperation.MLIL_ASR,
    }:
        # Overshift behavior varies by source/machine semantics. Refuse it instead
        # of hard-coding the old 0x3f mask.
        if right >= bits:
            return None
        if op == MediumLevelILOperation.MLIL_LSL:
            return (left << right) & mask
        if op == MediumLevelILOperation.MLIL_LSR:
            return left >> right
        return (_to_signed(left, width) >> right) & mask

    rol = getattr(MediumLevelILOperation, "MLIL_ROL", None)
    ror = getattr(MediumLevelILOperation, "MLIL_ROR", None)
    if rol is not None and op == rol:
        amount = right % bits
        return ((left << amount) | (left >> ((bits - amount) % bits))) & mask
    if ror is not None and op == ror:
        amount = right % bits
        return ((left >> amount) | (left << ((bits - amount) % bits))) & mask

    udiv = getattr(MediumLevelILOperation, "MLIL_DIVU", None)
    umod = getattr(MediumLevelILOperation, "MLIL_MODU", None)
    sdiv = getattr(MediumLevelILOperation, "MLIL_DIVS", None)
    smod = getattr(MediumLevelILOperation, "MLIL_MODS", None)
    division_ops = {item for item in (udiv, umod, sdiv, smod) if item is not None}
    if op in division_ops:
        if right == 0:
            return None
        if op == udiv:
            return (left // right) & mask
        if op == umod:
            return (left % right) & mask
        signed_left = _to_signed(left, width)
        signed_right = _to_signed(right, width)
        if signed_right == 0:
            return None
        if signed_left == -(1 << (bits - 1)) and signed_right == -1:
            return None
        quotient = abs(signed_left) // abs(signed_right)
        if (signed_left < 0) != (signed_right < 0):
            quotient = -quotient
        if op == sdiv:
            return quotient & mask
        return (signed_left - quotient * signed_right) & mask

    test_bit = getattr(MediumLevelILOperation, "MLIL_TEST_BIT", None)
    if test_bit is not None and op == test_bit:
        if right >= bits:
            return None
        return int(bool(left & (1 << right)))
    return None


_COMPARISON_OPS: FrozenSet[MediumLevelILOperation] = frozenset(
    getattr(MediumLevelILOperation, name)
    for name in (
        "MLIL_CMP_E",
        "MLIL_CMP_NE",
        "MLIL_CMP_ULT",
        "MLIL_CMP_ULE",
        "MLIL_CMP_UGT",
        "MLIL_CMP_UGE",
        "MLIL_CMP_SLT",
        "MLIL_CMP_SLE",
        "MLIL_CMP_SGT",
        "MLIL_CMP_SGE",
    )
    if hasattr(MediumLevelILOperation, name)
)


def _eval_if(
    if_instr: MediumLevelILIf,
    env: Mapping[Variable, int],
) -> Optional[bool]:
    cond = if_instr.condition
    op = cond.operation
    if op not in _COMPARISON_OPS:
        value = _eval(cond, env)
        return None if value is None else value != 0
    if not (hasattr(cond, "left") and hasattr(cond, "right")):
        return None
    left = _eval(cond.left, env)
    right = _eval(cond.right, env)
    width = _width(cond.left)
    if left is None or right is None or width is None:
        return None
    mask = _mask(width)
    left_u = left & mask
    right_u = right & mask
    if op == MediumLevelILOperation.MLIL_CMP_E:
        return left_u == right_u
    if op == MediumLevelILOperation.MLIL_CMP_NE:
        return left_u != right_u
    if op == MediumLevelILOperation.MLIL_CMP_ULT:
        return left_u < right_u
    if op == MediumLevelILOperation.MLIL_CMP_ULE:
        return left_u <= right_u
    if op == MediumLevelILOperation.MLIL_CMP_UGT:
        return left_u > right_u
    if op == MediumLevelILOperation.MLIL_CMP_UGE:
        return left_u >= right_u
    left_s = _to_signed(left_u, width)
    right_s = _to_signed(right_u, width)
    if op == MediumLevelILOperation.MLIL_CMP_SLT:
        return left_s < right_s
    if op == MediumLevelILOperation.MLIL_CMP_SLE:
        return left_s <= right_s
    if op == MediumLevelILOperation.MLIL_CMP_SGT:
        return left_s > right_s
    if op == MediumLevelILOperation.MLIL_CMP_SGE:
        return left_s >= right_s
    return None


# ---------------------------------------------------------------------------
# Iterative expression walk and observable-effect accounting
# ---------------------------------------------------------------------------


def _walk_expression(root: MediumLevelILInstruction) -> Iterator[MediumLevelILInstruction]:
    """Walk an IL expression without relying on version-specific ``traverse`` ABI."""

    stack: List[MediumLevelILInstruction] = [root]
    seen: Set[int] = set()
    while stack:
        node = stack.pop()
        expr_index = getattr(node, "expr_index", None)
        if isinstance(expr_index, int):
            if expr_index in seen:
                continue
            seen.add(expr_index)
        yield node
        try:
            operands = node.detailed_operands
        except Exception:
            return
        children: List[MediumLevelILInstruction] = []
        for _name, operand, _type_name in operands:
            if isinstance(operand, MediumLevelILInstruction):
                children.append(operand)
            elif isinstance(operand, (list, tuple)):
                children.extend(
                    item
                    for item in operand
                    if isinstance(item, MediumLevelILInstruction)
                )
        stack.extend(reversed(children))


def _enum_members(names: Iterable[str]) -> FrozenSet[MediumLevelILOperation]:
    return frozenset(
        getattr(MediumLevelILOperation, name)
        for name in names
        if hasattr(MediumLevelILOperation, name)
    )


_SIDE_EFFECT_OPS = _enum_members(
    (
        "MLIL_CALL",
        "MLIL_CALL_UNTYPED",
        "MLIL_CALL_SSA",
        "MLIL_CALL_UNTYPED_SSA",
        "MLIL_TAILCALL",
        "MLIL_TAILCALL_UNTYPED",
        "MLIL_TAILCALL_SSA",
        "MLIL_TAILCALL_UNTYPED_SSA",
        "MLIL_SYSCALL",
        "MLIL_SYSCALL_UNTYPED",
        "MLIL_SYSCALL_SSA",
        "MLIL_SYSCALL_UNTYPED_SSA",
        "MLIL_STORE",
        "MLIL_STORE_SSA",
        "MLIL_STORE_STRUCT",
        "MLIL_STORE_STRUCT_SSA",
        "MLIL_RET",
        "MLIL_RET_HINT",
        "MLIL_NORET",
        "MLIL_TRAP",
        "MLIL_BP",
        "MLIL_INTRINSIC",
        "MLIL_INTRINSIC_SSA",
        "MLIL_MEMORY_INTRINSIC_SSA",
        "MLIL_UNIMPL",
        "MLIL_UNIMPL_MEM",
    )
)

EffectSignature = Tuple[int, int]
EffectMultiset = Counter[EffectSignature]


def _collect_side_effect_signatures(mlil: MediumLevelILFunction) -> EffectMultiset:
    """Collect a recursive, multiplicity-preserving effect fingerprint."""

    effects: EffectMultiset = Counter()
    for top in mlil.instructions:
        for expr in _walk_expression(top):
            if expr.operation in _SIDE_EFFECT_OPS:
                effects[(int(expr.operation), int(expr.address))] += 1
    return effects


def _verify_no_side_effect_loss(
    before: Mapping[EffectSignature, int],
    after: Mapping[EffectSignature, int],
    function_name: str,
) -> bool:
    """Diagnostic backstop; certificates, not this fingerprint, authorize edits."""

    lost: EffectMultiset = Counter()
    for signature, count in before.items():
        missing = count - after.get(signature, 0)
        if missing > 0:
            lost[signature] = missing
    if not lost:
        return True
    log_error(
        f"[verified-cff] {function_name}: {sum(lost.values())} observable "
        "effect occurrence(s) disappeared after rewriting"
    )
    for (op_id, address), count in sorted(lost.items(), key=lambda item: item[0][1]):
        log_error(f"  lost x{count}: op_id={op_id} addr={hex(address)}")
    return False


# ---------------------------------------------------------------------------
# Parameter-free structural candidate discovery
# ---------------------------------------------------------------------------


def _tarjan_scc(adj: Mapping[int, Sequence[int]]) -> List[List[int]]:
    """Iterative Tarjan SCC in ``O(V + E)``."""

    next_index = 0
    node_stack: List[int] = []
    index: Dict[int, int] = {}
    low: Dict[int, int] = {}
    on_stack: Set[int] = set()
    result: List[List[int]] = []

    for root in adj:
        if root in index:
            continue
        index[root] = low[root] = next_index
        next_index += 1
        node_stack.append(root)
        on_stack.add(root)
        frames: List[Tuple[int, Iterator[int]]] = [
            (root, iter(adj.get(root, ())))
        ]
        while frames:
            node, successors = frames[-1]
            try:
                successor = next(successors)
            except StopIteration:
                frames.pop()
                if low[node] == index[node]:
                    component: List[int] = []
                    while True:
                        member = node_stack.pop()
                        on_stack.remove(member)
                        component.append(member)
                        if member == node:
                            break
                    result.append(component)
                if frames:
                    parent = frames[-1][0]
                    low[parent] = min(low[parent], low[node])
                continue
            if successor not in adj:
                continue
            if successor not in index:
                index[successor] = low[successor] = next_index
                next_index += 1
                node_stack.append(successor)
                on_stack.add(successor)
                frames.append((successor, iter(adj.get(successor, ()))))
            elif successor in on_stack:
                low[node] = min(low[node], index[successor])
    return result


def _cfg(mlil: MediumLevelILFunction):
    blocks = list(mlil.basic_blocks)
    by_start = {block.start: block for block in blocks}
    adjacency = {
        block.start: [edge.target.start for edge in block.outgoing_edges]
        for block in blocks
    }
    return blocks, by_start, adjacency


def _dominator_intervals(blocks: Sequence[MediumLevelILBasicBlock]):
    """Build Euler intervals for constant-time dominance checks."""

    by_start = {block.start: block for block in blocks}
    children = {
        block.start: [child.start for child in block.dominator_tree_children]
        for block in blocks
    }
    child_nodes = {child for values in children.values() for child in values}
    roots = [block.start for block in blocks if block.start not in child_nodes]
    entered: Set[int] = set()
    tin: Dict[int, int] = {}
    tout: Dict[int, int] = {}
    subtree: Dict[int, int] = {}
    clock = 0
    for root in roots:
        if root in entered:
            continue
        stack: List[Tuple[int, bool]] = [(root, False)]
        while stack:
            node, leaving = stack.pop()
            if leaving:
                tout[node] = clock
                subtree[node] = 1 + sum(
                    subtree.get(child, 0) for child in children.get(node, ())
                )
                continue
            if node in entered:
                continue
            entered.add(node)
            tin[node] = clock
            clock += 1
            stack.append((node, True))
            for child in reversed(children.get(node, ())):
                stack.append((child, False))
    # Defensive fallback for disconnected or malformed dominator forests.
    for start in by_start:
        if start not in tin:
            tin[start] = clock
            clock += 1
            tout[start] = clock
            subtree[start] = 1
    return tin, tout, subtree


def _detect_dispatcher_entries(
    mlil: MediumLevelILFunction,
    exclude: Optional[Set[int]] = None,
) -> List[MediumLevelILBasicBlock]:
    """Enumerate structural loop/SCC entries; ranking never authorizes edits."""

    blocks, by_start, adjacency = _cfg(mlil)
    if not blocks:
        return []
    excluded = exclude or set()
    tin, tout, subtree = _dominator_intervals(blocks)

    def dominates(header: int, node: int) -> bool:
        return (
            header in tin
            and node in tin
            and tin[header] <= tin[node] < tout.get(header, tin[header] + 1)
        )

    candidates: Set[int] = set()
    for block in blocks:
        if block.start in excluded:
            continue
        if any(
            edge.source.start == block.start
            or dominates(block.start, edge.source.start)
            for edge in block.incoming_edges
        ):
            candidates.add(block.start)

    # Irreducible SCCs need not have a natural-loop header.
    for component in _tarjan_scc(adjacency):
        members = set(component)
        cyclic = len(members) > 1 or any(
            node in adjacency.get(node, ()) for node in members
        )
        if not cyclic:
            continue
        entries = {
            node
            for node in members
            if any(
                edge.source.start not in members
                for edge in by_start[node].incoming_edges
            )
        }
        if not entries:
            entries = {min(members)}
        candidates.update(entries - excluded)

    return [
        by_start[start]
        for start in sorted(
            candidates,
            key=lambda start: (-subtree.get(start, 1), start),
        )
        if start in by_start
    ]


def _detect_dispatcher_entry(
    mlil: MediumLevelILFunction,
    exclude: Optional[Set[int]] = None,
    threshold: Optional[float] = None,
) -> Optional[MediumLevelILBasicBlock]:
    """Compatibility wrapper; the old empirical ``threshold`` is ignored."""

    del threshold
    entries = _detect_dispatcher_entries(mlil, exclude)
    return entries[0] if entries else None


def _component_for_entry(
    mlil: MediumLevelILFunction,
    entry_start: int,
) -> Set[int]:
    _blocks, _by_start, adjacency = _cfg(mlil)
    for component in _tarjan_scc(adjacency):
        if entry_start not in component:
            continue
        members = set(component)
        if len(members) > 1 or entry_start in adjacency.get(entry_start, ()):
            return members
        return set()
    return set()


def _cyclic_component_index(
    mlil: MediumLevelILFunction,
) -> Dict[int, FrozenSet[int]]:
    """Index every cyclic SCC once for all candidate entries in the function."""

    _blocks, _by_start, adjacency = _cfg(mlil)
    index: Dict[int, FrozenSet[int]] = {}
    for component in _tarjan_scc(adjacency):
        members = frozenset(component)
        if len(members) <= 1 and not any(
            node in adjacency.get(node, ()) for node in members
        ):
            continue
        for member in members:
            index[member] = members
    return index


def _collect_state_vars(
    mlil: MediumLevelILFunction,
    dispatcher_entry: MediumLevelILBasicBlock,
    component: Optional[Set[int]] = None,
) -> Set[Variable]:
    """Collect the backward data slice that feeds SCC branch predicates."""

    if component is None:
        component = _component_for_entry(mlil, dispatcher_entry.start)
    variables: Set[Variable] = set()
    dependencies: Dict[Variable, Set[Variable]] = defaultdict(set)
    for start in component:
        block = mlil.get_basic_block_at(start)
        if block is None:
            continue
        for index in range(block.start, block.end):
            instruction = mlil[index]
            if isinstance(instruction, MediumLevelILIf):
                for node in _walk_expression(instruction.condition):
                    try:
                        reads = node.vars_read
                    except Exception:
                        reads = ()
                    for value in reads:
                        variable = _base_variable(value)
                        if variable is not None:
                            variables.add(variable)
            elif isinstance(instruction, MediumLevelILSetVar):
                dest = _base_variable(instruction.dest)
                if dest is None:
                    continue
                sources: Set[Variable] = set()
                for node in _walk_expression(instruction.src):
                    try:
                        reads = node.vars_read
                    except Exception:
                        reads = ()
                    for value in reads:
                        variable = _base_variable(value)
                        if variable is not None:
                            sources.add(variable)
                dependencies[dest].update(sources)

    # Alias/encoding closure: when a predicate variable is defined from another
    # variable in the SCC, that source is part of the state tuple too. Unrelated
    # handler temporaries are deliberately excluded so pure real blocks are not
    # swallowed into the dispatcher closure.
    pending = deque(variables)
    while pending:
        destination = pending.popleft()
        for source in dependencies.get(destination, ()):
            if source in variables:
                continue
            variables.add(source)
            pending.append(source)
    return variables


def _function_looks_like_cff(
    mlil: MediumLevelILFunction,
    state_vars: Set[Variable],
) -> bool:
    """Parameter-free classifier used for discovery, never for authorization."""

    values: Dict[Variable, Set[int]] = defaultdict(set)
    for instruction in mlil.instructions:
        if not isinstance(instruction, MediumLevelILSetVar):
            continue
        dest = _base_variable(instruction.dest)
        if dest not in state_vars or not isinstance(instruction.src, MediumLevelILConst):
            continue
        width = _width(instruction)
        if width is None:
            continue
        values[dest].add(instruction.src.constant & _mask(width))
    # A branch state machine structurally needs more than one state. Constants do
    # not need to be random, sparse, large, or confined to a sample-tuned range.
    return any(len(constants) > 1 for constants in values.values())


# ---------------------------------------------------------------------------
# Pure dispatcher closure and local edge certificates
# ---------------------------------------------------------------------------


_PURE_VALUE_OPS = _enum_members(
    (
        "MLIL_CONST",
        "MLIL_CONST_PTR",
        "MLIL_VAR",
        "MLIL_VAR_FIELD",
        "MLIL_ZX",
        "MLIL_SX",
        "MLIL_LOW_PART",
        "MLIL_NEG",
        "MLIL_NOT",
        "MLIL_BOOL_TO_INT",
        "MLIL_ADD",
        "MLIL_SUB",
        "MLIL_MUL",
        "MLIL_AND",
        "MLIL_OR",
        "MLIL_XOR",
        "MLIL_LSL",
        "MLIL_LSR",
        "MLIL_ASR",
        "MLIL_ROL",
        "MLIL_ROR",
        "MLIL_DIVU",
        "MLIL_MODU",
        "MLIL_DIVS",
        "MLIL_MODS",
        "MLIL_TEST_BIT",
        "MLIL_CMP_E",
        "MLIL_CMP_NE",
        "MLIL_CMP_ULT",
        "MLIL_CMP_ULE",
        "MLIL_CMP_UGT",
        "MLIL_CMP_UGE",
        "MLIL_CMP_SLT",
        "MLIL_CMP_SLE",
        "MLIL_CMP_SGT",
        "MLIL_CMP_SGE",
    )
)


def _expression_is_supported_pure(expr: MediumLevelILInstruction) -> bool:
    return all(node.operation in _PURE_VALUE_OPS for node in _walk_expression(expr))


def _block_is_pure_dispatcher(
    mlil: MediumLevelILFunction,
    block: MediumLevelILBasicBlock,
    state_vars: Set[Variable],
) -> bool:
    """Accept replayable writes followed by exactly one pure terminator."""

    if block.length == 0:
        return False
    for index in range(block.start, block.end):
        instruction = mlil[index]
        is_last = index == block.end - 1
        if isinstance(instruction, MediumLevelILSetVar):
            dest = _base_variable(instruction.dest)
            if (
                is_last
                or dest not in state_vars
                or not _expression_is_supported_pure(instruction.src)
            ):
                return False
            continue
        if isinstance(instruction, MediumLevelILIf):
            return is_last and _expression_is_supported_pure(instruction.condition)
        if isinstance(instruction, MediumLevelILGoto):
            return is_last
        return False
    return False


def _identify_dispatcher_subgraph(
    mlil: MediumLevelILFunction,
    dispatcher_entry: MediumLevelILBasicBlock,
    state_vars: Set[Variable],
    component: Optional[Set[int]] = None,
) -> Set[int]:
    """Return the reachable replayable control closure inside the entry SCC."""

    if component is None:
        component = _component_for_entry(mlil, dispatcher_entry.start)
    if not component:
        return set()
    pure: Set[int] = set()
    for start in component:
        block = mlil.get_basic_block_at(start)
        if block is not None and _block_is_pure_dispatcher(mlil, block, state_vars):
            pure.add(start)
    if dispatcher_entry.start not in pure:
        return set()
    reachable: Set[int] = set()
    queue = deque([dispatcher_entry.start])
    while queue:
        start = queue.popleft()
        if start in reachable or start not in pure:
            continue
        reachable.add(start)
        block = mlil.get_basic_block_at(start)
        if block is None:
            continue
        queue.extend(
            edge.target.start
            for edge in block.outgoing_edges
            if edge.target.start in pure
        )
    return reachable


@dataclass(frozen=True)
class CertifiedEdge:
    """A local weak-simulation certificate for one incoming CFG edge."""

    dispatcher_start: int
    source_start: int
    terminator_expr: int
    arm: str
    original_target: int
    handler_target: int
    entry_state: Tuple[Tuple[Variable, int], ...]
    replay_exprs: Tuple[int, ...]

    @property
    def edge_key(self) -> Tuple[int, str, int]:
        return (self.terminator_expr, self.arm, self.original_target)

    @property
    def replay_key(self) -> Tuple[Tuple[int, ...], int]:
        return (self.replay_exprs, self.handler_target)

    def value_for(self, variable: Variable) -> Optional[int]:
        for candidate, value in self.entry_state:
            if candidate == variable:
                return value
        return None


def _state_at_terminator(
    mlil: MediumLevelILFunction,
    block: MediumLevelILBasicBlock,
    tracked: Set[Variable],
) -> Dict[Variable, int]:
    """Compute exact values established in this block; unknowns stay absent."""

    env: Dict[Variable, int] = {}
    for index in range(block.start, block.end - 1):
        instruction = mlil[index]
        if isinstance(instruction, MediumLevelILSetVar):
            dest = _base_variable(instruction.dest)
            if dest not in tracked:
                continue
            value = _eval(instruction.src, env)
            width = _width(instruction)
            if value is None or width is None:
                env.pop(dest, None)
            else:
                env[dest] = value & _mask(width)
            continue
        # An unhandled write invalidates a previously known tracked value.
        try:
            writes = {
                variable
                for raw in instruction.vars_written
                if (variable := _base_variable(raw)) is not None
            }
        except Exception:
            writes = set()
        for variable in writes & tracked:
            env.pop(variable, None)
    return env


def _walk_dispatcher_block(
    mlil: MediumLevelILFunction,
    block: MediumLevelILBasicBlock,
    env: MutableMapping[Variable, int],
    replay: List[int],
) -> Optional[int]:
    for index in range(block.start, block.end):
        instruction = mlil[index]
        if isinstance(instruction, MediumLevelILSetVar):
            dest = _base_variable(instruction.dest)
            value = _eval(instruction.src, env)
            width = _width(instruction)
            if dest is not None:
                if value is None or width is None:
                    env.pop(dest, None)
                else:
                    env[dest] = value & _mask(width)
            replay.append(instruction.expr_index)
            continue
        if isinstance(instruction, MediumLevelILGoto):
            return instruction.dest
        if isinstance(instruction, MediumLevelILIf):
            decision = _eval_if(instruction, env)
            if decision is None:
                return None
            return instruction.true if decision else instruction.false
        return None
    return None


ResolutionContext = Tuple[int, Tuple[Tuple[int, int], ...]]
ResolutionOutcome = Optional[Tuple[int, Tuple[int, ...]]]


@dataclass
class _ResolutionDomain:
    """Program-sized memo domain shared by every incoming edge of a dispatcher."""

    capacity: int
    admitted: Set[ResolutionContext]
    cache: Dict[ResolutionContext, ResolutionOutcome]


def _dispatcher_explicit_atoms(
    mlil: MediumLevelILFunction,
    dispatcher_blocks: Set[int],
) -> Set[Tuple[int, int]]:
    atoms: Set[Tuple[int, int]] = set()
    for start_index in dispatcher_blocks:
        dispatcher_block = mlil.get_basic_block_at(start_index)
        if dispatcher_block is None:
            continue
        for index in range(dispatcher_block.start, dispatcher_block.end):
            instruction = mlil[index]
            if not (
                isinstance(instruction, MediumLevelILSetVar)
                and isinstance(instruction.src, MediumLevelILConst)
            ):
                continue
            dest = _base_variable(instruction.dest)
            width = _width(instruction)
            if dest is not None and width is not None:
                atoms.add(
                    (dest.identifier, instruction.src.constant & _mask(width))
                )
    return atoms


def _resolution_context(
    block_start: int,
    env: Mapping[Variable, int],
) -> ResolutionContext:
    return (
        block_start,
        tuple(
            sorted(
                (variable.identifier, value)
                for variable, value in env.items()
            )
        ),
    )


def _resolve_dispatcher_path(
    mlil: MediumLevelILFunction,
    start: int,
    initial_env: Mapping[Variable, int],
    dispatcher_blocks: Set[int],
    domain: Optional[_ResolutionDomain] = None,
) -> Optional[Tuple[int, Tuple[int, ...]]]:
    """Resolve a macro-step in a finite, program-derived disjunctive domain.

    Flatteners often route through the same comparison root more than once while a
    constant transition block changes the state. Context is therefore
    ``(block, exact state tuple)``, as in context-sensitive abstract interpretation.
    To keep the fast profile polynomial, its disjunctive domain contains at most one
    context per dispatcher block and explicit state atom. Crossing that
    program-derived lattice capacity widens to Unknown and preserves the old edge.
    """

    env = dict(initial_env)
    if domain is None:
        explicit_atoms = _dispatcher_explicit_atoms(mlil, dispatcher_blocks)
        explicit_atoms.update(
            (variable.identifier, value)
            for variable, value in initial_env.items()
        )
        domain = _ResolutionDomain(
            capacity=len(dispatcher_blocks) * (len(explicit_atoms) + 1),
            admitted=set(),
            cache={},
        )
    trail: List[Tuple[ResolutionContext, Tuple[int, ...]]] = []
    local: Set[ResolutionContext] = set()
    current = start

    def reject() -> None:
        for context, _replay in trail:
            domain.cache.setdefault(context, None)

    def finish(handler: int, suffix: Tuple[int, ...]):
        for context, local_replay in reversed(trail):
            suffix = local_replay + suffix
            domain.cache[context] = (handler, suffix)
        return handler, suffix

    while True:
        block = mlil.get_basic_block_at(current)
        if block is None or block.start != current:
            reject()
            return None
        if current not in dispatcher_blocks:
            return finish(current, ())
        context = _resolution_context(current, env)
        if context in domain.cache:
            cached = domain.cache[context]
            if cached is None:
                reject()
                return None
            return finish(*cached)
        if context in local:
            reject()
            return None
        if context not in domain.admitted:
            if len(domain.admitted) >= domain.capacity:
                reject()
                return None
            domain.admitted.add(context)
        local.add(context)
        local_replay: List[int] = []
        next_index = _walk_dispatcher_block(
            mlil,
            block,
            env,
            local_replay,
        )
        if next_index is None:
            trail.append((context, tuple(local_replay)))
            reject()
            return None
        trail.append((context, tuple(local_replay)))
        current = next_index


def _certify_dispatcher_edges(
    mlil: MediumLevelILFunction,
    dispatcher_entry: MediumLevelILBasicBlock,
    state_vars: Set[Variable],
    dispatcher_blocks: Set[int],
) -> List[CertifiedEdge]:
    """Prove every independently resolvable real-block edge into a dispatcher."""

    work = []
    explicit_atoms = _dispatcher_explicit_atoms(mlil, dispatcher_blocks)
    for block in list(mlil.basic_blocks):
        if block.start in dispatcher_blocks or block.length == 0:
            continue
        terminator = mlil[block.end - 1]
        if isinstance(terminator, MediumLevelILGoto):
            arms = (("goto", terminator.dest),)
        elif isinstance(terminator, MediumLevelILIf):
            arms = (("true", terminator.true), ("false", terminator.false))
        else:
            continue
        env = _state_at_terminator(mlil, block, state_vars)
        state = tuple(sorted(env.items(), key=lambda item: item[0].identifier))
        explicit_atoms.update(
            (variable.identifier, value) for variable, value in env.items()
        )
        for arm, original_target in arms:
            target_block = mlil.get_basic_block_at(original_target)
            if (
                target_block is None
                or target_block.start != original_target
                or original_target not in dispatcher_blocks
            ):
                continue
            work.append(
                (block, terminator, arm, original_target, dict(env), state)
            )

    # This finite disjunctive domain is derived solely from the current program:
    # dispatcher blocks times explicit/entry state atoms. Shared memoization makes
    # each admitted (block, exact-state) context execute at most once across all
    # incoming edges, giving a polynomial fast profile without a step constant.
    domain = _ResolutionDomain(
        capacity=len(dispatcher_blocks) * (len(explicit_atoms) + 1),
        admitted=set(),
        cache={},
    )
    certificates: List[CertifiedEdge] = []
    for block, terminator, arm, original_target, env, state in work:
        resolved = _resolve_dispatcher_path(
            mlil,
            original_target,
            env,
            dispatcher_blocks,
            domain,
        )
        if resolved is None:
            continue
        handler, replay = resolved
        if handler in dispatcher_blocks:
            continue
        certificates.append(
            CertifiedEdge(
                dispatcher_start=dispatcher_entry.start,
                source_start=block.start,
                terminator_expr=terminator.expr_index,
                arm=arm,
                original_target=original_target,
                handler_target=handler,
                entry_state=state,
                replay_exprs=replay,
            )
        )
    return certificates


def _forward_resolve(
    mlil: MediumLevelILFunction,
    define_instr: MediumLevelILSetVar,
    state_vars: Set[Variable],
    dispatcher_blocks: Set[int],
) -> Optional[int]:
    """Compatibility wrapper over the finite proof evaluator."""

    block = mlil.get_basic_block_at(define_instr.instr_index)
    if block is None:
        return None
    env: Dict[Variable, int] = {}
    current: Optional[int] = None
    for index in range(block.start, block.end):
        instruction = mlil[index]
        if isinstance(instruction, MediumLevelILSetVar):
            dest = _base_variable(instruction.dest)
            if dest in state_vars:
                value = _eval(instruction.src, env)
                width = _width(instruction)
                if value is None or width is None:
                    env.pop(dest, None)
                else:
                    env[dest] = value & _mask(width)
            continue
        if index <= define_instr.instr_index:
            continue
        if isinstance(instruction, MediumLevelILGoto):
            current = instruction.dest
            break
        if isinstance(instruction, MediumLevelILIf):
            decision = _eval_if(instruction, env)
            if decision is None:
                return None
            current = instruction.true if decision else instruction.false
            break
        return None
    if current is None:
        return None
    resolved = _resolve_dispatcher_path(mlil, current, env, dispatcher_blocks)
    return None if resolved is None else resolved[0]


def _deduplicate_certificates(
    certificates: Iterable[CertifiedEdge],
) -> List[CertifiedEdge]:
    """Reject an edge if independent candidate analyses disagree."""

    grouped: Dict[Tuple[int, str, int], List[CertifiedEdge]] = defaultdict(list)
    for certificate in certificates:
        grouped[certificate.edge_key].append(certificate)
    accepted: List[CertifiedEdge] = []
    for group in grouped.values():
        outcomes = {
            (certificate.handler_target, certificate.replay_exprs)
            for certificate in group
        }
        if len(outcomes) == 1:
            accepted.append(group[0])
    return accepted


def _validate_certified_edge(
    mlil: MediumLevelILFunction,
    certificate: CertifiedEdge,
) -> bool:
    try:
        instruction = mlil.get_expr(certificate.terminator_expr)
    except Exception:
        return False
    if certificate.arm == "goto":
        return (
            isinstance(instruction, MediumLevelILGoto)
            and instruction.dest == certificate.original_target
        )
    if not isinstance(instruction, MediumLevelILIf):
        return False
    if certificate.arm == "true":
        return instruction.true == certificate.original_target
    if certificate.arm == "false":
        return instruction.false == certificate.original_target
    return False


def _collect_all_certificates(
    mlil: MediumLevelILFunction,
) -> List[CertifiedEdge]:
    certificates: List[CertifiedEdge] = []
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
        certificates.extend(
            _certify_dispatcher_edges(mlil, entry, state_vars, dispatcher_blocks)
        )
    return _deduplicate_certificates(certificates)


def build_real_block_transition_graph(
    mlil: MediumLevelILFunction,
) -> Dict[int, Set[int]]:
    """Return the certificate-backed real-block transition graph without mutation."""

    graph: Dict[int, Set[int]] = defaultdict(set)
    for certificate in _collect_all_certificates(mlil):
        graph[certificate.source_start].add(certificate.handler_target)
    return dict(graph)


def _current_mlil(analysis_context: AnalysisContext) -> Optional[MediumLevelILFunction]:
    """Use in-progress Workflow IL; ``Function.mlil`` can be stale here."""

    current = getattr(analysis_context, "mlil", None)
    if current is not None:
        return current
    function = getattr(analysis_context, "function", None)
    return None if function is None else function.mlil


def _indirect_location(instruction: MediumLevelILInstruction) -> ILSourceLocation:
    """Map a synthetic node to its origin without stealing the direct mapping."""

    return ILSourceLocation.from_instruction(instruction, il_direct=False)


def _set_builder_address(
    destination: MediumLevelILFunction,
    source: MediumLevelILInstruction,
) -> None:
    """Preserve per-block architecture metadata for mixed-architecture functions."""

    block = source.function.get_basic_block_at(source.instr_index)
    destination.set_current_address(
        source.address,
        getattr(block, "arch", None),
    )


def _copy_replay_expression(
    candidate: MediumLevelILFunction,
    original: MediumLevelILInstruction,
):
    """Shallow-copy the already translated expression without a second direct map.

    ``translate`` has already deep-copied every original expression into
    ``candidate``. Reusing that candidate expression's children is therefore both
    safe and preferable to a second ``old.copy_to(candidate)``: the latter records
    another direct MLIL/LLIL mapping and Binary Ninja resolves the 1:1 mapping by
    last-write-wins.
    """

    instruction_map = getattr(candidate, "_mlil_to_mlil_instr_map", None)
    if not isinstance(instruction_map, dict):
        raise ValueError("Binary Ninja exposes no MLIL builder instruction map")
    entries = instruction_map.get(original, ())
    direct = [index for index, is_direct in entries if is_direct]
    if len(direct) != 1:
        raise ValueError(
            f"original expression {original.expr_index} has {len(direct)} "
            "direct instruction mappings"
        )
    translated = candidate[direct[0]]
    copied = candidate.expr(
        translated.operation,
        translated.raw_operands[0],
        translated.raw_operands[1],
        translated.raw_operands[2],
        translated.raw_operands[3],
        translated.raw_operands[4],
        translated.size,
        _indirect_location(original),
    )
    candidate.set_expr_attributes(copied, original.attributes)
    return copied


def _preserve_replacement_attributes(
    destination: MediumLevelILFunction,
    replacement,
    original: MediumLevelILInstruction,
):
    destination.set_expr_attributes(replacement, original.attributes)
    return replacement


def _candidate_mapping_is_functional(
    original: MediumLevelILFunction,
    candidate: MediumLevelILFunction,
) -> bool:
    """Prove builder source mappings remain deterministic before committing.

    Binary Ninja's MLIL-to-MLIL/LLIL maps permit multiple indirect occurrences but
    instruction navigation is 1:1 for direct occurrences. Every original top-level
    instruction must retain exactly one direct target and no expression may have two
    direct targets. We also force construction of the derived LLIL-SSA maps here so
    an API/mapping failure rejects the detached candidate rather than surfacing after
    Workflow commit.
    """

    instruction_map = getattr(candidate, "_mlil_to_mlil_instr_map", None)
    expression_map = getattr(candidate, "_mlil_to_mlil_expr_map", None)
    if not isinstance(instruction_map, dict) or not isinstance(expression_map, dict):
        return False
    try:
        instruction_count = len(candidate)
        expression_count = candidate.get_expr_count()
        for mappings in instruction_map.values():
            direct = 0
            for index, is_direct in mappings:
                if int(index) < 0 or int(index) >= instruction_count:
                    return False
                direct += int(bool(is_direct))
            if direct > 1:
                return False
        for mappings in expression_map.values():
            direct = 0
            for index, is_direct in mappings:
                if int(index) < 0 or int(index) >= expression_count:
                    return False
                direct += int(bool(is_direct))
            if direct > 1:
                return False
        for instruction in original.instructions:
            mappings = instruction_map.get(instruction, ())
            if sum(bool(is_direct) for _index, is_direct in mappings) != 1:
                return False
            expr_mappings = expression_map.get(instruction, ())
            if sum(bool(is_direct) for _index, is_direct in expr_mappings) != 1:
                return False
        candidate._get_llil_ssa_to_mlil_instr_map(True)
        candidate._get_llil_ssa_to_mlil_expr_map(True)
    except Exception as error:
        log_warn(f"[verified-cff] source mapping validation failed: {error}")
        return False
    return True


def _candidate_cfg_is_closed(candidate: MediumLevelILFunction) -> bool:
    """Check that every explicit target resolves to a candidate block entry."""

    try:
        for block in candidate.basic_blocks:
            if block.length == 0:
                return False
            terminator = candidate[block.end - 1]
            targets: Iterable[int]
            if isinstance(terminator, MediumLevelILGoto):
                targets = (terminator.dest,)
            elif isinstance(terminator, MediumLevelILIf):
                targets = (terminator.true, terminator.false)
            elif terminator.operation == MediumLevelILOperation.MLIL_JUMP_TO:
                targets = tuple(terminator.targets.values())
            else:
                continue
            for target in targets:
                target_block = candidate.get_basic_block_at(target)
                if target_block is None or target_block.start != target:
                    return False
    except Exception:
        return False
    return True


def _validate_detached_candidate(
    original: MediumLevelILFunction,
    candidate: MediumLevelILFunction,
) -> bool:
    """Linear validation performed before the sole Workflow commit point."""

    if not _candidate_cfg_is_closed(candidate):
        return False
    if not _candidate_mapping_is_functional(original, candidate):
        return False
    # Replayed state writes are not observable effects, so an exact multiset match
    # is expected. This catches copy/mapping bugs in either direction.
    return (
        _collect_side_effect_signatures(original)
        == _collect_side_effect_signatures(candidate)
    )


def _build_detached_deflate_candidate(
    original: MediumLevelILFunction,
    certificates: Sequence[CertifiedEdge],
) -> Optional[MediumLevelILFunction]:
    """Copy the full MLIL, apply the edit plan to the copy, and validate it."""

    if not certificates or not hasattr(original, "translate"):
        return None
    by_expr: Dict[int, List[CertifiedEdge]] = defaultdict(list)
    for certificate in certificates:
        if _validate_certified_edge(original, certificate):
            by_expr[certificate.terminator_expr].append(certificate)
    if not by_expr:
        return None

    replay_labels = {
        certificate.replay_key: MediumLevelILLabel()
        for certificate in certificates
        if certificate.replay_exprs
    }

    def translated_target(
        new_function: MediumLevelILFunction,
        certificate: CertifiedEdge,
    ) -> MediumLevelILLabel:
        replay_label = replay_labels.get(certificate.replay_key)
        if replay_label is not None:
            return replay_label
        target = new_function.get_label_for_source_instruction(
            certificate.handler_target
        )
        if target is None:
            raise ValueError(
                f"handler {certificate.handler_target} has no copied label"
            )
        return target

    def transform(new_function, _old_block, old_instruction):
        replacements = by_expr.get(old_instruction.expr_index)
        if not replacements:
            return old_instruction.copy_to(new_function)
        location = ILSourceLocation.from_instruction(old_instruction)
        if isinstance(old_instruction, MediumLevelILGoto):
            certificate = replacements[0]
            if certificate.arm != "goto":
                raise ValueError("goto certificate arm mismatch")
            replacement = new_function.goto(
                translated_target(new_function, certificate), location
            )
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
        for certificate in replacements:
            if certificate.arm == "true":
                true_label = translated_target(new_function, certificate)
            elif certificate.arm == "false":
                false_label = translated_target(new_function, certificate)
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
        for replay_key, label in replay_labels.items():
            replay_exprs, handler = replay_key
            candidate.mark_label(label)
            originals = [original.get_expr(index) for index in replay_exprs]
            if not originals or not all(
                isinstance(item, MediumLevelILSetVar) for item in originals
            ):
                return None
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
        candidate.finalize()
        candidate.generate_ssa_form()
    except Exception as error:
        log_warn(f"[verified-cff] detached copy failed: {error}")
        return None
    return candidate if _validate_detached_candidate(original, candidate) else None


def _commit_detached_candidate(
    analysis_context: AnalysisContext,
    candidate: MediumLevelILFunction,
) -> bool:
    """The only mutation of Workflow state; failures leave the old MLIL installed."""

    try:
        setter = getattr(analysis_context, "set_mlil_function", None)
        if callable(setter):
            setter(candidate)
        else:
            analysis_context.mlil = candidate
        return True
    except Exception as error:
        log_warn(f"[verified-cff] candidate commit failed: {error}")
        return False


def build_verified_deflate_candidate(
    mlil: MediumLevelILFunction,
) -> Optional[Tuple[MediumLevelILFunction, int]]:
    """Return a validated detached candidate and its certified edge count."""

    certificates = _collect_all_certificates(mlil)
    valid = [
        certificate
        for certificate in certificates
        if _validate_certified_edge(mlil, certificate)
    ]
    candidate = _build_detached_deflate_candidate(mlil, valid)
    if candidate is None:
        return None
    return candidate, len(valid)


def pass_deflate_hard(analysis_context: AnalysisContext) -> bool:
    """Bypass only certificate-backed dispatcher edges, preserving all writes."""

    mlil = _current_mlil(analysis_context)
    function = getattr(analysis_context, "function", None)
    if mlil is None:
        return False
    function_name = getattr(function, "name", "<unknown>")
    effects_before = _collect_side_effect_signatures(mlil)

    planned = build_verified_deflate_candidate(mlil)
    candidate, changed = planned if planned is not None else (None, 0)
    if candidate is not None and _commit_detached_candidate(
        analysis_context, candidate
    ):
        log_info(
            f"[verified-deflate] {function_name}: committed {changed} "
            f"certificate-backed edge(s)"
        )
        return True

    # No candidate was installed: the authoritative in-progress IL is unchanged.
    _verify_no_side_effect_loss(effects_before, effects_before, function_name)
    return False
