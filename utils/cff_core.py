"""通用 CFF 分析的线性基础组件。

这是「通用去平坦化框架」的核心数据层，供未来的 general pass 使用：

1. ``DominatorInfo``
   把 dominator-tree 的 subtree 判定从 ``d in bb.dominators``（列表成员，
   最坏 O(N^2)）改成 DFS 区间 O(1)，使 Blazytko 检测整体 O(V+E)。

2. ``StateClass`` / ``find_state_classes``
   - 先走现有「比较变量被赋 ≥2 个常量」的直连路径（对标准 OLLVM 保持兼容）；
   - 直连路径为空时，用变量拷贝图的 union-find 做 alias 类识别，解决
     ``x19_1 = x7_1; if (x19_1 == K)`` 这类 alias-only 状态变量；
   - 返回全部候选状态类，供多状态变种逐个尝试。

3. ``EnvEvaluator``
   在 deflatHardPass 的整型解释器基础上补三件事：
   - 比较表达式求值为 0/1（bool 可存入 env）；
   - ``if (cond_var)`` 这种布尔 flag 变量条件；
   - NOT / AND / OR 的布尔组合。

4. ``collect_state_case_values``
   从 dispatcher 决策块的 if 条件 *和* ``flag = (state == const)`` SetVar 里
   收集全部比较常量，供 guarded jump_to 的 fallback 覆盖检查使用。

全部函数只做纯计算，不修改 MLIL。
"""

from dataclasses import dataclass
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from binaryninja import (
    MediumLevelILBasicBlock,
    MediumLevelILConst,
    MediumLevelILFunction,
    MediumLevelILIf,
    MediumLevelILInstruction,
    MediumLevelILOperation,
    MediumLevelILSetVar,
    MediumLevelILVar,
    MediumLevelILVarSsa,
    Variable,
)

from .mikuPlugin import log_info

_WIDTH_TO_MASK = {1: 0xFF, 2: 0xFFFF, 4: 0xFFFFFFFF, 8: 0xFFFFFFFFFFFFFFFF}

_CMP_OPS: Set = {
    MediumLevelILOperation.MLIL_CMP_E,
    MediumLevelILOperation.MLIL_CMP_NE,
    MediumLevelILOperation.MLIL_CMP_ULT,
    MediumLevelILOperation.MLIL_CMP_ULE,
    MediumLevelILOperation.MLIL_CMP_UGT,
    MediumLevelILOperation.MLIL_CMP_UGE,
    MediumLevelILOperation.MLIL_CMP_SLT,
    MediumLevelILOperation.MLIL_CMP_SLE,
    MediumLevelILOperation.MLIL_CMP_SGT,
    MediumLevelILOperation.MLIL_CMP_SGE,
}


def mask(width: int) -> int:
    return _WIDTH_TO_MASK.get(width, (1 << (width * 8)) - 1)


def to_signed(value: int, width: int) -> int:
    bits = width * 8
    value &= (1 << bits) - 1
    if value & (1 << (bits - 1)):
        return value - (1 << bits)
    return value


# ---------------------------------------------------------------------------
# Dominator 信息：subtree size + DFS interval
# ---------------------------------------------------------------------------


class DominatorInfo:
    """基于 BN dominator_tree_children 构造的 O(V) dominator 索引。

    ``is_in_subtree(a, b)`` 用 DFS 进出时间 O(1) 判断 b 是否在 a 的支配
    子树内，替代 ``a in bb.dominators``。
    """

    def __init__(self, bbs: List[MediumLevelILBasicBlock]):
        self.bbs = bbs
        self.bb_by_start: Dict[int, MediumLevelILBasicBlock] = {
            b.start: b for b in bbs
        }
        self.children: Dict[int, List[int]] = {b.start: [] for b in bbs}
        self.parent: Dict[int, Optional[int]] = {}
        for b in bbs:
            for child in b.dominator_tree_children:
                self.children[b.start].append(child.start)
                self.parent[child.start] = b.start

        self.tin: Dict[int, int] = {}
        self.tout: Dict[int, int] = {}
        self.subtree_size: Dict[int, int] = {}
        roots = [b.start for b in bbs if self.parent.get(b.start) is None]
        # 健壮性：BN 偶发 dominator tree 根不是函数入口，仍全部遍历
        timer = 0

        def traverse_tree(root: int) -> None:
            nonlocal timer
            stack: List[Tuple[int, int]] = [(root, 0)]
            self.tin[root] = timer
            timer += 1
            while stack:
                node, child_idx = stack[-1]
                children = self.children.get(node, [])
                if child_idx < len(children):
                    stack[-1] = (node, child_idx + 1)
                    child = children[child_idx]
                    self.tin[child] = timer
                    timer += 1
                    stack.append((child, 0))
                else:
                    self.tout[node] = timer
                    timer += 1
                    size = 1
                    for child in children:
                        size += self.subtree_size.get(child, 0)
                    self.subtree_size[node] = size
                    stack.pop()

        for root in roots:
            traverse_tree(root)
        # 防御性补扫：孤立节点也要有区间
        for b in bbs:
            if b.start not in self.tin:
                traverse_tree(b.start)

    def is_in_subtree(self, ancestor_start: int, node_start: int) -> bool:
        a = self.tin.get(ancestor_start)
        b = self.tin.get(node_start)
        if a is None or b is None:
            return False
        return a <= b < self.tout[ancestor_start]


def detect_flattening_candidate(
    mlil: MediumLevelILFunction,
    exclude: Optional[Set[int]] = None,
    threshold: float = 0.30,
    min_blocks: int = 5,
    min_subtree_blocks: int = 3,
) -> Optional[MediumLevelILBasicBlock]:
    """Blazytko 支配树检测，O(V+E)。

    返回 flattening_score 最高的 dispatcher 入口候选。
    """
    bbs = list(mlil.basic_blocks)
    n = len(bbs)
    if n < min_blocks:
        return None
    info = DominatorInfo(bbs)
    excluded = exclude or set()

    best: Optional[MediumLevelILBasicBlock] = None
    best_score = 0.0
    for d in bbs:
        if d.start in excluded:
            continue
        size = info.subtree_size.get(d.start, 0)
        if size < min_subtree_blocks:
            continue
        score = size / n
        if score < threshold:
            continue
        has_back_edge = any(
            info.is_in_subtree(d.start, edge.source.start)
            for edge in d.incoming_edges
        )
        if not has_back_edge:
            continue
        if score > best_score:
            best_score = score
            best = d
    return best


# ---------------------------------------------------------------------------
# 变量拷贝图 + 状态类识别
# ---------------------------------------------------------------------------


class _UnionFind:
    def __init__(self) -> None:
        self.parent: Dict[int, int] = {}

    def find(self, x: int) -> int:
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


@dataclass(frozen=True)
class StateClass:
    primary: Variable
    vars: FrozenSet[Variable]
    var_ids: FrozenSet[int]
    assigned_values: FrozenSet[int]
    unique_counts: Dict[int, int]

    def contains(self, var: Variable) -> bool:
        return var.identifier in self.var_ids

    def contains_id(self, identifier: int) -> bool:
        return identifier in self.var_ids


def _var_of(expr: MediumLevelILInstruction) -> Optional[Variable]:
    if isinstance(expr, (MediumLevelILVar, MediumLevelILVarSsa)):
        src = getattr(expr, "src", None)
        return src if isinstance(src, Variable) else None
    return None


def _collect_comparison_var_ids(
    mlil: MediumLevelILFunction,
    dispatcher_entry: MediumLevelILBasicBlock,
) -> Set[int]:
    """BFS 收集 dispatcher 可达区域里 ``if (var op const)`` 的 var。O(V+E)。"""
    result: Set[int] = set()
    visited: Set[int] = set()
    queue: List[MediumLevelILBasicBlock] = [dispatcher_entry]
    while queue:
        bb = queue.pop()
        if bb.start in visited:
            continue
        visited.add(bb.start)
        if bb.length == 0:
            continue
        last = mlil[bb.end - 1]
        if isinstance(last, MediumLevelILIf):
            cond = last.condition
            # 直接比较：if (state == const)
            if (
                hasattr(cond, "left")
                and hasattr(cond, "right")
                and isinstance(cond.right, MediumLevelILConst)
            ):
                var = _var_of(cond.left)
                if var is not None:
                    result.add(var.identifier)
            elif (
                hasattr(cond, "left")
                and hasattr(cond, "right")
                and isinstance(cond.left, MediumLevelILConst)
            ):
                var = _var_of(cond.right)
                if var is not None:
                    result.add(var.identifier)
            else:
                # flag 变量条件：if (flag)，在同块内找 flag 的比较定义
                flag_var = _var_of(cond)
                if flag_var is not None:
                    for idx in range(bb.start, bb.end - 1):
                        instr = mlil[idx]
                        if not isinstance(instr, MediumLevelILSetVar):
                            continue
                        if instr.dest != flag_var:
                            continue
                        src = instr.src
                        if (
                            hasattr(src, "left")
                            and hasattr(src, "right")
                            and isinstance(src.right, MediumLevelILConst)
                        ):
                            var = _var_of(src.left)
                            if var is not None:
                                result.add(var.identifier)
                        elif (
                            hasattr(src, "left")
                            and hasattr(src, "right")
                            and isinstance(src.left, MediumLevelILConst)
                        ):
                            var = _var_of(src.right)
                            if var is not None:
                                result.add(var.identifier)
        for edge in bb.outgoing_edges:
            queue.append(edge.target)
    return result


def _collect_const_value_sets(
    mlil: MediumLevelILFunction,
) -> Tuple[Dict[int, Set[int]], Dict[int, Variable]]:
    """一遍扫描收集每个变量的常量赋值集合与 id→Variable 映射。O(I)。"""
    values: Dict[int, Set[int]] = {}
    var_by_id: Dict[int, Variable] = {}
    for instr in mlil.instructions:
        if isinstance(instr, MediumLevelILSetVar):
            var_by_id[instr.dest.identifier] = instr.dest
            if isinstance(instr.src, MediumLevelILConst):
                values.setdefault(instr.dest.identifier, set()).add(
                    instr.src.constant & mask(instr.size or 4)
                )
            elif isinstance(instr.src, MediumLevelILVar):
                var_by_id.setdefault(instr.src.src.identifier, instr.src.src)
            elif isinstance(instr.src, MediumLevelILVarSsa):
                src = getattr(instr.src, "src", None)
                if isinstance(src, Variable):
                    var_by_id.setdefault(src.identifier, src)
    return values, var_by_id


def _looks_like_cff_values(all_values: Set[int]) -> bool:
    if len(all_values) < 4:
        return False
    return (max(all_values) - min(all_values)) >= 0x10000000


def find_state_classes(
    mlil: MediumLevelILFunction,
    dispatcher_entry: MediumLevelILBasicBlock,
    require_cff_heuristic: bool = True,
    limit: int = 4,
) -> List[StateClass]:
    """识别 dispatcher 的全部候选状态类，按 unique 常量数降序返回。

    路径 1：dispatcher 比较变量自身被赋 ≥2 个常量（标准 OLLVM，行为与
    ``_collect_state_vars`` 一致），每个比较变量一个直连状态类。

    路径 2：比较变量没有任何常量赋值时（alias-only 变种），在整函数
    ``alias = state`` 拷贝图上做 union-find，每个比较变量连通分量一个
    状态类；primary 取分量内常量赋值最多的变量。

    多状态变种（dispatcher 同时比较 x19/x5 等）会自然产生多个候选，
    调用方可以逐个尝试或进一步组合成元组。
    """
    cmp_ids = _collect_comparison_var_ids(mlil, dispatcher_entry)
    if not cmp_ids:
        return []
    const_values, var_by_id = _collect_const_value_sets(mlil)

    # 变量拷贝图：直连候选也先按拷贝连通分量归并，避免 BN 拆出的
    # x8_168 / x8_304 这类 SSA alias 被当成独立状态类（多候选爆炸）。
    uf = _UnionFind()
    for instr in mlil.instructions:
        if not isinstance(instr, MediumLevelILSetVar):
            continue
        if isinstance(instr.src, MediumLevelILVar):
            uf.union(instr.dest.identifier, instr.src.src.identifier)
        elif isinstance(instr.src, MediumLevelILVarSsa):
            src = getattr(instr.src, "src", None)
            if isinstance(src, Variable):
                uf.union(instr.dest.identifier, src.identifier)

    comp_vars: Dict[int, List[int]] = {}
    for vid in var_by_id:
        comp_vars.setdefault(uf.find(vid), []).append(vid)

    classes: List[StateClass] = []

    # 路径 1：直连候选按连通分量归并
    direct_roots: Dict[int, Set[int]] = {}
    for vid in cmp_ids:
        values = const_values.get(vid, set())
        if len(values) >= 2:
            direct_roots.setdefault(uf.find(vid), set()).add(vid)
    for root, member_ids in direct_roots.items():
        ids = comp_vars.get(root, [])
        union_values: Set[int] = set()
        counts: Dict[int, int] = {}
        for vid in ids:
            vs = const_values.get(vid, set())
            if vs:
                counts[vid] = len(vs)
            union_values.update(vs)
        if len(union_values) < 2:
            continue
        if require_cff_heuristic and not _looks_like_cff_values(union_values):
            continue
        primary_id = max(counts, key=lambda k: counts[k]) if counts else next(
            iter(member_ids)
        )
        primary = var_by_id.get(primary_id)
        if primary is None:
            continue
        state_vars: Set[Variable] = set()
        for vid in ids:
            var = var_by_id.get(vid)
            if var is not None:
                state_vars.add(var)
        classes.append(
            StateClass(
                primary=primary,
                vars=frozenset(state_vars),
                var_ids=frozenset(ids),
                assigned_values=frozenset(union_values),
                unique_counts=counts,
            )
        )

    if classes:
        classes.sort(key=lambda sc: -len(sc.assigned_values))
        return classes[:limit]

    # 路径 2：alias 类（复用上面的 uf / comp_vars）
    seen_roots: Set[int] = set()
    candidates: List[Tuple[int, int, List[int]]] = []
    for cmp_id in cmp_ids:
        root = uf.find(cmp_id)
        if root in seen_roots:
            continue
        seen_roots.add(root)
        ids = comp_vars.get(root, [])
        if not ids:
            continue
        union_values: Set[int] = set()
        counts: Dict[int, int] = {}
        for vid in ids:
            vs = const_values.get(vid, set())
            if vs:
                counts[vid] = len(vs)
            union_values.update(vs)
        if len(union_values) < 2:
            continue
        if require_cff_heuristic and not _looks_like_cff_values(union_values):
            continue
        primary_id = max(counts, key=lambda k: counts[k]) if counts else cmp_id
        candidates.append((len(union_values), primary_id, ids))

    candidates.sort(key=lambda t: -t[0])
    for _, primary_id, ids in candidates[:limit]:
        primary = var_by_id.get(primary_id)
        if primary is None:
            primary = var_by_id.get(next(iter(cmp_ids)))
        if primary is None:
            continue
        state_vars: Set[Variable] = set()
        counts: Dict[int, int] = {}
        union_values: Set[int] = set()
        for vid in ids:
            var = var_by_id.get(vid)
            if var is not None:
                state_vars.add(var)
            vs = const_values.get(vid, set())
            if vs:
                counts[vid] = len(vs)
            union_values.update(vs)
        classes.append(
            StateClass(
                primary=primary,
                vars=frozenset(state_vars),
                var_ids=frozenset(ids),
                assigned_values=frozenset(union_values),
                unique_counts=counts,
            )
        )

    for sc in classes:
        log_info(
            f"[cff_core] alias-aware state class: primary={sc.primary.name} "
            f"aliases={len(sc.vars)} values={len(sc.assigned_values)}"
        )
    return classes


def find_state_class(
    mlil: MediumLevelILFunction,
    dispatcher_entry: MediumLevelILBasicBlock,
    require_cff_heuristic: bool = True,
) -> Optional[StateClass]:
    """兼容入口：返回排名第一的状态类（等价于旧版单候选行为）。"""
    classes = find_state_classes(
        mlil, dispatcher_entry, require_cff_heuristic, limit=1
    )
    return classes[0] if classes else None


# ---------------------------------------------------------------------------
# 扩展布尔求值器
# ---------------------------------------------------------------------------


class EnvEvaluator:
    """常量环境解释器：整数 + 比较布尔值 + flag 变量 + NOT/AND/OR。"""

    @staticmethod
    def _binary(expr: MediumLevelILInstruction, env: Dict[Variable, int]):
        if not (hasattr(expr, "left") and hasattr(expr, "right")):
            return None
        lv = EnvEvaluator.eval(expr.left, env)
        rv = EnvEvaluator.eval(expr.right, env)
        if lv is None or rv is None:
            return None
        width = expr.size or expr.left.size or 4
        m = mask(width)
        lv &= m
        rv &= m
        op = expr.operation
        if op == MediumLevelILOperation.MLIL_ADD:
            return (lv + rv) & m
        if op == MediumLevelILOperation.MLIL_SUB:
            return (lv - rv) & m
        if op == MediumLevelILOperation.MLIL_MUL:
            return (lv * rv) & m
        if op == MediumLevelILOperation.MLIL_AND:
            return (lv & rv) & m
        if op == MediumLevelILOperation.MLIL_OR:
            return (lv | rv) & m
        if op == MediumLevelILOperation.MLIL_XOR:
            return (lv ^ rv) & m
        if op == MediumLevelILOperation.MLIL_LSL:
            return (lv << (rv & 0x3F)) & m
        if op == MediumLevelILOperation.MLIL_LSR:
            return lv >> (rv & 0x3F)
        if op == MediumLevelILOperation.MLIL_ASR:
            return (to_signed(lv, width) >> (rv & 0x3F)) & m
        if op in _CMP_OPS:
            return int(EnvEvaluator._compare(op, lv, rv, width))
        return None

    @staticmethod
    def _compare(op, lv: int, rv: int, width: int) -> bool:
        if op == MediumLevelILOperation.MLIL_CMP_E:
            return lv == rv
        if op == MediumLevelILOperation.MLIL_CMP_NE:
            return lv != rv
        if op == MediumLevelILOperation.MLIL_CMP_ULT:
            return lv < rv
        if op == MediumLevelILOperation.MLIL_CMP_ULE:
            return lv <= rv
        if op == MediumLevelILOperation.MLIL_CMP_UGT:
            return lv > rv
        if op == MediumLevelILOperation.MLIL_CMP_UGE:
            return lv >= rv
        ls, rs = to_signed(lv, width), to_signed(rv, width)
        if op == MediumLevelILOperation.MLIL_CMP_SLT:
            return ls < rs
        if op == MediumLevelILOperation.MLIL_CMP_SLE:
            return ls <= rs
        if op == MediumLevelILOperation.MLIL_CMP_SGT:
            return ls > rs
        if op == MediumLevelILOperation.MLIL_CMP_SGE:
            return ls >= rs
        return False

    @staticmethod
    def eval(expr: MediumLevelILInstruction, env: Dict[Variable, int]) -> Optional[int]:
        op = expr.operation
        if op == MediumLevelILOperation.MLIL_CONST:
            return expr.constant & mask(expr.size or 4)
        if op == MediumLevelILOperation.MLIL_CONST_PTR:
            return expr.constant & mask(expr.size or 8)
        if op in (MediumLevelILOperation.MLIL_VAR, MediumLevelILOperation.MLIL_VAR_SSA):
            var = _var_of(expr)
            if var is None:
                return None
            value = env.get(var)
            return None if value is None else value & mask(expr.size or 4)
        if op == MediumLevelILOperation.MLIL_VAR_FIELD:
            if getattr(expr, "offset", 0) != 0:
                return None
            var = _var_of(expr)
            if var is None:
                return None
            value = env.get(var)
            return None if value is None else value & mask(expr.size or 4)
        if op == MediumLevelILOperation.MLIL_ZX:
            v = EnvEvaluator.eval(expr.src, env)
            return v if v is None else v & mask(expr.size or 4)
        if op == MediumLevelILOperation.MLIL_SX:
            v = EnvEvaluator.eval(expr.src, env)
            if v is None:
                return None
            return to_signed(v, expr.src.size or 4) & mask(expr.size or 4)
        if op == MediumLevelILOperation.MLIL_LOW_PART:
            v = EnvEvaluator.eval(expr.src, env)
            return v if v is None else v & mask(expr.size or 4)
        if op == MediumLevelILOperation.MLIL_NEG:
            v = EnvEvaluator.eval(expr.src, env)
            return v if v is None else (-v) & mask(expr.size or 4)
        if op == MediumLevelILOperation.MLIL_NOT:
            v = EnvEvaluator.eval(expr.src, env)
            return v if v is None else (~v) & mask(expr.size or 4)
        if op in _CMP_OPS or (
            hasattr(expr, "left") and hasattr(expr, "right")
        ):
            return EnvEvaluator._binary(expr, env)
        return None

    @staticmethod
    def eval_cond(expr: MediumLevelILInstruction, env: Dict[Variable, int]) -> Optional[bool]:
        """布尔语义求值：用于 if 条件与 flag 变量定义。

        MLIL 的 AND/OR/NOT 同时表示位运算与布尔运算；在条件上下文里按
        布尔语义解释，避免 ``~0 == -1`` 被误判为 true。
        """
        op = expr.operation
        if op in _CMP_OPS:
            value = EnvEvaluator._binary(expr, env)
            return None if value is None else bool(value)
        if op == MediumLevelILOperation.MLIL_NOT:
            value = EnvEvaluator.eval_cond(expr.src, env)
            return None if value is None else not value
        if op == MediumLevelILOperation.MLIL_AND:
            left = EnvEvaluator.eval_cond(expr.left, env)
            right = EnvEvaluator.eval_cond(expr.right, env)
            if left is None or right is None:
                return None
            return left and right
        if op == MediumLevelILOperation.MLIL_OR:
            left = EnvEvaluator.eval_cond(expr.left, env)
            right = EnvEvaluator.eval_cond(expr.right, env)
            if left is None or right is None:
                return None
            return left or right
        value = EnvEvaluator.eval(expr, env)
        return None if value is None else bool(value)

    @staticmethod
    def eval_if(if_instr: MediumLevelILIf, env: Dict[Variable, int]) -> Optional[bool]:
        return EnvEvaluator.eval_cond(if_instr.condition, env)


def _collect_const_from_state_comparison(
    expr: MediumLevelILInstruction,
    state_class: StateClass,
    values: Set[int],
) -> None:
    op = expr.operation
    if op not in _CMP_OPS:
        return
    if not (hasattr(expr, "left") and hasattr(expr, "right")):
        return
    left, right = expr.left, expr.right
    if isinstance(right, MediumLevelILConst):
        var = _var_of(left)
        if var is not None and state_class.contains(var):
            values.add(right.constant & mask(right.size or left.size or 4))
    elif isinstance(left, MediumLevelILConst):
        var = _var_of(right)
        if var is not None and state_class.contains(var):
            values.add(left.constant & mask(left.size or right.size or 4))


def collect_state_case_values(
    mlil: MediumLevelILFunction,
    state_class: StateClass,
    block_starts: Set[int],
) -> Set[int]:
    """从决策块收集所有 ``(state|alias) op const`` 比较常量。

    同时扫描 if 条件与 ``flag = (state == const)`` 这类 SetVar 的 src，
    覆盖 boolean-flag 变种。
    """
    values: Set[int] = set()
    for start in block_starts:
        bb = mlil.get_basic_block_at(start)
        if bb is None:
            continue
        for idx in range(bb.start, bb.end):
            instr = mlil[idx]
            if isinstance(instr, MediumLevelILIf):
                _collect_const_from_state_comparison(
                    instr.condition, state_class, values
                )
            elif isinstance(instr, MediumLevelILSetVar):
                _collect_const_from_state_comparison(
                    instr.src, state_class, values
                )
    return values
