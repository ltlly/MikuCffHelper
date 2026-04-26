"""把 CFF dispatcher 重构为 MLIL JUMP_TO，让 BN 4.1+ 的 HLIL restructurer
显示成 switch-case 结构。

设计动机（参见 docs/pass_evaluation.md §2）：
  当前 deflate_hard 把每个 state SetVar=const 直接 patch 成 goto target，
  最终 HLIL 是一堆 goto 链，可读性中等。
  HLIL Restructurer (https://binary.ninja/2024/06/19/...) 已经能把 jump
  table 还原为 switch-case，但只针对编译器生成的合法 switch，不针对
  OLLVM cmp-tree dispatcher。

  本 pass 的思路：
  1. 用 deflate_hard 同样的 SCC + 副作用筛选识别 dispatcher 子图与 state
     变量
  2. 对每个 state SetVar=const，前向模拟到对应的真实块入口，建立
     {state_value → real_block_start} 映射
  3. 把 dispatcher_entry 块的第一条指令替换为
     `jump_to(state_var, {value: label})`，让 BN MLIL 把 dispatcher 看成
     带 N 个目标的 switch
  4. 同时 *保留* 真实块尾部的 `state = const; goto dispatcher` 不动，让
     state 值能正确流到 jump_to 的 dest

  这跟 deflate_hard 是 *互斥替代*：deflate 把 dispatcher 绕掉，本 pass 把
  dispatcher 重构成 switch。用户可在 mikuWorkflow.py 选其中一个。

形式化等价性：
  jump_to(state_var, {V → handler_V}) 在语义上等价于原 dispatcher 的
  if-tree 串联（已验证 _function_looks_like_cff 后我们知道每个 V 都对应
  唯一 handler，dispatcher 的 if-tree 也是把 state 路由到唯一 handler）。
  只要 forward-simulate 给出的 (V → handler) 映射正确，重构后的执行 trace
  与原 trace 在副作用层面等价。
"""

import time
from typing import Dict, Optional, Set, Tuple

from binaryninja import (
    AnalysisContext,
    ILSourceLocation,
    MediumLevelILBasicBlock,
    MediumLevelILConst,
    MediumLevelILFunction,
    MediumLevelILGoto,
    MediumLevelILIf,
    MediumLevelILLabel,
    MediumLevelILOperation,
    MediumLevelILSetVar,
    MediumLevelILVar,
    Variable,
)

from .deflatHardPass import (
    _collect_side_effect_signatures,
    _collect_state_vars,
    _detect_dispatcher_entry,
    _forward_resolve,
    _function_looks_like_cff,
    _identify_dispatcher_subgraph,
    _mask,
    _verify_no_side_effect_loss,
)
from ...utils import log_info, log_warn  # noqa: E402

_TIME_BUDGET_SECONDS = 15.0
_MIN_TRANSITIONS = 2
_MAX_SWITCH_ITERS = 8  # 嵌套 dispatcher 最多重构 8 层（实测 sub_407368 有 3+ 层）


def _vars_aliased_to(
    mlil: MediumLevelILFunction,
    primary,
    dispatcher_blocks,
):
    """收集所有在 dispatcher 内通过 `alias = primary` 形式被赋值的别名变量。

    BN SSA 经常拆出 `x9_1 = x8_2; if (x9_1 == K)` 这种 rename，x9_1 不在
    state_vars (没 const 赋值) 但实际承载 primary 的值。识别这种别名能让
    case_values 收集到正确的比较。
    """
    aliases = {primary}
    # 简单不动点迭代：只要发现 `new_alias = existing_alias` 就加入
    changed = True
    while changed:
        changed = False
        for bb_start in dispatcher_blocks:
            bb = mlil.get_basic_block_at(bb_start)
            if bb is None:
                continue
            for idx in range(bb.start, bb.end):
                instr = mlil[idx]
                if not isinstance(instr, MediumLevelILSetVar):
                    continue
                if instr.dest in aliases:
                    continue
                if (
                    isinstance(instr.src, MediumLevelILVar)
                    and instr.src.src in aliases
                ):
                    aliases.add(instr.dest)
                    changed = True
    return aliases


def _collect_dispatcher_case_values(
    mlil: MediumLevelILFunction,
    dispatcher_blocks,
    primary,
):
    """从 dispatcher 子图收集所有 (alias_of_primary == const) 比较中的 const。

    包含 primary 的 SSA 别名（BN var-rename 拆出的 x9_1=x8_2 类）。这避免
    sub_4259f4 上 x8_2 的 case_values=0 漏判，又避免 var-agnostic 把内层
    state machine 的 cmp 也算进来导致 sub_407368 误拒。
    """
    aliases = _vars_aliased_to(mlil, primary, dispatcher_blocks)
    values = set()
    for bb_start in dispatcher_blocks:
        bb = mlil.get_basic_block_at(bb_start)
        if bb is None:
            continue
        for idx in range(bb.start, bb.end):
            instr = mlil[idx]
            if not isinstance(instr, MediumLevelILIf):
                continue
            cond = instr.condition
            if cond.operation != MediumLevelILOperation.MLIL_CMP_E:
                continue
            if not (hasattr(cond, "left") and hasattr(cond, "right")):
                continue
            if not isinstance(cond.right, MediumLevelILConst):
                continue
            left = cond.left
            if not (hasattr(left, "src") and left.src in aliases):
                continue
            size = left.size if hasattr(left, "size") else 4
            values.add(cond.right.constant & _mask(size or 4))
    return values


def _candidate_state_vars_ranked(
    mlil: MediumLevelILFunction,
    state_vars,
):
    """返回按 unique 常量赋值数排序的状态变量列表 (从多到少)。允许调用方
    依次尝试每一个，避免单一启发式失败时整个 pass 放弃。
    """
    if not state_vars:
        return []
    unique_vals: Dict = {var: set() for var in state_vars}
    for instr in mlil.instructions:
        if (
            isinstance(instr, MediumLevelILSetVar)
            and instr.dest in state_vars
            and isinstance(instr.src, MediumLevelILConst)
        ):
            unique_vals[instr.dest].add(
                instr.src.constant & _mask(instr.size or 4)
            )
    return sorted(
        [v for v, s in unique_vals.items() if len(s) >= 2],
        key=lambda v: -len(unique_vals[v]),
    )


def _collect_transitions_for_var(
    mlil: MediumLevelILFunction,
    primary,
    state_vars,
    dispatcher_blocks,
    dispatcher_entry_start: int,
    deadline: float,
):
    """收集 primary state var 的 (state_value → target instr_index) 映射。

    返回 (transitions, all_assigned_values, fully_resolved):
      - transitions: 成功解析的 value → target
      - all_assigned_values: 函数中所有 `primary = const` 赋值的 const 值集合
      - fully_resolved: 所有 const 都有一个 SUCCESS 结果
    """
    transitions: Dict[int, int] = {}
    all_assigned = set()  # type: Set[int]
    failed_values = set()  # type: Set[int]
    for instr in mlil.instructions:
        if time.time() > deadline:
            break
        if (
            not isinstance(instr, MediumLevelILSetVar)
            or instr.dest != primary
            or not isinstance(instr.src, MediumLevelILConst)
        ):
            continue
        value = instr.src.constant & _mask(instr.size or 4)
        all_assigned.add(value)
        target = _forward_resolve(mlil, instr, state_vars, dispatcher_blocks)
        if target is None:
            failed_values.add(value)
            continue
        if target == dispatcher_entry_start:
            failed_values.add(value)
            continue
        target_bb = mlil.get_basic_block_at(target)
        if target_bb is None or target != target_bb.start:
            failed_values.add(value)
            continue
        if target_bb.start in dispatcher_blocks:
            failed_values.add(value)
            continue
        transitions.setdefault(value, target)
    # 一个值即使在某个位置失败，只要在另一个位置成功 (transitions 里有)，
    # 就视为已解析 —— 同 value 不同位置假设产出同 target (CFF 保证)
    fully_resolved = (failed_values - set(transitions.keys())) == set()
    return transitions, all_assigned, fully_resolved


def _redirect_edges_to_dispatcher(
    mlil: MediumLevelILFunction,
    dispatcher_entry: MediumLevelILBasicBlock,
    dispatcher_blocks: Set[int],
    guard_label: MediumLevelILLabel,
) -> int:
    """把 *real block* (不在 dispatcher_blocks 内) 末尾的 goto/if 中指向
    dispatcher_entry 的边重定向到 guard_label。

    这是 guarded jump_to 模式的关键步骤：让所有 handler 完成后流入新的
    guard，而不是原 dispatcher 的 cmp-tree 入口。原 cmp-tree 仍存在，但
    只能从 guard 的 fallback 路径到达。

    返回成功重定向的边数 (供调用方判断是否有意义重写)。
    """
    target_idx = dispatcher_entry.start
    guard_idx = guard_label.operand
    redirected = 0

    for b in list(mlil.basic_blocks):
        if b.start in dispatcher_blocks:
            # 不要碰 dispatcher 内部 (cmp-tree)，否则未解析 case 的兜底链
            # 会被破坏
            continue
        if b.length == 0:
            continue
        last = mlil[b.end - 1]
        loc = ILSourceLocation.from_instruction(last)
        try:
            if isinstance(last, MediumLevelILGoto):
                if last.dest != target_idx:
                    continue
                new_label = MediumLevelILLabel()
                new_label.operand = guard_idx
                mlil.replace_expr(
                    last.expr_index,
                    mlil.goto(new_label, loc),
                )
                redirected += 1
            elif isinstance(last, MediumLevelILIf):
                true_dst = last.true
                false_dst = last.false
                if true_dst != target_idx and false_dst != target_idx:
                    continue
                new_true = MediumLevelILLabel()
                new_true.operand = guard_idx if true_dst == target_idx else true_dst
                new_false = MediumLevelILLabel()
                new_false.operand = guard_idx if false_dst == target_idx else false_dst
                cond_copy = mlil.copy_expr(last.condition)
                new_if = mlil.if_expr(cond_copy, new_true, new_false, loc)
                mlil.replace_expr(last.expr_index, new_if)
                redirected += 1
        except Exception:
            continue
    return redirected


def _install_guarded_jump_to(
    mlil: MediumLevelILFunction,
    primary: Variable,
    transitions: Dict[int, int],
    case_values: Set[int],
    all_assigned: Set[int],
    dispatcher_entry: MediumLevelILBasicBlock,
    dispatcher_blocks: Set[int],
) -> bool:
    """在 MLIL 末尾追加 jump_to guard，然后重定向 real block 的回流边。

    方案:
      guard_label:
          jump_to(primary, {V_i → T_i  for V_i in transitions,
                            V_j → dispatcher_entry.start  for V_j unresolved})

    未解析 case 直接落到原 dispatcher_entry，cmp-tree 兜底处理。原 cmp-tree
    block 内容完全不变。所有 real block 末尾 *指向 dispatcher_entry* 的
    goto/if 被重写指向 guard_label。dispatcher_entry 仍然可达 —— 通过
    jump_to 的 unresolved labels。

    保留原 cmp-tree 兜底未解析的 case，安全恢复 fully_resolved 失败时的
    覆盖率。BN HLIL Restructurer 把 jump_to 渲染为 switch-case，所以
    即便部分 case 走 unresolved 也呈现为 switch + default。

    一处坑：每个 label_map entry 必须用 *独立* MediumLevelILLabel 实例；
    多个 key 共享同一个 Label 对象会让 BN 内部 add_label_map 注册多次同
    handle，后续操作 segfault (sub_407368 实测)。

    成功条件：
      - resolved transitions 非空
      - 至少有一条边被重定向 (否则 guard 永远不被执行，等于 no-op)
    返回是否做了变换。
    """
    if not transitions:
        return False
    anchor = mlil[dispatcher_entry.start]
    loc = ILSourceLocation.from_instruction(anchor)
    primary_size = primary.type.width if primary.type else 4

    try:
        guard_label = MediumLevelILLabel()

        # 1. mark_label guard at end-of-MLIL append point
        mlil.mark_label(guard_label)

        # 2. Build label_map:
        #    - resolved: V → 独立 label, .operand = T
        #    - unresolved: V → 独立 label, .operand = dispatcher_entry.start
        #      (即直接跳回原 cmp-tree 入口；BN 在该 entry 处仍有 cmp-tree 指令)
        #
        # 每个 entry 用独立 MediumLevelILLabel 实例。共享同一个 Label 对象
        # 会让 add_label_map 把同一 C handle 多次入表，后续 mark_label
        # 触发 segfault (实测 sub_407368)
        label_map: Dict[int, MediumLevelILLabel] = {}
        for value, target_idx in transitions.items():
            lbl = MediumLevelILLabel()
            lbl.operand = target_idx
            label_map[value] = lbl
        unresolved = (case_values | all_assigned) - set(transitions.keys())
        for value in unresolved:
            alias = MediumLevelILLabel()
            alias.operand = dispatcher_entry.start
            label_map[value] = alias

        if not label_map:
            return False

        dest_expr = mlil.var(primary_size, primary, loc)
        jump_to_expr = mlil.jump_to(dest_expr, label_map, loc)
        mlil.append(jump_to_expr, loc)

        # 3. 重定向 real block → dispatcher_entry 的所有边到 guard_label
        # 注意：dispatcher_entry 在 jump_to 的 unresolved label 中也是目标，
        # 所以 dispatcher_entry 仍然可达 (通过 guard 的 unresolved 路径)。
        # 这就是兜底机制。
        n_redirected = _redirect_edges_to_dispatcher(
            mlil, dispatcher_entry, dispatcher_blocks, guard_label
        )
        if n_redirected == 0:
            return False
    except Exception:
        return False
    return True


def _shortcircuit_state_writes(
    mlil: MediumLevelILFunction,
    primary: Variable,
    transitions: Dict[int, int],
) -> int:
    """对每个已解析 (V, T)，把函数中所有 `primary = V` SetVar 替换成
    `goto mini-block`，mini-block 内为 `[primary = V; goto T]` (path A
    风格)。

    动机：单纯安装 jump_to/guard 后，真实块仍然 `state=V; goto dispatcher`
    绕一圈到 jump_to/guard 才到 handler。BN HLIL Restructurer 看到的是
    "真实块 → dispatcher → switch → handler"，没法把它看作自然 CFG。
    短路后真实块直接 `goto handler`，dispatcher 只在初始 state 设置后
    被 jump_to 入口 *用一次* (P1) 或对未解析 case 兜底 (P2)。restructurer
    看到的是 "真实块 → handler" 的干净 CFG，能尝试识别 loop/if 结构，
    输出更接近源码原貌。

    保留原 SetVar 副本到 mini-block，维持 state 变量的写入语义不丢失。

    返回短路的 patch 数。
    """
    if not transitions:
        return 0
    cache: Dict[Tuple[int, int, int], MediumLevelILLabel] = {}
    patches = []
    for instr in list(mlil.instructions):
        if not isinstance(instr, MediumLevelILSetVar):
            continue
        if instr.dest != primary or not isinstance(instr.src, MediumLevelILConst):
            continue
        v = instr.src.constant & _mask(instr.size or 4)
        if v not in transitions:
            continue
        patches.append((instr, v, transitions[v]))

    n = 0
    for instr, v, target_idx in patches:
        try:
            key = (instr.dest.identifier, v, target_idx)
            cached_label = cache.get(key)
            loc = ILSourceLocation.from_instruction(instr)
            if cached_label is None:
                target_label = MediumLevelILLabel()
                target_label.operand = target_idx
                new_block_label = MediumLevelILLabel()
                mlil.mark_label(new_block_label)
                mlil.append(mlil.copy_expr(instr), loc)
                mlil.append(mlil.goto(target_label, loc), loc)
                cached_label = new_block_label
                cache[key] = cached_label
            mlil.replace_expr(
                instr.expr_index,
                mlil.goto(cached_label, loc),
            )
            n += 1
        except Exception:
            continue
    return n


def _try_synthesize_one_dispatcher(
    mlil: MediumLevelILFunction,
    deadline: float,
    already_rewritten: set,
) -> Optional[str]:
    """识别一个 dispatcher 并把它重构。

    返回值:
      - None: 没有可处理的 dispatcher (终止外层 loop)
      - "clean": P1 路径成功 (整 dispatcher_entry 被替换)，可继续 detect
        嵌套 dispatcher
      - "guarded": P2 路径成功 (guard chain 追加，原 cmp-tree 保留)；
        嵌套不再处理，因为再叠 guard 会让同一个原 dispatcher 多次重写，
        实测引入 BN 内部状态不一致 (segfault)
      - "fail": 找到 dispatcher 但所有候选都失败 (终止外层 loop 防 spin)

    通过 already_rewritten 集合跳过本次 pass 已经重构过的 dispatcher
    (按 dispatcher_entry.start 标识)。

    multi-候选策略：依次尝试 unique 常量赋值数最多的 state var 作为 dispatch
    primary，第一个能给出 ≥_MIN_TRANSITIONS 个 distinct target 的就用它。
    """
    fname = mlil.source_function.name
    dispatcher_entry = _detect_dispatcher_entry(mlil, exclude=already_rewritten)
    if dispatcher_entry is None:
        return None
    state_vars = _collect_state_vars(mlil, dispatcher_entry)
    if not state_vars:
        log_info(f"[synth] {fname}: no state vars found at dispatcher 0x{dispatcher_entry.start:x}")
        return None
    if not _function_looks_like_cff(mlil, state_vars):
        log_info(f"[synth] {fname}: failed CFF heuristic (rust/c++ false positive guard)")
        return None
    dispatcher_blocks = _identify_dispatcher_subgraph(
        mlil, dispatcher_entry, state_vars
    )
    if not dispatcher_blocks:
        log_info(f"[synth] {fname}: SCC ∩ pure-dispatcher empty")
        return None

    # 依次尝试每个候选 state var。一个候选合格当且仅当：
    #   1) ≥ _MIN_TRANSITIONS 个 case
    #   2) ≥ 2 个 distinct target
    #   3) candidate 是 *实际* dispatch 变量 (dispatcher 内有 (candidate 或
    #      其别名) == const 的比较，否则像 sub_408b94 上 lr_1 误选)
    #
    # 选定后，根据 fully_resolved + (case_values ⊆ transitions) 选择路径：
    #   - 路径 P1 (fully_resolved 且 case 完整覆盖)：替换 dispatcher_entry
    #     首指令为 jump_to，原 cmp-tree 被吃掉，HLIL 最干净
    #   - 路径 P2 (其它)：在 MLIL 末尾追加 guarded jump_to，未解析 case 直
    #     接 jump 到 dispatcher_entry，原 cmp-tree 兜底。已解析 case
    #     fast-path，覆盖率显著提升 (实测 5/39 → 34/39 函数显示 switch)
    primary = None
    transitions: Dict[int, int] = {}
    case_values: Set[int] = set()
    all_assigned_for_primary: Set[int] = set()
    fully_resolved_for_primary = False
    for candidate in _candidate_state_vars_ranked(mlil, state_vars):
        if time.time() > deadline:
            break
        cand_trans, cand_assigned, cand_full = _collect_transitions_for_var(
            mlil, candidate, state_vars, dispatcher_blocks,
            dispatcher_entry.start, deadline,
        )
        if len(cand_trans) < _MIN_TRANSITIONS:
            continue
        if len(set(cand_trans.values())) < 2:
            continue
        cand_case_values = _collect_dispatcher_case_values(
            mlil, dispatcher_blocks, candidate
        )
        if not cand_case_values:
            continue
        primary = candidate
        transitions = cand_trans
        case_values = cand_case_values
        all_assigned_for_primary = cand_assigned
        fully_resolved_for_primary = cand_full
        break

    if primary is None:
        log_info(
            f"[synth] {fname}: no qualifying state var at dispatcher "
            f"0x{dispatcher_entry.start:x} (state_vars={len(state_vars)})"
        )
        return "fail"

    use_clean_path = (
        fully_resolved_for_primary
        and case_values <= set(transitions.keys())
    )
    unresolved_count = len((case_values | all_assigned_for_primary) - set(transitions.keys()))

    try:
        if use_clean_path:
            # P1: 完整 jump_to 替换 dispatcher_entry
            label_map: Dict[int, MediumLevelILLabel] = {}
            for value, target_idx in transitions.items():
                label = MediumLevelILLabel()
                label.operand = target_idx
                label_map[value] = label

            first_instr = mlil[dispatcher_entry.start]
            size = primary.type.width if primary.type else 4
            dest_expr = mlil.var(
                size,
                primary,
                ILSourceLocation.from_instruction(first_instr),
            )
            jump_to_expr = mlil.jump_to(
                dest_expr,
                label_map,
                ILSourceLocation.from_instruction(first_instr),
            )
            mlil.replace_expr(first_instr.expr_index, jump_to_expr)
            mode = "clean"
        else:
            # P2: guarded jump_to fallback
            ok = _install_guarded_jump_to(
                mlil, primary, transitions, case_values,
                all_assigned_for_primary, dispatcher_entry, dispatcher_blocks,
            )
            if not ok:
                log_info(
                    f"[synth] {fname}: P2 install failed (no edges to redirect "
                    f"or label_map empty) at 0x{dispatcher_entry.start:x}"
                )
                return "fail"
            mode = "guarded"

        # 短路：把 real_block 末尾 `primary = V; goto dispatcher` 替换成
        # `goto mini_block` 直接到 handler。这一步关键 —— jump_to 让 HLIL
        # 显示 switch，但真实块还要绕 dispatcher 才到 handler；BN
        # restructurer 看到的不是自然 CFG。短路后真实块直接 goto handler，
        # restructurer 能尝试还原 if/while 结构，更接近源码
        n_short = _shortcircuit_state_writes(mlil, primary, transitions)

        already_rewritten.add(dispatcher_entry.start)
        mlil.finalize()
        mlil.generate_ssa_form()
        log_info(
            f"[synth] {fname}: {'P1' if mode == 'clean' else 'P2'} at "
            f"0x{dispatcher_entry.start:x} transitions={len(transitions)} "
            f"shortcircuited={n_short}"
            + (f" unresolved={unresolved_count}" if mode == "guarded" else "")
        )
        return mode
    except Exception as e:
        log_warn(f"[synth] {fname}: exception during rewrite: {e}")
        return "fail"


def pass_synthesize_switch(analysis_context: AnalysisContext) -> bool:
    """多迭代 synthesize_switch：每次重构一个 dispatcher。第一遍通常是最
    外层 dispatcher，重构后内层（嵌套）dispatcher 成为新的 detect 候选，
    第二遍处理内层，依此类推。最多 _MAX_SWITCH_ITERS 层。

    对应 sub_407368 这种"外层 switch x8, case 内含内层 switch i"的多层
    OLLVM CFF。

    返回是否对函数做了 *任何* 重构。auto-fallback workflow 用这个判断
    是否需要兜底跑 path A (deflate_hard)。
    """
    function = analysis_context.function
    mlil = function.mlil
    if mlil is None:
        return False

    side_effects_before = _collect_side_effect_signatures(mlil)
    function_name = function.name

    deadline = time.time() + _TIME_BUDGET_SECONDS
    already_rewritten: set = set()
    transformed = False

    for _ in range(_MAX_SWITCH_ITERS):
        if time.time() > deadline:
            break
        result = _try_synthesize_one_dispatcher(mlil, deadline, already_rewritten)
        if result is None or result == "fail":
            break
        transformed = True
        # 注：早期版本在 P2 后强制 break (嵌套 P2 mark_label(fallback_label)
        # 会 segfault)。当前 P2 简化为只 mark_label(guard_label) 一次，
        # 未解析 case 直接路由到 dispatcher_entry —— 没有第二个 mark_label，
        # 嵌套不再 segfault，可继续迭代尝试嵌套 dispatcher。

    side_effects_after = _collect_side_effect_signatures(mlil)
    _verify_no_side_effect_loss(side_effects_before, side_effects_after, function_name)
    return transformed
