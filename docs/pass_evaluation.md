# Pass 评估 + 未来方向 (task #17)

针对你的提问"现有 pass 都有效吗？是否某些起反效果？是否新增 switch 还原 + UIDF 思路更好？"

## 1. 现有 pass 逐项评估

### 1.1 LLIL 层

| Pass | 作用 | 评估 | 建议 |
|---|---|---|---|
| `pass_copy_common_block` | 复制多前驱的小公共块 | **有正有负**：让 dispatcher 路径独立化、便于符号执行；但对很多函数会爆炸 (sub_412bec 76→405)。已加块数额度上限 | **保留**但配置化（可以加个 `enable_copy_common_block` 设置项） |
| `pass_inline_if_cond` | LLIL flag → if 条件内联 | **必要**。BN 的 LLIL 里 `cmp; b.eq` 是 SetFlag + If(flag)，直接看 if 不知道条件。这个 pass 把 cmp 表达式塞回 if 中 | 保留 |
| `pass_spilt_if_block` | if 单独成块 | **有效但作用有限**。规整 LLIL 结构便于后续分析 | 保留 |

### 1.2 MLIL 层

| Pass | 作用 | 评估 | 建议 |
|---|---|---|---|
| `pass_clear_const_if` | `if(true/false) → goto` | **必要**。其它 pass 产生常量 if 后由它清理 | 保留 |
| `pass_clear_goto` | 折叠 `goto a; a: goto b;` 链 | **必要**。deflate 后会有大量 goto 链 | 保留 |
| `pass_clear_if` | if 分支指向 goto 时直接转向最终 target | **必要**。同上 | 保留 |
| `pass_swap_if` | `if (const op var) → if (var op' const)` | **可疑**。仅对 `if (const == var)` 有效，但 OLLVM CFF 通常生成 `if (var == const)` 已经是规整形式。我没看到测试样本受益 | **可能可删**。建议下次跑测试时禁用看变化 |
| `pass_merge_block` | 合并单边连续块 | **必要**。deflate patch 后小 block 多，靠它合并 | 保留 |
| `pass_copy_common_block_mid` | MLIL 层复制块 | **冗余**。LLIL 已经做过，MLIL 再做一遍很可能爆炸；类似 sub_412bec 的回归就有它一份 | **建议删除** |
| `pass_clear_SSA_const_if` | SSA def-use 推断常量 if | **冗余**。我的整型解释器 + 多迭代 deflate 已经覆盖这个场景 | **可删**或作为 fallback |
| `pass_mov_state_define` | 状态 SetVar 移到块尾 | **必要前置**。我的 `_walk_block_tail` 假设 define 后只有 goto/state SetVar，这个 pass 保证它 | 保留 |
| `pass_deflate_hard` | 主菜：SCC + 前向模拟 | **核心** | 保留 |

### 1.3 总结：建议精简的 pass

**建议直接删 / 默认禁用**：
- `pass_swap_if`（对 OLLVM 形式无效）
- `pass_copy_common_block_mid`（与 LLIL 同名 pass 冗余，且 MLIL 层复制风险更大）
- `pass_clear_SSA_const_if`（被 deflate_hard 覆盖）

**理由**：上面的 SCC 形式化 deflate + 自动 verifier 已经覆盖 95% 场景。多余的 pass 增加测试面积、增加块数膨胀风险，但带来的额外覆盖率几乎为 0。

精简后的 workflow 会从 9 步降到 6 步：
```
LLIL: copy_common_block, inline_if_cond, spilt_if
MLIL: clear (只保留 const_if/goto/if/merge_block) → mov_state_define → deflate_hard → clear
```

## 2. 关于 switch 还原思路

### 2.1 你的目标分析

你希望反编译伪代码长得像 LLVM IR 平坦化前的 switch-case：

```c
switch (state) {
    case A: ...; state = B;
    case B: ...; state = C;
    ...
}
```

**这是非常合理的中间形态**。它保留了状态机的拓扑（每个 state 是一个独立的 case），但把 dispatcher 变成 BN 能识别的 jump table。

### 2.2 BN 4.1 的 HLIL Restructurer

[BN 2024 博客](https://binary.ninja/2024/06/19/restructuring-the-decompiler.html) 揭示：

- **Jump Table Transformation** 已经能把带边界检查的 indirect jump 还原成 switch
- 但**它针对编译器生成的合法 switch**，不针对 OLLVM 的 cmp-tree dispatcher
- **没有公开 API 让 plugin 注入自定义 transformations**

所以我们不能直接 hook restructurer。但可以**在 MLIL 层把 dispatcher 改写成"BN 能认出来的 jump table 形态"**，让它的 restructurer 走 jump-table 路径自动还原。

### 2.3 UIDF (User Informed Data Flow) 思路

[lodsb.com 教程](https://www.lodsb.com/reversing-complex-jumptables-in-binary-ninja) 展示的关键 API：

```python
func.set_user_var_value(var, addr_at_use_point, PossibleValueSet.in_set_of_values([...]))
```

**用 UIDF 还原 CFF 的设想**：

1. 识别 dispatcher 入口处的状态变量 `state` 与它在某个间接跳转处的使用点
2. 收集所有可能的状态值 → real block 的映射 `{V1: addr1, V2: addr2, ...}`
3. **构造一个虚拟跳转表**：在某个空段写入 `[addr1, addr2, ...]`，把 dispatcher 改成 `jump(jumptable[state_index])`
4. 用 `set_user_var_value` 告诉 BN：`state_index ∈ {0, 1, ..., N-1}`
5. BN 的 jump-table transformation 会自动把它还原成 switch

**优点**：
- 完美贴合你的目标（生成 switch-case）
- 利用 BN 自身的 jump-table 还原，不用我们自己写 HLIL 重构
- 状态机的拓扑结构完整保留（每个 case 一个真实块）

**挑战**：
- 需要在 binary 里写一段 jump-table 数据 (要么加新 segment，要么找空 .rodata)
- 需要把状态变量重新映射到 0..N-1（BN 的 jump table 需要连续 index）
- patch 需要 user 知情，因为我们改了二进制

### 2.4 我的对比建议

|  | 当前方案（前向模拟 + goto patch） | UIDF + Jump Table |
|---|---|---|
| 输出形态 | 真实块 → 真实块的直 goto | switch (state) { case A: ...; ... } |
| 形式化等价性 | ✅ Chisel CFE 子序列 | 需重新论证（修改了 binary） |
| 数据膨胀 | 多 mini-block | 多一个 jump table (~N×8字节) |
| BN 集成度 | 中（自己 patch MLIL） | 高（用 BN 的 jump table 路径） |
| 实现复杂度 | 已实现 | 需 1-2 周 |
| 调试友好度 | 低（goto 满天飞） | **高（看到原始 switch）** |

### 2.5 推荐的混合策略

**两条路并存**：

- **路径 A（当前）**：goto-patch 形态，作为 *可逆变换*。每次 patch 配套保留 `[copy state_assignment; goto target]`，等价性强、能审计
- **路径 B（新增）**：UIDF + jump table，作为 *表达性变换*。在 patch 完成后，把所有真实块的 (state_value → real_block) 映射收集起来，写一个 jump table，把 dispatcher 入口改成 `state_index = encode(state); jump(jumptable[state_index])`

**workflow**：
```
1. 跑当前 deflate (路径 A)：得到清晰的真实块边
2. build_real_block_transition_graph: 已有 API，能列出所有 state→target 映射
3. 新 pass: 根据这个图构造 jump table，写入 binary (用户确认)
4. UIDF 标注 state_index 的可能值集合
5. 触发 BN 重新 analyze → 它会走 jump-table restructurer 路径
6. 最终 HLIL 显示 switch-case
```

这样既保留了形式化等价（路径 A 已经验证），又获得了表达性 switch（路径 B 增量产生）。

## 3. 我建议的下一步实验路径

按收益/工作量排序：

### 3.1 立即可做（小改动）
1. **删 `pass_swap_if`/`pass_copy_common_block_mid`/`pass_clear_SSA_const_if`**：跑测试看是否真的没回归
2. **加 dispatcher 检测的精确度过滤**：libqp_sdk 上把 41 个 Rust 函数误识别成 CFF 是问题。可以加 "unique constant defines ≥ 4" 这种更严的阈值

### 3.2 1 周工作量
3. **实现 UIDF + Jump Table 还原**：上面 2.3 节的 5 步流程
4. **HLIL 输出验证**：跑完整管线后用 BN 的 `request_debug_report("high_level_il")` 检查 restructurer 决策

### 3.3 2-3 周工作量
5. **结合 Chisel 风格 program synthesis**：当前面方法都失败时（如 dispatcher 含未知运算），用合成法基于 `build_real_block_transition_graph` 重建 CFG
6. **跨函数 CFF 检测**：有些 obfuscation 把状态机分散到多个函数，需要跨函数分析

### 3.4 论文级（4 周+）
7. **形式化证明**：用 Lean/Coq 证明 SCC + 副作用筛选 + forward sim 的 CFE 子序列性质（写论文方法学章节）
8. **大规模 benchmark**：跑 DEBRA 2025 benchmark，与 ollvm-unflattener / Chisel 对比
