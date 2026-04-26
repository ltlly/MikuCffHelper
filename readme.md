# MikuCffHelper

针对 OLLVM 风格控制流平坦化 (Control Flow Flattening, CFF) 的 Binary
Ninja 去混淆插件。

## 1. 简介

OLLVM `-fla` 把函数变成「dispatcher + 真实块」状态机。本插件用静态分析
识别 dispatcher 子图、前向模拟状态变量，把 CFF 还原成两种可读形态：

- **路径 B (synthesize_switch，推荐)**：保留 dispatcher，把它的 if-tree
  替换为 `MLIL_JUMP_TO`，BN 4.1+ 的 HLIL Restructurer 自动渲染为
  `switch-case`，最贴近源码原貌
- **路径 A (deflate_hard)**：把 dispatcher 整体绕掉，每个 `state = const`
  直接接到对应真实块，输出 goto 链；块数最少
- **路径 auto (推荐入口)**：先尝试 B，B 拒绝时自动 fallback 到 A，用户
  无需手动判断函数类型

实测 39 个 OLLVM CFF 函数 (arm64-v8a / libkste / libSeQing)：

- **半数以上函数 HLIL 行数下降 20-59%** (短路真实块到 handler 后 BN
  HLIL Restructurer 能识别 if/while)
- 0 副作用丢失，0 孤立跳转

## 2. 安装

把整个 `MikuCffHelper` 文件夹放到 Binary Ninja 的 `plugins` 目录下。

```
~/.binaryninja/plugins/MikuCffHelper/
```

依赖：Binary Ninja 4.1 或更高 (HLIL Restructurer 把 jump_to 渲染为 switch
依赖此版本)。

## 3. 使用

### 3.1 在 BN UI 中

打开二进制后，右键想去混淆的函数 → `Function Analysis`，选其中一个 activity
启用 (互斥)：

| activity | 行为 | 推荐场景 |
|----------|------|----------|
| `workflow_patch_mlil_auto` | **首选**：先 B，B 不动则 A 兜底 | 不确定函数特征时直接选这个 |
| `workflow_patch_mlil_switch` | 只跑 B (synthesize_switch) | 只想要 switch 形态、能接受部分函数无变换 |
| `workflow_patch_mlil` | 只跑 A (deflate_hard) | 函数已知不适合 switch、要最大压缩块数 |

启用后 BN 会自动重分析。HLIL 视图刷新后能看到 switch 或 goto 链形态。

### 3.2 命令行 (推荐用于批量 / 脚本化)

`tools/deflate_cli.py` 不需要打开 BN UI，直接对二进制跑工作流并输出 HLIL：

```bash
# 单函数 (auto 模式，B 优先 / A 兜底)
python tools/deflate_cli.py example/arm64-v8a.so --addr 0x4259f4

# 二进制内所有 CFF 候选 (按 Blazytko 启发式自动找)
python tools/deflate_cli.py example/arm64-v8a.so --all-cff

# 指定路径模式
python tools/deflate_cli.py example/arm64-v8a.so --addr 0x4259f4 --mode switch

# 输出到文件
python tools/deflate_cli.py example/arm64-v8a.so --addr 0x4259f4 --out /tmp/out.c

# 输出去混淆前 HLIL (对照参考)
python tools/deflate_cli.py example/arm64-v8a.so --addr 0x4259f4 --before
```

环境变量 `BN_PYTHON` 指向 BN 的 python 包目录 (默认
`/home/ltlly/tools/binaryninja/python`)。

### 3.3 嵌入式脚本

```python
import binaryninja as bn

bv = bn.load("/path/to/binary.so", update_analysis=True)
func = bv.get_function_at(0x4259f4)

settings = bn.Settings()
settings.set_string(
    "analysis.workflows.functionWorkflow", "MikuCffHelper_workflow", func
)
wf = bn.Workflow("MikuCffHelper_workflow", object_handle=func.handle)
wf._machine.override_set("analysis.plugins.workflow_patch_mlil_auto", True)
bv.reanalyze()
bv.update_analysis_and_wait()

# 输出去混淆后的 HLIL
for instr in func.hlil.instructions:
    print(instr)
```

## 4. 整体 Pipeline

### 4.1 LLIL 层 (低级 IL)

| Pass | 作用 |
|------|------|
| `pass_copy_common_block` | 把多前驱的公共后继块复制成各自独占的块 (避免后续 SSA 拆分让状态变量丢失) |
| `pass_inline_if_cond` | LLIL flag 条件内联到 if 中，消除 flag 中转 |
| `pass_spilt_if_block` | 让 if 指令独占基本块，方便后续识别 dispatcher |

### 4.2 MLIL 层 (核心)

| Pass | 作用 |
|------|------|
| `pass_clear` | 折叠常量 if、串联 goto、合并块 |
| `pass_mov_state_define` | 把状态常量赋值挪到块尾，方便从 define 处直接走 dispatcher |
| `pass_deflate_hard` | **路径 A 核心**：基于支配树识别 + 前向符号执行的去平坦化 |
| `pass_synthesize_switch` | **路径 B 核心**：识别 dispatcher 后写入 jump_to 让 HLIL 渲染为 switch |

### 4.3 HLIL 层

`suggest_stateVar` 命令辅助分析时手动标记状态变量。

## 5. 路径 B：synthesize_switch (双路径合成)

### 5.1 共享前置：dispatcher 识别

1. **CFF 检测 (Blazytko 支配树法)**：找 `flattening_score(D) ≥ 0.3` 且
   有 back-edge 的块 D 作为 dispatcher 候选；不满足判为非 CFF 函数直接跳过
2. **状态变量识别**：从 D 后继 BFS 收集"常量比较"的左操作数变量；要求
   每个变量被赋予 ≥ 2 个 unique 常量 (过滤 SSA 拆解假阳性)
3. **函数级 CFF 启发式**：所有状态变量的 unique 常量数 ≥ 4 且值域跨度
   ≥ `0x10000000` (避免 Rust match / C++ stdlib 的小常量分发被误判)
4. **dispatcher 子图识别 (Tarjan SCC + 副作用筛选)**：含 D 的最大 SCC 中
   过滤出"纯 dispatcher"块（指令副作用仅限状态变量；禁止 call / store /
   ret / intrinsic）
5. **前向模拟 (整数解释器)**：从每个 `state = const` 出发，在 dispatcher
   子图内逐块模拟到真实块入口，构建 `{state_value → real_block_start}`
   映射

### 5.2 P1 (干净 jump_to 替换)

P1 必须 *全部* 满足：

1. `transitions ≥ 2` 个，distinct targets ≥ 2
2. **fully_resolved**：函数里所有 `primary = const` 赋值都至少解析出一个
   target
3. **case_values ⊆ transitions**：dispatcher 内每一个 `(primary == const)`
   比较的 const 都被覆盖。任一未覆盖意味着该 state 值进 jump_to 时
   undefined，BN restructurer 会清掉对应 handler，函数语义被破坏
4. **case_values 非空**：candidate 必须实际是 dispatch 变量
   (避免 sub_408b94 上 lr_1 被误选)

满足 P1 时，dispatcher_entry 首指令直接被 `jump_to(state, label_map)`
替换，原 cmp-tree 被吃掉，HLIL 最干净。

### 5.3 P2 (guarded jump_to 兜底)

P1 失败时启用：

- 在 MLIL 末尾追加 guard block：
  `jump_to(primary, {V_resolved: T_resolved, V_unresolved: dispatcher_entry})`
- 所有 *real block* 末尾指向 dispatcher_entry 的 goto/if 重定向到 guard
- 原 cmp-tree 完整保留，未解析 case 通过 `jump_to → dispatcher_entry → cmp-tree`
  路径兜底
- HLIL 渲染为 switch + default

### 5.4 短路 state SetVar (让真实块脱离 dispatcher)

P1/P2 安装完后立即跑 `_shortcircuit_state_writes`：对每个已解析 (V, T)，
把函数中所有 `primary = V` SetVar 替换为 `goto mini_block`，mini-block 内
是 `[primary = V; goto T]` (path A 风格 mini-block)。

**为什么需要这一步**：

- 单纯安装 jump_to / guard 后，真实块仍然 `state = V; goto dispatcher`
  绕一圈到 jump_to / guard 才到 handler
- BN HLIL Restructurer 看到的是「真实块 → dispatcher → switch → handler」，
  没法把它看作自然 CFG，最终输出仍是状态机形态的 switch
- 短路后真实块直接 `goto handler`，dispatcher 几乎只在初始 state 设置
  后被入口跳一次，restructurer 看到的是「真实块 → handler」干净 CFG，
  能识别出 if / while / for 等结构，**输出更接近 OLLVM 平坦化前的源码**

**实测效果**: 13 个函数 HLIL 行数下降 20-59%。典型例子 sub_407368 的内层
状态机被还原为：

```c
// 短路前 (只有 switch + 状态值切换)
case 0xad2b5e0d:
    int32_t i = 0x3288bce9
    while (true)
        if (i == 0xdbb0e92f) ...
        i = -0x214b583
        ...

// 短路后 (BN 识别出 do-while + 嵌套 while)
case 0xad2b5e0d:
    int64_t x8_3 = *var_70
    int32_t i = 0x3288bce9
    while (i != 0xdbb0e92f)        // 自然 while 循环
        if (i == 0x3288bce9)
            i = -0x214b583
        if (i == 0xfdeb4a7d)
            int32_t x8_4 = 0x73b2f1f1
            while (true)            // 嵌套循环
                if (x8_4 == 0xde27171) break
                if (x8_4 == 0xdd08aef8)
                    int32_t j = -0x1e9ba5f2
                    while (j != 0xc0835fbf)   // 三层嵌套，原是状态机
                        if (j == 0x59207abb)
                            free(x8_3)        // 关键 call 完整保留
                            ...
```

保留原 SetVar 副本到 mini-block，state 变量的写入语义不丢失。

### 5.5 形式化等价性

参照 Chisel (OOPSLA 2024) 的 Control-Flow Extension (CFE) 形式化：去混淆
trace 是混淆 trace 的子序列，保留所有副作用，删去状态机内部状态写入与
分发判断。

具体到本插件：

- **真实块体未改** → call / store / return 完整保留
- **真实块之间的转移**由整型模拟给出，与原状态机分发的具体执行结果一致
- **状态写入**仍在 P1 (jump_to 之后) / P2 (guard 之前) 里执行 → 状态变量
  在外部读取时数值正确
- **删去的只是 dispatcher 内部的状态比较跳转** → T' 是 T 的子序列

∴ 对外可见副作用集合等价 (CFE 反向)。

### 5.6 自动 verifier

每次 pass 调用前后会快照所有副作用指令的 `(op_id, address)` 签名集合，
patch 完后比较 `after ⊇ before`。若发现丢失立即 `log_error`。`_SIDE_EFFECT_OPS`
覆盖 23 种 MLIL 操作 (call / store / ret / intrinsic / trap / syscall 等)。

实测 39 函数全部通过验证。

## 6. 路径 A：deflate_hard (块数最少)

### 6.1 算法步骤

```
1. CFF 门控 (与 5.1 步骤 1-3 共享)

2. dispatcher 子图识别 (与 5.1 步骤 4 共享)

3. 块级前向模拟:
   _walk_block_tail: 走完 define 所在块剩余指令 (要求只含 state SetVar/goto/if)
   进入 dispatcher 后逐基本块走 _walk_dispatcher_block，
   直到落到一个真实块入口

4. 安全约束:
   走出 dispatcher 时落点必须 == basic_block.start，
   否则放弃 patch (避免跳到块中段产生 jump(addr) 间接跳转)

5. Patch 形式:
   把 state SetVar 替换为 [原赋值副本; goto target_real_block_start]
   保留赋值副本以维持外部可见副作用
   相同 (state_var, value, target) 的 patch 共享同一个 mini-block
```

### 6.2 实现要点

- **整型解释器**：覆盖 const / var / add / sub / mul / and / or / xor /
  shift / zx / sx 与全部 10 种比较，完全不依赖 z3
- **单 pass 时间预算 30 秒**：超出停止保留已 patch 部分
- **复杂度**：O(defines × dispatcher_depth)，外层迭代上限 6

### 6.3 真实块转移图诊断 API

`build_real_block_transition_graph` 返回 `{R: set(R')}`，对每个真实块 R
枚举它内部的状态赋值，forward_resolve 找出对应的下一个真实块 R'。

```python
from MikuCffHelper.passes.mid.deflatHardPass import build_real_block_transition_graph
g = build_real_block_transition_graph(func.mlil)
```

类似 Chisel 的 Control-Flow Skeleton (CFS) 概念，可作为：

- **失败诊断**：哪些真实块之间的转移没被 patch
- **未来 synthesis 基础**：在此骨架上做 program synthesis 直接生成新函数

## 7. 路径 auto (B 优先 / A 兜底)

```
clear → mov_state_define
     → synthesize_switch (返回 bool 是否变换)
     → 若 B 没变换：deflate_hard ×2
     → clear
```

实测 39 函数 (B 含短路步骤)：

- **27** 函数 HLIL 仍含 `switch` 关键字 (BN restructurer 选择保留 switch)
- **7** 函数 BN 把 switch 进一步还原为纯 if/while/goto 链 (因短路后真实块
  脱离 dispatcher，自然 CFG 结构被识别出来)
- **5** 函数无 switch / 无显著块数下降 (仍包含 `sub_42a21c` 这类 multi-state
  跨函数引用 dispatcher，超出当前启发式覆盖范围)
- **13 个函数 HLIL 行数下降 20-59%** (典型 `sub_407994` 64→26 行，
  `sub_45d11c` 47→21 行)
- 0 SE_LOST，0 ORPHAN

## 8. 回归测试

`tools/regression_test.py` 把当前快照与 `tools/baseline.json` 对比，发现
回归非 0 退出：

```bash
# 与 baseline 对比 (默认)
python tools/regression_test.py

# 改 heuristic 后确认改进无误，更新 baseline
python tools/regression_test.py --update-baseline

# 只跑某个 binary
python tools/regression_test.py --only arm64-v8a.so

# 单函数调试
python tools/regression_test.py --func 0x4259f4 --bin arm64-v8a.so
```

详见 `tools/README.md`。

## 9. 诊断日志

所有关键决策点会输出到 BN Logger (channel `MikuCffHelper`)：

- `[synth]` synthesize_switch 的 P1/P2 选择、拒绝原因、transitions 计数
- `[deflate]` deflate_hard 的 dispatcher 检测、forward_resolve 解析失败
- `[auto]` auto workflow 的 B 成功 / fallback 到 A 的决策

UI 中 Log 面板按这些 prefix 过滤可快速定位 pass 行为。

## 10. 已知限制

- **状态变量识别启发式**：依赖"被赋予 ≥ 2 unique 常量"，对于使用单一加密
  函数生成状态值的变种可能失效
- **未实现条件状态赋值的精确处理**：`if (cond) state = A else state = B`
  目前为各 SetVar 独立 patch，没有把分支条件直接落到原 if 上
- **整型解释器局限**：状态转移含浮点 / 内存读 / 不支持的运算时会保守跳过
- **多 state 联合分发**：dispatcher 用多个 state 变量联合分发时，只会选
  unique 常量数最多的一个 primary，其余靠 BN 后续分析消化
- **跨函数 CFF**：state 经全局 / 参数跨函数传递的样本不处理
- **极大函数 (>800 块)**：dispatcher 检测开销 + 多次外层迭代可能超过 BN
  默认 60 秒单函数分析时间限制；可调高 `analysis.limits.maxFunctionAnalysisTime`

## 11. 设计参考的前沿工作

| 工作 | 关键贡献 | 我们的采纳 |
|------|----------|------------|
| **Chisel** (Mariano et al., OOPSLA 2024) [\[1\]](https://dl.acm.org/doi/10.1145/3689789) | Trace-informed compositional program synthesis；把 Control-Flow Extension (CFE) 形式化为"原 trace 是混淆 trace 的子序列" | 采纳 CFE 形式化作为等价性论证依据；因为没有 trace，改用支配树 + 状态变量 unique-value 启发式 |
| **Blazytko 自动检测 flattening** (synthesis.to, 2021) [\[2\]](https://synthesis.to/2021/03/03/flattening_detection.html) | flattening_score = #{被 D 支配的块} / #{总块数}；要求被 D 支配的块跳回 D | 直接作为 dispatcher 入口检测 + 函数级 CFF 门控 |
| **D810** (eshard 博客) [\[3\]](https://eshard.com/posts/D810-a-journey-into-control-flow-unflattening) | 基于 Hex-Rays microcode；MopTracker 反向追状态变量；多值时块复制 | 参考"状态变量反向追踪"思路 |
| **CaDeCFF** (Internetware 2022) [\[4\]](https://dl.acm.org/doi/10.1145/3545258.3545269) | forward DFA 找 useful blocks；selective symbolic execution 恢复 CFG | 启发"识别真实块"方向 |
| **FlowSight** (IEEE SEAI 2025) [\[5\]](https://ieeexplore.ieee.org/document/11108802) | data-flow-aware 的 OO Block 概念 | 借用"区分 dispatcher 块与真实块"的二分思路 |
| **DEBRA** (Workshop on SURE 2025) [\[6\]](https://dl.acm.org/doi/10.1145/3733822.3764674) | 真实世界去混淆方法的 benchmark | 评测方法论参考 |
| **ollvm-unflattener** [\[7\]](https://github.com/cdong1012/ollvm-unflattener) | 开源工具，~83% 通过率 | 对比基线 |
| **Zerotistic CFF Remover** [\[8\]](https://zerotistic.blog/posts/cff-remover/) | dispatcher 的 weighted scoring；3 阶段状态变量识别 | 参考多阶段验证 |

### 参考文献

[1] Mariano, B., Wang, Z., Pailoor, S., Collberg, C., & Dillig, I. (2024).
Control-Flow Deobfuscation Using Trace-Informed Compositional Program
Synthesis. *Proc. ACM Program. Lang.* 8, OOPSLA2, Article 349.

[2] Blazytko, T. (2021). Automated Detection of Control-flow Flattening.
*synthesis.to* blog.

[3] eshard. D810: A journey into control flow unflattening.

[4] CaDeCFF: Compiler-Agnostic Deobfuscator of Control Flow Flattening.
*Proceedings of the 13th Asia-Pacific Symposium on Internetware*, 2022.

[5] FlowSight: A Data Flow-Aware Control Flow Flattening Deobfuscation
Approach. *IEEE 5th International Conference on Software Engineering and
Artificial Intelligence (SEAI)*, 2025.

[6] DEBRA: A Real-World Benchmark For Evaluating Deobfuscation Methods.
*2025 Workshop on Software Understanding and Reverse Engineering*.

## 12. 后续 TODO

- 把 `if (cond) state = A else state = B` 模式直接 rewrite 成
  `if (cond) goto T_A else goto T_B`
- 跨函数 CFF：识别 state 变量的全局 / struct 偏移，跨调用图传递
  forward_resolve 的环境
- 动态等价性 fuzzer：随机输入跑前后两个版本，比 trace (call sequence +
  内存写 + 返回值)，比静态副作用签名更可靠
- 多 state primary 联合分发：把 N 个 state var 合成 (N×bitwidth) 虚拟
  var，jump_to 用合成 key
