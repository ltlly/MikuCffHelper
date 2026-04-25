# MikuCffHelper

A Binary Ninja plugin for deobfuscating OLLVM-style Control Flow Flattening (CFF).

## 0. Bug

4.3.7045 以上版本会闪退 不知道什么原因

## 1. Introduction

This is a helper for CFF (Control Flow Flattening). It can help you deflat OLLVM-style CFF obfuscated code.

Uses Binary Ninja workflow to deflat the CFF obfuscated code.

## 2. Installation

Move the folder `MikuCffHelper` to the `plugins` folder of BinaryNinja.

## 3. Usage

Open the CFF obfuscated file with `MikuCffHelper_workflow`.

1. Right click the function you want to deflat, and select `Function Analysis/analysis.plugins.workflow_patch_mlil`.

或者用脚本方式（headless / 自动化）：

```python
import binaryninja as bn
func = bv.get_function_at(addr)
settings = bn.Settings()
settings.set_string("analysis.workflows.functionWorkflow", "MikuCffHelper_workflow", func)
wf = bn.Workflow("MikuCffHelper_workflow", object_handle=func.handle)
wf._machine.override_set("analysis.plugins.workflow_patch_mlil", True)
bv.reanalyze()
bv.update_analysis_and_wait()
```

## 4. 整体 Pipeline

```
原始IL → LLIL 优化 (代码克隆 / 条件拆分)
       → MLIL 优化 (CFF 检测 + 状态识别 + 前向符号执行短路分发)
       → HLIL 优化 (语义恢复)
```

### 低级层 (LLIL)

| Pass | 作用 |
|---|---|
| `pass_copy_common_block` | 把多前驱的公共后继块复制成各自独占的块 |
| `pass_inline_if_cond` | 把 LLIL 的 flag 条件内联到 if 中，消除 flag 中转 |
| `pass_spilt_if_block` | 让 if 指令独占基本块 |

### 中级层 (MLIL，核心)

| Pass | 作用 |
|---|---|
| `pass_clear` | 折叠常量 if、串联 goto、合并块 |
| `pass_mov_state_define` | 把状态常量赋值挪到块尾，方便从 define 处直接走 dispatcher |
| `pass_deflate_hard` | **核心：基于支配树识别 + 前向符号执行的去平坦化** |

## 5. 核心算法 (`pass_deflate_hard`)

### 5.1 算法步骤

```
1. CFF 门控 (Blazytko 支配树法):
   flattening_score(D) = #{被 D 支配的块} / #{总块数}
   找最高分且有 back-edge 的块 D；score < 0.3 视为非 CFF 函数，跳过整个 pass

2. 状态变量识别 (unique-value 强化):
   从 D 的后继 BFS 收集"常量比较"的左操作数变量
   要求每个变量被赋予 ≥2 个 unique 常量值（过滤"SSA 拆解出的常量传播副本"假阳性）

3. *形式化 dispatcher 子图识别 (Tarjan SCC + 副作用筛选)*:
   - 用迭代 Tarjan 算法找含 D 的最大 SCC
   - 在该 SCC 中筛选 "pure-dispatcher" 块：所有指令的副作用仅限状态变量
     (禁止 call / store / ret / intrinsic / trap / 写非状态变量的 SetVar)
   - 形式判据: B ∈ Dispatcher ⟺ B ∈ SCC(D) ∧ side_effects(B) ⊆ state_vars
   参照 Chisel OOPSLA'24 中"dispatcher 不引入新可见副作用"的本质

4. 块级前向模拟 (在 dispatcher 子图内):
   - _walk_block_tail: 走完 define 所在块剩余指令 (要求只含 state SetVar/goto/if)
   - 进入 dispatcher 后逐基本块走 _walk_dispatcher_block，
     直到落到一个真实块入口（不在 dispatcher_blocks 集合中的块）

5. 安全约束 (避免孤立跳转):
   走出 dispatcher 时落点必须 == basic_block.start，
   否则放弃 patch（避免跳到块中段产生 jump(addr) 间接跳转）

6. Patch 形式:
   把状态赋值替换为 [原赋值副本; goto target_real_block_start]
   保留赋值副本以维持外部可见副作用
```

### 5.2 数学等价性论证 (参照 Chisel OOPSLA 2024 的 CFE 形式化)

令原 trace 为 T，去混淆后 trace 为 T'。

- **真实块体未改** → 副作用 (call / store / return) 完整保留
- **真实块之间的转移**由整型模拟给出，与原状态机分发的具体执行结果一致
- **状态写入**仍在赋值副本中执行 → 状态变量在 dispatcher 之外被读取时数值正确
- **删除的只是 dispatcher 内部的状态比较跳转** → T' 是 T 的子序列

∴ 对外可见副作用集合等价 (Chisel 论文中的 CFE 反向)

### 5.3 实现要点

- 自带的**整型解释器**（覆盖 const/var/add/sub/mul/and/or/xor/shift/zx/sx 与全部 10 种比较），
  完全不依赖 z3，避免 z3 4.16 在某些表达式下的崩溃，单条指令 Python 级开销
- 单 pass 30s 时间预算，超出停止保留已 patch 部分
- 复杂度：O(defines × dispatcher_depth)，外层迭代上限 6

### 5.4 等价性手工审计

`docs/audit_407368.md` 给出了 sub_407368 (31→2 块) 的完整手工 trace 对比：
原版的 5 层嵌套状态机展开后副作用序列为 `*(sp-0x10) = arg1; free(arg1); return`，
与去混淆后的 5 条 HLIL 逐项等价。

### 5.5 实测效果 (arm64-v8a.so，SCC 形式化版本)

| 函数 | 原 MLIL 块 | 去混淆后 | HLIL 指令 | 时间 | 孤立跳转 |
|---|---|---|---|---|---|
| target_function (cff-arm64-v8a.elf) | 31 | 41 | 55 | 0.1s | ✅ 无 |
| sub_4075a0 | 31 | 10 | **5** | 5.2s | ✅ |
| sub_407368 | 31 | **2** | 5 | 5.1s | ✅ |
| sub_406c0c | 97 | 63 | 68 | 6.8s | ✅ |
| sub_40d4fc | 36 | 34 | 54 | 7.0s | ✅ |
| sub_40608c | 170 | 191 | 341 | 12.1s | ✅ |
| sub_40db18 | 160 | 40 | 67 | 16.1s | ✅ |
| sub_408b94 | 82 | 96 | 216 | 17.8s | ✅ |
| sub_486a90 | 805 | 790 | (BN timeout) | 152s | ✅ |

## 6. 设计参考的前沿工作

实现时综合参考了以下 CFF 去混淆方面的论文与开源工具：

| 工作 | 关键贡献 | 我们的采纳 |
|---|---|---|
| **Chisel** (Mariano et al., OOPSLA 2024) [\[1\]](https://dl.acm.org/doi/10.1145/3689789) | Trace-informed compositional program synthesis；把 Control-Flow Extension (CFE) 形式化为"原 trace 是混淆 trace 的子序列" | 采纳了 CFE 形式化作为等价性论证的依据；因为静态分析没有 trace，改用支配树 + 状态变量 unique-value 启发式 |
| **Blazytko 自动检测 flattening** (synthesis.to, 2021) [\[2\]](https://synthesis.to/2021/03/03/flattening_detection.html) | flattening_score = #{被 D 支配的块} / #{总块数}；要求被 D 支配的块跳回 D | 直接作为 dispatcher 入口检测 + 函数级 CFF 门控 |
| **D810** (eshard 博客) [\[3\]](https://eshard.com/posts/D810-a-journey-into-control-flow-unflattening) | 基于 Hex-Rays microcode；MopTracker 反向追状态变量；多值时块复制 | 参考了"状态变量反向追踪"思路 |
| **CaDeCFF** (Internetware 2022) [\[4\]](https://dl.acm.org/doi/10.1145/3545258.3545269) | forward DFA 找 useful blocks；selective symbolic execution 恢复 CFG | 启发了"识别真实块"的方向 |
| **FlowSight** (IEEE SEAI 2025) [\[5\]](https://ieeexplore.ieee.org/document/11108802) | data-flow-aware 的 OO Block 概念 | 借用了"区分 dispatcher 块与真实块"的二分思路 |
| **DEBRA** (2025 Workshop on Software Understanding and RE) [\[6\]](https://dl.acm.org/doi/10.1145/3733822.3764674) | 真实世界去混淆方法的 benchmark | 评测方法论参考 |
| **ollvm-unflattener** [\[7\]](https://github.com/cdong1012/ollvm-unflattener) | 开源工具，~83% 通过率 | 对比基线 |
| **Zerotistic CFF Remover** [\[8\]](https://zerotistic.blog/posts/cff-remover/) | dispatcher 的 weighted scoring；3 阶段状态变量识别 | 参考了多阶段验证 |

### 参考文献

[1] Mariano, B., Wang, Z., Pailoor, S., Collberg, C., & Dillig, I. (2024). Control-Flow Deobfuscation Using Trace-Informed Compositional Program Synthesis. *Proc. ACM Program. Lang.* 8, OOPSLA2, Article 349.

[2] Blazytko, T. (2021). Automated Detection of Control-flow Flattening. *synthesis.to* blog.

[3] eshard. D810: A journey into control flow unflattening.

[4] CaDeCFF: Compiler-Agnostic Deobfuscator of Control Flow Flattening. *Proceedings of the 13th Asia-Pacific Symposium on Internetware*, 2022.

[5] FlowSight: A Data Flow-Aware Control Flow Flattening Deobfuscation Approach. *IEEE 5th International Conference on Software Engineering and Artificial Intelligence (SEAI)*, 2025.

[6] DEBRA: A Real-World Benchmark For Evaluating Deobfuscation Methods. *2025 Workshop on Software Understanding and Reverse Engineering*.

## 7. 已知限制

- **需手动启用 MLIL pass**：`workflow_patch_mlil` 默认 `eligibility.auto = false`
- **状态变量识别启发式**：依赖"被赋予 ≥2 unique 常量"，对于使用单一加密函数生成状态值的变种可能失效
- **未实现条件状态赋值的精确处理**：当 `if (cond) state = A else state = B` 时，目前为各 SetVar 独立 patch，没有把分支条件直接落到原 if 上
- **整型解释器局限**：状态转移含浮点 / 内存读 / 不支持的运算时会保守跳过
- **极大函数 (>800 块)**：dispatcher 检测开销 + 多次外层迭代可能超过 BN 默认 60s 单函数分析时间限制；可调高 `analysis.limits.maxFunctionAnalysisTime`

## 8. 后续 TODO

- 把 `if (cond) state = A else state = B` 模式直接 rewrite 成 `if (cond) goto T_A else goto T_B`
- 用 Tarjan SCC 严格识别 dispatcher 子图边界
- 用 Binary Ninja 内置的 dataflow 分析做 patch 前后行为序列等价性的形式化验证
- 集成 Chisel 风格的 program synthesis 作为 fallback：当启发式失败时用合成法重建 CFG

(来自 2025 届本科生正在开发的毕设项目)
