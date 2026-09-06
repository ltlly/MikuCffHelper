# MikuCffHelper

Binary Ninja 的控制流平坦化（Control-Flow Flattening, CFF）去混淆插件。

当前默认实现不是“猜中 dispatcher 就改写”，而是一个 **sound-but-incomplete、
fail-closed** 的局部 translation-validation 流程：先在 detached MLIL 上构造
候选，再验证本次改写；任何状态、算术、别名、副作用或 CFG 关系无法证明时，
保留原始 dispatcher。

研究、实现和冻结实测最后更新：**2026-08-30**。

## 1. 能保证什么，不能保证什么

对任意二进制同时要求“完整通用去混淆、总能判定语义等价、始终低复杂度”是不
可能的。一般程序等价是不可判定问题；工程上可实现的边界是：

- 发现阶段尽量宽，不用样本经验阈值排除候选；
- 接受阶段严格，只改写具有局部证书的边；
- 不认识的表达式返回 `Unknown`，而不是猜测；
- 超时或资源不足只会少改，不会放宽正确性条件；
- 允许有些函数保持不变，以换取可审计的安全边界。

当前证书证明的是受支持 MLIL 子集中的局部边等价：在精确入口 bit-vector 状态
下，原路径只穿过已认证的纯 dispatcher，并到达与新边相同的真实块；被跳过的
状态写按原顺序 replay。它还验证 CFG 闭合、源映射和 MLIL 可观察副作用集合。
这比回归测试强，但仍不是 Coq/SMT 对完整 Binary Ninja MLIL 语义的机器证明；
测试通过也不应被描述为任意程序的完整等价证明。

理论依据包括 [Rice 定理](https://doi.org/10.1090/S0002-9947-1953-0053041-6)、
[抽象解释](https://doi.org/10.1145/512950.512973) 和
[translation validation](https://doi.org/10.1007/BFb0054170)。

## 2. 默认算法

### 2.1 参数无关的候选发现

1. 对函数 CFG 计算 SCC、支配关系和循环分量。
2. 从 SCC 分支谓词做完整 backward slice，得到实际影响分发的状态变量。
3. 只把满足下列条件的块纳入 dispatcher 证明域：
   - 整数表达式的位宽来自 MLIL/类型事实；
   - 仅含已实现的精确 bit-vector 运算；
   - 只允许可 replay 的 `SetVar` 与终结 `If/Goto`；
   - 遇到 call、load、store、return、intrinsic、syscall、trap 等立即拒绝该路径。

这里没有 flattening score、最少常量数、常量跨度、固定轮数、固定 `k`、访问
次数阈值或算法内 timeout。`>= 2` 个分支结果只是“分支”的结构定义，不是从
样本拟合的参数。

### 2.2 精确状态解释与边证书

状态解释器使用 MLIL 指定宽度的有限 bit-vector 语义。每个上下文由
`(dispatcher block, exact state tuple)` 唯一标识；同一上下文只求值一次，并在
所有入边之间共享 memo。语法中出现的状态原子和 dispatcher 块数共同给出有限
状态域，达到域边界、遇环、除零、非法移位或未支持表达式时返回 `Unknown`。

每条 `CertifiedEdge` 记录：

- 被改写源块和终结器分支；
- 原 dispatcher 入口；
- 精确入口状态元组；
- 唯一真实块目标；
- 沿原路径发生的有序状态写。

同一源边得到冲突目标或冲突 replay 序列时，整条边拒绝改写。状态写不会被
删除：短接前会在新边上按原顺序 replay，保留 dispatcher 外部可能观察到的值。

### 2.3 两个候选与 auto 选择

- `deflate`：把已认证边直接短接到真实块，通常得到较简洁的
  `if/while/goto`。
- `switch`：仅对具有精确单例状态的入边增加 guarded `MLIL_JUMP_TO`；未知值
  继续走原比较树，不假设观察到的 case 已经穷尽。
- `auto`（默认）：独立构造并验证两个候选，按可达 CFG 的
  `(decision blocks, blocks, instructions)` 字典序选择更简单者。没有权重；完全
  相同时仅为显示效果优先 `switch`。

### 2.4 Detached MLIL 提交

默认路径遵守 Binary Ninja 当前 Workflow/IL 生命周期：

1. 从 `AnalysisContext.mlil` 读取本轮最新 IL；
2. `translate` 到 detached `MediumLevelILFunction`；
3. 使用已创建并正确 `mark_label` 的标签构造控制流；
4. synthetic 指令使用 indirect `ILSourceLocation`，原指令保持唯一 direct 映射；
5. `finalize()`，再 `generate_ssa_form()`；
6. 验证 CFG 目标、源映射、候选证书和可观察副作用；
7. 全部成功后，唯一一次写入 `AnalysisContext.set_mlil_function`。

构造或验证失败时 detached candidate 被丢弃，原 IL 不受影响。实现依据见 Binary
Ninja 官方的 [Modifying ILs](https://docs.binary.ninja/dev/bnil-modifying.html)
与 [Workflows](https://docs.binary.ninja/dev/workflows.html)。当前实测环境为 Binary
Ninja 6.1；兼容层采用 feature detection，不覆盖新版原生 API。

## 3. 复杂度

记函数 CFG 为 `V` 个块、`E` 条边、`I` 条指令；dispatcher 有 `D` 个块，语法
状态原子数为 `A`。当前实现的保守上界为：

| 阶段 | 复杂度轮廓 |
| --- | --- |
| SCC、CFG 邻接、工作表 backward slice | `O(V + E + I)` |
| 支配查询 | 预计算后区间查询；取决于 BN 的 dominator 实现 |
| 精确上下文解释 | `C <= D(A + 1)` 个程序派生上下文，每个至多求值一次 |
| 候选复制与验证 | 对候选 IL/CFG 线性扫描 |
| `auto` | 至多构造两个候选，常数倍开销 |

因此核心恢复不会出现固定 `k` 上下文的 `A^k` 爆炸；代价是条件状态、未知内存
或过于复杂的多状态关系会被保守拒绝。外部 `--timeout`、`--max-blocks` 只是用户
可配置的资源预算，绝不参与“是否语义安全”的判断。

上述是分阶段轮廓，不是整个实现的线性时间/空间保证。`D(A+1)` 是程序规模
派生的保守准入容量，不是任意算术或多变量精确状态空间的完备上界；到达容量
只能返回 Unknown。每个 context 还承担表达式求值和状态 fingerprint 成本，多个
dispatcher entry 会重复扫描区域。当前 replay memo 保存每个 context 的完整后缀：
长度为 `n`、每块一条 replay 写的链会存储 `n(n+1)/2` 个 tuple 元素引用。
候选构造的线性扫描也应以展开后的候选大小计费。后续应共享 replay 后缀节点，
按实际生成的 IL 大小核算输出成本，不能把“每个 context 求值一次”写成整体线性。

## 4. 安装与使用

将仓库放入 Binary Ninja 插件目录，或创建指向仓库的符号链接，然后重启 BN。
默认注册 `MikuCffHelper_workflow`，并只自动启用
`analysis.plugins.workflow_patch_mlil_auto`。旧 LLIL normalizer、显式
`deflate/switch` 和 HLIL 状态变量命名 helper 默认关闭。

UI 中可在 Workflow Activity 配置里选择：

- `workflow_patch_mlil_auto`：推荐；只提交已验证且结构成本最小的候选；
- `workflow_patch_mlil`：只尝试 `deflate`；
- `workflow_patch_mlil_switch`：只尝试 guarded `switch`。

不要同时启用 auto 与显式模式。

无头 CLI：

```bash
# 单函数，默认 auto
python tools/deflate_cli.py example/arm64-v8a.so --addr 0x4259f4

# 显式候选类型
python tools/deflate_cli.py example/arm64-v8a.so --addr 0x4259f4 --mode deflate
python tools/deflate_cli.py example/arm64-v8a.so --addr 0x4259f4 --mode switch

# 枚举存在局部可证边的函数；不使用样本阈值
python tools/deflate_cli.py example/arm64-v8a.so --all-cff

# 可选的人为资源预算；达到预算只会跳过
python tools/deflate_cli.py example/arm64-v8a.so --all-cff --max-blocks 500
```

CLI 默认禁用用户目录中的其他 BN 插件，显式加载当前工作区，并验证实际模块
路径，避免回归时误用旧安装。

环境变量：

- `BN_PYTHON`：Binary Ninja Python 包目录，默认
  `/home/ltlly/tools/binaryninja/python`；
- `SAMPLE_DIR`：严格回归样本目录，默认 `example/`。

## 5. 验证与实测

### 5.1 固定真实样本门禁

`tools/baseline.json` 固定 3 个样本的 SHA-256 和 39 个函数地址。缺样本、哈希
变化、函数缺失、unknown、异常、超时、orphan jump、MLIL/HLIL 副作用丢失，
以及 MLIL 副作用新增都会硬失败。报告同时保存完整 before/after JSON 和 CSV。

2026-08-30 在 Binary Ninja 6.1 的冻结实现上：

| 指标 | 结果 |
| --- | ---: |
| 正常完成 | 39 / 39 |
| 已认证变换 | 34 / 39（87.2%） |
| MLIL observable effects | 289 → 289，lost 0，added 0 |
| orphan jump | 0 |
| MLIL blocks / edges / instructions | 1430 → 1330 / 2044 → 1859 / 4280 → 4214 |
| HLIL blocks / edges / instructions | 1385 → 1315 / 1979 → 1836 / 2669 → 2567 |
| 总 wall time / 单函数中位数 | 140.741 s / 2.659 s |
| peak RSS | 约 2.74 GiB |

HLIL restructurer 仍会在结构视图中重复显示 5 个 `ret` 和 2 个 `store`；对应
MLIL 没有新增，故记录为诊断而不是执行语义变化。39 函数中 16 个的报告线性
列举顺序变化，但 observable-effect multiset 完全一致；这不是完整 trace proof，
也是后续接入 CF-GKAT 类控制流证书的动机。

```bash
python tools/regression_test.py
python tools/regression_test.py --only arm64-v8a.so
python tools/regression_test.py --func 0x4259f4 --bin arm64-v8a.so

# 只有完整 manifest 且绝对安全门禁全通过时才会更新
python tools/regression_test.py --update-baseline
```

### 5.2 独立可再生成语料

`tools/corpus/` 包含 8 个 0BSD C fixture：单 switch、if-chain、嵌套 CFF、
多状态/连续写、XOR alias、条件状态、副作用以及普通控制流负样本。构建器生成
24 个 artifact：x86-64 GCC O0/O2 可执行文件和 i386 O0 relocatable object；
16 个可执行 artifact 均运行 self-test。

固定地址 benchmark 对 24 个 artifact 的 27 个函数逐一新建 BinaryView，不靠
detector 选择“成功样本”。结果为 27/27 成功，7 个有证书的 CFF 被改写，20 个
保守不变；三个普通控制流负样本全部不变，MLIL call/store/ret 计数变化均为 0。
总 MLIL blocks `-26`、HLIL instructions `-62`；变换中位数 0.012 s，最大
0.035 s（小型合成函数数据，不能外推到大函数）。

```bash
python tools/corpus/build_corpus.py
python -m unittest \
  tools.tests.test_regression_gate \
  tools.corpus.tests.test_benchmark \
  tools.corpus.tests.test_index_samples

python tools/corpus/benchmark.py \
  --manifest tools/corpus/manifest.json --root . --plugin-root . \
  --json /tmp/miku-corpus.json --csv /tmp/miku-corpus.csv
```

语料的来源、许可、编译命令、SHA-256、符号地址和 loader image base 均记录在
`tools/corpus/manifest.json`。现有外部二进制来源未知，manifest 明确标为
`UNKNOWN/nonredistributable`；仓库自建 fixture 为 0BSD。

## 6. 已知限制

- 未建模的 load、内存别名、call 结果、浮点/向量表达式会使路径变为
  `Unknown`；
- 条件状态写只有在入口环境能唯一决定时才可短接；
- 多状态联合分发可能使程序派生状态域很大，达到域边界即不变换；
- 当前是函数内分析，不恢复跨函数 dispatcher；
- switch 候选只做 guarded partial rewrite，不宣称 case 集完备；
- Binary Ninja HLIL 是重构后的表示层，不应单独作为执行语义证书；
- 当前局部证书尚未实现完整 MLIL trace equivalence 或内存模型证明。

## 7. 研究结论与工程决策

### 7.1 总结论

研究结论不是寻找一个“万能识别阈值”，而是改变正确性契约：

> 对明确建模的 CFF/CFE 子类做 sound-but-incomplete、fail-closed 的恢复；发现
> 可以宽，提交必须有证书。Unknown、超时、别名不明或调用语义不明时保持原 IL。

原因是一般图灵完备程序上，以下三项不能同时实现：

1. 对任意混淆都通用；
2. 总能完整判定变换前后语义等价；
3. 始终保持低复杂度。

[Rice 定理](https://doi.org/10.1090/S0002-9947-1953-0053041-6) 给出第一、二项
无法同时满足的理论边界。因此，“保证等价性”必须限定为受支持语义子集内的
sound 证书，而“通用性”体现为宽发现和不依赖某个混淆器模板，并允许安全漏报。

### 7.2 一手研究的可用结论

| 工作 | 已核验事实 | 对本项目的结论 |
| --- | --- | --- |
| [Cousot & Cousot 1977：抽象解释](https://doi.org/10.1145/512950.512973) | 用抽象域和不动点安全近似具体语义，但允许不精确 | 状态传播必须有 `Unknown/Top`；只有唯一精确 bit-vector 才能短接 |
| [Pnueli 等 1998：Translation Validation](https://doi.org/10.1007/BFb0054170) | 每次验证本次变换的 refinement，而非先假设整个变换器永远正确 | detached candidate 验证通过后才提交；rewriter 本身不应成为唯一可信边界 |
| [CaDeCFF 2022](https://doi.org/10.1145/3545258.3545269) | 组合状态数据流、选择性符号执行和代码重建以适应编译器差异 | 数据流用于宽发现，昂贵推理只用于待改写 dispatcher 片段 |
| [Chisel 2024](https://doi.org/10.1145/3689789) | 用 trace-subsequence 描述 CFE，并以动态 trace 和组合式合成恢复多类 CFE | trace 投影是合适规格；动态覆盖与测试不能替代全路径等价证书 |
| [Alive2 2021](https://doi.org/10.1145/3453483.3454030) | 对 LLVM IR 做 bounded translation validation，资源限制会带来漏检边界 | SMT 适合局部 terminator/DAG refinement；不能直接拿 LLVM 语义证明 BN MLIL |
| [Baek & Lee 2026：DeFFai](https://doi.org/10.1109/TSE.2026.3659437) | 用抽象解释和 `k-switch context sensitivity` 静态恢复 CFF | 模式无关抽象解释方向成立，但公开原型的固定 `k` 与 loop threshold 不满足本项目要求 |
| [CF-GKAT 2025](https://doi.org/10.1145/3704857) | 对有限 indicator 的受限 goto/break/return 语言可 sound、complete 判定 trace equivalence；固定测试集合时接近线性 | 是最适合的下一层低成本控制流证书，但仍需审计 MLIL 编码并另证数据/内存语义 |

DeFFai 的参数限制不是推测：作者
[CLI](https://github.com/cnu-ants/DeFFai/blob/395e66a50a7e414c4ab7873e58a2b4307c90f342/README.md#L15-L17)
明确要求 `k` 和 loop-count threshold；其
[context 实现](https://github.com/cnu-ants/DeFFai/blob/395e66a50a7e414c4ab7873e58a2b4307c90f342/transformer/flaCtxt2.ml#L103-L173)
保存最近至多 `k` 次 switch 选择。若 outcome 字母表规模为 `A`，上下文数量由
实现结构可推得最坏为 `O(A^k)`。这是源码导出的复杂度结论，不是论文声称的正式
定理；本项目因此没有照搬固定 `k`。

CFG 廉价前置采用 [Tarjan SCC](https://doi.org/10.1137/0201010) 和支配关系；
支配算法复杂度参考
[Lengauer–Tarjan](https://doi.org/10.1145/357062.357071)。这些结构算法适合生成
候选，但 flattening score 之类结构分数不能成为语义安全证明。

### 7.3 落到当前实现的六条决策

1. **发现与授权分离**：SCC、支配、回边和 backward slice 只发现候选；只有
   `CertifiedEdge` 可以授权改写。
2. **精确值而非固定深度**：上下文是 `(block, exact state tuple)`，容量由当前
   程序的 dispatcher 块和语法状态原子推导；不保存固定长度历史。
3. **副作用全部可观察**：call/store/return/intrinsic/syscall/trap 不能被投影
   删除；状态写无法证明私有时必须 replay。
4. **局部验证而非全函数符号执行**：只解释纯 dispatcher 与被改写终结器，避免
   默认全路径 SMT 的复杂度和内存爆炸。
5. **资源预算不参与正确性**：timeout、内存或用户 `--max-blocks` 触发时唯一结果
   是拒绝/跳过，不会用近似结果继续提交。
6. **先验证后提交**：candidate 在 detached MLIL 中完成 label、source map、
   finalize、SSA、CFG/effect/certificate 验证，最后才替换 `AnalysisContext.mlil`。

### 7.4 当前保证分层

| 层级 | 当前状态 | 含义 |
| --- | --- | --- |
| 局部 bit-vector/边证书 | 已实现 | 对受支持表达式和精确入口状态证明 dispatcher macro-step 的唯一目标，并 replay 状态写 |
| detached 结构与 effect validation | 已实现 | CFG 闭合、source mapping 可用，MLIL observable-effect multiset 不增不减 |
| 固定真实样本与独立语料 | 已实现 | 防止已知回归、样本漂移、负样本误改和只挑成功样本 |
| 完整控制流 trace equivalence | 未实现 | 后续可用 CF-GKAT 风格 action/indicator 编码补强 |
| 完整 MLIL 内存/异常/跨函数形式语义证明 | 未实现 | 需要正式 MLIL 语义、内存模型和可信编码，不能用测试结果替代 |

当前证书依赖内部 planner、bit-vector 解释器和 builder 的共同正确性。
`_validate_certified_edge` 只复查原终结器的分支锚点；detached validator 检查
CFG、source mapping 和 effect multiset，并未独立重验入口状态、路径与 replay。
因此不能把这些内部接口直接用作不可信 AI/外部插件提交证书的认证入口，也不能
声称“已经形式化证明任意二进制完整语义等价”。

### 7.5 后续优先级

1. 先实现独立于候选生成器的局部证书检查：绑定原 MLIL 快照、源边与候选，
   重验入口条件、原路径、非陷阱性、唯一出口和有序 replay；保留未覆盖入边。
   使用局部有限步模拟及全局组合论证，避免把真实块内部执行展开成全函数路径。
2. 共享 replay 后缀、缓存每区域分析、按输入/上下文/证书/候选输出分别计费。
   先消除已知二次分配，再扩大恢复覆盖率。
3. 对局部 bit-vector terminator 加可选 SMT refinement；unsupported 或 timeout
   仍然 fail-closed。
4. 实验性接入 CF-GKAT 风格验证；明确 indicator 私有性、谓词规模和无限执行
   行为的语义契约，审计 MLIL 编码。建模异常边，只有证明不可观察的状态写才允许投影。
5. 扩充不同混淆器、架构、优化级别和联合状态语料，但不得由语料反向产生正确性
   阈值。

### 7.6 2026-09-06 复核与 AI 工具方向

在 Binary Ninja `6.1.10530-dev` 上显式加载当前工作区，复核结果为：21 项单元
门禁、语法与 Ruff 检查通过；固定回归 39/39 正常、34 个变换，MLIL effects
`289→289`，lost/added/orphan 均为 0。此次 wall 为 133.673 s，单函数中位
2.528 s，peak RSS 2,888,236 KiB。冻结 baseline 未更新。

在临时目录重新构建 24 个 artifact，16 个可执行 fixture 的 self-test 通过；
全部 27 个固定函数 benchmark 正常，7 个变换、20 个不变，三个普通控制流
负样本均不变；MLIL blocks 合计 `-26`、HLIL instructions `-62`，MLIL
call/store/ret 计数变化为 0。这里的 self-test 比较原始 C fixture 与参考实现，
并没有执行改写后的 MLIL；benchmark 与回归也不是完整执行等价证明。

另用真实样本 `sub_4259f4` 的内部证书构造 detached 候选：将入口状态清空，
或将原有 4 条 replay 全部删除，分支锚点检查和 detached builder 仍可接受。
候选未提交。这验证了上一节的信任边界缺口，不等于证明默认 planner 在该样本
实际生成了错误证书。隔离生产 resolver 的链形适配器实验还验证了 replay
后缀二次存储：1024/2048/4096 个 context 分别保存
524800/2098176/8390656 个 tuple 元素引用。

研究方向应补充两项限制：

- [CF-GKAT 2025 原文 §2.3、§3.5](https://arxiv.org/html/2411.13220v2)
  中的 indicator 不参与普通 action/test，最终值也不属于观察结果；不能把可在
  区域外读取的 MLIL 状态变量直接编码成可删除 indicator。接近线性的前提包括
  固定 primitive tests，indicator 域也产生额外成本。
- [Outrunning Big KATs，2026-08-31 v3](https://arxiv.org/pdf/2601.09986v3)
  用按需符号自动机与 SAT 改善实际性能，未给出计入全部谓词后的无条件多项式
  时间保证。Remark 2.2 区分有限终止 trace 与 infinite-trace/bisimilarity：后者
  才区分无限循环中不同的 action；论文性能评估未覆盖该变体。控制流验证不能
  忽略不终止执行中的 call/store。

增强 `bn-cli` 与保留本项目并不冲突。推荐由 `bn-cli` 提供结构化
`snapshot → propose → verify → commit` 协议，本项目提供 CFF 候选生成器与
可复用验证核心。AI 可提出区域、状态关系和受限改写，验证器必须从原程序导出
或证明入口条件，不能接受模型自行声明的前提；结果使用
`proved/disproved/unknown`，与“API 写入成功”分开。提交前校验原快照、候选 hash
和验证器版本。汇编补丁还需要单独处理 lowering、flags、ABI、异常、布局与
重定位，MLIL 分析层证书不能自动覆盖机器码。

[LLMLift](https://arxiv.org/html/2406.03003v1) 的受限 IR、模型生成摘要/不变量、
外部 oracle 验证架构可供参考，但其副作用自由 DSL 语义不是 BN MLIL。
[LLM-Vectorizer](https://arxiv.org/html/2406.04693v1) 在 149 个用例中，checksum
先拒绝 24 个，形式验证又拒绝 37 个；57 个通过结果仍受 loop-unrolling 边界
限制，31 个不确定。这支持“AI 负责搜索，确定性检查负责授权”，不支持依赖
模型置信度或测试通过率提交补丁。这里是架构建议，尚未实现新的 CLI 协议或
独立证明后端。

### 7.7 BN 上的 D810 类框架：项目方向与边界

本项目的长期方向是可验证、可扩展的 BN 去混淆引擎，CFF 是首个使用该引擎的
pass；`bn-cli` 提供面向人和 AI 的调用入口。先在当前仓库抽取通用模块，待第二类
pass 成熟后再决定是否改名或拆包，避免在 CLI bridge 内重复实现优化器。

D810 的可借鉴之处是表达式表示、规则编写/匹配、求值、规则配置与控制流修改
组件，而不是一组固定混淆器模板。作者将指令级优化与基本块优化分开，并在 CFF
恢复中复用 backward tracking、microcode emulation 和 CFG patching：

- [eShard，D810 架构，2020-11-20](https://www.eshard.com/blog/d810-deobfuscation-ida-pro)
- [eShard，D810 去平坦化，2021-10-21](https://www.eshard.com/blog/d810-a-journey-into-control-flow-unflattening)

BN 实现应遵循自己的 Workflow Activity 和 detached IL 构造机制，不能机械移植
IDA 的 microcode maturity、`optinsn_t` 或 `optblock_t` 回调。默认从 MLIL 开始；
LLIL 的寄存器/flags 相关规则和 HLIL 表示层处理仍需各自明确的语义契约，未经
证书的旧 LLIL normalizer 不因框架扩展而自动启用。

| 能力 | 归属 |
| --- | --- |
| 精确位宽表达式表示、语义解释与规则验证 | 本项目的通用核心 |
| 规则注册、匹配、规范化、调度、证据缓存 | 本项目的通用核心 |
| CFF、MBA、条件/分支简化 | 本项目中各自模块化的 pass |
| detached candidate、证书检查、唯一提交点 | 本项目的通用核心与 BN 适配层 |
| BN Workflow 与 GUI 集成 | 本项目 |
| 目标选择、后台任务、结构化输出与结果文件 | `bn-cli` |
| 快照、规则提案、验证、应用、差异命令 | `bn-cli` 适配层，调用同一核心 |

核心不得依赖 `bn-cli`；直接打开 BN 的用户也应能使用相同的规则和检查器。
GUI 与 CLI 共享验证和提交实现，避免两个入口的正确性契约发生分歧。

纯 bit-vector 规则与 CFG 改写分开认证。比如同位宽模 `2^w` 下
`(x+y)-2*(x&y) == x^y` 中的 `2` 是恒等式的一部分，不是样本阈值。规则可按
位宽、语义版本与前提验证并缓存，每处应用仍须检查类型、纯度和定义性。
分支短接、CFF 和状态写删除需要逐候选证明路径及可观察行为；不能把规则级
Z3 验证扩张成整个引擎的等价保证。

规则调度也必须有独立的复杂度/终止论证。采用确定性规范化、共享表达式 DAG
和受影响节点工作表，避免枚举交换律/结合律的全部排列。简化规则使用明确的
良基下降度量；需要扩张的变换另做受限候选。单条规则正确不保证规则组合终止，
不得靠固定轮数、经验阈值或无界 saturation 掩盖这一问题。结构候选选择应纳入
原函数这一备选，避免为了产生变换而提交没有结构收益的候选；这是待实现要求。

首版依次交付：独立局部 checker 与可靠改写事务；纯整数规则系统和 replay
共享后缀；通过 `bn-cli` 暴露受限提案、验证、应用及差异。AI 可提出新规则、
摘要和不变量，工具验证后再复用。通用内存推理、全函数符号执行与机器码重生成
不作为首版验收条件；这些方向需要单独的证明与工程预算。

### 7.8 bn-cli 集成前的实测缺口

2026-09-06 在 `bn-cli` commit
`14cc71738ceb292d4dc7c1c508b0e5c4528f0105` 上，完整 247 项单测通过，仍复现：

- `patch assemble` parser 保存 `assembly`，handler 读取 `args.asm`，真实
  parser/handler 调用在联系 bridge 前抛出 `AttributeError`；
- patch dispatch 直接进入 `_patch_*`，不经过有 undo/preview/readback 的
  `_mutation`。mock 注入 assembler 成功、`BinaryView.write` 返回 0 时，
  `_patch_assemble` 仍返回汇编字节和长度的成功形状；此项不是实际 BV 写入实验；
- `patch nop` 暴露 `--length`，handler 没有传递长度，bridge 只调用一次
  `convert_to_nop`。

上述记录是对特定版本的审计，不代表当前项目已修复它们。先补参数一致性、短写
检查、回读、失败回滚、preview 和指令边界测试，再增加语义认证入口。
`applied`、写入回读通过和 `semantic_proved` 必须区分；任意 Python 或原始字节
补丁不因 API 调用成功获得语义认证。检查器还需在提交时确认快照未过期，并将
原快照、候选和验证器版本绑定到验证记录。

小型局部 SMT 实验另验证了可行的精化方向：对条件状态赋值后 XOR 编码的
dispatcher，在 8/16/32/64 位下比较出口目标与最终状态，正确改写四次 UNSAT，
交换 handler 和删除状态写的错误改写八次 SAT。单次 `solver.check()` 为约
0.34–0.80 ms，不含编码和启动。此实验是总定义 bit-vector 合成模型，尚未验证
BN 到公式的编码、内存、循环、异常或机器码 lowering，不能外推成整函数证明
或性能承诺。

[BinDeObfBench 2026 预印本](https://arxiv.org/html/2604.08083v1) 的 semantic
preservation 使用 embedding cosine 与实体 Jaccard 的加权分数，不能作为执行
等价率或安全门禁。[Chisel §5](https://www.cs.utexas.edu/~isil/chisel.pdf) 的实际
实现仅对给定 trace 检查 reduction；理论算法对正确 oracle 的假设不能直接变成
该原型的全输入保证。这些工作可帮助候选发现，不能取代独立检查器。
