# AGENTS.md

本文是本仓库的开发约束。用户行为以 `readme.md` 为准；修改核心 pass 后必须同步
更新二者，并运行本文件列出的门禁。

## 1. 项目与默认路径

`MikuCffHelper` 是 Binary Ninja CFF 去混淆插件。默认 Activity 是
`workflow_patch_mlil_auto`：在原 MLIL 不变的前提下独立构造、验证 `switch` 与
`deflate` detached candidates，再按可达 CFG 的
`(decision blocks, blocks, instructions)` 字典序选择一个提交。

默认策略是 **sound-but-incomplete / fail-closed**：只有局部证书成立才改写；
Unknown、冲突、未支持语义、验证失败或资源耗尽都必须保留原 IL。不要把回归测试
或副作用计数描述成完整程序等价证明。

旧 LLIL normalizer、显式 `switch/deflate` 和 HLIL 状态命名 helper 默认关闭。
未经独立等价证书，不得接入默认 pipeline。

## 2. 目录

```text
__init__.py                     # Workflow/Activity 与 UI 命令注册
mikuWorkflow.py                 # verified auto 与显式模式
passes/mid/deflatHardPass.py    # 发现、bit-vector 解释、边证书、detached 验证
passes/mid/synthesizeSwitchPass.py # guarded partial JUMP_TO candidate
passes/low/                     # legacy LLIL pass，默认关闭
fix_binaryninja_api/            # 仅放 BN API 兼容处理
utils/                          # 日志与 legacy 工具；可选依赖必须 lazy import
tools/deflate_cli.py            # 无头 CLI
tools/regression_test.py        # 固定 manifest 的严格回归门禁
tools/baseline.json             # 3 个 SHA-256 样本、39 个固定函数与结果
tools/corpus/                   # 0BSD fixture、构建器、manifest、benchmark
tools/tests/                    # 回归门禁单元测试
readme.md                       # 用户手册、保证边界、实测与研究依据
```

## 3. 证书模型与安全红线

### 3.1 发现不能授权改写

SCC、支配、回边和 backward slice 只能产生候选。不得使用以下经验量决定语义
安全：

- flattening score 或嵌套 dispatcher 的不同阈值；
- 最少常量数、常量跨度、随机常量外观；
- 固定 pass/step/loop 次数、固定 context `k`；
- 内置 timeout 或函数大小阈值；
- 从现有 39 个样本拟合的权重。

结构 arity、MLIL 位宽和由程序语法推导的有限域不是经验参数。CLI/测试的用户
资源预算可以存在，但达到预算只能“不变换/失败”，不能降低证书要求。

### 3.2 状态与 dispatcher

- 状态变量来自 SCC 分支谓词的完整 backward slice，不来自名称或常量数量。
- 整数求值必须使用 MLIL/类型给出的精确位宽；不得默认 32/64 位。
- 每个分析上下文是 `(block, exact state fingerprint)`；跨入边共享 memo。
- 上下文容量由 dispatcher 块与显式语法状态原子推导；容量、环、除零、非法
  移位、未知表达式均返回 Unknown。
- 已认证 dispatcher 只允许支持的纯整数表达式、可 replay `SetVar` 和终结
  `If/Goto`。call/load/store/ret/intrinsic/syscall/trap 等禁止穿越。

### 3.3 `CertifiedEdge`

证书至少绑定源终结器分支、原 dispatcher 目标、精确入口状态、唯一真实目标和
有序 replay 写。必须满足：

1. 同一源边没有目标或 replay 冲突；
2. 原路径上的 dispatcher 块均通过纯度检查；
3. 所有被跳过的状态写按原顺序执行；
4. 未认证边继续走原 dispatcher；
5. 不产生指向 CFG 外部的 orphan target；
6. call/store/return/intrinsic/syscall/trap 等可观察作用既不丢失也不新增。

不要删除状态写，即使它看似只服务 dispatcher；区域外可能观察该变量。

### 3.4 Switch 只能 partial + guarded

`synthesizeSwitchPass` 不得假设观察到的 case 集完备。只有精确单例状态入边可进
`MLIL_JUMP_TO` guard；unknown/default 必须保留原比较树。状态值到真实目标必须
是数学函数，否则拒绝候选。

## 4. Binary Ninja IL/API 约束

当前实测 Binary Ninja 6.1，遵守官方 `Modifying ILs` 约定：

1. Workflow 中读取 `AnalysisContext.mlil`，不要读取可能滞后的 `Function.mlil`；
2. 先 `original.translate(transform)` 构造 detached candidate；
3. 新 CFG 使用同一个已正确创建、resolve/mark 的 label 对象；
4. synthetic replay/guard 使用 `ILSourceLocation(..., il_direct=False)`；
5. 每条旧 top-level instruction 保持唯一 direct mapping，instruction/expression
   均不得出现多个 direct source；
6. 保留原 instruction attributes 和 per-block architecture；
7. 顺序必须是 `finalize()` → `generate_ssa_form()` → 验证 → 唯一一次
   `AnalysisContext.set_mlil_function(candidate)`；
8. 不直接修改 SSA；不在失败路径上触碰原 MLIL。

兼容问题只放 `fix_binaryninja_api/`，先 feature-detect；不得覆盖 BN 新版本已有的
原生方法。修改 `__init__.py` 时检查每次 Activity 注册、anchor `contains`、
`insert` 和 Workflow `register` 的返回值。

## 5. 复杂度约束

保持快速路径为多项式：

- Tarjan SCC、邻接构造和工作表 slice：`O(V+E+I)`；
- dominator 信息每函数/候选复用，不在每条边重复构造；
- 每个 exact block-state context 至多求值一次；当前程序派生容量
  `C <= D(A+1)`；
- detached copy、CFG/effect/source-map validator 对 IL 线性扫描；
- auto 至多两个候选，是常数倍。

若加入符号/SMT 后端，只用于局部 dispatcher DAG/terminator refinement；timeout
必须拒绝候选。不要默认做全函数全路径符号执行。

## 6. 修改流程与命令

```bash
# 快速真实样本
python tools/deflate_cli.py example/arm64-v8a.so --addr 0x4259f4
python tools/deflate_cli.py example/arm64-v8a.so --addr 0x4259f4 --mode switch
python tools/deflate_cli.py example/arm64-v8a.so --addr 0x4259f4 --mode deflate

# 语法、静态与单元门禁
python -m py_compile __init__.py mikuWorkflow.py passes/mid/*.py tools/*.py
ruff check __init__.py mikuWorkflow.py fix_binaryninja_api passes tools utils
python -m unittest \
  tools.tests.test_regression_gate \
  tools.corpus.tests.test_benchmark \
  tools.corpus.tests.test_index_samples
git diff --check

# 可再生成跨架构/优化级别语料
python tools/corpus/build_corpus.py
python tools/corpus/benchmark.py \
  --manifest tools/corpus/manifest.json --root . --plugin-root . \
  --json /tmp/miku-corpus.json --csv /tmp/miku-corpus.csv

# 固定 39 函数严格门禁
BN_DISABLE_USER_PLUGINS=1 python tools/regression_test.py

# 仅在完整 manifest、样本哈希和全部绝对安全门禁通过后更新
BN_DISABLE_USER_PLUGINS=1 python tools/regression_test.py --update-baseline
```

核心行为变化后依次：单函数 smoke → 21 个单元测试 → corpus → 39 函数门禁。
更新 baseline 后重新运行 `build_corpus.py`，保持统一 manifest 索引。回归必须明确
加载当前工作区插件；不要依赖用户目录中的旧副本。

## 7. 当前冻结基线（2026-08-30）

- 39/39 正常，34 个有证书的变换，5 个保守不变；
- MLIL observable effects `289→289`，lost 0、added 0；
- call/store/ret loss 0，orphan 0；
- MLIL blocks `1430→1330`，edges `2044→1859`，instructions `4280→4214`；
- HLIL blocks `1385→1315`，edges `1979→1836`，instructions `2669→2567`；
- wall 140.741 s，单函数中位 2.659 s，peak RSS 约 2.74 GiB。

独立语料：8 个 fixture、24 个 artifact、27 个固定函数，27/27 正常；7 个变换、
20 个不变，普通控制流负样本全部不变，MLIL call/store/ret 计数变化为 0。

HLIL restructurer 会产生诊断性的重复语法；当前冻结结果为额外 5 个 `ret`、2 个
`store`，但 MLIL 没有对应新增。不要用 HLIL 文本计数替代 MLIL 执行层证书。

## 8. 文档与研究边界

- `readme.md` 是用户可见的权威说明，算法、保证范围、数字变化时同步更新。
- 不创建一次性 `docs/*.md` 结论；仍有效内容合并到本文件或 `readme.md`。
- 推荐研究方向是把真实块和副作用编码为不可删除 action，接入 CF-GKAT 类
  trace-equivalence 证书；MLIL→证书语言的编码本身必须审计。
- Alive2/LLVM、DeFFai、Chisel 等只能提供设计依据，不能直接证明 BN MLIL。
- 内部 `CertifiedEdge` 目前不是不可信输入的独立证明接口：锚点检查不重验
  入口状态、原路径或 replay。向 AI/外部工具开放提交前，必须增加绑定原快照
  与候选的独立检查；模型提供的入口假设本身也必须从原程序证明。
- `C <= D(A+1)` 是保守准入容量，不是任意多状态/算术状态空间的完备上界。
  复杂度核算应包含多 entry 扫描、fingerprint、完整 replay 后缀及候选展开；
  当前 replay tuple 后缀在链形输入上占二次空间，不能声称整个 pass 线性。
- CF-GKAT 的 indicator 必须满足私有性与不可观察性；固定谓词集合的复杂度
  前提必须注明。只比较有限终止 trace 不足以保护无限执行中的可观察作用，
  需使用适当的 infinite-trace/bisimilarity 或有限步模拟组合证书。
- MLIL 分析层的证书不自动覆盖机器码 patch。`bn-cli` 等接口的写入回读验证
  与语义验证必须明确分开；先验证后提交，快照过期须重新验证。

## 9. D810 类框架与 bn-cli 的职责边界

- 在本仓库逐步抽取表达式/规则/证书/候选构造核心，CFF 作为首个模块化 pass。
  核心不得依赖 `bn-cli`；后者仅负责目标、任务、结构化输入输出及调用适配。
  GUI、Workflow 与 CLI 必须共享验证和提交实现。
- 首版先补独立局部 checker，再加入纯整数规则和共享 replay 后缀，最后暴露
  受限提案/验证/应用协议；不得以扩展框架为由启用未经认证的 legacy pass。
- 纯 bit-vector 规则可按位宽、语义版本和前提验证缓存，但每次替换仍需检查
  类型、纯度与定义性；CFG 改写必须逐候选证明，不能复用表达式证书替代。
- 规则常量属于已证明的恒等式时不是经验参数。规则调度仍须明确终止度量、
  匹配/输出成本，避免交换结合排列穷举、无界 saturation 和固定轮数安全判据。
- AI 可提出规则、摘要、不变量和候选，但前提本身必须从原程序证明。外部
  输入的“proved”标签不能授权提交，验证记录须绑定原快照与实际候选。
- 分析层 IL 优化与可执行机器码重生成分别验收；后者还需验证 flags、ABI、
  异常、布局及重定位，不属于首版去混淆引擎的隐含能力。
