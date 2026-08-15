# AGENTS.md

本文档面向后续参与本仓库开发的 AI / 开发者，用于快速理解项目、遵守约定、
避免破坏语义等价性。

## 1. 项目定位

`MikuCffHelper` 是 Binary Ninja 插件，用于还原 OLLVM 风格控制流平坦化
(Control Flow Flattening, CFF)。

核心思路：

- 识别 `dispatcher + 真实块` 状态机。
- 通过支配树、SCC、副作用筛选和前向整型模拟，找出 `state 值 → 真实块入口`
  的映射。
- 提供三条变换路径：
  - **路径 A (`deflate_hard`)**：绕过 dispatcher，把 `state = const` 直接
    短接到真实块，输出最简 goto/if/while 形态。
  - **路径 B (`synthesize_switch`)**：把 dispatcher 的 cmp-tree 改写为
    `MLIL_JUMP_TO`，让 BN HLIL Restructurer 渲染成 `switch-case`。
  - **路径 C (`generalCffPass`，实验)**：线性检测 + alias-aware 状态类 +
    P3 preamble-preserving guard，面向 alias-only 状态变量 / 布尔 flag
    条件等变种，默认不进入 auto。
  - **路径 auto**：先 B，B 拒绝时自动 fallback 到 A，是推荐入口。

## 2. 目录结构

```text
__init__.py                  # 注册 Workflow / Activity / 插件命令
mikuWorkflow.py              # 各 workflow 的 pass 编排
passes/
  low/                       # LLIL 层预处理
    copyCommonBlockPass.py   # 复制多前驱公共块，避免状态变量丢失
    inlineIfCondPass.py      # flag 条件内联到 if
    spiltIfPass.py           # if 单独成块
  mid/                       # MLIL 层核心
    clearPass.py             # 常量 if / goto / merge / swap / SSA const 清理
    movStateDefine.py        # 状态常量赋值移到块尾
    deflatHardPass.py        # 路径 A：前向模拟 + 短路 state SetVar
    synthesizeSwitchPass.py  # 路径 B：生成 jump_to / guard
    generalCffPass.py        # 路径 C（实验）：线性检测 + P3 guarded jump_to
    reverseIfPass.py         # 备用/未接入 workflow 的反向 if pass
utils/                       # 公共工具
  cff_core.py                # 新框架基础：DominatorInfo / StateClass / EnvEvaluator
  state_machine.py           # 状态变量收集 / 启发式
  cfg_analyzer.py            # CFG 图分析
  instruction_analyzer.py    # 指令/表达式分析
  mikuPlugin.py              # UI 命令、日志
  instr_vistor.py            # 简易 visitor
fix_binaryninja_api/         # BN API 兼容层
tools/
  deflate_cli.py             # 无头命令行去混淆
  regression_test.py         # 回归测试 + baseline 对比
  README.md                  # 工具说明
tests/                       # 历史/脚本类测试，非 pytest 套件
readme.md                    # 用户手册（对外）
AGENTS.md                    # 本文档（开发/AI 指南）
```

## 3. 核心概念与不变量

### 3.1 状态变量识别

- 状态变量通常满足：出现在常量赋值中，且被赋予 **≥ 2 个 unique 常量**。
- 函数级 CFF 启发式：unique 常量数 ≥ 4 且值域跨度 ≥ `0x10000000`，避免把
  Rust match / C++ stdlib 的小常量分发误判为 CFF。
- 别名链 `_vars_aliased_to` 会在 **整个函数** 范围内追踪 `alias = primary`
  拷贝，确保 `case_values` 收集完整。

### 3.2 dispatcher 识别

- 使用 Blazytko 支配树法：`flattening_score(D) >= 0.3` 且有 back-edge。
- 嵌套 dispatcher 在 iter 2+ 使用更低阈值 `0.10`。
- dispatcher 子图用 Tarjan SCC + 副作用筛选：只允许状态变量副作用，禁止
  call / store / ret / intrinsic。

### 3.3 等价性安全红线

任何改动都必须保持：

1. **不丢失副作用**：call / store / return / intrinsic / syscall 等必须保留。
2. **不产生 orphan 跳转**：不能出现 `jump(0x...)` 形式的悬空间接跳转。
3. **保留状态写入语义**：P1 / P2 / mini-block 中仍执行 `state = const`，
   保证外部读取状态变量时数值正确。
4. **CFE 子序列**：去混淆后的 trace 应是原 trace 的子序列，只删除 dispatcher
   内部的状态比较与分发。

现有验证手段：

- pass 内嵌 MLIL 副作用集合比对；general 模式使用地址无关的语义签名
  （call 按 callee 计数，store/ret 按 op 计数），因为重写会移动指令地址。
  P3 只有 assigned 全解析且回边全为无条件 goto 时才省略 fallback。
- `tools/regression_test.py` 在 HLIL 层检查 call / store / ret 是否丢失、
  是否出现 orphan jump；general 模式默认与 `baseline_general.json` 对比。
- 修改后必须跑回归测试；确有改进时再更新对应 baseline。

## 4. 开发 / 修改指南

### 4.1 日常命令

```bash
# 快速验证单个函数（auto 模式）
python tools/deflate_cli.py example/arm64-v8a.so --addr 0x4259f4

# 只跑路径 B / A
python tools/deflate_cli.py example/arm64-v8a.so --addr 0x4259f4 --mode switch
python tools/deflate_cli.py example/arm64-v8a.so --addr 0x4259f4 --mode deflate

# 实验路径 C（alias-only 状态变量 / flag 条件变种）
python tools/deflate_cli.py example/cff-arm64-v8a.elf --addr 0x400698 --mode general

# 扫描所有 CFF 候选
python tools/deflate_cli.py example/arm64-v8a.so --all-cff

# 回归测试（默认与 baseline 对比）
python tools/regression_test.py

# 确认改进后更新 baseline
python tools/regression_test.py --update-baseline
```

环境变量：

- `BN_PYTHON`：Binary Ninja python 包目录，默认
  `/home/ltlly/tools/binaryninja/python`。
- `SAMPLE_DIR`：回归测试样本目录，默认 `example/`。

### 4.2 修改 pass 的流程

1. 先定位对应 pass 文件：
   - LLIL 预处理在 `passes/low/`。
   - MLIL 核心在 `passes/mid/`。
2. 修改后先用 `deflate_cli.py` 对受影响样本做冒烟测试。
3. 跑 `regression_test.py` 确认没有回归。
4. 如果新逻辑是预期改进，更新 `tools/baseline.json` 并提交。
5. 同步更新 `readme.md`（用户可见行为变化）和本文档（架构/约定变化）。

### 4.3 注意

- `pass_clear` 目前包含 `pass_swap_if` 和 `pass_clear_SSA_const_if`。历史文档
  曾建议删除它们，但当前实现对嵌套 CFF 迭代收敛有帮助，**不要仅凭旧结论删除**。
- `reverseIfPass.py` 未接入任何 workflow；若不需要可保留作参考，但不要把它
  默认加入 pipeline。
- 修改 `mikuWorkflow.py` 时注意 `workflow_patch_mlil_auto` 的 B→A fallback
  顺序：B 成功后不要再跑 A，否则可能把 guard block 误当 dispatcher。
- `workflow_patch_mlil_general` 是实验入口，注册在独立 workflow
  `MikuCffHelper_general_workflow`（不跑 LLIL copy/split）；**不要**未经
  验证就把它加入 auto pipeline。它面向 alias-only 状态变量 / flag 条件
  变种，标准 OLLVM 样本仍应优先走 B/A。
- BN 版本相关 API 兼容问题放在 `fix_binaryninja_api/` 中处理，不要在核心
  pass 里堆版本判断。

## 5. 文档维护约定

- `readme.md` 是面向用户的权威手册，保持与当前代码一致。
- `AGENTS.md` 是面向 AI / 后续开发的项目内记忆，简洁、可执行。
- 不再保留“一次性任务结论 / 历史评估 / 过期建议”类文档；如有必要，把仍有
  价值的内容合并进 `readme.md` 或 `AGENTS.md`，不要重新创建 `docs/` 下的
  任务式 md。
- 更新算法或启发式后，同步更新 `readme.md` 中的“实测数据 / 已知限制”，
  避免数字过时。

## 6. 当前状态摘要

- 默认入口：`workflow_patch_mlil_auto`。
- 回归基线（`tools/baseline.json`）当前覆盖 39 个函数：
  - 30 个输出含 `switch`；
  - 7 个被进一步还原为纯 if/while/goto 链；
  - 2 个未显著变换（`sub_42a21c`、`sub_45985c`）；
  - 总变换率 37/39，0 副作用丢失，0 orphan jump。
- general 回归基线 `tools/baseline_general.json`：39 函数，31/39 变换，
  0 orphan、0 语义副作用丢失；总体弱于 auto，但 B/A 失败的函数上有收益。
- 实验入口 `workflow_patch_mlil_general`（路径 C，独立 workflow）默认关闭；
  当前已支持
  alias-only 状态变量 + flag 条件变种、equality-hash / interval-bisect
  批量分裂、安全 tail-define 短路（含 dispatcher 前导重放）、条件状态
  分支改写、多候选状态类选择、两状态元组 P3（64-bit 编码）；N>2 嵌套
  jump_to 代码保留但默认关闭（嵌套 CFF 会误并内层状态机）；验证 0
  副作用丢失 / 0 orphan；标准样本仍以 auto 为准。
- 已知限制：条件状态赋值、多状态联合分发、跨函数 CFF、超大函数超时等，
  详见 `readme.md` 第 10 节。
