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
    clearPass.py             # 常量 if / goto / merge / SSA const 清理
    movStateDefine.py        # 状态常量赋值移到块尾
    deflatHardPass.py        # 路径 A：前向模拟 + 短路 state SetVar
    synthesizeSwitchPass.py  # 路径 B：生成 jump_to / guard
    generalCffPass.py        # 路径 C（实验）：线性检测 + P3 guarded jump_to
    orderJumpToPass.py       # general 后置：jump_to case 表排序
utils/                       # 公共工具
  cff_core.py                # 新框架基础：DominatorInfo / StateClass / EnvEvaluator
  state_machine.py           # 状态变量收集 / 启发式
  cfg_analyzer.py            # CFG 图分析
  instruction_analyzer.py    # 指令/表达式分析
  mikuPlugin.py              # UI 命令（含耗时预估）、日志
  time_estimator.py          # 按 MLIL 块数预估各模式耗时
  instr_vistor.py            # 简易 visitor
fix_binaryninja_api/         # BN API 兼容层
tools/
  deflate_cli.py             # 无头命令行去混淆
  regression_test.py         # 回归测试 + baseline 对比
  collect_cff_samples.py     # 样本扫描 → samples/manifest.json
  README.md                  # 工具说明
samples/                     # 多平台 CFF 样本库 (见 samples/README.md)
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
# 快速验证单个函数（CLI 默认 auto）
python tools/deflate_cli.py example/arm64-v8a.so --addr 0x4259f4

# 只跑路径 B / A
python tools/deflate_cli.py example/arm64-v8a.so --addr 0x4259f4 --mode switch
python tools/deflate_cli.py example/arm64-v8a.so --addr 0x4259f4 --mode deflate

# 实验路径 C（alias-only 状态变量 / flag 条件变种）
python tools/deflate_cli.py example/cff-arm64-v8a.elf --addr 0x400698 --mode general

# trial：实际试跑两种模式后按可读性选优
python tools/deflate_cli.py example/cff-arm64-v8a.elf --addr 0x400698 --mode trial

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

- `pass_clear` 目前包含 `pass_clear_SSA_const_if`；`pass_swap_if` 已移除。
  这两个决策都有 39 函数全量 A/B 证据：
  - 移除 `pass_clear_SSA_const_if` → `sub_4075a0` HLIL 4→19、
    `sub_407994` 26→39，**必须保留**；
  - 移除 `pass_swap_if` → auto 与 general 回归输出均与基线一致，
    无收益，已删除整段 dead pass。
  不要仅凭旧结论或代码洁癖再次增删这两条规则。
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

- UI activity 已标注 模式1 Deflate / 模式2 Switch / 模式3 General / Auto，
  并带耗时量级提示；右键 `miku\\estimate_cff_time` 可查详细预估。
- 默认入口：`workflow_patch_mlil_auto`。
- 回归基线（`tools/baseline.json`）当前覆盖 39 个函数：
  - 30 个输出含 `switch`；
  - 7 个被进一步还原为纯 if/while/goto 链；
  - 2 个未显著变换（`sub_42a21c`、`sub_45985c`）；
  - 总变换率 37/39，0 副作用丢失，0 orphan jump。
- general 回归基线 `tools/baseline_general.json`：39 函数，31/39 变换，
  0 orphan、0 语义副作用丢失；总体弱于 auto，但 B/A 失败的函数上有收益。
- `CFGIndex` 一次建前驱/度索引：per-instruction 块映射 O(1) 查询（保持
  `get_basic_block_at` 含块中段语义，不能用 start 精确匹配 map），SCC
  懒计算；LLIL copy 与 MLIL merge 已复用；`pass_clear_SSA_const_if`
  的 `find_state_var` 提升到外层循环外；别名链改 union-find；已删除
  未接入的 `reverseIfPass.py` 与 MLIL `pass_copy_common_block_mid`。
  pass 级基准（不含 BN 重分析）：sub_45ba24 auto 2.42s→0.74s
  （clear 2.22s→0.55s）、sub_406c0c 0.27s→0.19s，39 函数回归与基线
  一致。
- 曾尝试给 `_forward_resolve` 加 define 级缓存：带 seed-env 键的版本在
  39 样本上无重复键（0 命中）且额外开销，正确性收益为负，已废弃。现在
  的缓存是 **dispatcher 段 trace 缓存**：键 `(tail 去向, env)` 与 define
  块无关，命中后按 define 块是否出现在路径上做一次等价检查；deflate 与
  synthesize 候选收集都复用（sub_40831c 实测 21 次解析 10 次命中）。
  缓存只在「MLIL 收集阶段不变」的窗口内创建，勿跨 finalize 复用。
- `pass_clear` 各子 pass 无改动时不再执行多余的 finalize/generate_ssa_form，
  减少 pass_clear 链上的重复 SSA 重建；39 函数 auto + general 回归均通过。
- BN 持久化缓存调研（BN 5.4.9704-dev，实测）：
  - `bv.create_database("x.bndb")` + `bv.store_metadata/get_metadata/
    query_metadata`：当前快照 metadata 随 `.bndb` 重开恢复（int/str/list/dict
    可存，复杂对象先 json 序列化）；`bv.save_auto_snapshot()` 追加新快照。
  - `bv.file.database.write_global/read_global`、`write_global_data/
    read_global_data` 可持久化字符串/二进制全局值。
  - `Database.analysis_cache` 是 BN 自有的 KVS：自定义 `set_value` 后
    `save_auto_snapshot` 不保留（实测），**不要往里写插件缓存**。
  - `bn.get_system_cache_directory()` 返回 `~/.binaryninja/cache`，但目录
    可能尚未创建，插件需自行 `os.makedirs(exist_ok=True)`。
  - 结论：deflate trace 缓存要跨会话复用，必须带「二进制 sha256 + 函数地址
    + dispatcher 块指纹/MLIL 指纹」防陈旧；UI 场景可用 `.bndb` metadata，
    无头 `bn.load` 场景更推荐 `get_system_cache_directory()` 下的自定义
    JSON。当前 trace 缓存仍只做 pass 内窗口，持久层等新样本集命中率评估
    后再接。
- 新样本首轮调研（12 个跨架构函数，见 `samples/README.md`）：trace 缓存
  总命中率 26%（x86 85%/70% 最高，arm64 3-29%），但解析总耗时仅 ~2.3s，
  远小于 BN 加载/重分析；auto 在新 x86/x64 样本上 0 丢失且优于 general。
  **决策：暂不接 `.bndb` 持久缓存**（ROI 低）。
- cdong x86 深入研究（已落地）：`_eval` 支持 CMP_E/NE/U/ULT/… 全部比较，
  `_eval_if` 支持 `cond:N = a == b` 物化条件；fast 状态变量为空时用
  `StateMachine.find_state_var` 兜底；`_walk_block_tail` 只跳过
  「写后无读者」的死 store。效果：`CFF_win.exe` target_function auto 从
  无 switch 变为 switch(3 cases)、0 丢失（HLIL 63→65）；39 函数 auto +
  general 回归均 `[ok]`。
- cdong x86 更深一层的实验结论：放宽 `_block_is_pure_dispatcher` 允许
  temp/寄存器/死栈写入，linux64 dispatcher 子图 36→74 块、transition 从
  全 None 变为部分可解析，但 **39 回归 12 个函数 HLIL 显著变差**
  （sub_459ed8 17→45、sub_45aa54 18→43 等）→ 已回退严格过滤。根因是
  直接跳真实块会丢掉 dispatcher 沿途对栈/寄存器的写入。
- **path replay 已实现**（仅 deflate 路径）：前向模拟记录沿途 SetVar 与
  所有经过指令（tail + dispatcher），按「跳过路径外仍被读取」做数据流
  裁剪后在 mini-block 原样回放，再 goto target；状态变量写入一律回放。
  合成路径 synthesize 保持严格 pure 过滤不变。验证：
  - cdong linux64 部分 transition 可解析（如 0x6a3075b1→328、
    0x77004896→461），replay 裁剪后每个 patch 14-20 条写入；
  - auto 39 回归 `[ok]`：37/39 变换、0 丢失、0 orphan，并且
    sub_409488 HLIL 20→8（-60%）；
  - general 39 回归 `[ok]`（31/39）。
  - cdong win32/win64/linux64 的 auto 均 0 丢失，但 HLIL 仍略升
    （63→65 / 56→62 / 194→219），这些样本 general 仍然更好。
- **cdong full 系列 HLIL 膨胀根因已复核**：对 auto 输出做全局死写消除可
  删 52 条写入但 HLIL 仍 219；对照官方 deob 参考件（23 blocks / HLIL
  134 / calls 28）确认差距来自「依赖输入的条件状态转移未完整短路」
  （如 `if (arg1 != 0) state=A else state=B`），BN HLIL restructure 对
  残留 dispatcher 的直连边重复展开。
- **条件多目标解析器存在但默认关闭**（`_ENABLE_COND_TREES=False`）：
  `_resolve_conditional_path` 支持 state-chain dispatcher re-entry、按
  state 值判环；但 cdong 实测把 cond 树 patch 进 MLIL 后 HLIL
  219→227/259、auto 8.5s，stop-on-unknown-if 也 219→227，均已回退。
  当前稳定默认：仅 path replay，cdong auto HLIL 219、t≈3.0s。
  返回边重建原型同样 HLIL 不降（257），helpers 已删除。结论：剩余差距
  需要先解决 BN HLIL restructure 的重复展开，再谈 dispatcher 移除。
- **不可达 dispatcher 移除结论**：cdong auto 后 99/99 块仍可达、77 个
  dispatcher 块仍有来自真实块的返回边。安全移除不能靠 NOP 可达性清理，
  必须把「真实块 → dispatcher 入口」的返回边重定向到条件树/guard（等价于
  general P2 的 redirect），下一步再做；在此之前不要删 dispatcher 块。
- obpo ground truth 对齐结论：`.config.json` 的 func/dispatcher 地址多数
  不在 BN 自动函数内；`create_user_function` 后 MLIL 在 `undefined`
  指令处截断（7/5 blocks），BN 边界与 OLLVM 平坦化函数边界不一致。
  召回测量需按 dispatcher 地址逐个建函数后再跑检测，留在样本工具层做。
- 不硬编码模式选择规则；`tools/eval_modes.py` 实际试跑 auto/general 后，
  用多维可读性指标 + Pareto/可配置罚分选优；69 样本结果在
  `tools/eval_samples.json`（trial：general 37 / auto 32，0 丢失）。
- 实验入口 `workflow_patch_mlil_general`（路径 C，独立 workflow）默认关闭；
  当前已支持
  alias-only 状态变量 + flag 条件变种、equality-hash / interval-bisect
  批量分裂、安全 tail-define 短路（含 dispatcher 前导重放）、条件状态
  分支改写、多候选状态类选择、两状态元组 P3（64-bit 编码）；N>2 嵌套
  jump_to 代码保留但默认关闭（嵌套 CFF 会误并内层状态机）；验证 0
  副作用丢失 / 0 orphan；标准样本仍以 auto 为准。
- 已知限制：条件状态赋值、多状态联合分发、跨函数 CFF、超大函数超时等，
  详见 `readme.md` 第 10 节。
