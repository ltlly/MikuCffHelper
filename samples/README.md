# samples — CFF 样本库

本目录收集用于 MikuCffHelper 检测/去混淆验证的多平台二进制样本。
详细来源与版权说明见 [SOURCES.md](SOURCES.md)；机器可读清单见
[manifest.json](manifest.json)。

## 布局

```text
samples/
  manifest.json   # 每个二进制: sha256/arch/platform/CFF 候选函数/obpo ground truth
  SOURCES.md      # 来源、架构、语言、许可说明
  raw/            # 原始下载文件，不要改
    obpo-samples/                 # 17 个真实商业 so + config.json (ground truth)
    cdong-ollvm-unflattener/      # 已知 OLLVM 编译的 x86/x64 Linux/Windows 样本
    pshocker-de-ollvm-arm/        # PDD libpdd_secure.so (ARM32 真实样本)
    mips-android/                 # MIPS32/MIPS64 真实 Android 库 (平台覆盖)
    apk-125-arm64/                # 从 example/125_*.apk 复制出的 11 个 CFF 阳性 libs
```

`example/` 里的历史回归样本（arm64-v8a.so、libSeQing.so、libkste.so、
x86-64 Windows 内核样本）也已纳入 manifest.json，便于统一查询。
APK 解包目录中另外 45 个 fast 检测无候选的 arm64 libs 只保留在本地
`example/125_*`（被 .gitignore 忽略），不进仓库清单。

## 快速统计

- 清单条目：47 个二进制（另有一个 libavcodec.so 因 BN 无头加载超 2 分钟
  未完成，跳过）
- 检测到 CFF 候选的二进制：28 个，共 1629 个候选函数（fast 检测器）
- obpo 子集带 `.config.json` ground truth：14 个文件标注了被平坦化的函数
  与 dispatcher
- 架构覆盖：aarch64 / armv7 / x86 / x86_64 / mipsel32 / mipsel64
- 语言：以 C/C++ 为主，另有 Rust (libqrust.so)、Lua (liblua_v1_0_4.so)、
  Go 相关 (libgoblin_6_1_1.so) 的真实库

## 检测口径

清单由 `tools/collect_cff_samples.py` 同款检测器生成：

- `_detect_dispatcher_entry`（Blazytko 支配树门控）
- `_collect_state_vars` + `_function_looks_like_cff`
- 函数级过滤：15 ≤ MLIL blocks ≤ 200

已知局限：

- cdong 的 OLLVM 官方小样本（CFF.bin 等）fast 检测器报 0 候选，但
  README 里给出了被平坦化函数地址（如 CFF.bin @0x80491A0），可作为
  检测器改进的对照用例；用 `StateMachine.find_state_var` 慢路径能识别
  其状态变量 `var_1c`。
- MIPS 的 5 个真实库 fast 检测器报 0 候选，用于平台兼容性与误报评估。

## 首轮调研结论（2026-08-16，BN 5.4.9704-dev）

### trace 缓存命中率（12 个跨架构候选函数）

| 样本 | 架构 | blocks | 解析次数 | memo keys | 命中 | 解析耗时 |
|------|------|-------:|---------:|----------:|-----:|---------:|
| libSecShell sub_4b618 | armv7 | 151 | 51 | 47 | 4 (8%) | 0.10s |
| libcms sub_d293c | armv7 | 193 | 21 | 14 | 7 (33%) | 0.04s |
| libmetasec sub_6acd0 | armv7 | 59 | 17 | 12 | 5 (29%) | 0.03s |
| libpdd_secure sub_5ffdc | armv7 | 191 | 64 | 57 | 7 (11%) | 0.33s |
| libvdog 0x43f068 | aarch64 | 196 | 64 | 62 | 2 (3%) | 1.14s |
| libnative-lib 0x412ae4 | aarch64 | 185 | 87 | 67 | 20 (23%) | 0.14s |
| libcompatible 0x56cc98 | aarch64 | 200 | 7 | 5 | 2 (29%) | 0.01s |
| libmsaoaidsec 0x40dd60 | aarch64 | 196 | 47 | 41 | 6 (13%) | 0.21s |
| libshellx 0x3ebc0 | x86 | 162 | 54 | 8 | 46 (85%) | 0.06s |
| libcompatible_x86 0xdc7f0 | x86 | 173 | 27 | 8 | 19 (70%) | 0.05s |
| libcompatible_x86 0x58597e | x86_64 | 194 | 8 | 5 | 3 (38%) | 0.01s |
| 6fe4 0x14001e6e1 | x86_64 | 163 | 66 | 52 | 14 (21%) | 0.15s |

合计 513 次解析、135 次命中（26%）。解析本身总耗时约 2.3s，远小于 BN
加载/重分析与 HLIL 重建，因此**跨会话持久化 trace 缓存 ROI 低**，暂不接
`.bndb` metadata 持久层。

### auto/general 实际试跑（新样本抽查）

- libshellx-super.2019.so @0x3ebc0（x86）：auto 162→141、cyc 100→96、
  switch 3、0 丢失；general 162→146、cyc 100→124 → **auto 更优**。
- 6fe4（x86_64 kernel）@0x14001e6e1：auto 163→161、HLIL 395→349、
  switch 2、0 丢失；general 163→176 → **auto 更优**。

### cdong x86 深入研究（路径已逐步落地）

1. **已落地（39 回归通过）**：
   - fast `_collect_state_vars` 为空时，deflate/switch 都改用
     `StateMachine.find_state_var` 兜底，找到 `var_1c`/`var_38`；
   - `_eval` 支持全部 CMP 运算；`_eval_if` 支持 `cond:N = a == b` 这种
     x86/64 物化比较条件；
   - `_walk_block_tail` 只跳过「写后无读者」的死 store（数据流证明等价），
     有读者的局部 store 仍严格拒绝。
   - 效果：`CFF_win.exe` @0x401600 auto 从无 switch → switch(3 cases)、
     0 丢失（HLIL 63→65）；39 函数 auto + general 回归 `[ok]`。
2. **放宽 pure 过滤的教训**：直接放宽 `_block_is_pure_dispatcher`（允许
   temp/寄存器/死栈写入，但不回放）后，linux64 dispatcher 子图 36→74、
   transition 部分可解析，但 auto 39 回归 12 个函数 HLIL 变差，根因是
   直接跳真实块丢掉了 dispatcher 沿途写入。该实验已回退，之后用
   path replay（第 3 点）重新启用等价放宽。
3. **path replay 已实现（deflate 路径）**：模拟时记录沿途所有指令与
   SetVar 写入，按「跳过路径外仍被读取」做数据流裁剪后，在 mini-block
   按序回放再 `goto target`；状态变量写入一律回放。裁剪后 linux64 每个
   patch 仅 14-20 条写入（原始全量 56-123 条）。验证：
   - auto 39 回归 `[ok]`（37/39、0 丢失、0 orphan），且 sub_409488
     HLIL 20→8；
   - cdong linux64 transition 部分可解析（0x6a3075b1→328、
     0x77004896→461），auto 0 丢失，但 HLIL 194→219，general 仍是
     65 blocks / HLIL 194 更优。
4. **HLIL 膨胀根因复核（对照 deob 参考件）**：
   - `deob_CFF_full_linux64.bin` 参考：23 blocks、HLIL 134、calls 28；
   - 混淆前：91 blocks、HLIL 194；path replay 后 auto：99 blocks、
     HLIL 219；general：65 blocks、HLIL 194。
   - 对 auto 输出再做全局死写消除：可删 52 条写入，但 HLIL 仍 219——
     说明膨胀来自 BN HLIL restructure 对「部分 state 仍走原 dispatcher」
     的直连边重复展开，不是死代码。
   - 根因是 cdong full 系列存在**依赖输入的条件状态转移**
     （如 `if (arg1 != 0) state=A else state=B`），deflate 一个 state 值
     只对应一个目标，条件转移无法完整短路；下一步应做条件多目标解析/
     与 general 条件分支改写融合，而不是清理 pass。
5. **条件多目标解析已实现（仅 temp 比较形态，deflate 路径）**：
   - 解析树节点：`target` / `cond(if)`；未知条件对 true/false 两侧克隆
     env 递归；支持 **dispatcher re-entry**（state chain 结块
     `bb: goto dispatcher` 不算环）与同一 state 值二次入口的终止条件；
   - builder 先生成子块再生成父块，按 liveness 过滤回放并在 mini-block
     中生成条件 goto 树；深度上限 128、最多 4 次 re-entry。
   - 仅当 fast `_collect_state_vars` 为空（慢路径兜底，cdong x86 形态）
     时启用，普通 arm64 样本不付出解析/膨胀成本。
   - cdong linux64 现在 5 个 state define 生成 cond 树（例如
     0xb645f3b5→if(...) 435/422；0xf40566d8 生成三层嵌套），其余为具体
     target；auto 0 丢失，HLIL 194→219。
   - 验证：auto 39 回归 `[ok]`（37/39、0 丢失、0 orphan，sub_409488
     HLIL 20→8）；general 39 回归 `[ok]`。
   - 离 deob 参考件（23 blocks / HLIL 134）仍有距离：条件树把控制流直接
     化了，但 BN HLIL restructure 仍会按残留 dispatcher 展开；下一步是
     条件树 + 不可达 dispatcher 移除的融合。
6. **guard 重定向原型结论（未接入代码）**：auto 后只有 5 条真实块边仍直
   接回 dispatcher 入口，其余已进条件树 mini-block；对 19 个可解析 state
   值安装带完整 preamble 回放的 jump_to guard 并重定向这 5 条边，HLIL
   仍 219、0 orphan。说明残余展开来自已生成的条件树与真实块内条件转移，
   不是这 5 条边；要逼近参考件必须做**真实块返回边的条件树重建**
   （每个真实块尾部都按 state 生成条件 goto），而不是仅靠 guard。

### obpo ground truth 对齐结论

`.config.json` 的 `func`/`dispatcher` 地址多数不在 BN 自动识别的函数内；
`create_user_function` 后 MLIL 在 `undefined` 指令处截断（实测 libmetasec
两个函数只有 7/5 blocks），BN 函数边界与 OLLVM 平坦化函数边界不一致。
召回测量需要「按 dispatcher 地址逐个建函数 → 跑检测 → 统计 transition 是否
命中 config 的 `t` 地址」的专用工具；暂以 fast 检测候选为样本口径。

## 更新清单

```bash
# 扫描 raw 目录并覆盖 manifest.json
python tools/collect_cff_samples.py samples/raw -o samples/manifest.json

# 把 example/ 的历史样本也纳入
python tools/collect_cff_samples.py samples/raw example/arm64-v8a.so example/libSeQing.so \
  example/libkste.so example/cff-arm64-v8a.elf example/6fe4* example/source.out \
  example/125_*/lib/arm64-v8a -o samples/manifest.json
```
