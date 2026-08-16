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

### 两个明确缺口（暂不修）

1. **cdong x86 官方样本**：fast `_collect_state_vars` 漏掉经 temp 比较的
   `var_1c`；改用 `StateMachine.find_state_var` 后 dispatcher 子图可识别，
   但 `_walk_block_tail` 严格策略拒绝 define 块内的 prologue 局部 store，
   仍 0 解析。修复需要安全区分「prologue 无害 store」与「真实副作用」，
   历史上在 sub_40831c 上出过 SE_LOST=11，留待专项 A/B。
2. **obpo ground truth 对齐**：`.config.json` 的 `func`/`dispatcher` 地址
   多数不在 BN 自动识别的函数内（`get_function_at` 为 None）；用
   `create_user_function` 后也只有 1-7 blocks。要拿 ground truth 做召回
   统计，得先按 dispatcher 区域重建函数边界，暂以 fast 检测候选为口径。

## 更新清单

```bash
# 扫描 raw 目录并覆盖 manifest.json
python tools/collect_cff_samples.py samples/raw -o samples/manifest.json

# 把 example/ 的历史样本也纳入
python tools/collect_cff_samples.py samples/raw example/arm64-v8a.so example/libSeQing.so \
  example/libkste.so example/cff-arm64-v8a.elf example/6fe4* example/source.out \
  example/125_*/lib/arm64-v8a -o samples/manifest.json
```
