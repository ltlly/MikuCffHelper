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
```

`example/` 里的历史回归样本（arm64-v8a.so、libSeQing.so、libkste.so、
x86-64 Windows 内核样本、从 125_*.apk 解出的 56 个 arm64 libs）也已纳入
manifest.json，便于统一查询。

## 快速统计

- 清单条目：91 个二进制（不含 manifest 备注中跳过的一个 libavcodec.so）
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

## 更新清单

```bash
# 扫描 raw 目录并覆盖 manifest.json
python tools/collect_cff_samples.py samples/raw -o samples/manifest.json

# 把 example/ 的历史样本也纳入
python tools/collect_cff_samples.py samples/raw example/arm64-v8a.so example/libSeQing.so \
  example/libkste.so example/cff-arm64-v8a.elf example/6fe4* example/source.out \
  example/125_*/lib/arm64-v8a -o samples/manifest.json
```
