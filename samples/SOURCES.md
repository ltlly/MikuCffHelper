# samples 来源与版权说明

所有二进制仅用于 CFF 去混淆算法研究，保留在仓库内方便复现；分发/引用时
请遵循各来源仓库的许可证，商业 so 的再分发风险由使用方自行评估。

## 1. obpo-samples（真实商业 so + ground truth）

- 仓库：<https://github.com/obpo-project/samples>（commit c411ea87，2026-06-17 抓取）
- 项目主页：<https://github.com/obpo-project/obpo-plugin>
- 内容：17 个二进制 + 14 个 `.config.json`（记录被 OLLVM 平坦化的函数与 dispatcher）
- 来源链：maiyao1988/deobf、nProtect AppGuard、secneo、shuzilm 内存 dump、
  GoSSIP-SJTU/Armariris、amimo/ollvm-breaker 与 goron、PShocker/de-ollvm 等
  （见目录内 README.md）
- 架构：armv7 / aarch64 / x86 / x86_64
- 语言：C/C++（商业保护 SDK）
- 代表性文件：
  - `arm/libmetasec_ml.so`（抖音，ARM32）
  - `arm/libcms.so`、`arm/libSecShell.so`、`arm/libsecsdk.so`（msa/壳类）
  - `arm64/libvdog.so`、`x86_64/libcompatible_x86.so`（nProtect）
  - `x86/libshellx-super.2019.so`（腾讯系壳）

## 2. cdong-ollvm-unflattener（已知 OLLVM 编译样本）

- 仓库：<https://github.com/cdong1012/ollvm-unflattener>（master 分支）
- 文件：`samples/raw/cdong-ollvm-unflattener/*`
- 架构/平台：x86 Linux ELF、x86_64 Linux ELF、x86 PE32、x86_64 PE32+
- 说明：官方 README 给出被平坦化函数地址：
  - `CFF.bin` @ `0x80491A0`（x86 Linux）
  - `CFF_full.bin` @ `0x8049E00`（x86 Linux，含调用链）
  - `CFF_win.exe` @ `0x401600`（Win32）
  - `CFF_win_full.exe` @ `0x401F10`（Win32，含调用链）
  - `CFF_win64*.exe` 对应 64 位版本
- 另存三个 `deob_*` 参考件（官方 unflattener 输出）：`deob_CFF.bin`、
  `deob_CFF_full.bin`、`deob_CFF_full_linux64.bin`，用于对照 blocks/HLIL/
  圈复杂度。
- 注意：MikuCffHelper 的 fast 检测器（`_collect_state_vars`）当前对这些样本
  报 0 候选；`StateMachine.find_state_var` 可识别状态变量（如 `var_1c`），
  运行时会自动兜底。这是检测器改进的对照样本，不是回归基线的一部分。

## 3. pshocker-de-ollvm-arm

- 仓库：<https://github.com/PShocker/de-ollvm-arm>（main 分支，sample/ 目录）
- 文件：`samples/raw/pshocker-de-ollvm-arm/libpdd_secure.so`
- 架构：ARMv7（32 位）Android .so
- 说明：拼多多 App 保护库（OLLVM-like）；原仓库 README 声明仅作脱壳/去混淆研究
- fast 检测器结果：1 个候选函数 `sub_5ffdc`（191 blocks）

## 4. mips-android（平台覆盖样本）

| 文件 | 来源仓库（commit） | 架构 |
|------|--------------------|------|
| `libjcore240_mips32.so` | [xuexiangjys/XPush @a55df4a](https://github.com/xuexiangjys/XPush/tree/a55df4a008a49978de4336d70fc5d6b5a3005f09/xpush-jpush/libs/mips) | MIPS32（小端） |
| `libjcore240_mips64.so` | 同上 | MIPS64 |
| `libbmob_mips32.so` | [bmob/bmob-android-sdk-demo @b46300a](https://github.com/bmob/bmob-android-sdk-demo/tree/b46300aa2bb85ac554522bdefa6d355664d58c37/%E6%9C%AC%E5%9C%B0%E5%AF%BC%E5%85%A5SDK/libs) | MIPS32（小端） |
| `libbmob_mips64.so` | 同上 | MIPS64 |
| `libopencv_java3_mips.so` | [KePeng1019/SmartPaperScan @3f2df90](https://github.com/KePeng1019/SmartPaperScan/tree/3f2df903320eea9998bcebfc560c4ae112b4e7b0/app/src/main/jniLibs/mips) | MIPS32 |

- 语言：C/C++
- 说明：公开 Sourcegraph 搜索未找到带 OLLVM 标注的 MIPS 样本（`ollvm mips`
  0 命中），这些真实商业 SDK 用于 MIPS 平台兼容性/误报测试；fast 检测器
  均报 0 CFF 候选，BN 无头可正常加载（BN 5.4.9704-dev）。

## 5. 历史回归样本（example/）

- `arm64-v8a.so`：Android NDK r26b，真实 arm64 混淆库
- `libSeQing.so` / `libkste.so`：Android NDK r23c/r20b 真实 arm64 混淆库
- `cff-arm64-v8a.elf`：amimo/ollvm-breaker 的 arm64 CFF 测试样本
- `6fe4c921…`：x86-64 Windows kernel 驱动（PE32+，27 个 CFF 候选）
- `source.out`：x86-64 Linux ELF（无 CFF 候选，对照用）
- `125_6feb19…apk` 及其解包目录：真实 Android APK，`lib/arm64-v8a/` 下 56 个
  .so（Baidu、MNN、msaoaidsec、ffmpeg、Rust qrust、Lua 等），其中 11 个被
  fast 检测器报出候选并复制到 `samples/raw/apk-125-arm64/`；其余 45 个仅
  保留在本地 example 目录（.gitignore），不进仓库。

## 其他曾评估但未纳入的数据集

- Quarkslab diffing_obfuscation_dataset：仅 x64、约 92GB 下载，本次未纳入；
  需要大批量 x64 对照时再考虑。<https://github.com/quarkslab/diffing_obfuscation_dataset>
