# MikuCffHelper 开发工具

## deflate_cli.py — 无头命令行去混淆

不开 BN UI 直接对二进制跑工作流并输出 HLIL。

```bash
# 单函数 (默认 auto：先 B，失败 fallback A)
python tools/deflate_cli.py example/arm64-v8a.so --addr 0x4259f4

# 二进制内所有 CFF 候选
python tools/deflate_cli.py example/arm64-v8a.so --all-cff

# 指定模式：auto / switch (只跑 B) / deflate (只跑 A) / general (实验路径 C)
python tools/deflate_cli.py example/arm64-v8a.so --addr 0x4259f4 --mode switch


# 输出到文件
python tools/deflate_cli.py example/arm64-v8a.so --addr 0x4259f4 --out /tmp/out.c

# 输出去混淆前 HLIL (对照参考)
python tools/deflate_cli.py example/arm64-v8a.so --addr 0x4259f4 --before
```

## regression_test.py — 自动化回归测试

跑 `workflow_patch_mlil_auto` 在样本集上，输出 JSON + 摘要并与 baseline
对比。

```bash
# 与 baseline 对比 (默认)：发现回归就非 0 退出
python tools/regression_test.py

# 接受当前结果为新 baseline (改 heuristic 后确认改进无误时)
python tools/regression_test.py --update-baseline

# 只跑某个 binary
python tools/regression_test.py --only arm64-v8a.so

# 只跑某个函数 (debug 用)
python tools/regression_test.py --func 0x4259f4 --bin arm64-v8a.so

# general 实验路径的语义等价回归（默认 baseline_general.json）
python tools/regression_test.py --mode general
python tools/regression_test.py --mode general --update-baseline

# 多维可读性评估（实际试跑 auto/general，Pareto/罚分选优）
python tools/eval_modes.py --baseline-targets --out /tmp/eval_baseline.json
python tools/eval_modes.py example/arm64-v8a.so --scan --max-funcs 20
```

## collect_cff_samples.py — 样本扫描与清单生成

对一批二进制/目录跑 CFF 检测器，生成 `samples/manifest.json`
（sha256 / arch / platform / 候选函数列表）。

```bash
# 扫描 samples/raw（fast 检测器）
python tools/collect_cff_samples.py samples/raw -o samples/manifest.json

# 目录 + 单文件混合；--slow-state 对 dispatcher 命中但 _collect_state_vars
# 漏掉状态变量的函数改用 StateMachine.find_state_var（慢，但能覆盖 cdong x86 样本）
python tools/collect_cff_samples.py samples/raw example/arm64-v8a.so --slow-state
```

### baseline.json 维护

- 改 heuristic / pass 后跑 `regression_test.py` (默认对比模式)
- 没回归 → commit 改动
- 有改进 (新增 SWITCH / DEFLATED) → 跑 `--update-baseline` 后 commit
  baseline.json 一起进 PR
- 有回归 → 看 stderr 找哪些函数破坏了，修代码或调整 heuristic

## 环境变量

- `BN_PYTHON`：BN python 包目录 (默认 `/home/ltlly/tools/binaryninja/python`)
- `SAMPLE_DIR`：regression_test.py 的样本目录 (默认 `example/`)
