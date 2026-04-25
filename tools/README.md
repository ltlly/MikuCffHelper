# MikuCffHelper 开发工具

## regression_test.py

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
```

### baseline.json 维护

- 改 heuristic / pass 后跑 `regression_test.py` (默认对比模式)
- 没回归 → commit 改动
- 有改进 (新增 SWITCH / DEFLATED) → 跑 `--update-baseline` 后 commit
  baseline.json 一起进 PR
- 有回归 → 看 stderr 找哪些函数破坏了，修代码或调整 heuristic

### 环境变量

- `BN_PYTHON`: BN python 包目录 (默认 `/home/ltlly/tools/binaryninja/python`)
- `SAMPLE_DIR`: 样本目录 (默认 `example/`)
