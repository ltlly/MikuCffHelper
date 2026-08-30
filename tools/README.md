# MikuCffHelper 开发工具

## `deflate_cli.py`

无头加载当前工作区插件、运行指定 Workflow 并输出 HLIL。默认关闭用户目录中的
BN 插件，并核验实际导入路径，防止测到旧安装。

```bash
# 单函数，默认 auto
python tools/deflate_cli.py example/arm64-v8a.so --addr 0x4259f4

# 显式候选模式；CLI 会保证三个 MLIL Activity 互斥
python tools/deflate_cli.py example/arm64-v8a.so --addr 0x4259f4 --mode switch
python tools/deflate_cli.py example/arm64-v8a.so --addr 0x4259f4 --mode deflate

# 枚举真正存在局部边证书的函数，不使用 block/常量经验阈值
python tools/deflate_cli.py example/arm64-v8a.so --all-cff

# 可选资源预算；超出只跳过，不改变证书规则
python tools/deflate_cli.py example/arm64-v8a.so --all-cff --max-blocks 500

python tools/deflate_cli.py example/arm64-v8a.so --addr 0x4259f4 --out /tmp/out.c
python tools/deflate_cli.py example/arm64-v8a.so --addr 0x4259f4 --before
```

扫描期间的单函数异常会显示并令进程非零退出，不再静默吞掉。

## `regression_test.py`

严格回归门禁不重新发现“前 N 个候选”。`baseline.json` schema v2 固定：

- 3 个样本路径及精确 SHA-256；
- 39 个函数地址；
- 逐函数预期结构指标；
- 可配置的单函数资源 timeout。

下列任一情况硬失败：manifest/schema 错误、样本缺失或哈希变化、函数/结果缺失、
未知 key、异常、timeout、orphan jump、MLIL/HLIL call/store/return 丢失、MLIL
可观察副作用丢失或新增。HLIL restructurer 的语法重复和 effect 线性列举顺序变化
保留为诊断；执行层以 MLIL 为准。

```bash
python tools/regression_test.py
python tools/regression_test.py --only arm64-v8a.so
python tools/regression_test.py --func 0x4259f4 --bin arm64-v8a.so

# 输出目录、资源预算
python tools/regression_test.py --timeout 60 --out-dir /tmp/miku-regression

# 只在完整 manifest 和所有绝对安全门禁通过时写 baseline
python tools/regression_test.py --update-baseline
```

每次运行生成：

- JSON：完整环境、命令、样本哈希、before/after MLIL/HLIL CFG、指令、ordered
  effects、耗时和 RSS；
- CSV：方便比较的逐函数摘要。

单函数调试可显式允许 manifest 外地址，但绝对安全错误仍失败：

```bash
python tools/regression_test.py \
  --bin custom.so --func 0x1000 --allow-unmanifested
```

## `tools/corpus/`

可再生成的独立语料，避免只在既有 39 个目标上调参。

- `src/`：8 个 0BSD fixture，覆盖 switch、if-chain、nested、多状态、alias、
  conditional state、副作用和普通控制流负样本；
- `build_corpus.py`：构建 x86-64 GCC O0/O2 executable 和 i386 O0 ET_REL，
  运行 16 个 executable self-test，并用 `nm` 严格索引地址；
- `manifest.json`：来源、许可证、编译命令、SHA-256、地址来源、image base；
- `benchmark.py`：按 manifest 固定地址测量，不用 detector 或成功变换筛样本；
- `tests/`：地址歧义、0 地址、image base 和 target selection 门禁。

```bash
python tools/corpus/build_corpus.py

python tools/corpus/benchmark.py \
  --manifest tools/corpus/manifest.json \
  --root . --plugin-root . --mode auto \
  --timeout-seconds 60 \
  --json /tmp/miku-corpus.json \
  --csv /tmp/miku-corpus.csv

# 可重复指定精确 manifest target
python tools/corpus/benchmark.py \
  --manifest tools/corpus/manifest.json --root . --plugin-root . \
  --target tools/corpus/artifacts/nested--x86_64-gcc-o0-exe.bin@0x401116 \
  --json /tmp/one.json --csv /tmp/one.csv
```

benchmark 为每个函数新建 BinaryView，记录 before/after 的 block、edge、
instruction、operation counts 与文本 SHA-256，并输出 JSON/CSV。`--repeat` 用于
测量重复性；`--timeout-seconds` 是资源预算，超时只产生失败结果。

## 单元与静态门禁

```bash
python -m unittest \
  tools.tests.test_regression_gate \
  tools.corpus.tests.test_benchmark \
  tools.corpus.tests.test_index_samples

ruff check tools
git diff --check
```

环境变量：

- `BN_PYTHON`：默认 `/home/ltlly/tools/binaryninja/python`；
- `SAMPLE_DIR`：默认仓库的 `example/`。
