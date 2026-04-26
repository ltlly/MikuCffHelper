"""无头命令行去混淆工具：直接对二进制运行 MikuCffHelper 工作流并输出 HLIL，
不需要打开 Binary Ninja UI。

用法示例:
    # 单函数 (auto 模式，B 优先 / A 兜底)
    python tools/deflate_cli.py example/arm64-v8a.so --addr 0x4259f4

    # 二进制内所有 CFF 候选函数 (按启发式自动找)
    python tools/deflate_cli.py example/arm64-v8a.so --all-cff

    # 指定路径模式
    python tools/deflate_cli.py example/arm64-v8a.so --addr 0x4259f4 --mode switch

    # 输出到文件而非 stdout
    python tools/deflate_cli.py example/arm64-v8a.so --addr 0x4259f4 --out /tmp/out.c

    # 输出去混淆前的 HLIL (对照参考)
    python tools/deflate_cli.py example/arm64-v8a.so --addr 0x4259f4 --before

模式:
    auto    - workflow_patch_mlil_auto  (推荐)：先 B (synthesize_switch)，
              失败 fallback A (deflate_hard)
    switch  - workflow_patch_mlil_switch：只跑 B
    deflate - workflow_patch_mlil：只跑 A

环境变量:
    BN_PYTHON   Binary Ninja python 包目录 (默认 /home/ltlly/tools/binaryninja/python)
"""
import argparse
import os
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

MODES = {
    "auto": "analysis.plugins.workflow_patch_mlil_auto",
    "switch": "analysis.plugins.workflow_patch_mlil_switch",
    "deflate": "analysis.plugins.workflow_patch_mlil",
}


def setup_path():
    """让 import binaryninja 与 import plugins.MikuCffHelper 都能找到包"""
    bn_path = os.environ.get("BN_PYTHON", "/home/ltlly/tools/binaryninja/python")
    if bn_path not in sys.path:
        sys.path.insert(0, bn_path)
    bninja_root = REPO_ROOT.parent.parent  # = .binaryninja
    if str(bninja_root) not in sys.path:
        sys.path.insert(0, str(bninja_root))


def find_cff_funcs(bv, max_blocks=200):
    """返回二进制中所有疑似 CFF 函数列表 [(addr, name, blocks), ...]"""
    from plugins.MikuCffHelper.passes.mid.deflatHardPass import (
        _detect_dispatcher_entry,
        _collect_state_vars,
        _function_looks_like_cff,
    )
    out = []
    for f in bv.functions:
        if f.mlil is None or len(list(f.mlil.basic_blocks)) < 15:
            continue
        if len(list(f.mlil.basic_blocks)) > max_blocks:
            continue
        try:
            de = _detect_dispatcher_entry(f.mlil)
            if de is None:
                continue
            sv = _collect_state_vars(f.mlil, de)
            if not sv or not _function_looks_like_cff(f.mlil, sv):
                continue
            out.append((f.start, f.name, len(list(f.mlil.basic_blocks))))
        except Exception:
            pass
    return out


def hlil_text(func):
    """把函数的 HLIL 渲染成字符串"""
    if func.hlil is None:
        return "<no HLIL>"
    lines = []
    for instr in func.hlil.instructions:
        lines.append(str(instr))
    return "\n".join(lines)


def run_workflow(bv, func, mode_key):
    """对函数启用指定 activity，触发重分析并等待"""
    import binaryninja as bn
    activity = MODES[mode_key]
    settings = bn.Settings()
    settings.set_string(
        "analysis.workflows.functionWorkflow", "MikuCffHelper_workflow", func
    )
    wf = bn.Workflow("MikuCffHelper_workflow", object_handle=func.handle)
    wf._machine.override_set(activity, True)
    bv.reanalyze()
    bv.update_analysis_and_wait()


def emit_one(bv, func, mode, before_only):
    """跑一个函数，返回包含 (header, hlil_str, metrics) 的字典"""
    blocks_before = len(list(func.mlil.basic_blocks)) if func.mlil else 0
    if before_only:
        return {
            "header": f"// {func.name} @ 0x{func.start:x} (before, blocks={blocks_before})",
            "body": hlil_text(func),
            "blocks_before": blocks_before,
            "blocks_after": blocks_before,
            "time": 0.0,
        }
    t0 = time.time()
    run_workflow(bv, func, mode)
    elapsed = time.time() - t0
    blocks_after = len(list(func.mlil.basic_blocks)) if func.mlil else 0
    return {
        "header": (
            f"// {func.name} @ 0x{func.start:x} "
            f"({blocks_before}→{blocks_after} blocks, mode={mode}, t={elapsed:.1f}s)"
        ),
        "body": hlil_text(func),
        "blocks_before": blocks_before,
        "blocks_after": blocks_after,
        "time": elapsed,
    }


def main():
    ap = argparse.ArgumentParser(
        description="MikuCffHelper 无头命令行：去混淆并输出 HLIL"
    )
    ap.add_argument("binary", help="目标二进制文件路径 (.so / .elf / .exe …)")
    grp = ap.add_mutually_exclusive_group()
    grp.add_argument("--addr", help="单函数地址 (hex 或 dec)")
    grp.add_argument(
        "--all-cff", action="store_true",
        help="处理所有 CFF 候选函数 (按 Blazytko 启发式自动找)",
    )
    ap.add_argument(
        "--mode", choices=list(MODES.keys()), default="auto",
        help="工作流模式 (默认 auto)",
    )
    ap.add_argument(
        "--out", metavar="FILE",
        help="输出文件 (默认 stdout)",
    )
    ap.add_argument(
        "--before", action="store_true",
        help="只输出去混淆前 HLIL (调试 / 对照用，不跑工作流)",
    )
    ap.add_argument(
        "--max-blocks", type=int, default=200,
        help="--all-cff 模式：跳过块数超过此值的函数 (默认 200)",
    )
    args = ap.parse_args()

    if not args.addr and not args.all_cff:
        ap.error("必须指定 --addr 或 --all-cff")

    setup_path()
    import binaryninja as bn

    bin_path = Path(args.binary)
    if not bin_path.exists():
        print(f"[err] 二进制不存在: {bin_path}", file=sys.stderr)
        sys.exit(2)

    print(f"[load] {bin_path.name} (mode={args.mode})", file=sys.stderr, flush=True)
    bv = bn.load(str(bin_path), update_analysis=True)

    if args.all_cff:
        targets = find_cff_funcs(bv, max_blocks=args.max_blocks)
        print(f"[scan] 找到 {len(targets)} 个 CFF 候选", file=sys.stderr, flush=True)
        funcs = [bv.get_function_at(addr) for addr, _, _ in targets]
    else:
        addr = int(args.addr, 0)
        f = bv.get_function_at(addr)
        if f is None:
            print(f"[err] 0x{addr:x} 处没有函数", file=sys.stderr)
            bv.file.close()
            sys.exit(2)
        funcs = [f]

    out_handle = sys.stdout if not args.out else open(args.out, "w")
    try:
        for i, f in enumerate(funcs):
            if f is None:
                continue
            try:
                result = emit_one(bv, f, args.mode, args.before)
            except Exception as e:
                print(f"// {f.name} ERR: {e}", file=out_handle)
                continue
            if i > 0:
                print("\n" + "=" * 70 + "\n", file=out_handle)
            print(result["header"], file=out_handle)
            print(result["body"], file=out_handle)
            print(
                f"[done] {f.name} {result['blocks_before']}→{result['blocks_after']} "
                f"t={result['time']:.1f}s",
                file=sys.stderr, flush=True,
            )
    finally:
        if args.out:
            out_handle.close()
        bv.file.close()


if __name__ == "__main__":
    main()
