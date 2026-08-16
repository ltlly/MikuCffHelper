"""多模式 × 多维可读性评估工具。

对同一函数在 fresh BinaryView 上分别跑 auto / general（可扩展），记录：
- 变换前后 MLIL 块数/边数/圈复杂度/分支数；
- HLIL 行数、if/loop/goto/jump/switch/case/call 数、表达式最大深度；
- 语义副作用丢失（地址无关 multiset）；
- orphan jump。

输出 JSON，供后续用 Pareto / 可配置权重做 trial 选择，而不是在源码里
硬编码“哪个函数该走哪条路径”。

用法:
    python tools/eval_modes.py --baseline-targets --out /tmp/eval_baseline.json
    python tools/eval_modes.py example/arm64-v8a.so --scan --max-funcs 20
    python tools/eval_modes.py example/cff-arm64-v8a.elf --addr 0x400698
"""

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from regression_test import (
    _collect_hlil_side_effects_semantic,
    setup_path,
    REPO_ROOT,
)

setup_path()

import binaryninja as bn  # noqa: E402

from plugins.MikuCffHelper.passes.mid.deflatHardPass import (  # noqa: E402
    _collect_side_effect_signatures_semantic,
)
from plugins.MikuCffHelper.utils.readability import (  # noqa: E402
    ReadabilityMetrics,
    default_penalty,
    dominates,
    readability_for_function,
)

MODES = {
    "auto": ("MikuCffHelper_workflow", "analysis.plugins.workflow_patch_mlil_auto"),
    "general": ("MikuCffHelper_general_workflow", "analysis.plugins.workflow_patch_mlil_general"),
}


def _counter_loss(before, after) -> int:
    if hasattr(before, "items"):
        return sum(max(c - after.get(k, 0), 0) for k, c in before.items())
    return max(0, before - after)


def run_one_mode(path: str, addr: int, mode: str):
    workflow_name, activity = MODES[mode]
    t0 = time.time()
    bv = bn.load(path, update_analysis=True)
    try:
        func = bv.get_function_at(addr)
        if func is None:
            return {"error": "no function"}
        before = readability_for_function(func).as_dict()
        se0 = _collect_side_effect_signatures_semantic(func.mlil)
        h0 = _collect_hlil_side_effects_semantic(func)
        settings = bn.Settings()
        settings.set_string(
            "analysis.workflows.functionWorkflow", workflow_name, func
        )
        wf = bn.Workflow(workflow_name, object_handle=func.handle)
        wf._machine.override_set(activity, True)
        bv.reanalyze()
        bv.update_analysis_and_wait()
        after = readability_for_function(func).as_dict()
        if after["hlil_lines"] == 0 and before["hlil_lines"] > 0:
            return {"error": "HLIL 未生成（函数过大或超时）"}
        se1 = _collect_side_effect_signatures_semantic(func.mlil)
        h1 = _collect_hlil_side_effects_semantic(func)
        text = "\n".join(str(x) for x in func.hlil.instructions) if func.hlil else ""
        return {
            "before": before,
            "after": after,
            "se_lost": _counter_loss(se0, se1),
            "calls_lost": _counter_loss(h0["calls"], h1["calls"]),
            "stores_lost": _counter_loss(h0["stores"], h1["stores"]),
            "rets_lost": _counter_loss(h0["rets"], h1["rets"]),
            "orphan": "jump(0x" in text,
            "time": round(time.time() - t0, 2),
        }
    finally:
        bv.file.close()


def baseline_targets():
    baseline = json.load(open(REPO_ROOT / "tools" / "baseline.json"))
    out = []
    for bres in baseline["report"]:
        for addr in bres["results"]:
            out.append((str(REPO_ROOT / "example" / bres["binary"]), int(addr, 16)))
    return out


def scan_targets(path: str, max_funcs: int):
    from plugins.MikuCffHelper.passes.mid.deflatHardPass import (
        _detect_dispatcher_entry,
        _collect_state_vars,
        _function_looks_like_cff,
    )

    bv = bn.load(path, update_analysis=True)
    targets = []
    try:
        for f in bv.functions:
            if len(targets) >= max_funcs:
                break
            blocks = len(list(f.mlil.basic_blocks)) if f.mlil else 0
            if f.mlil is None or blocks < 15 or blocks > 120:
                continue
            try:
                de = _detect_dispatcher_entry(f.mlil)
                if de is None:
                    continue
                sv = _collect_state_vars(f.mlil, de)
                if not sv or not _function_looks_like_cff(f.mlil, sv):
                    continue
            except Exception:
                continue
            targets.append((path, f.start))
    finally:
        bv.file.close()
    return targets


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary", nargs="?")
    group = ap.add_mutually_exclusive_group()
    group.add_argument("--addr", help="单个函数地址")
    group.add_argument("--scan", action="store_true", help="扫描 binary 中的 CFF 候选")
    group.add_argument("--baseline-targets", action="store_true", help="39 函数基线目标")
    ap.add_argument("--modes", default="auto,general", help="逗号分隔模式")
    ap.add_argument("--max-funcs", type=int, default=20)
    ap.add_argument("--out", default="/tmp/eval_modes.json")
    args = ap.parse_args()

    modes = [m for m in args.modes.split(",") if m in MODES]
    if args.baseline_targets:
        targets = baseline_targets()
    elif args.scan:
        if not args.binary:
            ap.error("--scan 需要 binary")
        targets = scan_targets(args.binary, args.max_funcs)
    else:
        if not args.binary or not args.addr:
            ap.error("需要 --addr 或 --scan 或 --baseline-targets")
        targets = [(args.binary, int(args.addr, 0))]

    out = []
    for idx, (path, addr) in enumerate(targets, 1):
        row = {"path": path, "addr": hex(addr), "modes": {}}
        print(f"[{idx}/{len(targets)}] {Path(path).name} 0x{addr:x}", flush=True)
        for mode in modes:
            try:
                row["modes"][mode] = run_one_mode(path, addr, mode)
                r = row["modes"][mode]
                if "error" in r:
                    print(f"  {mode}: {r['error']}", flush=True)
                else:
                    b, a = r["before"], r["after"]
                    print(
                        f"  {mode}: blocks {b['mlil_blocks']}->{a['mlil_blocks']} "
                        f"cyc {b['mlil_cyclomatic']}->{a['mlil_cyclomatic']} "
                        f"lines {b['hlil_lines']}->{a['hlil_lines']} "
                        f"goto {a['hlil_goto']} switch {a['hlil_switch']} "
                        f"t={r['time']}s loss="
                        f"{r['se_lost']}+{r['calls_lost']}+{r['stores_lost']}+{r['rets_lost']}",
                        flush=True,
                    )
            except Exception as e:
                row["modes"][mode] = {"error": repr(e)}
                print(f"  {mode}: ERR {e}", flush=True)
        # 实际试跑后的选择：先排除错误/丢失/orphan，再 Pareto，再罚分
        valid = {}
        for mode in modes:
            r = row["modes"].get(mode, {})
            if "error" in r or not r:
                continue
            if (
                r.get("se_lost")
                or r.get("calls_lost")
                or r.get("stores_lost")
                or r.get("rets_lost")
                or r.get("orphan")
            ):
                continue
            valid[mode] = ReadabilityMetrics(**r["after"])
        best = None
        reason = "no_valid"
        if valid:
            for mode, metric in valid.items():
                other = next((m for m in valid if m != mode), None)
                if other is not None and dominates(metric, valid[other]):
                    best, reason = mode, "pareto"
                    break
            if best is None and len(valid) == 1:
                best, reason = next(iter(valid.items()))
                best, reason = best, "only_valid"
            if best is None:
                best = min(valid, key=lambda m: default_penalty(valid[m]))
                reason = "penalty"
        row["best"] = {"mode": best, "reason": reason}
        print(f"  => best={best} ({reason})", flush=True)
        out.append(row)

    with open(args.out, "w") as fh:
        json.dump(out, fh, indent=1)
    print(f"[saved] {args.out}")


if __name__ == "__main__":
    main()
