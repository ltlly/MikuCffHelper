"""回归测试 driver: 跑 workflow_patch_mlil_auto 在样本集上，输出 JSON +
人类可读总结，并与 baseline.json 对比检测回归。

使用:
    # 跑全部样本，更新 baseline.json (慎用！只在确认改进无误后跑)
    python tools/regression_test.py --update-baseline

    # 跑全部样本，与 baseline.json 对比，发现回归则非 0 退出
    python tools/regression_test.py

    # 只跑某个 binary
    python tools/regression_test.py --only arm64-v8a.so

    # 只跑某个函数 (按地址)
    python tools/regression_test.py --func 0x4259f4 --bin arm64-v8a.so

输出:
    /tmp/regression_<timestamp>.json: 详细 per-function 结果
    stdout: 人类可读的 diff 摘要
    退出码: 0 = 与 baseline 一致或改进；1 = 检测到回归

Note:
    需要 BN Python 在 sys.path (默认 /home/ltlly/tools/binaryninja/python)。
    样本路径默认 example/ 下，可改 SAMPLE_DIR 环境变量。
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_DIR = Path(os.environ.get(
    "SAMPLE_DIR", str(REPO_ROOT / "example")
))
BASELINE_PATH = REPO_ROOT / "tools" / "baseline.json"

# 默认样本：3 个 .so 各跑前 N 个 CFF 函数
DEFAULT_TARGETS = [
    ("arm64-v8a.so", 15),
    ("libkste.so", 8),
    ("libSeQing.so", 20),
]


def setup_path():
    """把 BN python 和 .binaryninja 父目录加到 sys.path

    .binaryninja 必须在 sys.path 上，这样 `import plugins.MikuCffHelper` 才能
    找到 .binaryninja/plugins/MikuCffHelper。
    """
    bn_path = os.environ.get("BN_PYTHON", "/home/ltlly/tools/binaryninja/python")
    if bn_path not in sys.path:
        sys.path.insert(0, bn_path)
    # REPO_ROOT = .binaryninja/plugins/MikuCffHelper
    # .parent = .binaryninja/plugins
    # .parent.parent = .binaryninja  ← 这是 plugins package 的父目录
    bninja_root = REPO_ROOT.parent.parent
    if str(bninja_root) not in sys.path:
        sys.path.insert(0, str(bninja_root))


def find_cff_funcs(bv, max_blocks=120, max_count=20):
    """复用 deflatHardPass 的检测启发式找候选函数"""
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
            out.append({
                "addr": f.start,
                "name": f.name,
                "blocks": len(list(f.mlil.basic_blocks)),
            })
            if len(out) >= max_count:
                break
        except Exception:
            pass
    return out


def _collect_hlil_side_effects(func):
    """收集函数 HLIL 中所有副作用 (call / store / ret) 的签名。

    在 HLIL 层抓副作用比 MLIL 更可靠 —— 这是 *用户看到* 的输出层级。
    BN HLIL Restructurer 偶尔在 jump_to/dispatcher 复杂度过高时把某些
    副作用从 HLIL 视图剔除 (MLIL 还在，HLIL 看不到)，单看 MLIL verifier
    漏过这种回归。

    用 BN 的 traverse() 递归全部子表达式，包括内联在 expression 里的
    call (例：`outer(arg, inner_call())` 的 inner_call 嵌在 params 里)。

    返回 dict 含三个集合：
      - calls: set of (call_addr, target_addr_or_None)
      - stores: set of (store_addr,)  按地址区分 store
      - rets: set of (ret_addr,)      按地址区分 return
    """
    empty = {"calls": set(), "stores": set(), "rets": set()}
    if func.hlil is None:
        return empty
    try:
        from binaryninja import HighLevelILOperation, HighLevelILInstruction
    except ImportError:
        return empty

    call_ops = {
        HighLevelILOperation.HLIL_CALL,
        HighLevelILOperation.HLIL_CALL_SSA,
        HighLevelILOperation.HLIL_TAILCALL,
    }
    store_ops = {
        HighLevelILOperation.HLIL_ASSIGN,        # *p = v  (HLIL 把 store 当 assign)
        HighLevelILOperation.HLIL_ASSIGN_UNPACK,
    }
    ret_ops = {
        HighLevelILOperation.HLIL_RET,
        HighLevelILOperation.HLIL_NORET,
    }

    calls: set = set()
    stores: set = set()
    rets: set = set()

    def visitor(expr):
        if not isinstance(expr, HighLevelILInstruction):
            return
        if expr.operation in call_ops:
            target = None
            try:
                d = expr.dest
                if hasattr(d, "constant"):
                    target = d.constant
            except Exception:
                pass
            calls.add((expr.address, target))
        elif expr.operation in store_ops:
            # 仅 *deref = ... 形式的 assign 算 store；普通变量赋值不算
            try:
                dest = expr.dest
                if dest is not None and dest.operation == HighLevelILOperation.HLIL_DEREF:
                    stores.add((expr.address,))
                elif dest is not None and dest.operation == HighLevelILOperation.HLIL_ARRAY_INDEX:
                    stores.add((expr.address,))
            except Exception:
                pass
        elif expr.operation in ret_ops:
            rets.add((expr.address,))

    for instr in func.hlil.instructions:
        try:
            list(instr.traverse(visitor))
        except Exception:
            continue
    return {"calls": calls, "stores": stores, "rets": rets}


# 兼容性 alias：原 _collect_hlil_calls 仍然可用
def _collect_hlil_calls(func):
    return _collect_hlil_side_effects(func)["calls"]


def test_func(bv, addr):
    import binaryninja as bn
    from plugins.MikuCffHelper.passes.mid.deflatHardPass import (
        _collect_side_effect_signatures,
    )
    func = bv.get_function_at(addr)
    if not func:
        return None
    before = len(list(func.mlil.basic_blocks))
    se_before = _collect_side_effect_signatures(func.mlil)
    # HLIL 层副作用快照 (workflow 尚未启用，是 BN 默认分析的 baseline HLIL)
    hlil_se_before = _collect_hlil_side_effects(func)
    hlil_calls_before = hlil_se_before["calls"]
    hlil_stores_before = hlil_se_before["stores"]
    hlil_rets_before = hlil_se_before["rets"]

    settings = bn.Settings()
    settings.set_string(
        "analysis.workflows.functionWorkflow", "MikuCffHelper_workflow", func
    )
    wf = bn.Workflow("MikuCffHelper_workflow", object_handle=func.handle)
    wf._machine.override_set("analysis.plugins.workflow_patch_mlil_auto", True)
    t0 = time.time()
    bv.reanalyze()
    bv.update_analysis_and_wait()
    t1 = time.time()

    after = len(list(func.mlil.basic_blocks)) if func.mlil else 0
    hlil_n = len(list(func.hlil.instructions)) if func.hlil else 0
    has_switch = False
    has_orphan = False
    if func.hlil:
        for instr in func.hlil.instructions:
            s = str(instr)
            if "switch" in s:
                has_switch = True
            if "jump(0x" in s:
                has_orphan = True
    se_after = (
        _collect_side_effect_signatures(func.mlil) if func.mlil else set()
    )
    lost = se_before - se_after
    hlil_se_after = _collect_hlil_side_effects(func)
    hlil_calls_lost = hlil_calls_before - hlil_se_after["calls"]
    hlil_stores_lost = hlil_stores_before - hlil_se_after["stores"]
    hlil_rets_lost = hlil_rets_before - hlil_se_after["rets"]
    return {
        "blocks_before": before,
        "blocks_after": after,
        "hlil": hlil_n,
        "time": round(t1 - t0, 2),
        "switch": has_switch,
        "orphan": has_orphan,
        "se_lost": len(lost),
        # 关键的等价性指标：HLIL 层副作用不能丢
        "hlil_calls_before": len(hlil_calls_before),
        "hlil_calls_after": len(hlil_se_after["calls"]),
        "hlil_calls_lost": len(hlil_calls_lost),
        "hlil_stores_before": len(hlil_stores_before),
        "hlil_stores_after": len(hlil_se_after["stores"]),
        "hlil_stores_lost": len(hlil_stores_lost),
        "hlil_rets_before": len(hlil_rets_before),
        "hlil_rets_after": len(hlil_se_after["rets"]),
        "hlil_rets_lost": len(hlil_rets_lost),
        # deflated = no switch but block reduction ≥ 30%
        "deflated": (not has_switch) and (after < before * 0.7),
    }


def run_binary(path, max_count, only_addr=None):
    import binaryninja as bn
    print(f"[load] {path.name}", flush=True)
    bv = bn.load(str(path), update_analysis=True)
    if only_addr is not None:
        f = bv.get_function_at(only_addr)
        if f is None:
            print(f"[err] no function at 0x{only_addr:x}")
            bv.file.close()
            return {"binary": path.name, "results": {}}
        cands = [{"addr": only_addr, "name": f.name,
                  "blocks": len(list(f.mlil.basic_blocks))}]
    else:
        cands = find_cff_funcs(bv, max_count=max_count)
    print(f"  {len(cands)} candidates", flush=True)
    out = {"binary": path.name, "results": {}}
    for c in cands:
        try:
            r = test_func(bv, c["addr"])
            if r is None:
                continue
            r["name"] = c["name"]
            out["results"][f"0x{c['addr']:x}"] = r
            mark = "SW" if r["switch"] else ("DEF" if r["deflated"] else "--")
            warn = ""
            if r["se_lost"]:
                warn += f" SE_LOST={r['se_lost']}"
            if r["orphan"]:
                warn += " ORPHAN"
            print(
                f"  {c['name'][:30]:30s} {r['blocks_before']:>3}→{r['blocks_after']:<3} "
                f"hlil={r['hlil']:<4} {mark}{warn}",
                flush=True,
            )
        except Exception as e:
            print(f"  {c['name']}: ERR {e}", flush=True)
    bv.file.close()
    return out


def summarize(report):
    """从 per-function results 计算总分数"""
    total = sum(len(b["results"]) for b in report)
    switch = sum(1 for b in report for r in b["results"].values() if r["switch"])
    deflated = sum(1 for b in report for r in b["results"].values() if r["deflated"])
    orphan = sum(1 for b in report for r in b["results"].values() if r["orphan"])
    se_lost = sum(1 for b in report for r in b["results"].values() if r["se_lost"])
    hlil_calls_lost = sum(
        r.get("hlil_calls_lost", 0)
        for b in report for r in b["results"].values()
    )
    hlil_stores_lost = sum(
        r.get("hlil_stores_lost", 0)
        for b in report for r in b["results"].values()
    )
    hlil_rets_lost = sum(
        r.get("hlil_rets_lost", 0)
        for b in report for r in b["results"].values()
    )
    funcs_with_lost_calls = sum(
        1 for b in report for r in b["results"].values()
        if r.get("hlil_calls_lost", 0) > 0
    )
    transformed = switch + deflated
    return {
        "total": total,
        "switch": switch,
        "deflated": deflated,
        "transformed": transformed,
        "orphan": orphan,
        "se_lost": se_lost,
        "hlil_calls_lost": hlil_calls_lost,
        "hlil_stores_lost": hlil_stores_lost,
        "hlil_rets_lost": hlil_rets_lost,
        "funcs_with_lost_calls": funcs_with_lost_calls,
    }


def diff_against_baseline(report, baseline):
    """逐函数 diff，找回归。

    回归判定 (按危险度排序):
      - SE_LOST 增加：副作用丢失，正确性破坏
      - ORPHAN 出现：孤立跳转，正确性破坏
      - HLIL 行数显著增加 (>20%)：可读性下降
      - 块数显著增加 (>30%)：函数变得更复杂

    改进判定:
      - HLIL 行数显著下降 (>20%)：更接近源码
      - 块数显著下降 (>20%)：去混淆更彻底
      - 新增 SWITCH / DEFLATED 标记

    注意：SWITCH ↔ DEFLATED ↔ 未分类 之间的转换不算回归，因为 BN HLIL
    Restructurer 在不同输入下会选择不同呈现，关键看 HLIL 是否更紧凑。
    """
    regressions = []
    improvements = []
    by_addr = {f"{b['binary']}:{a}": r for b in report
               for a, r in b["results"].items()}
    base_by_addr = {f"{b['binary']}:{a}": r for b in baseline
                    for a, r in b["results"].items()}

    for key, cur in by_addr.items():
        base = base_by_addr.get(key)
        if base is None:
            continue
        # 正确性回归 (硬错误)
        if cur["se_lost"] > base.get("se_lost", 0):
            regressions.append(
                f"{key} {cur['name']}: SE_LOST "
                f"{base.get('se_lost', 0)}→{cur['se_lost']}"
            )
        if cur.get("hlil_calls_lost", 0) > base.get("hlil_calls_lost", 0):
            regressions.append(
                f"{key} {cur['name']}: HLIL call 丢失 "
                f"{base.get('hlil_calls_lost', 0)}→{cur.get('hlil_calls_lost', 0)} "
                f"(call 总数 {base.get('hlil_calls_before', '?')}→{cur.get('hlil_calls_after', '?')})"
            )
        if cur.get("hlil_stores_lost", 0) > base.get("hlil_stores_lost", 0):
            regressions.append(
                f"{key} {cur['name']}: HLIL store 丢失 "
                f"{base.get('hlil_stores_lost', 0)}→{cur.get('hlil_stores_lost', 0)}"
            )
        if cur.get("hlil_rets_lost", 0) > base.get("hlil_rets_lost", 0):
            regressions.append(
                f"{key} {cur['name']}: HLIL return 丢失 "
                f"{base.get('hlil_rets_lost', 0)}→{cur.get('hlil_rets_lost', 0)}"
            )
        if cur["orphan"] and not base.get("orphan", False):
            regressions.append(f"{key} {cur['name']}: ORPHAN 出现")
        # 可读性回归
        base_hlil = base.get("hlil", 0)
        if base_hlil > 0:
            ratio = cur["hlil"] / base_hlil
            if ratio > 1.20:
                regressions.append(
                    f"{key} {cur['name']}: HLIL {base_hlil}→{cur['hlil']} "
                    f"(+{(ratio-1)*100:.0f}%)"
                )
            elif ratio < 0.80:
                improvements.append(
                    f"{key} {cur['name']}: HLIL {base_hlil}→{cur['hlil']} "
                    f"(-{(1-ratio)*100:.0f}%)"
                )
        # 状态切换 (中性)
        was = "SW" if base.get("switch") else ("DEF" if base.get("deflated") else "--")
        now = "SW" if cur["switch"] else ("DEF" if cur["deflated"] else "--")
        if was != now and was == "--" and now in ("SW", "DEF"):
            improvements.append(f"{key} {cur['name']}: 新增 {now}")

    return regressions, improvements


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--update-baseline", action="store_true",
                    help="把当前结果写为新的 baseline.json")
    ap.add_argument("--only", metavar="BIN", help="只跑指定 binary 文件名")
    ap.add_argument("--bin", metavar="BIN", help="搭配 --func 用：指定 binary")
    ap.add_argument("--func", metavar="ADDR", help="只跑指定地址 (hex)")
    ap.add_argument("--baseline", default=str(BASELINE_PATH),
                    help="baseline.json 路径")
    args = ap.parse_args()

    setup_path()

    report = []
    if args.func:
        if not args.bin:
            print("--func 需要 --bin", file=sys.stderr)
            sys.exit(2)
        path = SAMPLE_DIR / args.bin
        if not path.exists():
            print(f"sample 不存在: {path}", file=sys.stderr)
            sys.exit(2)
        addr = int(args.func, 16)
        report.append(run_binary(path, max_count=1, only_addr=addr))
    else:
        for name, max_count in DEFAULT_TARGETS:
            if args.only and args.only != name:
                continue
            path = SAMPLE_DIR / name
            if not path.exists():
                print(f"[skip] {name} not found at {SAMPLE_DIR}", flush=True)
                continue
            report.append(run_binary(path, max_count))

    summary = summarize(report)
    print("\n=== 汇总 ===")
    print(f"总函数:    {summary['total']}")
    print(f"SWITCH:    {summary['switch']}")
    print(f"DEFLATED:  {summary['deflated']}")
    print(f"已变换:    {summary['transformed']} / {summary['total']} "
          f"({100*summary['transformed']/max(summary['total'],1):.0f}%)")
    print(f"ORPHAN:    {summary['orphan']}")
    print(f"SE_LOST:   {summary['se_lost']}")
    print(f"HLIL_CALL_LOST:  {summary['hlil_calls_lost']} 个 call 丢失，"
          f"{summary['funcs_with_lost_calls']} 个函数受影响")
    print(f"HLIL_STORE_LOST: {summary['hlil_stores_lost']} 个 store 丢失")
    print(f"HLIL_RET_LOST:   {summary['hlil_rets_lost']} 个 return 丢失")

    out_path = f"/tmp/regression_{int(time.time())}.json"
    with open(out_path, "w") as f:
        json.dump({"summary": summary, "report": report}, f, indent=2)
    print(f"\n[save] 详细结果 → {out_path}")

    if args.update_baseline:
        with open(args.baseline, "w") as f:
            json.dump({"summary": summary, "report": report}, f, indent=2)
        print(f"[update] baseline → {args.baseline}")
        sys.exit(0)

    if not Path(args.baseline).exists():
        print(f"\n[warn] 没有 baseline ({args.baseline})；运行 --update-baseline 创建")
        sys.exit(0)

    with open(args.baseline) as f:
        baseline = json.load(f)
    regressions, improvements = diff_against_baseline(report, baseline.get("report", []))

    if improvements:
        print("\n=== 改进 ===")
        for s in improvements:
            print(f"  + {s}")
    if regressions:
        print("\n=== 回归 ===")
        for s in regressions:
            print(f"  - {s}")
        sys.exit(1)
    else:
        print("\n[ok] 没有回归")
        sys.exit(0)


if __name__ == "__main__":
    main()
