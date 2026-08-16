#!/usr/bin/env python3
"""收集/扫描 CFF 样本：对一批二进制跑 MikuCffHelper 的检测器，输出样本清单。

检测分两档：
  - fast (默认)：_detect_dispatcher_entry (Blazytko 支配树) + _collect_state_vars
    + _function_looks_like_cff，与路径 A/B 实际使用的门控一致，速度快。
  - slow (--slow-state)：dispatcher 命中后用 StateMachine.find_state_var 找
    状态变量，能覆盖 _collect_state_vars 漏掉的样本（例如 cdong 的 x86 样本），
    但会全函数重扫，大库慢很多。

用法：
  # 扫描单个/多个文件或目录（目录只递归 *.so/*.elf/*.exe/*.bin）
  python tools/collect_cff_samples.py samples/raw/obpo-samples -o /tmp/m.json

  # 覆盖仓库清单 samples/manifest.json（提交前用）
  python tools/collect_cff_samples.py samples/raw -o samples/manifest.json

依赖 BN_PYTHON 环境变量（默认 /home/ltlly/tools/binaryninja/python）。
"""
import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BIN_EXTS = {".so", ".elf", ".elf64", ".exe", ".dll", ".bin"}


def setup_path():
    bn_path = os.environ.get("BN_PYTHON", "/home/ltlly/tools/binaryninja/python")
    if bn_path not in sys.path:
        sys.path.insert(0, bn_path)
    bninja_root = str(REPO_ROOT.parent.parent)  # .binaryninja
    if bninja_root not in sys.path:
        sys.path.insert(0, str(bninja_root))


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def collect_targets(paths):
    files = set()
    for p in paths:
        p = Path(p)
        if p.is_dir():
            for root, _dirs, names in os.walk(p):
                for n in names:
                    fp = Path(root) / n
                    if fp.suffix.lower() in BIN_EXTS and not n.startswith("."):
                        files.add(fp)
        elif p.is_file():
            files.add(p)
    return sorted(files)


def detect_candidates(bv, slow_state=False, min_blocks=15, max_blocks=200):
    """返回 [(addr, name, blocks, dispatcher_start)]，失败/非 CFF 被过滤。"""
    import binaryninja as bn  # noqa: F401

    from plugins.MikuCffHelper.passes.mid.deflatHardPass import (
        _collect_state_vars,
        _detect_dispatcher_entry,
        _function_looks_like_cff,
    )
    from plugins.MikuCffHelper.utils.state_machine import StateMachine

    out = []
    for f in bv.functions:
        try:
            mlil = f.mlil
            if mlil is None:
                continue
            n = len(list(mlil.basic_blocks))
            if n < min_blocks or n > max_blocks:
                continue
            de = _detect_dispatcher_entry(mlil)
            if de is None:
                continue
            sv = _collect_state_vars(mlil, de)
            if slow_state and not sv:
                sv = StateMachine.find_state_var(f)
            if not sv or not _function_looks_like_cff(mlil, sv):
                continue
            out.append((f.start, f.name, n, de.start))
        except Exception:
            continue
    return out


def scan_one(bv, path, slow_state, min_blocks, max_blocks):
    entry = {
        "path": str(Path(path).resolve().relative_to(REPO_ROOT)),
        "sha256": sha256(Path(path)),
        "size": os.path.getsize(path),
        "arch": str(bv.arch) if bv.arch else None,
        "platform": str(bv.platform) if bv.platform else None,
        "candidates": [],
    }
    for addr, name, blocks, disp in detect_candidates(
        bv, slow_state=slow_state, min_blocks=min_blocks, max_blocks=max_blocks
    ):
        entry["candidates"].append(
            {
                "addr": addr,
                "name": name,
                "blocks": blocks,
                "dispatcher": disp,
            }
        )
    entry["candidate_count"] = len(entry["candidates"])
    return entry


def load_config_entries(path: Path):
    """解析 obpo 风格 .config.json，返回 (func 数, dispatcher 数)。"""
    try:
        cfg = json.loads(path.read_text())
    except Exception:
        return None
    funcs = {e.get("func") for e in cfg if isinstance(e, dict)}
    dispatchers = sum(len(e.get("dispatchers", [])) for e in cfg if isinstance(e, dict))
    return {"ground_truth_funcs": len(funcs), "ground_truth_dispatchers": dispatchers}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("inputs", nargs="+", help="二进制文件或目录")
    ap.add_argument("-o", "--out", default=str(REPO_ROOT / "samples" / "manifest.json"))
    ap.add_argument("--slow-state", action="store_true")
    ap.add_argument("--min-blocks", type=int, default=15)
    ap.add_argument("--max-blocks", type=int, default=200)
    ap.add_argument("--merge", action="store_true", help="与已有清单按 sha256 合并")
    args = ap.parse_args()

    setup_path()
    import binaryninja as bn

    targets = collect_targets(args.inputs)
    print(f"[collect] {len(targets)} binaries", file=sys.stderr, flush=True)

    entries = []
    for i, path in enumerate(targets):
        t0 = time.time()
        try:
            bv = bn.load(str(path), update_analysis=True)
        except Exception as e:
            print(f"[err] {path}: {e}", file=sys.stderr, flush=True)
            continue
        try:
            entry = scan_one(
                bv, path, args.slow_state, args.min_blocks, args.max_blocks
            )
        finally:
            try:
                bv.file.close()
            except Exception:
                pass
        cfg_path = Path(str(path) + ".config.json")
        if cfg_path.exists():
            entry["ground_truth"] = load_config_entries(cfg_path)
        entries.append(entry)
        print(
            f"[{i+1}/{len(targets)}] {entry['path']} "
            f"cands={entry['candidate_count']} "
            f"({entry['arch']}/{entry['platform']}) t={time.time()-t0:.1f}s",
            file=sys.stderr,
            flush=True,
        )

    if args.merge and os.path.exists(args.out):
        old = json.loads(Path(args.out).read_text())
        old_entries = old.get("entries", []) if isinstance(old, dict) else old
        by_sha = {e["sha256"]: e for e in old_entries}
        for e in entries:
            by_sha[e["sha256"]] = e
        entries = sorted(by_sha.values(), key=lambda e: e["path"])

    manifest = {
        "generated_by": "tools/collect_cff_samples.py",
        "slow_state": args.slow_state,
        "min_blocks": args.min_blocks,
        "max_blocks": args.max_blocks,
        "entries": entries,
    }
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(manifest, indent=2, ensure_ascii=False))
    print(f"[save] {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
