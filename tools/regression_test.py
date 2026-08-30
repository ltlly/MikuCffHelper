"""MikuCffHelper 严格、可复现回归门禁。

默认测试集合来自 ``baseline.json`` 内固定的样本 SHA-256 与函数地址 manifest，
不再通过启发式重新发现“前 N 个候选”。样本变化、函数/结果缺失、未知结果、
异常、超时、副作用丢失和 orphan jump 都会令进程非零退出。

兼容原命令：
    python tools/regression_test.py
    python tools/regression_test.py --only arm64-v8a.so
    python tools/regression_test.py --func 0x4259f4 --bin arm64-v8a.so
    python tools/regression_test.py --update-baseline

每次动态运行同时输出 JSON（完整 before/after 证据）和 CSV（逐函数摘要）。
这些检查是严格回归门禁，不是完整程序等价性证明。
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib
import json
import os
import platform
import re
import signal
import sys
import time
import traceback
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Mapping, Optional, Sequence, Set, Tuple


REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_DIR = Path(os.environ.get("SAMPLE_DIR", str(REPO_ROOT / "example")))
BASELINE_PATH = REPO_ROOT / "tools" / "baseline.json"
REPORT_SCHEMA_VERSION = 2
BASELINE_SCHEMA_VERSION = 2

_ORPHAN_RE = re.compile(r"\bjump\(0x[0-9a-fA-F]+\)")
_MLIL_CALL_OPS = {
    "MLIL_CALL", "MLIL_CALL_UNTYPED", "MLIL_CALL_SSA",
    "MLIL_CALL_UNTYPED_SSA", "MLIL_TAILCALL", "MLIL_TAILCALL_UNTYPED",
    "MLIL_TAILCALL_SSA", "MLIL_TAILCALL_UNTYPED_SSA", "MLIL_SYSCALL",
    "MLIL_SYSCALL_UNTYPED", "MLIL_SYSCALL_SSA", "MLIL_SYSCALL_UNTYPED_SSA",
}
_MLIL_STORE_OPS = {
    "MLIL_STORE", "MLIL_STORE_SSA", "MLIL_STORE_STRUCT", "MLIL_STORE_STRUCT_SSA",
}
_MLIL_RET_OPS = {"MLIL_RET", "MLIL_RET_HINT", "MLIL_NORET"}
_MLIL_OTHER_EFFECT_OPS = {
    "MLIL_INTRINSIC", "MLIL_INTRINSIC_SSA", "MLIL_MEMORY_INTRINSIC_SSA",
    "MLIL_TRAP", "MLIL_BP", "MLIL_UNIMPL_MEM",
}
_HLIL_CALL_OPS = {"HLIL_CALL", "HLIL_CALL_SSA", "HLIL_TAILCALL"}
_HLIL_RET_OPS = {"HLIL_RET", "HLIL_NORET"}
_HLIL_STORE_DEST_OPS = {"HLIL_DEREF", "HLIL_ARRAY_INDEX"}
_ABSOLUTE_EFFECT_FIELDS = {
    "se_lost": "MLIL 副作用丢失",
    "mlil_calls_lost": "MLIL call 丢失",
    "mlil_stores_lost": "MLIL store 丢失",
    "mlil_rets_lost": "MLIL return 丢失",
    "hlil_calls_lost": "HLIL call 丢失",
    "hlil_stores_lost": "HLIL store 丢失",
    "hlil_rets_lost": "HLIL return 丢失",
    "se_added": "MLIL 副作用新增",
    "mlil_calls_added": "MLIL call 新增",
    "mlil_stores_added": "MLIL store 新增",
    "mlil_rets_added": "MLIL return 新增",
}


class FunctionTimeout(TimeoutError):
    pass


def _normalize_addr(value: Any) -> str:
    number = value if isinstance(value, int) else int(str(value).strip(), 0)
    if number < 0:
        raise ValueError(f"负函数地址: {value!r}")
    return f"0x{number:x}"


def _result_key(binary: str, address: Any) -> str:
    return f"{binary}:{_normalize_addr(address)}"


def setup_path() -> None:
    """优先加载当前工作区，并默认关闭 BN 用户目录插件自动加载。"""
    os.environ.setdefault("BN_DISABLE_USER_PLUGINS", "1")
    bn_path = os.environ.get("BN_PYTHON", "/home/ltlly/tools/binaryninja/python")
    workspace_parent = str(REPO_ROOT.parent)
    for path in (bn_path, workspace_parent):
        if path in sys.path:
            sys.path.remove(path)
    sys.path.insert(0, bn_path)
    sys.path.insert(0, workspace_parent)


def _load_workspace_plugin():
    plugin = importlib.import_module("MikuCffHelper")
    actual = Path(plugin.__file__).resolve().parent
    expected = REPO_ROOT.resolve()
    if actual != expected:
        raise RuntimeError(f"加载的不是当前工作区插件: expected={expected}, actual={actual}")
    return plugin


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _manifest_index(
    manifest: Mapping[str, Any],
) -> Tuple[Dict[str, Dict[str, Any]], List[str]]:
    errors: List[str] = []
    samples = manifest.get("samples")
    if not isinstance(samples, list) or not samples:
        return {}, ["manifest.samples 必须是非空列表"]
    timeout = manifest.get("function_timeout_seconds")
    if not isinstance(timeout, (int, float)) or timeout <= 0:
        errors.append("manifest.function_timeout_seconds 必须为正数")
    index: Dict[str, Dict[str, Any]] = {}
    all_keys: Set[str] = set()
    for position, raw in enumerate(samples):
        if not isinstance(raw, dict):
            errors.append(f"manifest.samples[{position}] 不是对象")
            continue
        binary = raw.get("binary")
        sample_hash = raw.get("sha256")
        functions = raw.get("functions")
        if not isinstance(binary, str) or not binary:
            errors.append(f"manifest.samples[{position}].binary 无效")
            continue
        if binary in index:
            errors.append(f"manifest binary 重复: {binary}")
            continue
        if not isinstance(sample_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", sample_hash):
            errors.append(f"{binary}: sha256 必须是 64 位小写十六进制")
        if not isinstance(functions, list) or not functions:
            errors.append(f"{binary}: functions 必须是非空列表")
            functions = []
        normalized: List[str] = []
        for raw_addr in functions:
            try:
                address = _normalize_addr(raw_addr)
            except (TypeError, ValueError) as exc:
                errors.append(f"{binary}: 地址 {raw_addr!r} 无效: {exc}")
                continue
            key = _result_key(binary, address)
            if key in all_keys:
                errors.append(f"manifest 函数重复: {key}")
                continue
            all_keys.add(key)
            normalized.append(address)
        index[binary] = {
            "binary": binary,
            "sha256": sample_hash,
            "functions": normalized,
        }
    return index, errors


def manifest_keys(manifest: Mapping[str, Any]) -> Set[str]:
    index, errors = _manifest_index(manifest)
    if errors:
        raise ValueError("; ".join(errors))
    return {
        _result_key(binary, address)
        for binary, sample in index.items()
        for address in sample["functions"]
    }


def _index_report(
    report: Sequence[Mapping[str, Any]],
) -> Tuple[Dict[str, Dict[str, Any]], List[str]]:
    indexed: Dict[str, Dict[str, Any]] = {}
    errors: List[str] = []
    for row in report:
        binary = row.get("binary")
        results = row.get("results")
        if not isinstance(binary, str) or not isinstance(results, dict):
            errors.append(f"非法 report row: {row!r}")
            continue
        for raw_addr, raw_result in results.items():
            try:
                key = _result_key(binary, raw_addr)
            except (TypeError, ValueError) as exc:
                errors.append(f"{binary}:{raw_addr}: 非法地址: {exc}")
                continue
            if key in indexed:
                errors.append(f"report 结果重复: {key}")
                continue
            if not isinstance(raw_result, dict):
                errors.append(f"{key}: result 不是对象")
                continue
            indexed[key] = dict(raw_result)
    return indexed, errors


def absolute_safety_violations(
    key: str, result: Mapping[str, Any]
) -> List[str]:
    violations: List[str] = []
    status = result.get("status", "ok")
    if status != "ok":
        detail = result.get("error") or result.get("reason") or "无详情"
        return [f"{key}: status={status}: {detail}"]
    if bool(result.get("orphan", False)):
        violations.append(f"{key}: ORPHAN 出现")
    for field, label in _ABSOLUTE_EFFECT_FIELDS.items():
        raw_value = result.get(field, 0)
        try:
            value = int(raw_value)
        except (TypeError, ValueError):
            violations.append(f"{key}: {field} 不是整数: {raw_value!r}")
            continue
        if value > 0:
            violations.append(f"{key}: {label} {value}")
    return violations


def validate_baseline_document(baseline: Mapping[str, Any]) -> List[str]:
    errors: List[str] = []
    if baseline.get("schema_version") != BASELINE_SCHEMA_VERSION:
        errors.append(
            f"baseline schema_version 必须为 {BASELINE_SCHEMA_VERSION}，"
            f"实际为 {baseline.get('schema_version')!r}"
        )
    manifest = baseline.get("manifest")
    if not isinstance(manifest, dict):
        return errors + ["baseline 缺少 manifest 对象"]
    _, manifest_errors = _manifest_index(manifest)
    errors.extend(manifest_errors)
    report = baseline.get("report")
    if not isinstance(report, list):
        return errors + ["baseline.report 必须是列表"]
    base_map, report_errors = _index_report(report)
    errors.extend(report_errors)
    if not manifest_errors:
        expected = manifest_keys(manifest)
        actual = set(base_map)
        errors.extend(
            f"baseline 缺失 manifest 函数: {key}"
            for key in sorted(expected - actual)
        )
        errors.extend(
            f"baseline 存在 manifest 外函数: {key}"
            for key in sorted(actual - expected)
        )
    for key, result in base_map.items():
        errors.extend(
            f"baseline 不得固化不安全结果: {message}"
            for message in absolute_safety_violations(key, result)
        )
    return errors


def _compare_result_to_baseline(
    key: str, current: Mapping[str, Any], base: Mapping[str, Any]
) -> Tuple[List[str], List[str]]:
    regressions: List[str] = []
    improvements: List[str] = []
    base_hlil = int(base.get("hlil", 0) or 0)
    current_hlil = int(current.get("hlil", 0) or 0)
    if base_hlil > 0:
        if current_hlil > base_hlil:
            regressions.append(
                f"{key}: HLIL {base_hlil}→{current_hlil} "
                f"(+{current_hlil - base_hlil})"
            )
        elif current_hlil < base_hlil:
            improvements.append(
                f"{key}: HLIL {base_hlil}→{current_hlil} "
                f"(-{base_hlil - current_hlil})"
            )
    was = "SW" if base.get("switch") else ("DEF" if base.get("deflated") else "--")
    now = "SW" if current.get("switch") else ("DEF" if current.get("deflated") else "--")
    if was == "--" and now in {"SW", "DEF"}:
        improvements.append(f"{key}: 新增 {now}")
    return regressions, improvements


def diff_against_baseline(
    report: Sequence[Mapping[str, Any]], baseline: Sequence[Mapping[str, Any]]
) -> Tuple[List[str], List[str]]:
    """兼容旧 API；现在严格检查空报告、缺失/未知 key 和绝对安全错误。"""
    regressions: List[str] = []
    improvements: List[str] = []
    current_map, current_errors = _index_report(report)
    base_map, base_errors = _index_report(baseline)
    regressions.extend(current_errors)
    regressions.extend(base_errors)
    regressions.extend(
        f"当前报告缺失 baseline 函数: {key}"
        for key in sorted(set(base_map) - set(current_map))
    )
    regressions.extend(
        f"当前报告出现 baseline 外函数: {key}"
        for key in sorted(set(current_map) - set(base_map))
    )
    for key, current in sorted(current_map.items()):
        regressions.extend(absolute_safety_violations(key, current))
        base = base_map.get(key)
        if base is None or current.get("status", "ok") != "ok":
            continue
        reg, imp = _compare_result_to_baseline(key, current, base)
        regressions.extend(reg)
        improvements.extend(imp)
    return list(dict.fromkeys(regressions)), list(dict.fromkeys(improvements))


def validate_current_report(
    report: Sequence[Mapping[str, Any]],
    expected_keys: Set[str],
    *,
    allow_unmanifested: bool = False,
    manifest_key_set: Optional[Set[str]] = None,
) -> List[str]:
    errors: List[str] = []
    current_map, index_errors = _index_report(report)
    errors.extend(index_errors)
    actual = set(current_map)
    errors.extend(
        f"当前报告缺失预期函数: {key}" for key in sorted(expected_keys - actual)
    )
    errors.extend(
        f"当前报告出现未请求函数: {key}" for key in sorted(actual - expected_keys)
    )
    if manifest_key_set is not None and not allow_unmanifested:
        errors.extend(
            f"请求了 manifest 外函数: {key}"
            for key in sorted(expected_keys - manifest_key_set)
        )
    for key, result in sorted(current_map.items()):
        errors.extend(absolute_safety_violations(key, result))
    return list(dict.fromkeys(errors))


def evaluate_gate(
    report: Sequence[Mapping[str, Any]],
    baseline: Mapping[str, Any],
    expected_keys: Optional[Set[str]] = None,
    *,
    allow_unmanifested: bool = False,
) -> Tuple[List[str], List[str], List[str]]:
    """纯 Python 门禁判定；单元测试不需要 Binary Ninja。"""
    errors = validate_baseline_document(baseline)
    improvements: List[str] = []
    warnings: List[str] = []
    manifest = baseline.get("manifest") if isinstance(baseline, dict) else None
    if not isinstance(manifest, dict):
        return errors, improvements, warnings
    manifest_set = manifest_keys(manifest)
    expected = set(manifest_set if expected_keys is None else expected_keys)
    errors.extend(
        validate_current_report(
            report,
            expected,
            allow_unmanifested=allow_unmanifested,
            manifest_key_set=manifest_set,
        )
    )
    current_map, _ = _index_report(report)
    base_map, _ = _index_report(baseline.get("report", []))
    for key in sorted(expected):
        current = current_map.get(key)
        base = base_map.get(key)
        if current is None:
            continue
        if base is None:
            if not allow_unmanifested:
                errors.append(f"baseline 没有当前函数: {key}")
            continue
        if current.get("status", "ok") != "ok":
            continue
        reg, imp = _compare_result_to_baseline(key, current, base)
        errors.extend(reg)
        improvements.extend(imp)
        delta = current.get("ordered_effect_delta", {})
        if isinstance(delta, dict):
            for layer in ("mlil", "hlil"):
                layer_delta = delta.get(layer, {})
                if isinstance(layer_delta, dict) and not layer_delta.get("ordered_exact", True):
                    warnings.append(f"{key}: {layer.upper()} effect 线性顺序变化（仅诊断）")
    return (
        list(dict.fromkeys(errors)),
        list(dict.fromkeys(improvements)),
        list(dict.fromkeys(warnings)),
    )


def _operation_name(instr: Any) -> str:
    operation = getattr(instr, "operation", None)
    return getattr(operation, "name", str(operation))


def _effect_category(layer: str, instr: Any) -> Optional[str]:
    name = _operation_name(instr)
    if layer == "mlil":
        if name in _MLIL_CALL_OPS:
            return "call"
        if name in _MLIL_STORE_OPS:
            return "store"
        if name in _MLIL_RET_OPS:
            return "ret"
        if name in _MLIL_OTHER_EFFECT_OPS:
            return "other"
        return None
    if name in _HLIL_CALL_OPS:
        return "call"
    if name in _HLIL_RET_OPS:
        return "ret"
    if name in {"HLIL_ASSIGN", "HLIL_ASSIGN_UNPACK"}:
        dest = getattr(instr, "dest", None)
        if dest is not None and _operation_name(dest) in _HLIL_STORE_DEST_OPS:
            return "store"
    return None


def _effect_semantics(category: str, instr: Any) -> Dict[str, Any]:
    semantics: Dict[str, Any] = {}
    if category == "call":
        dest = getattr(instr, "dest", None)
        constant = getattr(dest, "constant", None) if dest is not None else None
        semantics["target"] = int(constant) if isinstance(constant, int) else None
        params = getattr(instr, "params", None)
        if params is not None:
            semantics["params"] = [str(param) for param in params]
    elif category == "store":
        dest = getattr(instr, "dest", None)
        src = getattr(instr, "src", None)
        semantics["dest"] = None if dest is None else str(dest)
        semantics["value"] = None if src is None else str(src)
    elif category == "ret":
        src = getattr(instr, "src", None)
        if src is not None:
            values = src if isinstance(src, (list, tuple)) else [src]
            semantics["values"] = [str(value) for value in values]
    return semantics


def _collect_ordered_effects(il: Any, layer: str) -> List[Dict[str, Any]]:
    """递归收集副作用，保留出现次数及 IL 线性遍历顺序。"""
    from binaryninja import HighLevelILInstruction, MediumLevelILInstruction

    instruction_type = (
        MediumLevelILInstruction if layer == "mlil" else HighLevelILInstruction
    )
    effects: List[Dict[str, Any]] = []
    for top_order, top in enumerate(il.instructions):
        traversal_order = 0

        def visitor(expr: Any) -> None:
            nonlocal traversal_order
            current_order = traversal_order
            traversal_order += 1
            if not isinstance(expr, instruction_type):
                return
            category = _effect_category(layer, expr)
            if category is None:
                return
            address = getattr(expr, "address", None)
            effects.append(
                {
                    "ordinal": len(effects),
                    "top_order": top_order,
                    "traversal_order": current_order,
                    "category": category,
                    "operation": _operation_name(expr),
                    "address": (
                        f"0x{int(address):x}" if isinstance(address, int) else None
                    ),
                    "text": str(expr),
                    "semantics": _effect_semantics(category, expr),
                }
            )

        list(top.traverse(visitor))
    return effects


def _collect_hlil_side_effects(func: Any) -> Dict[str, Set[Tuple[Any, ...]]]:
    """兼容原调用者的集合视图；报告内部使用 ordered effects。"""
    empty: Dict[str, Set[Tuple[Any, ...]]] = {
        "calls": set(), "stores": set(), "rets": set()
    }
    if func.hlil is None:
        return empty
    effects = _collect_ordered_effects(func.hlil, "hlil")
    calls = {
        (int(effect["address"], 16), effect["semantics"].get("target"))
        for effect in effects
        if effect["category"] == "call" and effect["address"] is not None
    }
    stores = {
        (int(effect["address"], 16),)
        for effect in effects
        if effect["category"] == "store" and effect["address"] is not None
    }
    rets = {
        (int(effect["address"], 16),)
        for effect in effects
        if effect["category"] == "ret" and effect["address"] is not None
    }
    return {"calls": calls, "stores": stores, "rets": rets}


def _collect_hlil_calls(func: Any) -> Set[Tuple[Any, ...]]:
    return _collect_hlil_side_effects(func)["calls"]


def _effect_signature(effect: Mapping[str, Any]) -> Tuple[Any, ...]:
    # 地址/op/类别跨 SSA 重排较稳定；Counter 额外保留出现次数。
    return (effect.get("category"), effect.get("operation"), effect.get("address"))


def _counter_records(counter: Counter) -> List[Dict[str, Any]]:
    return [
        {
            "category": signature[0],
            "operation": signature[1],
            "address": signature[2],
            "count": count,
        }
        for signature, count in sorted(
            counter.items(), key=lambda item: tuple(str(value) for value in item[0])
        )
    ]


def _compare_ordered_effects(
    before: Sequence[Mapping[str, Any]], after: Sequence[Mapping[str, Any]]
) -> Dict[str, Any]:
    before_sequence = [_effect_signature(effect) for effect in before]
    after_sequence = [_effect_signature(effect) for effect in after]
    lost = Counter(before_sequence) - Counter(after_sequence)
    added = Counter(after_sequence) - Counter(before_sequence)
    lost_by_category: Counter = Counter()
    added_by_category: Counter = Counter()
    for signature, count in lost.items():
        lost_by_category[signature[0]] += count
    for signature, count in added.items():
        added_by_category[signature[0]] += count
    return {
        "before_count": len(before_sequence),
        "after_count": len(after_sequence),
        "ordered_exact": before_sequence == after_sequence,
        "lost": _counter_records(lost),
        "added": _counter_records(added),
        "lost_by_category": dict(sorted(lost_by_category.items())),
        "added_by_category": dict(sorted(added_by_category.items())),
    }


def _instruction_snapshot(il: Any) -> Dict[str, Any]:
    instructions: List[Dict[str, Any]] = []
    for order, instr in enumerate(il.instructions):
        address = getattr(instr, "address", None)
        instructions.append(
            {
                "order": order,
                "instr_index": getattr(instr, "instr_index", None),
                "address": (
                    f"0x{int(address):x}" if isinstance(address, int) else None
                ),
                "operation": _operation_name(instr),
                "text": str(instr),
            }
        )
    return {"instruction_count": len(instructions), "instructions": instructions}


def _cfg_snapshot(il: Any) -> Dict[str, Any]:
    blocks: List[Dict[str, Any]] = []
    edge_count = 0
    for block in il.basic_blocks:
        edges = [
            {
                "target": getattr(getattr(edge, "target", None), "start", None),
                "type": str(getattr(edge, "type", "unknown")),
                "back_edge": bool(getattr(edge, "back_edge", False)),
            }
            for edge in block.outgoing_edges
        ]
        edge_count += len(edges)
        blocks.append(
            {
                "start": block.start,
                "end": block.end,
                "length": block.length,
                "outgoing": edges,
            }
        )
    return {"block_count": len(blocks), "edge_count": edge_count, "blocks": blocks}


def _snapshot_function(func: Any) -> Dict[str, Any]:
    if func.mlil is None:
        raise RuntimeError(f"{func.name}: MLIL 不可用")
    if func.hlil is None:
        raise RuntimeError(f"{func.name}: HLIL 不可用")
    return {
        "cfg": {"mlil": _cfg_snapshot(func.mlil), "hlil": _cfg_snapshot(func.hlil)},
        "mlil": _instruction_snapshot(func.mlil),
        "hlil": _instruction_snapshot(func.hlil),
        "ordered_effects": {
            "mlil": _collect_ordered_effects(func.mlil, "mlil"),
            "hlil": _collect_ordered_effects(func.hlil, "hlil"),
        },
    }


def _current_rss_kib() -> Optional[int]:
    status_path = Path("/proc/self/status")
    if status_path.exists():
        for line in status_path.read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    return None


def _peak_rss_kib() -> Optional[int]:
    try:
        import resource
    except ImportError:
        return None
    value = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    return value // 1024 if platform.system() == "Darwin" else value


@contextmanager
def _function_timeout(seconds: float) -> Iterator[None]:
    """POSIX 硬超时；不支持 setitimer 的平台退化为事后超时检查。"""
    if seconds <= 0 or not hasattr(signal, "setitimer"):
        started = time.perf_counter()
        yield
        if time.perf_counter() - started > seconds:
            raise FunctionTimeout(f"单函数超过 {seconds:g}s")
        return

    def handler(signum: int, frame: Any) -> None:
        del signum, frame
        raise FunctionTimeout(f"单函数超过 {seconds:g}s")

    previous_handler = signal.getsignal(signal.SIGALRM)
    signal.signal(signal.SIGALRM, handler)
    previous_timer = signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_timer[0] > 0:
            signal.setitimer(signal.ITIMER_REAL, *previous_timer)


def _count_category(
    effects: Sequence[Mapping[str, Any]], category: str
) -> int:
    return sum(effect.get("category") == category for effect in effects)


def _orphan_sites(snapshot: Mapping[str, Any]) -> List[Dict[str, Any]]:
    sites: List[Dict[str, Any]] = []
    for layer in ("mlil", "hlil"):
        for instruction in snapshot[layer]["instructions"]:
            if _ORPHAN_RE.search(instruction["text"]):
                sites.append(
                    {
                        "layer": layer,
                        "order": instruction["order"],
                        "address": instruction["address"],
                        "text": instruction["text"],
                    }
                )
    return sites


def test_func(bv: Any, addr: int) -> Dict[str, Any]:
    import binaryninja as bn

    func = bv.get_function_at(addr)
    if func is None:
        raise LookupError(f"0x{addr:x} 处没有函数")
    rss_before = _current_rss_kib()
    before = _snapshot_function(func)
    blocks_before = before["cfg"]["mlil"]["block_count"]

    settings = bn.Settings()
    settings.set_string(
        "analysis.workflows.functionWorkflow", "MikuCffHelper_workflow", func
    )
    workflow = bn.Workflow("MikuCffHelper_workflow", object_handle=func.handle)
    workflow._machine.override_set("analysis.plugins.workflow_patch_mlil_auto", True)
    started = time.perf_counter()
    bv.reanalyze()
    bv.update_analysis_and_wait()
    analysis_seconds = time.perf_counter() - started

    after = _snapshot_function(func)
    blocks_after = after["cfg"]["mlil"]["block_count"]
    hlil_count = after["hlil"]["instruction_count"]
    mlil_changed = before["mlil"] != after["mlil"]
    has_switch = any(
        "switch" in instruction["text"]
        for instruction in after["hlil"]["instructions"]
    )
    orphan_sites = _orphan_sites(after)
    mlil_delta = _compare_ordered_effects(
        before["ordered_effects"]["mlil"], after["ordered_effects"]["mlil"]
    )
    hlil_delta = _compare_ordered_effects(
        before["ordered_effects"]["hlil"], after["ordered_effects"]["hlil"]
    )
    mlil_lost = mlil_delta["lost_by_category"]
    mlil_added = mlil_delta["added_by_category"]
    hlil_lost = hlil_delta["lost_by_category"]
    before_hlil = before["ordered_effects"]["hlil"]
    after_hlil = after["ordered_effects"]["hlil"]
    return {
        "status": "ok",
        "name": func.name,
        "blocks_before": blocks_before,
        "blocks_after": blocks_after,
        "hlil": hlil_count,
        "time": round(analysis_seconds, 3),
        "analysis_seconds": analysis_seconds,
        "rss_before_kib": rss_before,
        "rss_after_kib": _current_rss_kib(),
        "peak_rss_kib": _peak_rss_kib(),
        "switch": has_switch,
        "deflated": (not has_switch) and mlil_changed,
        "orphan": bool(orphan_sites),
        "orphan_sites": orphan_sites,
        "se_lost": sum(int(value) for value in mlil_lost.values()),
        "se_added": sum(int(value) for value in mlil_added.values()),
        "mlil_calls_lost": int(mlil_lost.get("call", 0)),
        "mlil_stores_lost": int(mlil_lost.get("store", 0)),
        "mlil_rets_lost": int(mlil_lost.get("ret", 0)),
        "mlil_calls_added": int(mlil_added.get("call", 0)),
        "mlil_stores_added": int(mlil_added.get("store", 0)),
        "mlil_rets_added": int(mlil_added.get("ret", 0)),
        "hlil_calls_before": _count_category(before_hlil, "call"),
        "hlil_calls_after": _count_category(after_hlil, "call"),
        "hlil_calls_lost": int(hlil_lost.get("call", 0)),
        "hlil_stores_before": _count_category(before_hlil, "store"),
        "hlil_stores_after": _count_category(after_hlil, "store"),
        "hlil_stores_lost": int(hlil_lost.get("store", 0)),
        "hlil_rets_before": _count_category(before_hlil, "ret"),
        "hlil_rets_after": _count_category(after_hlil, "ret"),
        "hlil_rets_lost": int(hlil_lost.get("ret", 0)),
        "ordered_effect_delta": {"mlil": mlil_delta, "hlil": hlil_delta},
        "evidence": {"before": before, "after": after},
    }


def _failure_result(
    name: str,
    status: str,
    error: str,
    started: float,
    *,
    trace: Optional[str] = None,
) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "status": status,
        "name": name,
        "error": error,
        "time": round(time.perf_counter() - started, 3),
        "peak_rss_kib": _peak_rss_kib(),
        "orphan": False,
        "se_lost": 0,
        "mlil_calls_lost": 0,
        "mlil_stores_lost": 0,
        "mlil_rets_lost": 0,
        "hlil_calls_lost": 0,
        "hlil_stores_lost": 0,
        "hlil_rets_lost": 0,
    }
    if trace:
        result["traceback"] = trace
    return result


def run_binary(
    path: Path, addresses: Sequence[str], timeout_seconds: float
) -> Dict[str, Any]:
    import binaryninja as bn

    print(f"[load] {path.name}", flush=True)
    bv = bn.load(str(path), update_analysis=True)
    output: Dict[str, Any] = {"binary": path.name, "results": {}}
    abort_reason: Optional[str] = None
    try:
        for raw_addr in addresses:
            address_text = _normalize_addr(raw_addr)
            address = int(address_text, 0)
            if abort_reason is not None:
                output["results"][address_text] = _failure_result(
                    f"sub_{address:x}", "blocked", abort_reason, time.perf_counter()
                )
                continue
            started = time.perf_counter()
            func = bv.get_function_at(address)
            name = func.name if func is not None else f"sub_{address:x}"
            if func is None:
                output["results"][address_text] = _failure_result(
                    name, "missing", f"0x{address:x} 处没有函数", started
                )
                print(f"  {name}: MISSING", flush=True)
                continue
            try:
                with _function_timeout(timeout_seconds):
                    result = test_func(bv, address)
            except FunctionTimeout as exc:
                result = _failure_result(
                    name, "timeout", str(exc), started, trace=traceback.format_exc()
                )
                abort_reason = f"前一函数 {name} timeout，BinaryView 状态不再可信"
            except Exception as exc:
                result = _failure_result(
                    name,
                    "error",
                    f"{type(exc).__name__}: {exc}",
                    started,
                    trace=traceback.format_exc(),
                )
                abort_reason = f"前一函数 {name} 异常，BinaryView 状态不再可信"
            output["results"][address_text] = result
            if result["status"] == "ok":
                mark = "SW" if result["switch"] else (
                    "DEF" if result["deflated"] else "--"
                )
                warning = f" SE_LOST={result['se_lost']}" if result["se_lost"] else ""
                warning += " ORPHAN" if result["orphan"] else ""
                print(
                    f"  {name[:30]:30s} {result['blocks_before']:>3}→"
                    f"{result['blocks_after']:<3} hlil={result['hlil']:<4} {mark}{warning}",
                    flush=True,
                )
            else:
                print(
                    f"  {name}: {result['status'].upper()} {result['error']}",
                    flush=True,
                )
    finally:
        bv.file.close()
    return output


def summarize(report: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    results = [
        result
        for binary in report
        for result in binary.get("results", {}).values()
    ]
    ok_results = [
        result for result in results if result.get("status", "ok") == "ok"
    ]
    switch = sum(bool(result.get("switch")) for result in ok_results)
    deflated = sum(bool(result.get("deflated")) for result in ok_results)
    return {
        "total": len(results),
        "ok": len(ok_results),
        "failed": len(results) - len(ok_results),
        "switch": switch,
        "deflated": deflated,
        "transformed": switch + deflated,
        "orphan": sum(bool(result.get("orphan")) for result in results),
        "se_lost": sum(bool(result.get("se_lost", 0)) for result in results),
        "se_lost_total": sum(
            int(result.get("se_lost", 0) or 0) for result in results
        ),
        "se_added": sum(bool(result.get("se_added", 0)) for result in results),
        "se_added_total": sum(
            int(result.get("se_added", 0) or 0) for result in results
        ),
        "hlil_calls_lost": sum(
            int(result.get("hlil_calls_lost", 0) or 0) for result in results
        ),
        "hlil_stores_lost": sum(
            int(result.get("hlil_stores_lost", 0) or 0) for result in results
        ),
        "hlil_rets_lost": sum(
            int(result.get("hlil_rets_lost", 0) or 0) for result in results
        ),
        "funcs_with_lost_calls": sum(
            bool(result.get("hlil_calls_lost", 0)) for result in results
        ),
    }


def _compact_result(result: Mapping[str, Any]) -> Dict[str, Any]:
    excluded = {
        "evidence", "ordered_effect_delta", "traceback",
        "rss_before_kib", "rss_after_kib",
    }
    return {key: value for key, value in result.items() if key not in excluded}


def _compact_report(
    report: Sequence[Mapping[str, Any]],
) -> List[Dict[str, Any]]:
    return [
        {
            "binary": binary["binary"],
            "results": {
                address: _compact_result(result)
                for address, result in binary.get("results", {}).items()
            },
        }
        for binary in report
    ]


def _write_csv(report: Sequence[Mapping[str, Any]], path: Path) -> None:
    fieldnames = [
        "binary", "address", "name", "status", "blocks_before", "blocks_after",
        "hlil", "switch", "deflated", "orphan", "se_lost", "se_added",
        "mlil_calls_lost", "mlil_stores_lost", "mlil_rets_lost",
        "mlil_calls_added", "mlil_stores_added", "mlil_rets_added",
        "hlil_calls_lost", "hlil_stores_lost", "hlil_rets_lost",
        "analysis_seconds", "peak_rss_kib", "error",
    ]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for binary in report:
            for address, result in binary.get("results", {}).items():
                row = {"binary": binary["binary"], "address": address}
                row.update(
                    {
                        field: result.get(field)
                        for field in fieldnames
                        if field not in {"binary", "address"}
                    }
                )
                writer.writerow(row)


def _print_summary(summary: Mapping[str, Any]) -> None:
    print("\n=== 汇总 ===")
    print(
        f"总函数:    {summary['total']} "
        f"(ok={summary['ok']}, failed={summary['failed']})"
    )
    print(f"SWITCH:    {summary['switch']}")
    print(f"DEFLATED:  {summary['deflated']}")
    print(
        f"已变换:    {summary['transformed']} / {summary['total']} "
        f"({100 * summary['transformed'] / max(summary['total'], 1):.0f}%)"
    )
    print(f"ORPHAN:    {summary['orphan']}")
    print(
        f"SE_LOST:   {summary['se_lost_total']} 个副作用，"
        f"{summary['se_lost']} 个函数"
    )
    print(
        f"SE_ADDED:  {summary['se_added_total']} 个副作用，"
        f"{summary['se_added']} 个函数"
    )
    print(f"HLIL_CALL_LOST:  {summary['hlil_calls_lost']}")
    print(f"HLIL_STORE_LOST: {summary['hlil_stores_lost']}")
    print(f"HLIL_RET_LOST:   {summary['hlil_rets_lost']}")


def _load_baseline(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"baseline 不存在: {path}")
    with path.open(encoding="utf-8") as handle:
        document = json.load(handle)
    if not isinstance(document, dict):
        raise ValueError("baseline 顶层必须是对象")
    return document


def _requested_samples(
    manifest_index: Mapping[str, Mapping[str, Any]],
    *,
    only: Optional[str],
    binary: Optional[str],
    function: Optional[str],
) -> Tuple[List[Dict[str, Any]], Set[str]]:
    if function is not None:
        if not binary:
            raise ValueError("--func 需要 --bin")
        if binary not in manifest_index:
            raise ValueError(f"--bin 不在 manifest: {binary}")
        address = _normalize_addr(function)
        sample = dict(manifest_index[binary])
        sample["functions"] = [address]
        return [sample], {_result_key(binary, address)}
    if only is not None:
        if only not in manifest_index:
            raise ValueError(f"--only 不在 manifest: {only}")
        sample = dict(manifest_index[only])
        return [sample], {
            _result_key(only, address) for address in sample["functions"]
        }
    samples = [dict(sample) for sample in manifest_index.values()]
    expected = {
        _result_key(sample["binary"], address)
        for sample in samples
        for address in sample["functions"]
    }
    return samples, expected


def _sample_failure_report(
    sample: Mapping[str, Any], status: str, error: str
) -> Dict[str, Any]:
    return {
        "binary": sample["binary"],
        "results": {
            address: _failure_result(
                f"sub_{int(address, 0):x}",
                status,
                error,
                time.perf_counter(),
            )
            for address in sample["functions"]
        },
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--update-baseline", action="store_true",
        help="安全门禁通过后更新结构 baseline",
    )
    parser.add_argument("--only", metavar="BIN", help="只跑 manifest 中指定 binary")
    parser.add_argument("--bin", metavar="BIN", help="搭配 --func 指定 binary")
    parser.add_argument(
        "--func", metavar="ADDR",
        help="只跑指定地址；manifest 外地址默认门禁失败",
    )
    parser.add_argument("--baseline", default=str(BASELINE_PATH), help="baseline 路径")
    parser.add_argument("--timeout", type=float, help="覆盖 manifest 的单函数超时秒数")
    parser.add_argument("--out-dir", default="/tmp", help="JSON/CSV 输出目录")
    parser.add_argument(
        "--allow-unmanifested", action="store_true",
        help="调试时允许 manifest 外单函数；绝对安全错误仍失败",
    )
    args = parser.parse_args(argv)
    if args.only and args.func:
        parser.error("--only 与 --func 不能同时使用")

    baseline_path = Path(args.baseline)
    try:
        baseline = _load_baseline(baseline_path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"[fatal] {exc}", file=sys.stderr)
        return 2
    baseline_errors = validate_baseline_document(baseline)
    if baseline_errors:
        print("[fatal] baseline/manifest 无效:", file=sys.stderr)
        for error in baseline_errors:
            print(f"  - {error}", file=sys.stderr)
        return 2

    manifest = baseline["manifest"]
    manifest_index, _ = _manifest_index(manifest)
    try:
        samples, expected_keys = _requested_samples(
            manifest_index,
            only=args.only,
            binary=args.bin,
            function=args.func,
        )
    except ValueError as exc:
        print(f"[fatal] {exc}", file=sys.stderr)
        return 2
    timeout_seconds = float(
        args.timeout
        if args.timeout is not None
        else manifest["function_timeout_seconds"]
    )
    if timeout_seconds <= 0:
        print("[fatal] --timeout 必须为正数", file=sys.stderr)
        return 2
    if args.update_baseline and (args.only or args.func or args.allow_unmanifested):
        print("[fatal] --update-baseline 只允许完整 manifest 运行", file=sys.stderr)
        return 2

    setup_path()
    run_started = time.perf_counter()
    report: List[Dict[str, Any]] = []
    sample_observations: List[Dict[str, Any]] = []
    environment: Dict[str, Any] = {
        "python": sys.version,
        "platform": platform.platform(),
        "bn_disable_user_plugins": os.environ.get("BN_DISABLE_USER_PLUGINS"),
    }
    try:
        plugin = _load_workspace_plugin()
        import binaryninja as bn

        environment["binaryninja_core"] = bn.core_version()
        environment["plugin_module"] = str(Path(plugin.__file__).resolve())
    except Exception as exc:
        print(
            f"[fatal] 工作区插件加载失败: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        traceback.print_exc()
        return 2

    for sample in samples:
        binary = sample["binary"]
        path = SAMPLE_DIR / binary
        observation: Dict[str, Any] = {
            "binary": binary,
            "path": str(path.resolve()),
            "expected_sha256": sample["sha256"],
        }
        if not path.exists():
            observation.update({"status": "missing", "actual_sha256": None})
            report.append(
                _sample_failure_report(
                    sample, "sample_missing", f"样本不存在: {path}"
                )
            )
            sample_observations.append(observation)
            continue
        actual_hash = _sha256_file(path)
        observation["actual_sha256"] = actual_hash
        if actual_hash != sample["sha256"]:
            observation["status"] = "hash_mismatch"
            report.append(
                _sample_failure_report(
                    sample,
                    "hash_mismatch",
                    f"SHA-256 expected={sample['sha256']} actual={actual_hash}",
                )
            )
        else:
            observation["status"] = "ok"
            try:
                report.append(
                    run_binary(path, sample["functions"], timeout_seconds)
                )
            except Exception as exc:
                trace = traceback.format_exc()
                print(
                    f"[error] {binary} 加载/执行失败: "
                    f"{type(exc).__name__}: {exc}\n{trace}",
                    file=sys.stderr,
                )
                failed = _sample_failure_report(
                    sample,
                    "binary_error",
                    f"{type(exc).__name__}: {exc}",
                )
                for result in failed["results"].values():
                    result["traceback"] = trace
                report.append(failed)
        sample_observations.append(observation)

    summary = summarize(report)
    errors, improvements, warnings = evaluate_gate(
        report,
        baseline,
        expected_keys,
        allow_unmanifested=args.allow_unmanifested,
    )
    wall_seconds = time.perf_counter() - run_started
    _print_summary(summary)

    output_dir = Path(args.out_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    stem = f"regression_{int(time.time())}_{os.getpid()}"
    json_path = output_dir / f"{stem}.json"
    csv_path = output_dir / f"{stem}.csv"
    artifact = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "command": [
            sys.executable,
            str(Path(__file__).resolve()),
            *(argv if argv is not None else sys.argv[1:]),
        ],
        "environment": environment,
        "samples": sample_observations,
        "metrics": {
            "wall_seconds": wall_seconds,
            "peak_rss_kib": _peak_rss_kib(),
        },
        "summary": summary,
        "gate": {
            "passed": not errors,
            "errors": errors,
            "warnings": warnings,
            "improvements": improvements,
        },
        "report": report,
    }
    with json_path.open("w", encoding="utf-8") as handle:
        json.dump(artifact, handle, indent=2, ensure_ascii=False)
    _write_csv(report, csv_path)
    print(f"\n[save] JSON → {json_path}")
    print(f"[save] CSV  → {csv_path}")
    print(f"[metrics] wall={wall_seconds:.3f}s peak_rss_kib={_peak_rss_kib()}")

    if warnings:
        print("\n=== 诊断警告 ===")
        for warning in warnings:
            print(f"  ! {warning}")
    if improvements:
        print("\n=== 改进 ===")
        for improvement in improvements:
            print(f"  + {improvement}")

    if args.update_baseline:
        full_manifest_keys = manifest_keys(manifest)
        current_errors = validate_current_report(
            report,
            full_manifest_keys,
            manifest_key_set=full_manifest_keys,
        )
        if current_errors:
            print(
                "\n[refuse] 存在安全/完整性错误，不更新 baseline:",
                file=sys.stderr,
            )
            for error in current_errors:
                print(f"  - {error}", file=sys.stderr)
            return 1
        new_baseline = {
            "schema_version": BASELINE_SCHEMA_VERSION,
            "manifest": manifest,
            "summary": summary,
            "report": _compact_report(report),
        }
        with baseline_path.open("w", encoding="utf-8") as handle:
            json.dump(new_baseline, handle, indent=2, ensure_ascii=False)
        print(f"[update] baseline → {baseline_path}")
        return 0

    if errors:
        print("\n=== 门禁失败 ===")
        for error in errors:
            print(f"  - {error}")
        return 1
    print("\n[ok] 严格回归门禁通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
