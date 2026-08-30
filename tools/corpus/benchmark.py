#!/usr/bin/env python3
# SPDX-License-Identifier: 0BSD
"""Benchmark manifest-declared functions without CFF candidate discovery.

Each measurement opens a fresh BinaryView, looks up exactly one declared
address, records an unmodified snapshot, enables the selected workflow, and
records the transformed snapshot.  Selection never depends on detector output,
block counts, state values, or a successful transformation.
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
import statistics
import sys
import time
import traceback
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence


REPO_ROOT = Path(__file__).resolve().parents[2]
MODE_ACTIVITIES = {
    "auto": "analysis.plugins.workflow_patch_mlil_auto",
    "switch": "analysis.plugins.workflow_patch_mlil_switch",
    "deflate": "analysis.plugins.workflow_patch_mlil",
}
WORKFLOW_NAME = "MikuCffHelper_workflow"


class ManifestError(ValueError):
    pass


class MeasurementTimeout(TimeoutError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalize_address(value: Any) -> str:
    number = value if isinstance(value, int) else int(str(value).strip(), 0)
    if number < 0:
        raise ManifestError(f"negative function address: {value!r}")
    return f"0x{number:x}"


def parse_target_spec(spec: str) -> tuple[str, str]:
    if "@" not in spec:
        raise ManifestError(f"target must be PATH@ADDRESS: {spec!r}")
    path, raw_address = spec.rsplit("@", 1)
    if not path:
        raise ManifestError(f"target path is empty: {spec!r}")
    try:
        address = normalize_address(raw_address)
    except (TypeError, ValueError) as exc:
        raise ManifestError(f"invalid target address in {spec!r}: {exc}") from exc
    return path, address


def select_targets(
    manifest: Mapping[str, Any], requested_specs: Sequence[str]
) -> list[dict[str, Any]]:
    """Return only explicitly declared addresses, optionally exact-filtered."""
    entries = manifest.get("entries")
    if not isinstance(entries, list):
        raise ManifestError("manifest.entries must be a list")

    indexed: dict[tuple[str, str], dict[str, Any]] = {}
    seen_binaries: set[str] = set()
    for entry_index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ManifestError(f"manifest.entries[{entry_index}] is not an object")
        binary = entry.get("path")
        expected_hash = entry.get("sha256")
        functions = entry.get("expected_functions", [])
        if not isinstance(binary, str) or not binary:
            raise ManifestError(f"manifest.entries[{entry_index}].path is invalid")
        if binary in seen_binaries:
            raise ManifestError(f"duplicate manifest binary: {binary}")
        seen_binaries.add(binary)
        if not isinstance(expected_hash, str) or re.fullmatch(
            r"[0-9a-f]{64}", expected_hash
        ) is None:
            raise ManifestError(f"{binary}: sha256 must be 64 lowercase hex digits")
        if not isinstance(functions, list):
            raise ManifestError(f"{binary}: expected_functions must be a list")

        for function_index, function in enumerate(functions):
            if not isinstance(function, dict):
                raise ManifestError(
                    f"{binary}: expected_functions[{function_index}] is not an object"
                )
            if "address" not in function:
                raise ManifestError(
                    f"{binary}: expected function {function.get('name')!r} has no address"
                )
            try:
                address = normalize_address(function["address"])
            except (TypeError, ValueError) as exc:
                raise ManifestError(
                    f"{binary}: invalid address {function.get('address')!r}: {exc}"
                ) from exc
            key = (binary, address)
            if key in indexed:
                raise ManifestError(f"duplicate manifest target: {binary}@{address}")
            loader_image_base = function.get("loader_image_base")
            if loader_image_base is not None:
                try:
                    loader_image_base = normalize_address(loader_image_base)
                except (TypeError, ValueError) as exc:
                    raise ManifestError(
                        f"{binary}@{address}: invalid loader_image_base "
                        f"{function.get('loader_image_base')!r}: {exc}"
                    ) from exc
            indexed[key] = {
                "binary": binary,
                "sha256": expected_hash,
                "address": address,
                "manifest_name": function.get("name"),
                "symbol_status": function.get("symbol_status"),
                "address_source": function.get("address_source"),
                "loader_image_base": loader_image_base,
            }

    if requested_specs:
        requested: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for spec in requested_specs:
            key = parse_target_spec(spec)
            if key in seen:
                raise ManifestError(f"duplicate requested target: {key[0]}@{key[1]}")
            seen.add(key)
            requested.append(key)
        missing = [key for key in requested if key not in indexed]
        if missing:
            rendered = ", ".join(f"{path}@{address}" for path, address in missing)
            raise ManifestError(f"requested target is not declared in manifest: {rendered}")
        targets = [indexed[key] for key in requested]
    else:
        targets = list(indexed.values())

    if not targets:
        raise ManifestError("manifest selection contains no declared function addresses")
    return targets


def resolve_binary(root: Path, relative_path: str) -> Path:
    if Path(relative_path).is_absolute():
        raise ManifestError(f"manifest binary path must be relative: {relative_path}")
    resolved = (root / relative_path).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ManifestError(f"manifest binary escapes --root: {relative_path}") from exc
    return resolved


def configure_import_paths(plugin_root: Path, bn_python: Path | None) -> None:
    os.environ.setdefault("BN_DISABLE_USER_PLUGINS", "1")
    paths = [plugin_root.parent]
    if bn_python is not None:
        paths.insert(0, bn_python)
    for path in reversed(paths):
        path_text = str(path.resolve())
        if path_text in sys.path:
            sys.path.remove(path_text)
        sys.path.insert(0, path_text)


def load_workspace_plugin(plugin_root: Path) -> Any:
    plugin = importlib.import_module(plugin_root.name)
    actual = Path(plugin.__file__).resolve().parent
    if actual != plugin_root.resolve():
        raise RuntimeError(
            f"loaded plugin does not match --plugin-root: expected={plugin_root}, "
            f"actual={actual}"
        )
    return plugin


def operation_name(instruction: Any) -> str:
    operation = getattr(instruction, "operation", None)
    return getattr(operation, "name", str(operation))


def il_snapshot(il: Any) -> dict[str, Any]:
    instructions = list(il.instructions)
    blocks = list(il.basic_blocks)
    text = "\n".join(str(instruction) for instruction in instructions)
    operations = Counter(operation_name(instruction) for instruction in instructions)
    return {
        "block_count": len(blocks),
        "edge_count": sum(len(list(block.outgoing_edges)) for block in blocks),
        "instruction_count": len(instructions),
        "operation_counts": dict(sorted(operations.items())),
        "text_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
    }


def function_snapshot(function: Any) -> dict[str, Any]:
    if function.mlil is None:
        raise RuntimeError(f"{function.name}: MLIL unavailable")
    if function.hlil is None:
        raise RuntimeError(f"{function.name}: HLIL unavailable")
    return {
        "actual_name": function.name,
        "actual_address": f"0x{int(function.start):x}",
        "mlil": il_snapshot(function.mlil),
        "hlil": il_snapshot(function.hlil),
    }


def snapshot_delta(before: Mapping[str, Any], after: Mapping[str, Any]) -> dict[str, Any]:
    delta: dict[str, Any] = {}
    for layer in ("mlil", "hlil"):
        delta[layer] = {
            field: int(after[layer][field]) - int(before[layer][field])
            for field in ("block_count", "edge_count", "instruction_count")
        }
    return delta


def current_rss_kib() -> int | None:
    status = Path("/proc/self/status")
    if not status.exists():
        return None
    for line in status.read_text(encoding="utf-8").splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1])
    return None


@contextmanager
def measurement_deadline(seconds: float | None) -> Iterator[None]:
    if seconds is None:
        yield
        return
    if seconds <= 0:
        raise ValueError("--timeout-seconds must be positive")
    if not hasattr(signal, "setitimer"):
        raise RuntimeError("--timeout-seconds requires signal.setitimer")

    def timeout_handler(signum: int, frame: Any) -> None:
        del signum, frame
        raise MeasurementTimeout(f"measurement exceeded {seconds:g} seconds")

    previous_handler = signal.getsignal(signal.SIGALRM)
    signal.signal(signal.SIGALRM, timeout_handler)
    previous_timer = signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_timer[0] > 0:
            signal.setitimer(signal.ITIMER_REAL, *previous_timer)


def enable_workflow(bn: Any, view: Any, function: Any, mode: str) -> None:
    settings = bn.Settings()
    if not settings.set_string(
        "analysis.workflows.functionWorkflow", WORKFLOW_NAME, function
    ):
        raise RuntimeError("failed to select MikuCffHelper function workflow")
    workflow = bn.Workflow(WORKFLOW_NAME, object_handle=function.handle)
    for activity in MODE_ACTIVITIES.values():
        workflow._machine.override_set(activity, False)
    workflow._machine.override_set(MODE_ACTIVITIES[mode], True)
    view.reanalyze()
    view.update_analysis_and_wait()


def measure_once(
    bn: Any,
    path: Path,
    target: Mapping[str, Any],
    mode: str,
    repeat: int,
    timeout_seconds: float | None,
) -> dict[str, Any]:
    started = time.perf_counter()
    result: dict[str, Any] = {
        **target,
        "path": str(path),
        "mode": mode,
        "repeat": repeat,
        "status": "error",
    }
    view = None
    try:
        with measurement_deadline(timeout_seconds):
            phase = time.perf_counter()
            load_options = {}
            if target.get("loader_image_base") is not None:
                load_options["loader.imageBase"] = int(
                    str(target["loader_image_base"]), 0
                )
            view = bn.load(str(path), update_analysis=True, options=load_options)
            if view is None:
                raise RuntimeError("Binary Ninja returned no BinaryView")
            result["load_seconds"] = time.perf_counter() - phase

            address = int(str(target["address"]), 0)
            function = view.get_function_at(address)
            if function is None:
                raise LookupError(f"no function at declared address 0x{address:x}")

            phase = time.perf_counter()
            before = function_snapshot(function)
            result["before_snapshot_seconds"] = time.perf_counter() - phase
            result["before"] = before

            rss_before = current_rss_kib()
            result["rss_before_kib"] = rss_before
            phase = time.perf_counter()
            try:
                enable_workflow(bn, view, function, mode)
            finally:
                result["transform_seconds"] = time.perf_counter() - phase
                result["rss_after_kib"] = current_rss_kib()

            transformed = view.get_function_at(address)
            if transformed is None:
                raise LookupError(
                    f"function disappeared after workflow at address 0x{address:x}"
                )
            phase = time.perf_counter()
            after = function_snapshot(transformed)
            result["after_snapshot_seconds"] = time.perf_counter() - phase
            result.update(
                {
                    "status": "ok",
                    "after": after,
                    "delta": snapshot_delta(before, after),
                }
            )
    except MeasurementTimeout as exc:
        result.update({"status": "timeout", "error": str(exc)})
    except Exception as exc:
        result.update(
            {
                "status": "error",
                "error": f"{type(exc).__name__}: {exc}",
                "traceback": traceback.format_exc(),
            }
        )
    finally:
        if view is not None:
            view.file.close()
        result["total_seconds"] = time.perf_counter() - started
    return result


def failure_result(
    target: Mapping[str, Any], path: Path, mode: str, repeat: int, error: str
) -> dict[str, Any]:
    return {
        **target,
        "path": str(path),
        "mode": mode,
        "repeat": repeat,
        "status": "input-error",
        "error": error,
        "total_seconds": 0.0,
    }


def summarize(results: Sequence[Mapping[str, Any]], wall_seconds: float) -> dict[str, Any]:
    ok = [result for result in results if result.get("status") == "ok"]
    transform_times = [float(result["transform_seconds"]) for result in ok]
    summary: dict[str, Any] = {
        "measurements": len(results),
        "ok": len(ok),
        "failed": len(results) - len(ok),
        "wall_seconds": wall_seconds,
    }
    if transform_times:
        summary["transform_seconds"] = {
            "sum": sum(transform_times),
            "min": min(transform_times),
            "median": statistics.median(transform_times),
            "max": max(transform_times),
        }
    return summary


CSV_FIELDS = [
    "binary", "address", "manifest_name", "actual_name", "symbol_status",
    "address_source", "loader_image_base",
    "mode", "repeat", "status", "error", "load_seconds",
    "before_snapshot_seconds", "transform_seconds", "after_snapshot_seconds",
    "total_seconds", "rss_before_kib", "rss_after_kib",
    "before_mlil_blocks", "after_mlil_blocks", "delta_mlil_blocks",
    "before_mlil_edges", "after_mlil_edges", "delta_mlil_edges",
    "before_mlil_instructions", "after_mlil_instructions",
    "delta_mlil_instructions", "before_hlil_blocks", "after_hlil_blocks",
    "delta_hlil_blocks", "before_hlil_edges", "after_hlil_edges",
    "delta_hlil_edges", "before_hlil_instructions", "after_hlil_instructions",
    "delta_hlil_instructions", "before_mlil_text_sha256",
    "after_mlil_text_sha256", "before_hlil_text_sha256",
    "after_hlil_text_sha256",
]


def csv_row(result: Mapping[str, Any]) -> dict[str, Any]:
    row = {field: result.get(field) for field in CSV_FIELDS}
    row["actual_name"] = result.get("after", result.get("before", {})).get(
        "actual_name"
    )
    before = result.get("before", {})
    after = result.get("after", {})
    delta = result.get("delta", {})
    for layer in ("mlil", "hlil"):
        for field in ("block_count", "edge_count", "instruction_count"):
            label = {
                "block_count": "blocks",
                "edge_count": "edges",
                "instruction_count": "instructions",
            }[field]
            row[f"before_{layer}_{label}"] = before.get(layer, {}).get(field)
            row[f"after_{layer}_{label}"] = after.get(layer, {}).get(field)
            row[f"delta_{layer}_{label}"] = delta.get(layer, {}).get(field)
        row[f"before_{layer}_text_sha256"] = before.get(layer, {}).get(
            "text_sha256"
        )
        row[f"after_{layer}_text_sha256"] = after.get(layer, {}).get(
            "text_sha256"
        )
    return row


def write_outputs(
    artifact: Mapping[str, Any], json_path: Path, csv_path: Path
) -> None:
    json_path.parent.mkdir(parents=True, exist_ok=True)
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(
        json.dumps(artifact, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    with csv_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for result in artifact["results"]:
            writer.writerow(csv_row(result))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--json", type=Path, required=True)
    parser.add_argument("--csv", type=Path, required=True)
    parser.add_argument("--mode", choices=sorted(MODE_ACTIVITIES), default="auto")
    parser.add_argument("--repeat", type=int, default=1)
    parser.add_argument(
        "--target", action="append", default=[], metavar="PATH@ADDRESS",
        help="exact manifest target; repeat to select more than one",
    )
    parser.add_argument("--timeout-seconds", type=float)
    parser.add_argument("--bn-python", type=Path)
    parser.add_argument("--plugin-root", type=Path, default=REPO_ROOT)
    args = parser.parse_args(argv)

    if args.repeat <= 0:
        parser.error("--repeat must be positive")
    if args.timeout_seconds is not None and args.timeout_seconds <= 0:
        parser.error("--timeout-seconds must be positive")

    manifest_path = args.manifest.resolve()
    root = args.root.resolve()
    plugin_root = args.plugin_root.resolve()
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(manifest, dict):
            raise ManifestError("manifest root must be an object")
        targets = select_targets(manifest, args.target)
        resolved = {
            target["binary"]: resolve_binary(root, target["binary"])
            for target in targets
        }
    except (OSError, json.JSONDecodeError, ManifestError) as exc:
        print(f"[fatal] {exc}", file=sys.stderr)
        return 2

    configure_import_paths(plugin_root, args.bn_python)
    try:
        plugin = load_workspace_plugin(plugin_root)
        import binaryninja as bn
    except Exception as exc:
        print(f"[fatal] plugin/Binary Ninja load failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        traceback.print_exc()
        return 2

    binary_errors: dict[str, str] = {}
    actual_hashes: dict[str, str | None] = {}
    expected_hashes = {
        target["binary"]: target["sha256"] for target in targets
    }
    for binary, path in resolved.items():
        if not path.is_file():
            actual_hashes[binary] = None
            binary_errors[binary] = f"binary does not exist: {path}"
            continue
        actual_hash = sha256_file(path)
        actual_hashes[binary] = actual_hash
        expected_hash = expected_hashes[binary]
        if actual_hash != expected_hash:
            binary_errors[binary] = (
                f"sha256 mismatch: expected={expected_hash} actual={actual_hash}"
            )

    started = time.perf_counter()
    results: list[dict[str, Any]] = []
    for target in targets:
        path = resolved[target["binary"]]
        for repeat in range(1, args.repeat + 1):
            error = binary_errors.get(target["binary"])
            if error is not None:
                result = failure_result(target, path, args.mode, repeat, error)
            else:
                print(
                    f"[measure] {target['binary']}@{target['address']} "
                    f"repeat={repeat} mode={args.mode}",
                    file=sys.stderr,
                    flush=True,
                )
                result = measure_once(
                    bn,
                    path,
                    target,
                    args.mode,
                    repeat,
                    args.timeout_seconds,
                )
            results.append(result)

    wall_seconds = time.perf_counter() - started
    artifact = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "command": [sys.executable, str(Path(__file__).resolve()), *(
            list(argv) if argv is not None else sys.argv[1:]
        )],
        "manifest": {
            "path": str(manifest_path),
            "sha256": sha256_file(manifest_path),
            "selection": "expected_functions.address only",
        },
        "parameters": {
            "root": str(root),
            "mode": args.mode,
            "repeat": args.repeat,
            "targets": list(args.target),
            "timeout_seconds": args.timeout_seconds,
        },
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
            "binaryninja_core": bn.core_version(),
            "plugin": str(Path(plugin.__file__).resolve()),
            "bn_disable_user_plugins": os.environ.get("BN_DISABLE_USER_PLUGINS"),
        },
        "binaries": [
            {
                "path": binary,
                "resolved_path": str(resolved[binary]),
                "expected_sha256": expected_hashes[binary],
                "actual_sha256": actual_hashes[binary],
                "status": "error" if binary in binary_errors else "ok",
                "error": binary_errors.get(binary),
            }
            for binary in resolved
        ],
        "summary": summarize(results, wall_seconds),
        "results": results,
    }
    write_outputs(artifact, args.json, args.csv)
    print(f"[save] JSON {args.json}", file=sys.stderr)
    print(f"[save] CSV  {args.csv}", file=sys.stderr)
    return 0 if artifact["summary"]["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
