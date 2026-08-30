#!/usr/bin/env python3
# SPDX-License-Identifier: 0BSD
"""Content-addressed binary corpus indexer.

This tool deliberately does not decide whether a function is CFF. It records
file identity and declared expectations, leaving algorithm evaluation to a
separate test runner.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import struct
import subprocess
from pathlib import Path
from typing import Any, Iterable


ELF_MACHINES = {
    3: "i386",
    8: "MIPS",
    20: "PowerPC",
    21: "PowerPC64",
    40: "ARM",
    62: "x86-64",
    183: "AArch64",
    243: "RISC-V",
}

PE_MACHINES = {
    0x014C: "i386",
    0x01C0: "ARM",
    0x01C4: "ARMv7",
    0x8664: "x86-64",
    0xAA64: "AArch64",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_binary(path: Path) -> dict[str, Any] | None:
    with path.open("rb") as stream:
        data = stream.read(4096)
    if data.startswith(b"\x7fELF") and len(data) >= 20:
        bits = {1: 32, 2: 64}.get(data[4])
        endian = {1: "little", 2: "big"}.get(data[5])
        if endian is None:
            return None
        machine = struct.unpack_from("<H" if endian == "little" else ">H", data, 18)[0]
        elf_type = struct.unpack_from("<H" if endian == "little" else ">H", data, 16)[0]
        return {
            "format": "ELF",
            "bits": bits,
            "endianness": endian,
            "architecture": ELF_MACHINES.get(machine, f"ELF-machine-{machine}"),
            "object_type": {
                1: "relocatable",
                2: "executable",
                3: "shared-object",
                4: "core",
            }.get(elf_type, f"ELF-type-{elf_type}"),
        }

    if data.startswith(b"MZ") and len(data) >= 0x40:
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_offset + 6 <= len(data) and data[pe_offset : pe_offset + 4] == b"PE\0\0":
            machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
            optional_offset = pe_offset + 24
            magic = (
                struct.unpack_from("<H", data, optional_offset)[0]
                if optional_offset + 2 <= len(data)
                else 0
            )
            return {
                "format": "PE",
                "bits": {0x10B: 32, 0x20B: 64}.get(magic),
                "endianness": "little",
                "architecture": PE_MACHINES.get(machine, f"PE-machine-{machine:#x}"),
                "object_type": "executable-image",
            }
    return None


def tool_output(argv: list[str]) -> str | None:
    if shutil.which(argv[0]) is None:
        return None
    result = subprocess.run(argv, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def parse_defined_symbols(output: str) -> dict[str, set[int]]:
    """Parse GNU/LLVM ``nm`` output into name -> distinct addresses.

    Keeping all distinct addresses is intentional: silently selecting one of
    two same-named symbols would make a manifest target non-reproducible.
    Repeated rows at the same address are harmless and collapse in the set.
    """
    symbols: dict[str, set[int]] = {}
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 3:
            continue
        try:
            address = int(fields[0], 16)
        except ValueError:
            continue
        symbols.setdefault(fields[-1], set()).add(address)
    return symbols


def defined_symbols(path: Path, nm: str) -> dict[str, set[int]] | None:
    output = tool_output([nm, "-an", "--defined-only", str(path)])
    if output is None:
        return None
    return parse_defined_symbols(output)


def normalized_address(value: Any) -> str:
    number = value if isinstance(value, int) else int(str(value).strip(), 0)
    if number < 0:
        raise ValueError(f"negative address: {value!r}")
    return f"0x{number:x}"


def annotate_symbol(
    function: dict[str, Any],
    symbols: dict[str, set[int]] | None,
    object_type: str | None,
) -> None:
    """Add deterministic symbol status/address evidence to one expectation."""
    name = function.get("name")
    if symbols is None:
        function["symbol_status"] = "nm-unavailable"
        return

    addresses = sorted(symbols.get(name, set()))
    if not addresses:
        function["symbol_status"] = (
            "not-present-or-stripped"
            if object_type == "shared-object"
            else "missing"
        )
        return

    if len(addresses) > 1:
        function["symbol_status"] = "ambiguous"
        function["symbol_addresses"] = [f"0x{address:x}" for address in addresses]
        return

    symbol_address = f"0x{addresses[0]:x}"
    declared = function.get("address")
    if declared is None:
        function["address"] = symbol_address
        function["address_source"] = "nm"
        if object_type in {"relocatable", "shared-object"}:
            # nm reports an ELF symbol value relative to the image/section for
            # these file types.  Declare the corresponding loader base instead
            # of making downstream tools guess Binary Ninja's default base.
            function["loader_image_base"] = "0x0"
        function["symbol_status"] = "present"
        return

    try:
        function["address"] = normalized_address(declared)
    except (TypeError, ValueError):
        function["symbol_status"] = "invalid-declared-address"
        function["symbol_address"] = symbol_address
        return

    if function["address"] == symbol_address:
        function["symbol_status"] = "present"
    else:
        function["symbol_status"] = "address-mismatch"
        function["symbol_address"] = symbol_address


def iter_files(inputs: Iterable[Path]) -> Iterable[Path]:
    seen: set[Path] = set()
    for item in inputs:
        candidates = [item] if item.is_file() else sorted(p for p in item.rglob("*") if p.is_file())
        for candidate in candidates:
            resolved = candidate.resolve()
            if resolved not in seen:
                seen.add(resolved)
                yield resolved


def relative_name(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name


def load_json(path: Path | None) -> Any:
    if path is None or not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def baseline_expectations(path: Path | None) -> dict[str, list[dict[str, str]]]:
    baseline = load_json(path)
    by_binary: dict[str, list[dict[str, str]]] = {}
    for binary in baseline.get("report", []):
        funcs = []
        for address, result in sorted(binary.get("results", {}).items()):
            funcs.append(
                {
                    "name": result.get("name", ""),
                    "address": address,
                    "source": "tools/baseline.json",
                }
            )
        by_binary[binary.get("binary", "")] = funcs
    return by_binary


def normalize_expected(items: list[Any]) -> list[dict[str, Any]]:
    normalized = []
    for item in items:
        if isinstance(item, str):
            normalized.append({"name": item})
        elif isinstance(item, dict):
            normalized.append(dict(item))
    return normalized


def build_manifest(
    inputs: list[Path],
    root: Path,
    metadata_files: list[Path],
    baseline: Path | None,
    file_tool: str,
    nm_tool: str,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    for metadata_path in metadata_files:
        metadata.update(load_json(metadata_path))
    baseline_by_binary = baseline_expectations(baseline)

    entries = []
    for path in iter_files(inputs):
        binary = inspect_binary(path)
        if binary is None:
            continue
        rel = relative_name(path, root)
        declared = dict(metadata.get(rel, {}))
        expected = normalize_expected(declared.pop("expected_functions", []))
        if not expected:
            expected = baseline_by_binary.get(path.name, [])

        symbols = defined_symbols(path, nm_tool)
        for function in expected:
            annotate_symbol(function, symbols, binary.get("object_type"))

        description = tool_output([file_tool, "-b", str(path)])
        entry = {
            "path": rel,
            "sha256": sha256_file(path),
            "size": path.stat().st_size,
            **binary,
            "file_description": description,
            "expected_functions": expected,
            **declared,
        }
        entries.append(entry)

    return {
        "schema_version": 1,
        "identity": "sha256",
        "selection_policy": "declared corpus entries only; no CFF detection heuristic",
        "entries": sorted(entries, key=lambda item: item["path"]),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", type=Path, help="Files or directories to index")
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="Base for manifest paths")
    parser.add_argument("--metadata", type=Path, action="append", default=[])
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--file-tool", default="file")
    parser.add_argument("--nm-tool", default="nm")
    args = parser.parse_args()

    root = args.root.resolve()
    manifest = build_manifest(
        [path.resolve() for path in args.inputs],
        root,
        [path.resolve() for path in args.metadata],
        args.baseline.resolve() if args.baseline else None,
        args.file_tool,
        args.nm_tool,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"indexed {len(manifest['entries'])} binaries -> {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
