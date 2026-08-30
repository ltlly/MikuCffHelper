#!/usr/bin/env python3
# SPDX-License-Identifier: 0BSD
"""Build declared synthetic CFF fixtures and refresh their content manifest."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Any

from index_samples import build_manifest


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def compiler_version(compiler: str) -> str:
    result = subprocess.run(
        [compiler, "--version"], text=True, capture_output=True, check=False
    )
    if result.returncode != 0:
        return "unknown"
    return result.stdout.splitlines()[0] if result.stdout else "unknown"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    default_spec = Path(__file__).with_name("spec.json")
    parser.add_argument("--spec", type=Path, default=default_spec)
    parser.add_argument("--cc", default=os.environ.get("CC", "cc"))
    parser.add_argument("--profile", action="append", help="Build only the named profile")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--file-tool", default="file")
    parser.add_argument("--nm-tool", default="nm")
    args = parser.parse_args()

    root = args.root.resolve()
    spec_path = args.spec.resolve()
    spec = load_json(spec_path)
    compiler = shutil.which(args.cc)
    if compiler is None:
        raise SystemExit(f"compiler not found: {args.cc}")

    requested = set(args.profile or [])
    profiles = [
        profile
        for profile in spec["profiles"]
        if not requested or profile["id"] in requested
    ]
    missing = requested - {profile["id"] for profile in profiles}
    if missing:
        raise SystemExit(f"unknown profile(s): {', '.join(sorted(missing))}")

    artifact_dir = root / spec["artifact_directory"]
    artifact_dir.mkdir(parents=True, exist_ok=True)
    build_metadata_path = root / spec["build_metadata"]
    build_metadata: dict[str, Any] = (
        load_json(build_metadata_path)
        if requested and build_metadata_path.exists()
        else {}
    )
    built_count = 0
    version = compiler_version(compiler)

    for source_spec in spec["sources"]:
        source = root / source_spec["path"]
        if not source.exists():
            raise SystemExit(f"missing source: {source}")
        for profile in profiles:
            output_name = f"{source_spec['id']}--{profile['id']}{profile['suffix']}"
            output = artifact_dir / output_name
            source_arg = source.relative_to(root).as_posix()
            output_arg = output.relative_to(root).as_posix()
            command = [compiler, *profile["flags"], source_arg, "-o", output_arg]
            print("+", shlex.join(command))
            result = subprocess.run(command, cwd=root, check=False)
            if result.returncode != 0:
                raise SystemExit(f"build failed ({result.returncode}): {output_name}")

            self_test = "not-applicable"
            if profile.get("self_test"):
                test = subprocess.run([str(output)], cwd=root, check=False)
                self_test = "passed" if test.returncode == 0 else f"failed:{test.returncode}"
                if test.returncode != 0:
                    raise SystemExit(f"self-test failed ({test.returncode}): {output_name}")

            rel = output.relative_to(root).as_posix()
            build_metadata[rel] = {
                "provenance": "Repository-authored deterministic synthetic fixture",
                "license": spec["license"],
                "redistributable": True,
                "source": source_spec["path"],
                "source_id": source_spec["id"],
                "role": profile.get("artifact_role", source_spec["role"]),
                "source_role": source_spec["role"],
                "variant": f"{source_spec['variant']}; {profile['description']}",
                "expected_functions": source_spec["expected_functions"],
                "generator": {
                    "compiler": compiler,
                    "compiler_version": version,
                    "profile": profile["id"],
                    "command": command,
                },
                "validation": {"self_test": self_test},
            }
            built_count += 1

    build_metadata_path.write_text(
        json.dumps(build_metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    index_inputs = [root / item for item in spec["index_inputs"]]
    metadata_files = [root / spec["metadata"], build_metadata_path]
    manifest = build_manifest(
        index_inputs,
        root,
        metadata_files,
        root / spec["baseline"],
        args.file_tool,
        args.nm_tool,
    )
    manifest_path = root / spec["manifest"]
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"built {built_count} artifacts")
    print(f"indexed {len(manifest['entries'])} binaries -> {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
