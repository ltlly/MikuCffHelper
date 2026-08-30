# CFF corpus

This directory contains a small, reproducible control-flow-flattening corpus.
It is deliberately separate from the optimization passes: corpus membership is
declared by provenance metadata, not by the plugin's current CFF detector.

## What is included

`src/` contains repository-authored 0BSD fixtures:

| Source | Purpose |
|---|---|
| `single_switch.c` | Sparse 32-bit state values and a switch dispatcher |
| `if_chain.c` | Equality-comparison dispatcher |
| `nested.c` | Nested outer and inner dispatchers |
| `multi_state.c` | Joint dispatch over two states; consecutive state writes |
| `encoded_alias.c` | XOR-encoded alias used by dispatcher comparisons |
| `conditional_state.c` | Conditional state assignments |
| `side_effects.c` | Calls and volatile stores in real handlers |
| `natural_control.c` | Negative control with a natural loop and switch |

`spec.json` declares sources, expected symbols, and compiler profiles. The
checked-in artifacts cover:

- x86-64 ELF at GCC `-O0`, where the declared flattened shape is retained;
- x86-64 ELF at GCC `-O2`, an optimizer control showing that a normal compiler
  may recover structured control flow before MikuCffHelper sees the function;
- i386 ELF relocatable objects at GCC `-O0`.

Every positive executable calls a structured reference implementation on
several inputs and exits nonzero on a mismatch; the negative control runs a
basic sanity check. `build_corpus.py` runs those checks before updating the
manifest.

## Rebuild and verify

From the repository root:

```bash
python tools/corpus/build_corpus.py
sha256sum tools/corpus/artifacts/*
file tools/corpus/artifacts/*
nm -an --defined-only tools/corpus/artifacts/*
```

The compiler can be selected without editing the script:

```bash
CC=/path/to/gcc python tools/corpus/build_corpus.py
python tools/corpus/build_corpus.py --cc /path/to/gcc --profile x86_64-gcc-o0-exe
```

`manifest.json` records SHA-256, size, format, architecture, endianness,
object type, generator command, source variant, expected functions, symbol
addresses, and symbol verification. `build-metadata.json` records the exact
generated-artifact provenance.

The indexer parses every distinct address printed by `nm`. A unique address,
including `0x0`, is copied to the expected function. Repeated same-name rows at
one address are deduplicated. Same-name rows at different addresses are kept as
`symbol_status: "ambiguous"` with every value in `symbol_addresses`; no address
is guessed. A mismatch between an explicitly declared address and the unique
symbol address is likewise recorded as `address-mismatch`.

For relocatable and shared ELF files whose address came from `nm`, the function
also declares `loader_image_base: "0x0"`. This makes the symbol-value address
space explicit; consumers do not have to guess a loader default.

## Index existing or user-supplied samples

The indexer only parses file identity and merges declared metadata. It has no
block-count, state-value, flattening-score, or other CFF recognition threshold.

```bash
python tools/corpus/index_samples.py \
  /path/to/user/samples \
  --root /path/to/user/samples \
  --metadata /path/to/user-metadata.json \
  --output /tmp/user-cff-manifest.json
```

Metadata is a JSON object keyed by the path relative to `--root`:

```json
{
  "sample.bin": {
    "provenance": "Built locally from revision ...",
    "license": "SPDX identifier or UNKNOWN",
    "redistributable": false,
    "role": "positive",
    "variant": "generator and exact options",
    "expected_functions": [
      {"name": "target", "address": "0x1234", "source": "build map"}
    ]
  }
}
```

The six pre-existing files under `example/` are indexed in the checked-in
manifest, but are not copied. Their original source and license are not
documented, so `existing-metadata.json` marks all six `UNKNOWN` and
`redistributable: false`. The known regression addresses are imported from
`tools/baseline.json`.

## Strict before/after benchmark

`benchmark.py` uses only `expected_functions.address` entries from the manifest.
It never scans for CFF candidates and never filters by role, block count,
flattening score, state values, or transformation success. Each repetition
opens a fresh BinaryView, checks the binary SHA-256, calls
`get_function_at(address)` directly, captures MLIL/HLIL metrics, runs the
selected workflow, and captures the same metrics again.

Run a small explicit selection:

```bash
python tools/corpus/benchmark.py \
  --manifest tools/corpus/manifest.json \
  --root . \
  --plugin-root . \
  --bn-python /path/to/binaryninja/python \
  --target 'tools/corpus/artifacts/single-switch--x86_64-gcc-o0-exe.bin@0x401116' \
  --mode auto \
  --timeout-seconds 60 \
  --json /tmp/cff-benchmark.json \
  --csv /tmp/cff-benchmark.csv
```

Omit `--target` to measure every declared function. Repeat `--target` for an
exact multi-function selection and use `--repeat` for fresh-view repetitions.
The timeout is optional and comes only from the CLI; there is no embedded
function-size or runtime cutoff. JSON retains the complete nested metrics and
CSV provides one flat row per measurement.

Pure-Python regression tests do not require Binary Ninja:

```bash
python -m unittest discover -s tools/corpus/tests -v
```

## Reproducible external generators

### Obfuscator-LLVM

The official Obfuscator-LLVM project documents `-mllvm -fla` and optional
basic-block splitting. Its obfuscation passes use the permissive University of
Illinois/NCSA license:

- <https://github.com/obfuscator-llvm/obfuscator/wiki/Control-Flow-Flattening>
- <https://github.com/obfuscator-llvm/obfuscator/wiki/License>

No compiler fork is downloaded automatically. With a locally built, pinned
compiler, generate a sample and then index it with the exact revision and
command in metadata:

```bash
OLLVM_CLANG=/path/to/pinned/obfuscator-llvm/build/bin/clang
"$OLLVM_CLANG" -O0 -fno-pie -no-pie \
  -mllvm -fla \
  tools/corpus/src/natural_control.c -o /tmp/ollvm-fla.bin
```

For a split variant, add the documented `-mllvm -split` options explicitly and
record them verbatim. Do not infer the generator from the resulting CFG.

### Tigress

Tigress supports switch, direct-goto, indirect-goto, call, and concurrent
flattening, plus branch/compute/flag conditional encodings:

- <https://tigress.wtf/flatten.html>
- <https://tigress.wtf/usage.html>

Tigress is not open source. Its official download page says research use is
free for non-profit organizations and commercial use requires a University of
Arizona license: <https://tigress.wtf/download.html>. Always inspect the exact
installed terms with `tigress --license`. Consequently, this repository does
not download Tigress or commit Tigress-generated output by default.

A licensed local installation can generate declared variants using an explicit
seed and environment, for example:

```bash
: "${TIGRESS_ENVIRONMENT:?set the documented Tigress target environment}"
: "${TIGRESS_SEED:?set and record a deterministic seed}"
: "${TIGRESS_INCLUDE:?set the directory containing tigress.h}"

tigress \
  -D CORPUS_WITH_TIGRESS \
  -I "$TIGRESS_INCLUDE" \
  --Environment="$TIGRESS_ENVIRONMENT" \
  --Seed="$TIGRESS_SEED" \
  --Transform=Flatten \
  --Functions=corpus_natural_control \
  --FlattenDispatch=switch \
  --FlattenConditionalKinds=branch \
  --out=/tmp/tigress-switch.c \
  tools/corpus/src/natural_control.c
```

The generated C, installed Tigress version/license output, compiler version,
seed, and all transform options should be captured in user metadata. Only
commit generated output after its redistribution terms have been reviewed.

## Corpus policy

- A hash identifies bytes, not provenance. Both must be present.
- Unknown-origin binaries are indexed locally and are not duplicated.
- Generated artifacts must name the source, generator version, exact command,
  architecture, variant, and expected functions.
- A detector's output must never decide which samples enter the corpus; that
  would hide false negatives through selection bias.
- Self-tests provide concrete checks only. They do not replace static
  translation validation or broad differential testing.
