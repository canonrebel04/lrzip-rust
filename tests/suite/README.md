# lrzip-rust Compression Test Suite

This suite runs end-to-end compression benchmarks and compatibility tests on lrzip-rust.

## Workflow Overview

1. **harvest.py** – Populate SAMPLES/ with diverse test files from DataPool
2. **benchmark.py** – Run level sweeps (L1/L4/L9) and backend sweeps
3. **compat_cross.py** – Cross-compatibility: rust→next and next→rust decompression
4. **Results** – CSVs in results/ summarizing all runs

## Environment Variables

All scripts respect these overrides (set at top of each script):

| Variable | Default |
|----------|---------|
| `LRZIP_RUST_BIN` | `/home/cachy/Projects/lrzip-rust/target/release/lrzip-rust` |
| `LRZIP_NEXT_BIN` | `/home/cachy/.local/bin/lrzip-next` |
| `SUITE_DIR` | Directory containing SAMPLES/ |

## Step 1: Harvest Sample Files

```bash
# Harvest from DataPool (~64MB per category)
python3 harvest.py

# Customize size or per-category count
python3 harvest.py --size-mb 32 --per-category 2
```

This creates SAMPLES/manifest.json listing all sample files.

## Step 2: Run Level Sweeps

```bash
# Default: L1, L4, L9 for rust/next/zpaq
python3 benchmark.py

# Custom levels
python3 benchmark.py --levels 1 9

# Only rust backend
python3 benchmark.py --tools rust

# With custom tag (results-<tag>.csv)
python3 benchmark.py --tag mytest

# Custom LRZIP_RUST_BIN
LRZIP_RUST_BIN=/path/to/lrzip-rust python3 benchmark.py
```

## Step 3: Backend Sweeps (lrzip-rust only)

```bash
# Test specific backends (zstd, zpaq, lzma)
python3 benchmark.py --backend zstd --tools rust
python3 benchmark.py --backend zpaq --tools rust
python3 benchmark.py --backend lzma --tools rust
```

## Step 4: Cross-Compatibility

```bash
# Test rust→next and next→rust at L1 and L9
python3 compat_cross.py

# Custom binaries
LRZIP_RUST_BIN=/path/to/rust LRZIP_NEXT_BIN=/path/to/next python3 compat_cross.py
```

## Output Files

| File | Description |
|------|-------------|
| `results/results-<tag>.csv` | Full benchmark results |
| `results/summary.md` | Human-readable summary |
| `work/<tag>/` | Temporary work files |
| `work/compat/` | Cross-compat test artifacts |

## Example Full Run

```bash
# 1. Harvest samples
python3 harvest.py

# 2. Run full benchmark suite
python3 benchmark.py

# 3. Verify cross-compat
python3 compat_cross.py

# 4. View results
cat results/results-main.csv | head
```
