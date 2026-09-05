#!/usr/bin/env python3
"""Compression benchmark suite for lrzip-rust vs lrzip-next vs custom zpaq.

For each sample in SAMPLES/:
  - compress with each tool (timed), record size
  - decompress (timed), verify MD5 roundtrip
Results: results/results.csv + results/summary.md

Usage: benchmark.py [--levels 1 4 9] [--tools rust next zpaq] [--rounds 1]
"""
import argparse
import csv
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time

SUITE_DIR = os.environ.get('SUITE_DIR', os.path.dirname(os.path.abspath(__file__)))
SAMPLES = os.path.join(SUITE_DIR, "SAMPLES")
RESULTS = os.path.join(SUITE_DIR, "results")
WORK = os.path.join(SUITE_DIR, "work")

RUST_BIN = os.environ.get('LRZIP_RUST_BIN', '/home/cachy/Projects/lrzip-rust/target/release/lrzip-rust')
NEXT_BIN = os.environ.get('LRZIP_NEXT_BIN', '/home/cachy/.local/bin/lrzip-next')
if not os.path.exists(NEXT_BIN):
    for cand in ("/home/cachy/.local/bin/lrzip-next", shutil.which("lrzip-next")):
        if cand and os.path.exists(cand):
            NEXT_BIN = cand
            break
ZPAQ_DIR = "/home/cachy/Projects/zpaq"
ZPAQ_BIN = os.path.join(ZPAQ_DIR, "zpaq")


def md5(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def run(cmd, timeout=1800):
    t0 = time.perf_counter()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        rc, err = r.returncode, r.stderr[-400:]
    except subprocess.TimeoutExpired:
        rc, err = -99, "TIMEOUT"
    dt = time.perf_counter() - t0
    return rc, dt, err


def bench_rust(path, out, level, backend=None):
    cmd = [RUST_BIN, "-f", "-o", out, "-L", str(level), path]
    if backend:
        cmd = [RUST_BIN, "-f", "--backend", backend, "-o", out, "-L", str(level), path]
    return run(cmd)


def bench_next(path, out, level):
    return run([NEXT_BIN, "-f", "-o", out, f"-L{level}", path])


def bench_zpaq(path, out, level):
    # zpaq: add <archive> <files> -m<level>; zpaq levels 1..5 (custom build)
    lvl = max(1, min(5, (level + 2) // 2))  # map 1-9 -> 1-5
    if os.path.exists(out):
        os.remove(out)
    return run([ZPAQ_BIN, "add", out, path, f"-m{lvl}"])


TOOLBACKS = {
    "rust": (bench_rust, ".lrz", "decomp"),
    "next": (bench_next, ".lrz", "decomp"),
    "zpaq": (bench_zpaq, ".zpaq", "extract"),
}


def decomp_rust(arc, out):
    return run([RUST_BIN, "-d", "-f", "-o", out, arc])


def decomp_next(arc, out):
    return run([NEXT_BIN, "-d", "-f", "-o", out, arc])


def decomp_zpaq(arc, out):
    return run([ZPAQ_BIN, "extract", arc, out])


DEC = {"rust": decomp_rust, "next": decomp_next, "zpaq": decomp_zpaq}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--levels", type=int, nargs="+", default=[1, 4, 9])
    ap.add_argument("--tools", nargs="+", default=["rust", "next", "zpaq"])
    ap.add_argument("--rounds", type=int, default=1)
    ap.add_argument("--tag", default="main", help="unique run tag: results-<tag>.csv + work/<tag>/")
    ap.add_argument("--backend", default=None, help="lrzip-rust backend override (e.g. zstd, zpaq)")
    args = ap.parse_args()
    work = os.path.join(WORK, args.tag)
    os.makedirs(work, exist_ok=True)

    for t in args.tools:
        if t == "rust" and not os.path.exists(RUST_BIN):
            sys.exit(f"missing {RUST_BIN} — cargo build --release first")
        if t == "next" and not os.path.exists(NEXT_BIN):
            sys.exit(f"missing lrzip-next binary")
        if t == "zpaq" and not os.path.exists(ZPAQ_BIN):
            sys.exit(f"missing {ZPAQ_BIN}")

    manifest = json.load(open(os.path.join(SAMPLES, "manifest.json")))
    os.makedirs(RESULTS, exist_ok=True)
    os.makedirs(WORK, exist_ok=True)

    rows = []
    for entry in manifest:
        sample, orig_md5 = entry["sample"], entry["md5"]
        base = os.path.basename(sample)
        for tool in args.tools:
            for lvl in args.levels:
                for rnd in range(args.rounds):
                    arc = os.path.join(work, f"{base}.{tool}.l{lvl}")
                    out = os.path.join(work, f"{base}.{tool}.l{lvl}.out")
                    for p in (arc, out):
                        if os.path.exists(p):
                            os.remove(p)
                    csuffix = TOOLBACKS[tool][1]
                    arc = arc + csuffix

                    fn = {"rust": bench_rust, "next": bench_next, "zpaq": bench_zpaq}[tool]
                    rc, ct, err = fn(sample, arc, lvl, backend=args.backend) if tool == "rust" else fn(sample, arc, lvl)
                    if rc != 0:
                        rows.append(dict(sample=base, category=entry["category"], tool=tool,
                                         level=lvl, round=rnd, status=f"COMPRESS_FAIL",
                                         comp_s=round(ct, 3), err=err))
                        print(f"FAIL c {base} {tool} L{lvl}: {err[:120]}")
                        continue
                    csize = os.path.getsize(arc)
                    orig = entry["bytes"]
                    ratio = csize / orig

                    dfn = DEC[tool]
                    if tool == "zpaq":
                        rc, dt, derr = dfn(arc, out + "/")
                    else:
                        rc, dt, derr = dfn(arc, out)
                    if rc != 0:
                        rows.append(dict(sample=base, category=entry["category"], tool=tool,
                                         level=lvl, round=rnd, status="DECOMP_FAIL",
                                         orig_bytes=orig, comp_bytes=csize, ratio=round(ratio, 4),
                                         comp_s=round(ct, 3), err=derr))
                        print(f"FAIL d {base} {tool} L{lvl}: {derr[:120]}")
                        continue

                    got = md5(out if os.path.isfile(out) else os.path.join(out, base))
                    ok = got == orig_md5
                    c_mbs = orig / 1e6 / ct
                    d_mbs = orig / 1e6 / dt
                    rows.append(dict(sample=base, category=entry["category"], tool=tool, level=lvl,
                                     round=rnd, status="OK" if ok else "MD5_MISMATCH",
                                     orig_bytes=orig, comp_bytes=csize, ratio=round(ratio, 4),
                                     comp_s=round(ct, 3), decomp_s=round(dt, 3),
                                     comp_MBps=round(c_mbs, 1), decomp_MBps=round(d_mbs, 1),
                                     backend=args.backend or "default", err=""))
                    print(f"{'OK ' if ok else 'BAD'} {base:32s} {tool:5s} L{lvl}  "
                          f"ratio {ratio:.3f}  c {c_mbs:6.1f}MB/s  d {d_mbs:6.1f}MB/s")
                    for p in (arc, out):
                        if os.path.isfile(p):
                            os.remove(p)
                        elif os.path.isdir(p):
                            shutil.rmtree(p)

    # write CSV
    csv_path = os.path.join(RESULTS, f"results-{args.tag}.csv")
    if rows:
        keys = list(rows[0].keys())
        for r in rows:  # normalize keys
            for k in keys:
                r.setdefault(k, "")
        with open(csv_path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=keys)
            w.writeheader()
            w.writerows(rows)
    print(f"\n{len(rows)} runs -> {csv_path}")


if __name__ == "__main__":
    main()
