#!/usr/bin/env python3
"""Cross-compatibility: rust-compressed -> next-decomp, next-compressed -> rust-decomp, at L1 and L9."""
import hashlib, os, subprocess, sys
SUITE_DIR = os.environ.get('SUITE_DIR', os.path.dirname(os.path.abspath(__file__)))
RUST = os.environ.get('LRZIP_RUST_BIN', '/home/cachy/Projects/lrzip-rust/target/release/lrzip-rust')
NEXT = os.environ.get('LRZIP_NEXT_BIN', '/home/cachy/.local/bin/lrzip-next')
WORK = os.path.join(SUITE_DIR, "work", "compat"); os.makedirs(WORK, exist_ok=True)

def md5(p):
    h = hashlib.md5()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""): h.update(c)
    return h.hexdigest()

fails = 0
for entry in __import__("json").load(open(os.path.join(SUITE_DIR, "SAMPLES", "manifest.json"))):
    s = entry["sample"]; base = os.path.basename(s)
    for lvl in (1, 9):
        for cw, cd, tag in ((RUST, NEXT, "rust->next"), (NEXT, RUST, "next->rust")):
            arc = os.path.join(WORK, f"{base}.{lvl}.{cw.split('/')[-1]}.lrz")
            out = arc + ".out"
            for p in (arc, out):
                if os.path.exists(p): os.remove(p)
            r = subprocess.run([cw, "-f", "-o", arc, f"-L{lvl}", s], capture_output=True, text=True)
            if r.returncode: print(f"FAIL comp {tag} {base} L{lvl}: {r.stderr[-150:]}"); fails += 1; continue
            r = subprocess.run([cd, "-d", "-f", "-o", out, arc], capture_output=True, text=True)
            if r.returncode: print(f"FAIL decomp {tag} {base} L{lvl}: {r.stderr[-150:]}"); fails += 1; continue
            ok = md5(out) == entry["md5"]
            if not ok: fails += 1
            print(f"{'OK ' if ok else 'BAD'} {tag:11s} {base} L{lvl}")
            os.remove(out)
print(f"\ncompat failures: {fails}")
sys.exit(1 if fails else 0)
