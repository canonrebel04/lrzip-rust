#!/usr/bin/env python3
"""Harvest a diverse compression-test corpus from DataPool into SAMPLES/.

Picks 1 representative file per category, each capped at SAMPLE_SIZE_MB,
copied (first N bytes via head) to keep the fast-SSD working set small.

Usage: harvest.py [--size-mb 64] [--per-category 1]
"""
import argparse
import hashlib
import os
import shutil
import subprocess
import sys

DATAPOOL = "/mnt/DataPool"
SUITE_DIR = os.environ.get('SUITE_DIR', os.path.dirname(os.path.abspath(__file__)))
SAMPLES = os.path.join(SUITE_DIR, "SAMPLES")

# category -> (search roots, extensions, label)
CATEGORIES = {
    "game_data":      ([f"{DATAPOOL}/Games", f"{DATAPOOL}/SteamLibrary"], [".pak", ".bin", ".dat", ".assets", ".arc", ".big", ".pck"], "uncompressed game data"),
    "game_archive":   ([f"{DATAPOOL}/Games"], [".tar", ".zip", ".rar", ".7z"], "already-compressed archive"),
    "compressed_tar": ([f"{DATAPOOL}/Games"], [".tar.zst", ".tar.lz4", ".tar.xz", ".tar.gz", ".tar.lrz", ".tar.zpaq"], "compressed tar"),
    "movie":          ([f"{DATAPOOL}/Media/Movies", f"{DATAPOOL}/Media/Series"], [".mkv", ".mp4", ".avi"], "video (highly compressed)"),
    "music":          ([f"{DATAPOOL}/Music"], [".flac", ".mp3", ".ogg"], "audio"),
    "image":          ([f"{DATAPOOL}/immich_library", f"{DATAPOOL}/Media"], [".jpg", ".png", ".webp", ".heic"], "image"),
    "document":       ([f"{DATAPOOL}", "/home/cachy/Documents", "/home/cachy/Downloads"], [".pdf", ".docx", ".xlsx", ".odt", ".epub"], "document"),
    "text":           (["/home/cachy"], [".md", ".txt", ".json", ".log"], "plain text (compressible)"),
    "iso":            ([f"{DATAPOOL}"], [".iso", ".img"], "disk image"),
    "model":          ([f"{DATAPOOL}"], [".gguf", ".safetensors"], "ML model weights"),
    "database":       ([f"{DATAPOOL}", "/home/cachy/.local/share/Steam/steamapps"], [".db", ".sqlite", ".sqlite3"], "database"),
    "executable":     (["/usr/bin"], [""], "ELF binary"),
}

SKIP_DIRS = {"$RECYCLE.BIN", "System Volume Information", "Duplicati_Backups", "node_modules", "target", ".git"}


def find_files(roots, exts, limit=40):
    """Yield candidate files, largest-first per root (big files = realistic)."""
    found = []
    for root in roots:
        if not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fn in filenames:
                if exts and not any(fn.lower().endswith(e) for e in exts):
                    continue
                p = os.path.join(dirpath, fn)
                try:
                    sz = os.path.getsize(p)
                except OSError:
                    continue
                if sz > 1024:  # skip tiny
                    found.append((sz, p))
    found.sort(reverse=True)
    return [p for _, p in found[:limit]]


def take_head(src, dst, max_bytes):
    """Copy first max_bytes of src to dst (sparse-friendly)."""
    size = os.path.getsize(src)
    if size <= max_bytes:
        shutil.copy2(src, dst)
        return size
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        remaining = max_bytes
        while remaining > 0:
            chunk = fi.read(min(remaining, 4 * 1024 * 1024))
            if not chunk:
                break
            fo.write(chunk)
            remaining -= len(chunk)
    return max_bytes - remaining


def md5(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--size-mb", type=int, default=64)
    ap.add_argument("--per-category", type=int, default=1)
    args = ap.parse_args()
    max_bytes = args.size_mb * 1024 * 1024

    os.makedirs(SAMPLES, exist_ok=True)
    manifest = []
    for cat, (roots, exts, label) in CATEGORIES.items():
        picked = 0
        for cand in find_files(roots, exts):
            if picked >= args.per_category:
                break
            ext = os.path.splitext(cand)[1] or ".bin"
            dst = os.path.join(SAMPLES, f"{cat}_{picked}{ext}")
            try:
                got = take_head(cand, dst, max_bytes)
            except OSError as e:
                print(f"  skip {cand}: {e}", file=sys.stderr)
                continue
            if got < 4096:
                os.remove(dst)
                continue
            manifest.append({"category": cat, "label": label, "source": cand,
                             "sample": dst, "bytes": got, "md5": md5(dst)})
            print(f"[{cat}] {got/1e6:7.1f}MB  {cand}")
            picked += 1
        if picked == 0:
            print(f"[{cat}] NO SAMPLE FOUND")

    import json
    with open(os.path.join(SAMPLES, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"\n{len(manifest)} samples, manifest at {SAMPLES}/manifest.json")


if __name__ == "__main__":
    main()
