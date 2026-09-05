#!/usr/bin/env python3
"""FileFoundation - a dependency-light file investigation CLI.

Walks a directory tree and reports per-file forensic properties plus an
aggregate summary. Pure stdlib (Python 3.9+).
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import math
import mimetypes
import os
import stat
import sys
from collections import Counter
from datetime import datetime, timezone
from typing import Iterable

__version__ = "0.1.0"

EXIT_OK = 0
EXIT_IO = 1
EXIT_ARGS = 2

HASH_CHUNK = 65536
DEFAULT_ENTROPY_THRESHOLD = 7.5  # bits/byte; near-random


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _mime(path: str) -> str:
    mt, _ = mimetypes.guess_type(path)
    return mt or "application/octet-stream"


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def analyze_file(path: str, hash_bytes: int = HASH_CHUNK) -> dict:
    """Return forensic record for one file. Streams hash for large files."""
    st = os.stat(path, follow_symlinks=False)
    sha = hashlib.sha256()
    with open(path, "rb") as f:
        remaining = hash_bytes
        while remaining > 0:
            chunk = f.read(min(HASH_CHUNK, remaining))
            if not chunk:
                break
            sha.update(chunk)
            remaining -= len(chunk)
    with open(path, "rb") as f:
        sample = f.read(65536)
    return {
        "path": path,
        "size": st.st_size,
        "sha256": sha.hexdigest(),
        "mime": _mime(path),
        "entropy": round(_shannon_entropy(sample), 4),
        "mtime": _iso(st.st_mtime),
        "ctime": _iso(st.st_ctime),
        "atime": _iso(st.st_atime),
        "mode": stat.filemode(st.st_mode),
    }


def walk(root: str, excludes: Iterable[str] = (), follow_symlinks: bool = False) -> tuple:
    records = []
    warnings = []
    excl = list(excludes)

    def is_excluded(p: str) -> bool:
        base = os.path.basename(p)
        return any(fnmatch.fnmatch(base, g) or fnmatch.fnmatch(p, g) for g in excl)

    for parent, dirs, files in os.walk(root, followlinks=follow_symlinks):
        dirs[:] = [d for d in dirs if not is_excluded(os.path.join(parent, d))]
        for name in files:
            full = os.path.join(parent, name)
            if is_excluded(full):
                continue
            try:
                records.append(analyze_file(full))
            except PermissionError as e:
                warnings.append(f"permission denied: {full} ({e})")
            except OSError as e:
                warnings.append(f"io error: {full} ({e})")
    return records, warnings


def aggregate(records, top_n: int = 5, high_entropy_threshold: float = DEFAULT_ENTROPY_THRESHOLD) -> dict:
    total_bytes = sum(r["size"] for r in records)
    type_hist = Counter(r["mime"] for r in records)
    largest = sorted(records, key=lambda r: r["size"], reverse=True)[:top_n]
    high_ent = [r for r in records if r["entropy"] >= high_entropy_threshold]
    return {
        "file_count": len(records),
        "total_bytes": total_bytes,
        "type_histogram": dict(type_hist.most_common()),
        "top_largest": [{"path": r["path"], "size": r["size"]} for r in largest],
        "high_entropy_files": [{"path": r["path"], "entropy": r["entropy"]} for r in high_ent],
        "high_entropy_threshold": high_entropy_threshold,
    }


def emit_json(records, summary, warnings) -> str:
    return json.dumps({"summary": summary, "warnings": warnings, "files": records}, indent=2, sort_keys=False)


def emit_table(records, summary, warnings) -> str:
    cols = ("size", "entropy", "mime", "sha256", "path")
    rows = [
        (
            str(r["size"]).rjust(10),
            f"{r['entropy']:.3f}".rjust(7),
            r["mime"][:24].ljust(24),
            r["sha256"][:12],
            r["path"],
        )
        for r in records
    ]
    widths = [max(len(c), max((len(r[i]) for r in rows), default=0)) for i, c in enumerate(cols)]
    out = []
    header = "  ".join(c.ljust(widths[i]) if i != 1 else c.rjust(widths[i]) for i, c in enumerate(cols))
    out.append(header)
    out.append("-" * len(header))
    for r in rows:
        out.append("  ".join(
            r[i].rjust(widths[i]) if i in (0, 1) else r[i].ljust(widths[i])
            for i in range(len(cols))
        ))
    out.append("")
    out.append(f"files: {summary['file_count']}  bytes: {summary['total_bytes']}")
    if warnings:
        out.append(f"warnings: {len(warnings)}")
        for w in warnings:
            out.append(f"  ! {w}")
    return "\n".join(out)


def parse_args(argv=None):
    p = argparse.ArgumentParser(prog="filefoundation",
                                description="Walk a directory tree and report per-file forensic properties.")
    p.add_argument("path", nargs="?", default=".", help="root directory (default: cwd)")
    p.add_argument("--table", action="store_true", help="human-readable table instead of JSON")
    p.add_argument("--exclude", "-x", action="append", default=[], metavar="GLOB",
                   help="glob pattern to exclude (repeatable; matches basename or full path)")
    p.add_argument("--high-entropy-threshold", type=float, default=DEFAULT_ENTROPY_THRESHOLD,
                   metavar="F", help=f"flag files with entropy >= F (default {DEFAULT_ENTROPY_THRESHOLD})")
    p.add_argument("--hash-bytes", type=int, default=HASH_CHUNK,
                   metavar="N", help=f"cap SHA-256 stream to N bytes (default {HASH_CHUNK})")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p.parse_args(argv)


def main(argv=None) -> int:
    try:
        args = parse_args(argv)
    except SystemExit as e:
        return EXIT_ARGS if e.code != 0 else EXIT_OK

    root = os.path.abspath(args.path)
    if not os.path.isdir(root):
        print(f"error: not a directory: {root}", file=sys.stderr)
        return EXIT_ARGS

    try:
        records, warnings = walk(root, excludes=args.exclude)
        summary = aggregate(records, high_entropy_threshold=args.high_entropy_threshold)
    except OSError as e:
        print(f"io error: {e}", file=sys.stderr)
        return EXIT_IO

    if args.table:
        print(emit_table(records, summary, warnings))
    else:
        print(emit_json(records, summary, warnings))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
