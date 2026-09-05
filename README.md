# FileFoundation

A dependency-light **file investigation** CLI. Walk a directory tree and report
per-file forensic properties plus an aggregate summary.

- Pure Python 3.9+ stdlib — no third-party packages
- SHA-256 (streamed, capped), MIME guess, Shannon entropy, timestamps
- JSON (default) or human-readable table output
- Glob-based excludes, high-entropy flagging

## Install / Run

No install required. From the repo root:

```bash
python filefoundation.py [PATH] [options]
```

## Examples

```bash
# JSON report on the current directory
python filefoundation.py .

# Human-readable table
python filefoundation.py . --table

# Exclude everything matching a glob
python filefoundation.py /var/log --exclude "*.gz" --exclude "*.1"

# Tune the high-entropy threshold
python filefoundation.py . --high-entropy-threshold 6.0
```

## Output schema (JSON)

```json
{
  "summary": {
    "file_count": 12,
    "total_bytes": 102400,
    "type_histogram": {"text/plain": 8, "application/octet-stream": 4},
    "top_largest": [{"path": "...", "size": 50000}],
    "high_entropy_files": [{"path": "...", "entropy": 7.92}],
    "high_entropy_threshold": 7.5
  },
  "warnings": [],
  "files": [
    {
      "path": "...",
      "size": 123,
      "sha256": "...",
      "mime": "text/plain",
      "entropy": 3.12,
      "mtime": "2026-09-06T...",
      "ctime": "2026-09-06T...",
      "atime": "2026-09-06T...",
      "mode": "-rw-r--r--"
    }
  ]
}
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0    | success |
| 1    | IO error during walk |
| 2    | bad arguments / path not found |

## Test

```bash
python -m unittest tests.test_filefoundation -v
```

## License

See `LICENSE`.
