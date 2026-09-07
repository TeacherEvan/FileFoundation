"""Unit tests for filefoundation.

Run: python -m unittest tests.test_filefoundation -v
"""
import hashlib
import json
import os
import tempfile
import unittest
from unittest import mock

import filefoundation as ff


class TestAnalyzeFile(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "hello.txt")
        with open(self.path, "wb") as f:
            f.write(b"hello world\n" * 10)

    def test_returns_required_fields(self):
        rec = ff.analyze_file(self.path)
        for key in ("path", "size", "sha256", "mime", "entropy",
                    "mtime", "ctime", "atime", "mode"):
            self.assertIn(key, rec)
        self.assertEqual(rec["size"], 120)
        self.assertEqual(rec["sha256"], hashlib.sha256(b"hello world\n" * 10).hexdigest())
        self.assertGreater(rec["entropy"], 0.0)

    def test_mime_for_text(self):
        rec = ff.analyze_file(self.path)
        self.assertTrue(rec["mime"].startswith("text/"))


class TestWalk(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        for name, body in (("a.txt", b"alpha"), ("b.py", b"print(1)\n"),
                           ("c.bin", os.urandom(2048))):
            with open(os.path.join(self.tmp, name), "wb") as f:
                f.write(body)
        os.makedirs(os.path.join(self.tmp, "sub"))
        with open(os.path.join(self.tmp, "sub", "d.txt"), "wb") as f:
            f.write(b"nested")

    def test_walks_all_files(self):
        recs, warns = ff.walk(self.tmp)
        self.assertEqual(len(recs), 4)
        self.assertEqual(warns, [])

    def test_exclude_glob_filters(self):
        recs, _ = ff.walk(self.tmp, excludes=["*.py"])
        names = [os.path.basename(r["path"]) for r in recs]
        self.assertNotIn("b.py", names)
        self.assertIn("a.txt", names)
        # dir prune: sub/ has no .py files but we should still descend
        self.assertIn("d.txt", names)

    def test_permission_denied(self):
        # create a read-only file
        ro = os.path.join(self.tmp, "ro.txt")
        with open(ro, "wb") as f:
            f.write(b"x")
        os.chmod(ro, 0o000)
        try:
            _recs, warns = ff.walk(self.tmp)
            # either permission denied surfaces in warnings, or root strips it (some envs allow)
            # check that walk did NOT crash
            self.assertIsInstance(warns, list)
        finally:
            os.chmod(ro, 0o644)


class TestAggregate(unittest.TestCase):
    def test_empty(self):
        s = ff.aggregate([])
        self.assertEqual(s["file_count"], 0)
        self.assertEqual(s["total_bytes"], 0)
        self.assertEqual(s["type_histogram"], {})

    def test_top_n_and_high_entropy(self):
        # deterministic: known-low-entropy text and high-entropy random
        recs = [
            {"size": 10, "mime": "text/plain", "path": "/x/a", "entropy": 1.0},
            {"size": 99, "mime": "text/plain", "path": "/x/b", "entropy": 2.0},
            {"size": 50, "mime": "application/octet-stream", "path": "/x/c", "entropy": 7.9},
        ]
        s = ff.aggregate(recs, top_n=2)
        self.assertEqual(s["file_count"], 3)
        self.assertEqual(s["total_bytes"], 159)
        self.assertEqual(s["top_largest"][0]["path"], "/x/b")
        # c (7.9) above default 7.5 -> flagged
        self.assertEqual(len(s["high_entropy_files"]), 1)
        self.assertEqual(s["high_entropy_files"][0]["path"], "/x/c")


class TestEmit(unittest.TestCase):
    def test_json_emits_valid_json_with_required_blocks(self):
        rec = {"path": "/a", "size": 1, "sha256": "x", "mime": "text/plain",
               "entropy": 0.0, "mtime": "t", "ctime": "t", "atime": "t", "mode": "-"}
        s = {"file_count": 1, "total_bytes": 1, "type_histogram": {"text/plain": 1},
             "top_largest": [{"path": "/a", "size": 1}],
             "high_entropy_files": [], "high_entropy_threshold": 7.5}
        out = ff.emit_json([rec], s, [])
        parsed = json.loads(out)
        self.assertIn("summary", parsed)
        self.assertIn("files", parsed)
        self.assertIn("warnings", parsed)

    def test_table_contains_columns(self):
        rec = {"path": "/a", "size": 1, "sha256": "abcdef0123456789", "mime": "text/plain",
               "entropy": 1.234, "mtime": "t", "ctime": "t", "atime": "t", "mode": "-"}
        s = {"file_count": 1, "total_bytes": 1, "type_histogram": {}, "top_largest": [],
             "high_entropy_files": [], "high_entropy_threshold": 7.5}
        out = ff.emit_table([rec], s, [])
        self.assertIn("path", out)
        self.assertIn("sha256", out)
        self.assertIn("files:", out)


class TestCLI(unittest.TestCase):
    def test_help_exits_zero(self):
        with mock.patch("sys.argv", ["ff", "--help"]):
            rc = ff.main()
            self.assertEqual(rc, ff.EXIT_OK)

    def test_bad_path_exits_two(self):
        with mock.patch("sys.argv", ["ff", "/no/such/dir/hopefully"]):
            rc = ff.main()
            self.assertEqual(rc, ff.EXIT_ARGS)

    def test_real_walk_emits_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "x.txt"), "w") as f:
                f.write("hi")
            with mock.patch("sys.argv", ["ff", tmp]):
                rc = ff.main()
            self.assertEqual(rc, ff.EXIT_OK)

    def test_table_flag_works(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "x.txt"), "w") as f:
                f.write("hi")
            with mock.patch("sys.argv", ["ff", "--table", tmp]):
                rc = ff.main()
            self.assertEqual(rc, ff.EXIT_OK)



class TestHashBytesCap(unittest.TestCase):
    """Verify the --hash-bytes cap is honored end-to-end (bug-fix wiring)."""

    def test_analyze_file_caps_hash_at_n_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "big.bin")
            payload = bytes(range(256)) * 4  # 1024 bytes, deterministic
            with open(p, "wb") as f:
                f.write(payload)
            rec = ff.analyze_file(p, hash_bytes=16)
            expected = hashlib.sha256(payload[:16]).hexdigest()
            self.assertEqual(rec["sha256"], expected)
            # file is bigger than the cap — hash must NOT match full-file sha
            self.assertNotEqual(rec["sha256"], hashlib.sha256(payload).hexdigest())

    def test_walk_propagates_hash_bytes_kwarg(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "big.bin")
            payload = b"A" * 200 + b"B" * 200  # 400 bytes
            with open(p, "wb") as f:
                f.write(payload)
            recs, _ = ff.walk(tmp, hash_bytes=32)
            self.assertEqual(len(recs), 1)
            self.assertEqual(recs[0]["sha256"], hashlib.sha256(payload[:32]).hexdigest())

    def test_cli_hash_bytes_flag_affects_output(self):
        import io
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "x.bin")
            payload = b"hello world\n" * 100  # 1200 bytes
            with open(p, "wb") as f:
                f.write(payload)
            # capture stdout
            buf = io.StringIO()
            with mock.patch("sys.argv", ["ff", "--hash-bytes", "10", tmp]), \
                 mock.patch("sys.stdout", buf):
                rc = ff.main()
            self.assertEqual(rc, ff.EXIT_OK)
            parsed = json.loads(buf.getvalue())
            self.assertEqual(len(parsed["files"]), 1)
            self.assertEqual(
                parsed["files"][0]["sha256"],
                hashlib.sha256(payload[:10]).hexdigest(),
            )


if __name__ == "__main__":
    unittest.main()

class TestDefaultIgnore(unittest.TestCase):
    """OBJ-003: default VCS-skip + --no-ignore-vcs override."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        # a fake .git/HEAD file
        os.makedirs(os.path.join(self.tmp, ".git"))
        with open(os.path.join(self.tmp, ".git", "HEAD"), "w") as f:
            f.write("ref: refs/heads/main\n")
        # and a real source file
        with open(os.path.join(self.tmp, "real.txt"), "w") as f:
            f.write("hello\n")

    def test_default_skips_git_dir(self):
        recs, _ = ff.walk(self.tmp)
        paths = [r["path"] for r in recs]
        # real.txt IS walked
        self.assertTrue(any(p.endswith("real.txt") for p in paths))
        # nothing under .git/ leaks out
        self.assertFalse(any("/.git/" in p for p in paths),
                         f".git/* leaked through default ignore: {paths}")

    def test_no_ignore_vcs_includes_git_dir(self):
        recs, _ = ff.walk(self.tmp, ignore_vcs_default=False)
        paths = [r["path"] for r in recs]
        # now .git/HEAD is in the records
        self.assertTrue(any(p.endswith(".git/HEAD") or p.endswith("HEAD") and "/.git/" in p
                            for p in paths),
                        f".git/HEAD missing when ignore_vcs_default=False: {paths}")

    def test_user_exclude_overrides_default(self):
        # user explicitly excludes .git; default ignore_vcs_default=True;
        # the merge logic must still skip .git (idempotent re: user intent).
        recs, _ = ff.walk(self.tmp, excludes=[".git"])
        paths = [r["path"] for r in recs]
        self.assertFalse(any("/.git/" in p for p in paths))

    def test_cli_flag_round_trip(self):
        # default run: no .git/*; --no-ignore-vcs: .git/* present.
        import io
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, ".git"))
            with open(os.path.join(tmp, ".git", "HEAD"), "w") as f:
                f.write("x")
            with open(os.path.join(tmp, "real.txt"), "w") as f:
                f.write("hi")
            # default
            buf = io.StringIO()
            with mock.patch("sys.argv", ["ff", tmp]), mock.patch("sys.stdout", buf):
                self.assertEqual(ff.main(), ff.EXIT_OK)
            default_parsed = json.loads(buf.getvalue())
            self.assertFalse(any("/.git/" in r["path"] for r in default_parsed["files"]),
                             "default CLI walk leaked .git/*")
            # --no-ignore-vcs
            buf2 = io.StringIO()
            with mock.patch("sys.argv", ["ff", "--no-ignore-vcs", tmp]), mock.patch("sys.stdout", buf2):
                self.assertEqual(ff.main(), ff.EXIT_OK)
            forced = json.loads(buf2.getvalue())
            self.assertTrue(any("/.git/" in r["path"] for r in forced["files"]),
                            "--no-ignore-vcs CLI flag did not surface .git/*")

class TestDefaultHashBytes(unittest.TestCase):
    """OBJ-006: pin CLI default --hash-bytes = full-file SHA for small files."""

    def test_cli_default_hash_bytes_full_file_sha(self):
        import io
        with tempfile.TemporaryDirectory() as tmp:
            payload = b"hello world\n" * 10  # 120 bytes
            with open(os.path.join(tmp, "hello.txt"), "wb") as f:
                f.write(payload)
            buf = io.StringIO()
            with mock.patch("sys.argv", ["ff", tmp]), mock.patch("sys.stdout", buf):
                self.assertEqual(ff.main(), ff.EXIT_OK)
            parsed = json.loads(buf.getvalue())
            self.assertEqual(len(parsed["files"]), 1)
            self.assertEqual(
                parsed["files"][0]["sha256"],
                hashlib.sha256(payload).hexdigest(),
            )

