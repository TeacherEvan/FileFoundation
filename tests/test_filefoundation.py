"""Unit tests for filefoundation.

Run: python -m unittest tests.test_filefoundation -v
"""
import hashlib
import json
import os
import stat as stat_mod
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
            recs, warns = ff.walk(self.tmp)
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


if __name__ == "__main__":
    unittest.main()
