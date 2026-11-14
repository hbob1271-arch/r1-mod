import hashlib
import csv
import io
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("reconcile", Path(__file__).parents[1] / "reconcile.py")
r = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(r)


class ReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.tree = self.base / "tree"
        self.tree.mkdir()
        self.manifest = self.base / "manifest.json"
        self.expected = {"size": 3, "sha256": hashlib.sha256(b"abc").hexdigest()}
        self.write_manifest({"a.bin": self.expected})

    def write_manifest(self, files):
        self.manifest.write_text(json.dumps({"files": files}))

    def test_matches_do_not_complete_gameplay(self):
        (self.tree / "a.bin").write_bytes(b"abc")
        report = r.reconcile({"a.bin": self.expected}, {"original": self.tree}, "hash")
        self.assertTrue(report["allExpectedFilesMatch"])
        self.assertEqual(report["entries"][0]["stages"]["complete"]["status"], "unknown")
        self.assertEqual(report["gameCompletion"], "unverified")

    def test_unavailable_is_not_missing(self):
        self.assertEqual(r.verify_file(None, "a.bin", self.expected)["status"], "unavailable")
        self.assertEqual(r.verify_file(self.tree, "a.bin", self.expected)["status"], "missing")

    def test_same_size_corruption(self):
        (self.tree / "a.bin").write_bytes(b"abd")
        self.assertEqual(r.verify_file(self.tree, "a.bin", self.expected)["status"], "mismatch")

    def test_wrong_size_even_with_matching_digest(self):
        (self.tree / "a.bin").write_bytes(b"abc")
        self.assertEqual(r.verify_file(self.tree, "a.bin", {**self.expected, "size": 4})["status"], "mismatch")

    def test_unsafe_and_windows_paths(self):
        for name in ("../x", "/x", "C:/x", "a/../x", "a\\x", "a//x", "a/CON.txt", "x:stream", "a."):
            with self.subTest(name=name):
                self.write_manifest({name: self.expected})
                with self.assertRaises(ValueError):
                    r.load_manifest(self.manifest)

    def test_duplicate_keys_and_case_collision(self):
        self.manifest.write_text('{"files": {}, "files": {}}')
        with self.assertRaises(ValueError):
            r.load_manifest(self.manifest)
        self.write_manifest({"a.bin": self.expected, "A.BIN": self.expected})
        with self.assertRaises(ValueError):
            r.load_manifest(self.manifest)
        self.write_manifest({"a": self.expected, "a/b": self.expected})
        with self.assertRaises(ValueError):
            r.load_manifest(self.manifest)

    def test_invalid_hash_and_size(self):
        for expected in ({**self.expected, "size": True}, {**self.expected, "size": -1},
                         {**self.expected, "sha256": "bad"}):
            self.write_manifest({"a": expected})
            with self.assertRaises(ValueError):
                r.load_manifest(self.manifest)

    def test_symlink_file_and_directory_rejected(self):
        target = self.base / "outside"
        target.mkdir()
        (target / "a.bin").write_bytes(b"abc")
        (self.tree / "a.bin").symlink_to(target / "a.bin")
        (self.tree / "dir").symlink_to(target, target_is_directory=True)
        for name in ("a.bin", "dir/a.bin"):
            self.assertEqual(r.verify_file(self.tree, name, self.expected)["status"], "unsafe")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX FIFO fixture")
    def test_fifo_does_not_block(self):
        os.mkfifo(self.tree / "a.bin")
        self.assertEqual(r.verify_file(self.tree, "a.bin", self.expected)["status"], "unsafe")

    def test_unlisted_files_accounted_for(self):
        (self.tree / "extra").write_bytes(b"x")
        report = r.reconcile({"a.bin": self.expected}, {"original": self.tree}, "hash")
        self.assertEqual(report["unlistedPaths"]["original"], ["extra"])
        self.assertEqual(report["entryCount"], 1)

    def test_cli_refuses_writes_inside_inputs_and_overwrites(self):
        for output in (self.tree / "report.json", self.manifest):
            self.assertEqual(r.main(["--manifest", str(self.manifest), "--original", str(self.tree),
                                     "--output", str(output)]), 2)
        output = self.base / "existing.json"
        output.write_text("keep")
        self.assertEqual(r.main(["--manifest", str(self.manifest), "--output", str(output)]), 2)
        self.assertEqual(output.read_text(), "keep")

    def test_cli_emits_every_entry_and_incomplete_exit(self):
        output = self.base / "report.json"
        self.assertEqual(r.main(["--manifest", str(self.manifest), "--output", str(output)]), 1)
        report = json.loads(output.read_text())
        self.assertEqual(report["entryCount"], 1)
        self.assertEqual(set(report["summary"]), {"original", "archive", "restoration"})
        self.assertEqual(report["summary"]["archive"], {"unavailable": 1})

    def test_tsv_accounts_for_every_row_and_preserves_unknowns(self):
        files = {"a.bin": self.expected, "nested/b.bin": self.expected}
        (self.tree / "a.bin").write_bytes(b"abc")
        report = r.reconcile(files, {"original": self.tree, "archive": None,
                                     "restoration": None}, "manifest-hash")
        stream = io.StringIO()
        r.write_tsv(report, stream)
        rows = list(csv.DictReader(io.StringIO(stream.getvalue()), delimiter="\t"))
        self.assertEqual({row["path"] for row in rows}, set(files))
        self.assertEqual(rows[0]["original_status"], "match")
        self.assertEqual(rows[1]["original_status"], "missing")
        self.assertEqual(rows[0]["archive_status"], "unavailable")
        self.assertEqual(rows[0]["manifest_sha256"], "manifest-hash")
        for row in rows:
            for stage in r.STAGES:
                self.assertEqual(row[stage], "unknown")
            self.assertEqual(row["game_completion"], "unverified")

    def test_tsv_unicode_and_quotes_round_trip(self):
        name = '地图/weapon\'name.bin'
        report = r.reconcile({name: self.expected}, {"original": None}, "hash")
        stream = io.StringIO()
        r.write_tsv(report, stream)
        row = next(csv.DictReader(io.StringIO(stream.getvalue()), delimiter="\t"))
        self.assertEqual(row["path"], name)

    def test_cli_tsv_output_and_preservation(self):
        output = self.base / "ledger.tsv"
        args = ["--manifest", str(self.manifest), "--format", "tsv", "--output", str(output)]
        self.assertEqual(r.main(args), 1)
        before = output.read_bytes()
        with output.open(newline="", encoding="utf-8") as stream:
            rows = list(csv.DictReader(stream, delimiter="\t"))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["generated_by"], "CodeRabbit")
        self.assertEqual(r.main(args), 2)
        self.assertEqual(output.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
