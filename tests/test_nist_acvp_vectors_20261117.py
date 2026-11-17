#!/usr/bin/env python3
# Copyright 2026 Roberto Locatelli — Apache-2.0
"""The ML-DSA-65 vectors of the KAT gate (0.12.0): built by tools/build_nist_acvp_mldsa65.py from the NIST ACVP-Server
JSON (pinned commit and SHA-256), in this repository's closed JSON Lines format.

Positive and negative control from NIST's own verdicts: every case NIST marks testPassed true verifies, every case it
marks false is refused (with cryptography >= 48). The provenance line names the same commit and hashes as the tool.
The reader is closed: an unknown key, upper-case hex, a short key, a missing provenance line are refused."""
import json
import os
import shutil
import sys
import tempfile
import unittest
import unittest.mock

sys.dont_write_bytecode = True
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))
from omega_evidence.pqbackends import mldsa  # noqa: E402
import build_nist_acvp_mldsa65 as B  # noqa: E402


class TestNistVectors(unittest.TestCase):
    def test_provenance_matches_the_tool(self):
        with open(mldsa.KAT_FILE, encoding="utf-8") as f:
            head = json.loads(f.readline())
        self.assertEqual((head["commit"], head["sha256"], head["group"]), (B.COMMIT, B.SHA256, B.GROUP))
        cases = mldsa.load_cases()
        self.assertEqual(sum(c["file"] == "sigVer" for c in cases), 15)               # the whole sigVer group
        self.assertTrue(all(c["context"] == "" for c in cases if c["file"] == "sigGen"))
        self.assertEqual({c["file"] for c in cases if c["testPassed"] and c["context"] == ""}, {"sigGen"})

    @unittest.skipUnless(mldsa.available(), "cryptography >= 48 (ML-DSA) absent")
    def test_nist_verdicts(self):   # positive AND negative control, from NIST's testPassed
        for c in mldsa.load_cases():
            got = mldsa.verify_raw(bytes.fromhex(c["pk"]), bytes.fromhex(c["message"]), bytes.fromhex(c["signature"]),
                                   bytes.fromhex(c["context"]))
            self.assertEqual(got, c["testPassed"], (c["file"], c["tgId"], c["tcId"], c["reason"]))
        self.assertTrue(mldsa.try_load()["registered"])

    def test_reader_is_closed(self):
        with open(mldsa.KAT_FILE, encoding="utf-8") as f:
            head, first = f.readline(), f.readline()
        c = json.loads(first)
        bad = {"unknown key": json.dumps(dict(c, extra=1)), "upper-case hex": json.dumps(dict(c, pk=c["pk"].upper())),
               "short key": json.dumps(dict(c, pk=c["pk"][:-2])), "kind": json.dumps(dict(c, kind="x")),
               "testPassed string": json.dumps(dict(c, testPassed="true"))}
        d = tempfile.mkdtemp()
        try:
            for name, line in bad.items():
                p = os.path.join(d, "k.jsonl")
                with open(p, "w") as f:
                    f.write(head + line + "\n")
                with unittest.mock.patch.object(mldsa, "KAT_FILE", p):
                    with self.assertRaises(ValueError, msg=name):
                        mldsa.load_cases()
            p = os.path.join(d, "k.jsonl")
            open(p, "w").close()                                                         # empty file
            with unittest.mock.patch.object(mldsa, "KAT_FILE", p):
                with self.assertRaises(ValueError):
                    mldsa.load_cases()
                if mldsa.available():
                    self.assertIn("unusable", mldsa.try_load()["reason"])               # a verdict, never a crash
            with open(p, "w") as f:
                f.write(first)                                                         # no provenance line
            with unittest.mock.patch.object(mldsa, "KAT_FILE", p):
                with self.assertRaises(ValueError):
                    mldsa.load_cases()
                self.assertFalse(mldsa.try_load()["registered"] if mldsa.available() else False)
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
