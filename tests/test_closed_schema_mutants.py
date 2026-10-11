# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""CI wrapper of verifiers/closed_schema_mutants.py (closed sidecars and ledger entries, 2026-10-10; generative + differential
across the pack verifiers that build here: Python and Node always, Go and Java when their toolchains are present).

Two tests: the quick bench is GREEN on this tree; and the bench CAN go red — pointed at a copy of the Node verifier whose
sidecar rule is switched off it must count silent passes (a positive control of the bench, not of a verifier)."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BENCH = os.path.join(ROOT, "verifiers", "closed_schema_mutants.py")
JS = os.path.join(ROOT, "verifiers", "js", "oeverify.mjs")


class TestClosedSchemaMutants(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="oe-mutants-")
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)

    def _run(self, *extra):
        out = os.path.join(self.d, "out.json")
        r = subprocess.run([sys.executable, BENCH, "--quick", "--seed", "20261011", "--out", out, *extra], capture_output=True, text=True, timeout=1800, cwd=ROOT)
        with open(out, encoding="utf-8") as f:
            return r.returncode, json.load(f), r.stdout[-2000:] + r.stderr[-800:]

    def test_quick_bench_is_green_on_every_verifier_that_builds(self):
        rc, s, tail = self._run()
        self.assertEqual(rc, 0, tail)
        self.assertEqual(s["disagreements"], 0, tail)
        self.assertFalse(any(s["out_of_class"].values()), s["out_of_class"])
        self.assertFalse(any(s["unnamed_foreign_key"].values()), s["unnamed_foreign_key"])
        self.assertIn("python", s["verifiers"]); self.assertIn("js", s["verifiers"])
        self.assertGreaterEqual(sum(c["n"] for k, c in s["per_class"].items() if "unknown" in k and "in_data" not in k), 30)

    def test_bench_can_fail_lax_js_copy_counts_silent_passes(self):
        with open(JS, encoding="utf-8") as f:
            src = f.read()
        lax = src.replace("if (side && unknownKeys(side, SIG_SIDECAR_KEYS).length) {", "if (false) {", 1)
        self.assertNotEqual(lax, src, "the sidecar rule to switch off was not found: the control is void")
        # the name must END with "oeverify.mjs": the verifier runs main() only then (the first version of this control was named
        # otherwise, gave NONJSON/CRASH on every mutation and was void — caught by its own assertion on 11/10/2026)
        lax_path = os.path.join(ROOT, "verifiers", "js", "lax_control_tmp_oeverify.mjs")
        with open(lax_path, "w", encoding="utf-8") as f:
            f.write(lax)
        self.addCleanup(lambda: os.path.exists(lax_path) and os.remove(lax_path))
        rc, s, tail = self._run("--only", "python,js", "--js", lax_path)
        self.assertEqual(rc, 1, tail)
        self.assertGreater(s["silent_pass_on_expected_fail"]["js"], 0, s)
        self.assertEqual(s["silent_pass_on_expected_fail"]["python"], 0, s)

    def test_bench_lists_match_the_reference_lists(self):
        sys.path.insert(0, ROOT); sys.path.insert(0, os.path.join(ROOT, "verifiers"))
        from omega_evidence import verifier as V   # noqa: E402
        import closed_schema_mutants as B   # noqa: E402
        self.assertEqual(set(B.SIG_KEYS), set(V.SIG_SIDECAR_KEYS)); self.assertEqual(set(B.TSR_KEYS), set(V.TSR_SIDECAR_KEYS))
        self.assertEqual(set(B.ENTRY_KEYS), set(V.LEDGER_ENTRY_KEYS)); self.assertEqual(set(B.FORMAT_KEYS), set(V.PACK_FORMAT_KEYS))


if __name__ == "__main__":
    unittest.main(verbosity=2)
