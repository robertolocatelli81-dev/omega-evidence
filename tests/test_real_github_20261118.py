# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""Integration test on REAL third-party material from GitHub (opt-in: OMEGA_EVIDENCE_REAL_GITHUB=1, network, `gh`
logged in). Downloads at run time what tests/fixtures/real_github_20261118.json names — 24 GitHub artifact
attestations (sigstore bundles v0.3, DSSE, ECDSA P-256) with 16 RFC 3161 tokens of GitHub's TSA, and 1 message-signature
bundle with 1 token of Sigstore's TSA — and the two trusted roots for the TSA certificates. Nothing downloaded is
committed. Measured on 0.11.4 (18/11/2026) and on 381f881: DSSE 0/24, RFC 3161 0/17 (tools/real_github_check.py)."""
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(HERE, "..", "tools"))

import real_github_check as R  # noqa: E402


@unittest.skipUnless(os.environ.get("OMEGA_EVIDENCE_REAL_GITHUB") == "1" and shutil.which("gh") and shutil.which("openssl"),
                     "opt-in: OMEGA_EVIDENCE_REAL_GITHUB=1 with gh and openssl (downloads from GitHub)")
class TestRealGitHub(unittest.TestCase):
    def test_counts(self):
        d = os.environ.get("OMEGA_EVIDENCE_REAL_GITHUB_DIR") or tempfile.mkdtemp(prefix="real_github_")
        if not os.path.exists(os.path.join(d, "SHA256SUMS")):
            R.fetch(d)
        r = R.measure(d)
        self.assertEqual((r["dsse"], r["dsse_verified"], r["dsse_tampered_refused"]), (24, 24, 24), r["dsse_errors"])
        self.assertEqual((r["rfc3161"], r["rfc3161_verified"], r["rfc3161_wrong_digest"]), (17, 17, 0),
                         r["rfc3161_reasons"])
        self.assertEqual((r["bundle"], r["bundle_verified"], r["bundle_tampered_refused"]), (25, 25, 25),
                         r["bundle_errors"])
        self.assertEqual((r["bundle_subject_checked"], r["bundle_wrong_artifact_refused"]), (25, 25))
        self.assertEqual(r["bundle_time_checked"], 17)   # the 17 bundles with an RFC 3161 token; 8 carry a log entry only
        # at the current time a token whose TSA certificate has expired is refused, with that reason (1/17 on 18/11)
        for _name, at_gen, now in r["rfc3161_reasons"]:
            self.assertIsNone(at_gen)
            self.assertTrue(now)


if __name__ == "__main__":
    unittest.main()
