# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""Closed schemas (2026-10-10): a key nobody defined in the signature sidecar, in the RFC 3161 sidecar or at a ledger
entry's top level is a NAMED FAIL, never a silent pass; the pack's body keys are REPORTED (kind-defined, not judged).
Everything is built in a temporary directory removed at the end; the intact pack is the positive control."""
import json
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from omega_evidence import pack as P, verifier as VF, signing as S, ledger as L   # noqa: E402

KEY = "x_unknown_2026"
SCOPE = "Proves the recorded facts' integrity and order; does NOT prove their truth and is NOT an accredited certification."


class TestClosedSchema(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="oe-closed-")
        self.addCleanup(shutil.rmtree, self.d, ignore_errors=True)
        self.path = os.path.join(self.d, "pack.json")
        P.write_pack(self.path, P.build_pack("probe-kind", {"subject": "probe", "records": [{"a": 1}]}, SCOPE))
        self.ident = S.Identity("probe-signer", seed=bytes(range(32)))
        P.sign_pack(self.path, self.ident)
        self.led = os.path.join(self.d, "ledger.jsonl"); P.anchor_pack(self.path, self.led)
        self.sig = str(P._sig_sidecar(self.path))

    def layers(self, r):
        return {x["layer"]: x for x in r["layers"]}

    def test_intact_is_valid_and_reports_body_keys(self):
        r = VF.verify_pack(self.path, self.led)
        self.assertTrue(r["valid"]); self.assertTrue(r["authenticated"])
        pf = self.layers(r)["pack-fields"]
        self.assertEqual(pf["status"], "SKIP"); self.assertIn("records", pf["detail"]); self.assertIn("subject", pf["detail"])

    def test_unknown_sig_sidecar_field_is_a_named_fail(self):
        with open(self.sig, encoding="utf-8") as f:
            side = json.load(f)
        side[KEY] = "x"
        with open(self.sig, "w", encoding="utf-8") as f:
            json.dump(side, f)
        r = VF.verify_pack(self.path, self.led)
        self.assertFalse(r["valid"]); self.assertFalse(r["authenticated"])
        self.assertIn(KEY, self.layers(r)["producer-signature"]["detail"])

    def test_unknown_tsr_sidecar_field_is_a_named_fail(self):
        ts = self.path[:-5] + ".tsr.json"
        with open(ts, "w", encoding="utf-8") as f:
            json.dump({"digest_sha256": "0" * 64, "tsa": "x", "tsr_b64": "AA==", "stamped_utc": "2026-10-10T00:00:00+00:00", KEY: "x"}, f)
        r = VF.verify_pack(self.path, self.led)
        self.assertFalse(r["valid"]); self.assertIn(KEY, self.layers(r)["rfc3161"]["detail"])

    def test_unknown_ledger_entry_field_written_at_creation_is_a_named_fail(self):
        with open(self.led, encoding="utf-8") as f:
            es = [json.loads(ln) for ln in f if ln.strip()]
        es[0][KEY] = "x"
        out, prev = [], None
        for e in es:
            e = dict(e); e.pop("self_hash", None)
            if prev is not None:
                e["prev_hash"] = prev
            e["self_hash"] = L._hash_entry(e); prev = e["self_hash"]; out.append(e)
        with open(self.led, "w", encoding="utf-8") as f:
            for e in out:
                f.write(json.dumps(e, ensure_ascii=False) + "\n")
        r = VF.verify_pack(self.path, self.led)
        self.assertFalse(r["valid"]); lc = self.layers(r)["ledger-chain"]
        self.assertEqual(lc["status"], "FAIL"); self.assertIn(KEY, lc["detail"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
