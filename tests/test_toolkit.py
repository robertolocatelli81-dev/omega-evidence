# Copyright 2026 Roberto Locatelli — Apache-2.0
"""End-to-end tests for the omega_evidence open toolkit.

Self-contained: imports only omega_evidence + stdlib. Positive and negative
controls for every property; a fabricated pack must not pass."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from omega_evidence import (attestation, canonical, ledger, pack,  # noqa: E402
                            signing, trust, verify_pack)


class TestCanonicalLedger(unittest.TestCase):
    def test_canonical_deterministic_and_injective(self):
        self.assertEqual(canonical.sha3({"a": 1, "b": [2, 3]}),
                         canonical.sha3({"b": [2, 3], "a": 1}))
        from decimal import Decimal
        self.assertNotEqual(canonical.sha3(Decimal("1.0")), canonical.sha3("1.0"))

    def test_ledger_append_verify_and_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "l.jsonl")
            lg = ledger.Ledger(p)
            lg.append({"x": 1}); lg.append({"x": 2})
            self.assertTrue(lg.verify()[0])
            lines = Path(p).read_text().splitlines()
            e = json.loads(lines[0]); e["data"]["x"] = 99
            Path(p).write_text(json.dumps(e, separators=(",", ":")) + "\n" + lines[1] + "\n")
            with self.assertRaises(RuntimeError):
                ledger.Ledger(p)


class TestBatchDurability(unittest.TestCase):
    """Modalità batch: throughput alto, catena valida, consistenza in lettura."""

    def test_batch_produce_catena_valida_e_leggibile(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "b.jsonl")
            lg = ledger.Ledger(p, durability="batch", batch_size=64)
            for i in range(500):
                lg.append({"i": i})
            # verify() riapre il file: DEVE vedere tutto (flush→OS per append)
            ok, bad = lg.verify()
            self.assertTrue(ok, bad)
            self.assertEqual(lg.count, 500)
            lg.close()

    def test_context_manager_fa_il_flush_finale(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "b.jsonl")
            with ledger.Ledger(p, durability="batch", batch_size=1000) as lg:
                for i in range(10):
                    lg.append({"i": i})
            # dopo il blocco: fsync fatto, riapribile con catena valida
            lg2 = ledger.Ledger(p)
            self.assertTrue(lg2.verify()[0])
            self.assertEqual(lg2.count, 10)

    def test_riapertura_batch_continua_la_catena(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "b.jsonl")
            with ledger.Ledger(p, durability="batch") as lg:
                lg.append({"i": 1}); lg.append({"i": 2})
            lg2 = ledger.Ledger(p, durability="batch")   # riprende dal disco
            lg2.append({"i": 3}); lg2.close()
            lg3 = ledger.Ledger(p)
            self.assertTrue(lg3.verify()[0])
            self.assertEqual(lg3.count, 3)

    def test_tamper_rilevato_anche_in_batch(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = os.path.join(tmp, "b.jsonl")
            with ledger.Ledger(p, durability="batch", batch_size=8) as lg:
                for i in range(20):
                    lg.append({"i": i})
            lines = Path(p).read_text().splitlines()
            e = json.loads(lines[10]); e["data"]["i"] = 999
            lines[10] = json.dumps(e, separators=(",", ":"))
            Path(p).write_text("\n".join(lines) + "\n")
            with self.assertRaises(RuntimeError):
                ledger.Ledger(p)

    def test_flush_in_sync_e_noop_e_durability_invalida_solleva(self):
        with tempfile.TemporaryDirectory() as tmp:
            lg = ledger.Ledger(os.path.join(tmp, "s.jsonl"))   # sync
            lg.append({"x": 1})
            lg.flush()   # no-op, non deve sollevare
            self.assertTrue(lg.verify()[0])
            with self.assertRaises(ValueError):
                ledger.Ledger(os.path.join(tmp, "z.jsonl"), durability="invalida")


class TestPackVerify(unittest.TestCase):
    def _pack(self, tmp, with_ledger=True):
        lg = None
        if with_ledger:
            lg = ledger.Ledger(os.path.join(tmp, "pack.ledger.jsonl"))
            lg.append({"event": "demo"})
        pk = pack.build_pack("demo_pack", {"payload": "x"},
                             "reference evidence; NOT a conformity assessment")
        pp = os.path.join(tmp, "pack.json")
        pack.write_pack(pp, pk)
        return pp

    def test_honest_scope_mandatory(self):
        with self.assertRaises(ValueError):
            pack.build_pack("k", {}, "this proves everything")   # no NOT

    def test_anchored_by_ledger_valid(self):
        with tempfile.TemporaryDirectory() as tmp:
            pp = self._pack(tmp, with_ledger=True)
            v = verify_pack(pp)
            self.assertTrue(v["valid"])
            auth = [x for x in v["layers"] if x["layer"] == "authenticity"][0]
            self.assertIn("anchored", auth["detail"])

    def test_bare_pack_cannot_authenticate(self):
        with tempfile.TemporaryDirectory() as tmp:
            pp = self._pack(tmp, with_ledger=False)   # no anchor, no signature
            v = verify_pack(pp)
            self.assertFalse(v["valid"])
            auth = [x for x in v["layers"] if x["layer"] == "authenticity"][0]
            self.assertEqual(auth["status"], "FAIL")

    def test_signed_and_trusted_reaches_trusted_signed(self):
        with tempfile.TemporaryDirectory() as tmp:
            pp = self._pack(tmp, with_ledger=False)
            ident = signing.Identity("acme")
            pack.sign_pack(pp, ident)
            store = os.path.join(tmp, "trust.jsonl")
            trust.TrustRegistry(store).trust("acme", ident.public_key_b64)
            v = verify_pack(pp, trust_store=store)
            auth = [x for x in v["layers"] if x["layer"] == "authenticity"][0]
            self.assertIn("trusted-signed", auth["detail"])
            self.assertTrue(v["valid"])

    def test_untrusted_signer_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            pp = self._pack(tmp, with_ledger=False)
            pack.sign_pack(pp, signing.Identity("acme"))
            store = os.path.join(tmp, "trust.jsonl")   # empty
            trust.TrustRegistry(store)
            v = verify_pack(pp, trust_store=store)
            self.assertFalse(v["valid"])

    def test_tampered_pack_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            pp = self._pack(tmp, with_ledger=True)
            d = json.loads(Path(pp).read_text()); d["payload"] = "TAMPERED"
            Path(pp).write_text(json.dumps(d))
            self.assertFalse(verify_pack(pp)["valid"])


class TestTrustAndAttestation(unittest.TestCase):
    def test_revoked_not_trusted_and_no_silent_retrust(self):
        with tempfile.TemporaryDirectory() as tmp:
            tr = trust.TrustRegistry(os.path.join(tmp, "t.jsonl"))
            ident = signing.Identity("acme")
            tr.trust("acme", ident.public_key_b64)
            tr.revoke("acme", "compromised")
            self.assertFalse(tr.is_trusted("acme", ident.public_key_b64))
            with self.assertRaises(ValueError):
                tr.trust("acme", ident.public_key_b64)   # silent re-trust blocked

    def test_pii_free_no_linkability(self):
        a1 = attestation.attest("subj-1", {"iban": "IT60X"})
        a2 = attestation.attest("subj-2", {"iban": "IT60X"})
        self.assertNotEqual(a1.attribute_digests["iban"], a2.attribute_digests["iban"])
        self.assertTrue(attestation.matches(a1, "iban", "IT60X"))
        self.assertFalse(attestation.matches(a1, "iban", "OTHER"))
        # the raw value never appears in the record
        self.assertNotIn("IT60X", json.dumps(a1.__dict__, default=str))


if __name__ == "__main__":
    unittest.main(verbosity=2)
