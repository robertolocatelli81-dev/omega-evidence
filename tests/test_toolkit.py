# Copyright 2026 Roberto Locatelli — Apache-2.0
"""End-to-end tests for the omega_evidence open toolkit.

Self-contained: imports only omega_evidence + stdlib. Positive and negative
controls for every property; a fabricated pack must not pass."""

import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from omega_evidence import (_ed25519_pure, agent, attestation, canonical,  # noqa: E402
                            chip_registry, cra, ledger, ots, pack,
                            preservation, signing, trust, verify_pack)
from omega_evidence.interop import dsse, sdjwt  # noqa: E402
from omega_evidence.pqbackends import gate as pqgate  # noqa: E402


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
        pk = pack.build_pack("demo_pack", {"payload": "x"},
                             "reference evidence; NOT a conformity assessment")
        pp = os.path.join(tmp, "pack.json")
        pack.write_pack(pp, pk)
        if with_ledger:
            # anchor the pack's own pack_sha3 into the ledger (real binding)
            pack.anchor_pack(pp, os.path.join(tmp, "pack.ledger.jsonl"))
        return pp

    def test_honest_scope_mandatory(self):
        with self.assertRaises(ValueError):
            pack.build_pack("k", {}, "this proves everything")   # no NOT

    def test_verifier_honest_scope_no_substring_bypass(self):
        # REGRESSIONE (stress 4-menti 04/09): il verifier NON deve accettare un pack
        # a mano che infila 'NOT' come sottostringa (NOTE/CANNOT) mentre rivendica
        # accreditamento. Deve usare lo stesso gate forte del builder.
        import json as _json
        with tempfile.TemporaryDirectory() as tmp:
            for scope, want in [
                ("NOTE: this pack is a fully accredited certified guaranteed attestation.", "FAIL"),
                ("fully certified accredited solution", "FAIL"),
                ("This pack does NOT prove accreditation; internal demo only.", "PASS"),
            ]:
                pk = {"kind": "x", "body": {}, "honest_scope": scope}
                pk["pack_sha3"] = canonical.sha3({k: v for k, v in pk.items() if k != "pack_sha3"})
                fp = os.path.join(tmp, "p.json"); open(fp, "w").write(_json.dumps(pk))
                hs = next(l for l in verify_pack(fp)["layers"] if l["layer"] == "honest-scope")
                self.assertEqual(hs["status"], want, f"scope={scope!r}")

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


class TestAgentGovernance(unittest.TestCase):
    """Open-core agent governance: same pack format, same verifier, cross-domain.
    Positive + negative controls; an inconsistent or self-asserted case is caught."""

    def _log(self, tmp):
        return agent.AgentEvidenceLog(
            os.path.join(tmp, "agent.ledger.jsonl"), runtime_id="openshell")

    def test_record_chain_and_consistency(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = self._log(tmp)
            log.record("a1", "s1", "credential_access", "vault://prod", "deny-default",
                       agent.Decision.DENY, agent.Outcome.BLOCKED)
            log.record("a1", "s1", "file_write", "/etc/x", "sensitive",
                       agent.Decision.ALLOW_WITH_APPROVAL, agent.Outcome.EXECUTED,
                       human_approver="Roberto")
            v = log.verify()
            self.assertTrue(v["chain_ok"])
            st = log.stats()
            self.assertEqual(st["total"], 2)
            self.assertEqual(st["deny"], 1)
            self.assertTrue(st["all_consistent"])

    def test_inconsistency_is_visible_not_hidden(self):
        # ALLOW recorded as BLOCKED is incoherent — must be surfaced, not swallowed.
        with tempfile.TemporaryDirectory() as tmp:
            log = self._log(tmp)
            log.record("a1", "s1", "tool_call", "x", "r",
                       agent.Decision.ALLOW, agent.Outcome.BLOCKED)
            st = log.stats()
            self.assertFalse(st["all_consistent"])
            self.assertEqual(len(st["inconsistent"]), 1)

    def test_approval_required_for_allow_with_approval(self):
        a = agent.AgentAction("a", "s", "x", "r", "rule",
                              agent.Decision.ALLOW_WITH_APPROVAL.value,
                              agent.Outcome.EXECUTED.value, human_approver=None)
        self.assertFalse(a.consistent())          # no approver → incoherent
        b = agent.AgentAction("a", "s", "x", "r", "rule",
                              agent.Decision.ALLOW_WITH_APPROVAL.value,
                              agent.Outcome.EXECUTED.value, human_approver="Roberto")
        self.assertTrue(b.consistent())

    def test_attestation_never_trustworthy_here(self):
        # NEMESIS re-attack fix: trustworthy is NEVER asserted here (the toolkit
        # does not verify the vendor crypto; every field is caller-forgeable).
        # The signal is attestation_status, and trustworthy stays False always.
        good = agent.check_attestation(
            {"attestation_class": "amd-sev-snp", "verified_by_service": True})
        self.assertFalse(good["trustworthy"])
        self.assertEqual(good["expected_service"], "amd-kds")
        self.assertEqual(good["attestation_status"], "producer-claimed")   # boolean only
        # with token+report → recorded but still UNVERIFIED (never trustworthy here)
        withtok = agent.check_attestation(
            {"attestation_class": "amd-sev-snp", "verified_by_service": True,
             "service_attestation_token": "T", "report_sha256": "r"})
        self.assertFalse(withtok["trustworthy"])
        self.assertEqual(withtok["attestation_status"], "service-token-recorded-UNVERIFIED")
        # untrusted / unknown classes → untrusted-class status, never trustworthy
        for att in ({"attestation_class": "self-asserted", "verified_by_service": True},
                    {"attestation_class": "totally-made-up", "verified_by_service": True},
                    None):
            r = agent.check_attestation(att)
            self.assertFalse(r["trustworthy"])

    def test_pack_verifies_with_the_same_toolkit_verifier(self):
        # The whole point: an agent pack is verified by the SAME offline verifier
        # as any other domain — cross-domain uniformity, one verifier.
        with tempfile.TemporaryDirectory() as tmp:
            log = self._log(tmp)
            log.record("a1", "s1", "tool_call", "x", "r",
                       agent.Decision.ALLOW, agent.Outcome.EXECUTED)
            pk = log.evidence_pack()
            self.assertEqual(pk["kind"], "agent_governance_evidence_pack")
            self.assertIn("NOT", pk["honest_scope"])
            pp = os.path.join(tmp, "pack.json")
            pack.write_pack(pp, pk)
            pack.anchor_pack(pp, log.ledger_path)   # record this pack's sha3 in the ledger
            v = verify_pack(pp, ledger_path=log.ledger_path)
            self.assertTrue(v["valid"])
            auth = [x for x in v["layers"] if x["layer"] == "authenticity"][0]
            self.assertIn("anchored", auth["detail"])

    def test_action_hash_is_tamper_evident(self):
        a = agent.AgentAction("a", "s", "x", "r", "rule",
                              agent.Decision.ALLOW.value, agent.Outcome.EXECUTED.value)
        # a different field → a different digest (injective canonical hash)
        b = agent.AgentAction("a", "s", "x", "r", "rule",
                              agent.Decision.DENY.value, agent.Outcome.BLOCKED.value,
                              timestamp_utc=a.timestamp_utc)
        self.assertNotEqual(a.digest(), b.digest())


class TestChipRegistrySelfUpdate(unittest.TestCase):
    """A FUTURE chip becomes known ONLY via a trusted-signed update; discovery is
    online but never trusted; untrusted/self-asserted can never be promoted."""

    FUTURE = "nvidia-rubin-cc"

    def _signed_update(self, tmp, classes, signer_name="curator"):
        ident = signing.Identity(signer_name)
        up = os.path.join(tmp, "update.json")
        chip_registry.publish_signed_update(up, classes, ident)
        return up, ident

    def test_future_chip_unknown_until_trusted_update(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg = chip_registry.ChipRegistry()
            self.assertFalse(reg.is_known(self.FUTURE))
            # unknown class → untrusted-class status
            self.assertEqual(agent.check_attestation(
                {"attestation_class": self.FUTURE, "verified_by_service": True}, reg)["attestation_status"],
                "untrusted-class")
            up, ident = self._signed_update(tmp, {self.FUTURE: "nvidia-nras"})
            store = os.path.join(tmp, "trust.jsonl")
            trust.TrustRegistry(store).trust(ident.name, ident.public_key_b64)
            r = reg.apply_signed_update(up, store)
            self.assertTrue(r["applied"])
            self.assertIn(self.FUTURE, r["added"])
            self.assertTrue(reg.is_known(self.FUTURE))
            # now known → no longer untrusted-class (but still never trustworthy here)
            att = agent.check_attestation(
                {"attestation_class": self.FUTURE, "verified_by_service": True}, reg)
            self.assertEqual(att["attestation_status"], "producer-claimed")
            self.assertFalse(att["trustworthy"])

    def test_untrusted_signer_update_is_rejected_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg = chip_registry.ChipRegistry()
            up, _ = self._signed_update(tmp, {self.FUTURE: "nvidia-nras"})
            store = os.path.join(tmp, "trust.jsonl")
            trust.TrustRegistry(store)              # empty: signer not trusted
            r = reg.apply_signed_update(up, store)
            self.assertFalse(r["applied"])
            self.assertFalse(reg.is_known(self.FUTURE))   # unchanged

    def test_tampered_update_pack_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg = chip_registry.ChipRegistry()
            up, ident = self._signed_update(tmp, {self.FUTURE: "nvidia-nras"})
            store = os.path.join(tmp, "trust.jsonl")
            trust.TrustRegistry(store).trust(ident.name, ident.public_key_b64)
            d = json.loads(Path(up).read_text())
            d["chip_classes"]["evil-chip"] = "attacker-service"   # tamper after signing
            Path(up).write_text(json.dumps(d))
            r = reg.apply_signed_update(up, store)
            self.assertFalse(r["applied"])                 # pack_sha3/signature mismatch
            self.assertFalse(reg.is_known("evil-chip"))

    def test_self_asserted_never_promotable_even_if_signed(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg = chip_registry.ChipRegistry()
            up, ident = self._signed_update(tmp, {"self-asserted": "x", "none": "y"})
            store = os.path.join(tmp, "trust.jsonl")
            trust.TrustRegistry(store).trust(ident.name, ident.public_key_b64)
            r = reg.apply_signed_update(up, store)
            self.assertEqual(r["added"], [])
            self.assertIn("self-asserted", r["rejected"])
            self.assertFalse(agent.check_attestation(
                {"attestation_class": "self-asserted", "verified_by_service": True}, reg)["trustworthy"])

    def test_baseline_not_overridable_by_a_feed(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg = chip_registry.ChipRegistry()
            # a signed feed tries to redirect a baseline chip to a rogue service
            up, ident = self._signed_update(tmp, {"nvidia-hopper-cc": "rogue-service"})
            store = os.path.join(tmp, "trust.jsonl")
            trust.TrustRegistry(store).trust(ident.name, ident.public_key_b64)
            reg.apply_signed_update(up, store)
            self.assertEqual(reg.service_for("nvidia-hopper-cc"), "nvidia-nras")  # unchanged

    def test_discovery_records_unverified_candidate_not_trusted(self):
        reg = chip_registry.ChipRegistry()
        out = reg.ingest_candidates(
            [{"attestation_class": "acme-tee-cc", "vendor": "ACME", "technology": "TEE-X"}],
            source="https://feed.example/candidates.json")
        self.assertIn("acme-tee-cc", out["discovered"])
        self.assertFalse(reg.is_known("acme-tee-cc"))          # discovered ≠ known
        self.assertIn("acme-tee-cc", reg.candidates())
        self.assertEqual(reg.candidates()["acme-tee-cc"]["status"], "UNVERIFIED")
        self.assertFalse(agent.check_attestation(
            {"attestation_class": "acme-tee-cc", "verified_by_service": True}, reg)["trustworthy"])


class TestPortabilityPureEd25519(unittest.TestCase):
    """The pure-Python fallback lets signing work on ANY machine (no native wheel).
    Validated against the official RFC 8032 vectors AND cross-checked, when
    available, against the cryptography backend as an oracle."""

    # RFC 8032 section 7.1 — official Ed25519 test vectors (known truth)
    VECTORS = [
        ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
         "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
         "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb882"
         "1590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
        ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
         "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
         "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1"
         "e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ]

    def test_rfc8032_official_vectors(self):
        for sk, pk, msg, sig in self.VECTORS:
            seed, m = bytes.fromhex(sk), bytes.fromhex(msg)
            self.assertEqual(_ed25519_pure.secret_to_public(seed).hex(), pk)
            self.assertEqual(_ed25519_pure.sign(seed, m).hex(), sig)
            self.assertTrue(_ed25519_pure.verify(bytes.fromhex(pk), m, bytes.fromhex(sig)))

    def test_pure_rejects_tampered_signature(self):
        sk, pk, msg, sig = self.VECTORS[1]
        bad = bytearray(bytes.fromhex(sig)); bad[0] ^= 0x01
        self.assertFalse(_ed25519_pure.verify(bytes.fromhex(pk), bytes.fromhex(msg), bytes(bad)))
        self.assertFalse(_ed25519_pure.verify(bytes.fromhex(pk), b"other message", bytes.fromhex(sig)))

    @unittest.skipUnless(signing.BACKEND == "cryptography",
                         "cross-backend oracle needs the cryptography package")
    def test_cross_backend_interop_oracle(self):
        # pure and cryptography must agree on pubkey, signature, and verification
        # for many inputs — an independent proof the fallback is standard-correct.
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        import hashlib
        for i in range(64):
            seed = hashlib.sha256(f"seed-{i}".encode()).digest()   # deterministic
            msg = f"message-{i}".encode()
            sk = Ed25519PrivateKey.from_private_bytes(seed)
            c_pub = sk.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            c_sig = sk.sign(msg)
            self.assertEqual(_ed25519_pure.secret_to_public(seed), c_pub)  # same pubkey
            self.assertEqual(_ed25519_pure.sign(seed, msg), c_sig)          # same signature
            self.assertTrue(_ed25519_pure.verify(c_pub, msg, c_sig))        # pure verifies native

    def test_identity_and_verify_roundtrip_active_backend(self):
        idt = signing.Identity("acme")
        sig = idt.sign(b"payload")
        self.assertTrue(signing.verify_signature(idt.public_key_b64, sig, b"payload"))
        self.assertFalse(signing.verify_signature(idt.public_key_b64, sig, b"tampered"))
        self.assertTrue(idt.fingerprint.startswith("ed25519:"))


class TestCryptoAgility(unittest.TestCase):
    """sig_alg dispatch + hybrid PQ co-signature, with honest (non-binary) states:
    classical / pq-present-unverified / pq-protected, and fail-closed on bad PQ."""

    def tearDown(self):
        # keep the global sig-alg registry clean between tests
        signing.SIG_ALGS.pop("test-pq", None)
        signing.PQ_SIG_ALGS.pop("test-pq", None)

    def _signed_pack(self, tmp):
        pp = os.path.join(tmp, "pack.json")
        pack.write_pack(pp, pack.build_pack("demo", {"x": 1},
                                            "ref; NOT a conformity assessment"))
        ident = signing.Identity("acme")
        pack.sign_pack(pp, ident)
        store = os.path.join(tmp, "trust.jsonl")
        trust.TrustRegistry(store).trust("acme", ident.public_key_b64)
        return pp, store

    def test_sig_alg_present_and_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            pp, store = self._signed_pack(tmp)
            side = json.loads(Path(pp[:-5] + ".sig.json").read_text())
            self.assertEqual(side["sig_alg"], "ed25519")
            self.assertTrue(verify_pack(pp, trust_store=store)["valid"])

    def test_legacy_sidecar_without_sig_alg_still_verifies(self):
        with tempfile.TemporaryDirectory() as tmp:
            pp, store = self._signed_pack(tmp)
            sp = pp[:-5] + ".sig.json"
            side = json.loads(Path(sp).read_text()); side.pop("sig_alg")
            Path(sp).write_text(json.dumps(side))
            self.assertTrue(verify_pack(pp, trust_store=store)["valid"])  # back-compat

    def test_unknown_sig_alg_is_skip_never_false_green(self):
        with tempfile.TemporaryDirectory() as tmp:
            pp, store = self._signed_pack(tmp)
            sp = pp[:-5] + ".sig.json"
            side = json.loads(Path(sp).read_text()); side["sig_alg"] = "martian-sig"
            Path(sp).write_text(json.dumps(side))
            v = verify_pack(pp, trust_store=store)
            prod = [l for l in v["layers"] if l["layer"] == "producer-signature"][0]
            self.assertEqual(prod["status"], "SKIP")

    def test_pq_present_without_backend_is_unverified_not_trusted(self):
        with tempfile.TemporaryDirectory() as tmp:
            pp, store = self._signed_pack(tmp)
            pack.add_pq_signature(pp, "test-pq", "PK", "SIG")   # no backend registered
            v = verify_pack(pp, trust_store=store)
            pq = [l for l in v["layers"] if l["layer"] == "pq-signature"][0]
            self.assertEqual(pq["status"], "SKIP")
            self.assertIn("unverified", pq["detail"])
            self.assertTrue(v["valid"])           # still valid, classically signed

    def test_pq_valid_backend_reports_pq_protected(self):
        signing.register_sig_alg("test-pq", lambda pk, sig, msg: sig == "GOOD", post_quantum=True)
        with tempfile.TemporaryDirectory() as tmp:
            pp, store = self._signed_pack(tmp)
            pack.add_pq_signature(pp, "test-pq", "PK", "GOOD")
            # 0.7.0 (pinned contract, as cryptovalid 0.13.0): a valid PQ signature by an UNPINNED key is present,
            # not protection — anyone can add their own layer. Pinned (caller or trust registry) → pq-protected.
            v = verify_pack(pp, trust_store=store)
            pq = [l for l in v["layers"] if l["layer"] == "pq-signature"][0]
            self.assertEqual(pq["status"], "SKIP"); self.assertIn("unpinned", pq["detail"]); self.assertIsNone(v["pq_protected"])
            v = verify_pack(pp, trust_store=store, expected_pq_public_key_b64="PK")
            pq = [l for l in v["layers"] if l["layer"] == "pq-signature"][0]
            self.assertEqual(pq["status"], "PASS")
            self.assertIn("pq-protected", pq["detail"])
            self.assertTrue(v["valid"]); self.assertIs(v["pq_protected"], True)
            self.assertFalse(verify_pack(pp, trust_store=store, expected_pq_public_key_b64="OTHER")["valid"])   # foreign key

    def test_pq_invalid_with_backend_is_fail_closed(self):
        signing.register_sig_alg("test-pq", lambda pk, sig, msg: sig == "GOOD", post_quantum=True)
        with tempfile.TemporaryDirectory() as tmp:
            pp, store = self._signed_pack(tmp)
            pack.add_pq_signature(pp, "test-pq", "PK", "BAD")   # backend rejects it
            v = verify_pack(pp, trust_store=store)
            self.assertFalse(v["valid"])          # hybrid claimed but PQ fails -> invalid


class TestPreservationRFC4998(unittest.TestCase):
    """Long-term evidence record: renewal across a hash-algorithm change must stay
    verifiable OFFLINE; tampering and mismatched data are caught."""

    def _packs(self, tmp, n=3):
        paths = []
        for i in range(n):
            p = os.path.join(tmp, f"p{i}.json")
            pack.write_pack(p, pack.build_pack("demo", {"i": i},
                                               "ref; NOT a conformity assessment"))
            paths.append(p)
        return paths

    def test_build_and_verify_offline(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._packs(tmp)
            rec = preservation.build_evidence_record(paths, hash_alg="sha256")
            v = preservation.verify_evidence_record(rec, pack_paths=paths)
            self.assertTrue(v["valid"])
            self.assertIn("NOT", rec["honest_scope"])

    def test_renewal_across_hash_change_stays_verifiable(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._packs(tmp)
            rec = preservation.build_evidence_record(paths, hash_alg="sha256")
            rec = preservation.renew_timestamp(rec)
            self.assertTrue(preservation.renewal_due(rec, ["sha256"])["due"])
            rec = preservation.renew_hash_tree(rec, paths, "sha3_256")
            v = preservation.verify_evidence_record(rec, pack_paths=paths)
            self.assertTrue(v["valid"])           # offline, across sha256 -> sha3_256
            self.assertEqual([a["type"] for a in rec["archive_timestamps"]],
                             ["initial", "timestamp-renewal", "hash-tree-renewal"])

    def test_tampered_renewal_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._packs(tmp)
            rec = preservation.build_evidence_record(paths)
            rec = preservation.renew_hash_tree(rec, paths, "sha3_256")
            rec["archive_timestamps"][-1]["merkle_root"] = "00" * 32
            rec = preservation._finalize(rec)     # re-seal so we test the CHAIN, not integrity
            self.assertFalse(preservation.verify_evidence_record(rec, pack_paths=paths)["valid"])

    def test_mismatched_packs_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = self._packs(tmp)
            rec = preservation.build_evidence_record(paths)
            other = os.path.join(tmp, "other.json")
            pack.write_pack(other, pack.build_pack("demo", {"z": 9}, "ref; NOT x"))
            v = preservation.verify_evidence_record(rec, pack_paths=paths[:2] + [other])
            self.assertFalse(v["valid"])


class TestDSSEInterop(unittest.TestCase):
    """DSSE envelope + in-toto Statement v1: PAE matches the official vector, the
    round-trip verifies, tampering and wrong keys are caught."""

    def test_pae_matches_official_vector(self):
        self.assertEqual(
            dsse.pae("http://example.com/HelloWorld", b"hello world"),
            b"DSSEv1 29 http://example.com/HelloWorld 11 hello world")

    def test_roundtrip_and_statement_shape(self):
        pk = pack.build_pack("demo_pack", {"payload": "x"}, "ref; NOT a conformity assessment")
        env = dsse.to_dsse(pk, signing.Identity("acme"))
        self.assertEqual(env["payloadType"], "application/vnd.in-toto+json")
        st = dsse.build_statement(pk)
        self.assertEqual(st["_type"], "https://in-toto.io/Statement/v1")
        self.assertEqual(set(st["subject"][0]["digest"]), {"sha256", "sha3_256"})
        r = dsse.from_dsse(env)
        self.assertTrue(r["verified"])
        self.assertEqual(r["pack"], pk)

    def test_tampered_payload_fails(self):
        pk = pack.build_pack("demo_pack", {"payload": "x"}, "ref; NOT a conformity assessment")
        env = dsse.to_dsse(pk, signing.Identity("acme"))
        st = json.loads(base64.b64decode(env["payload"]))
        st["predicate"]["payload"] = "TAMPERED"
        env["payload"] = base64.b64encode(json.dumps(st).encode()).decode()
        self.assertFalse(dsse.from_dsse(env)["verified"])

    def test_wrong_key_fails(self):
        pk = pack.build_pack("demo_pack", {"payload": "x"}, "ref; NOT a conformity assessment")
        env = dsse.to_dsse(pk, signing.Identity("acme"))
        self.assertFalse(dsse.from_dsse(env, public_key_b64=signing.Identity("m").public_key_b64)["verified"])


class TestSDJWT(unittest.TestCase):
    """SD-JWT (RFC 9901): selective disclosure holds — undisclosed claims never
    leak, a forged disclosure not in the signed _sd is rejected."""

    def test_issue_full_verify(self):
        iss = signing.Identity("kyc")
        tok = sdjwt.issue({"country": "IT", "over_18": True}, iss,
                          plain_claims={"iss": "omega"})
        v = sdjwt.verify(tok, iss.public_key_b64)
        self.assertTrue(v["verified"])
        self.assertEqual(v["disclosed_claims"], {"country": "IT", "over_18": True})
        self.assertEqual(v["plain_claims"], {"iss": "omega"})

    def test_selective_disclosure_hides_the_rest(self):
        iss = signing.Identity("kyc")
        tok = sdjwt.issue({"country": "IT", "over_18": True, "full_name": "PII"}, iss)
        pres = sdjwt.present(tok, ["country"])
        v = sdjwt.verify(pres, iss.public_key_b64)
        self.assertTrue(v["verified"])
        self.assertEqual(v["disclosed_claims"], {"country": "IT"})
        self.assertNotIn("full_name", v["disclosed_claims"])
        self.assertEqual(len(v["undisclosed_digests"]), 2)   # over_18, full_name

    def test_wrong_key_fails(self):
        iss = signing.Identity("kyc")
        tok = sdjwt.issue({"country": "IT"}, iss)
        self.assertFalse(sdjwt.verify(tok, signing.Identity("x").public_key_b64)["verified"])

    def test_forged_disclosure_not_in_sd_is_ignored(self):
        iss = signing.Identity("kyc")
        tok = sdjwt.issue({"country": "IT"}, iss)
        forged = sdjwt._disclosure("s", "admin", True)
        tampered = tok.rstrip("~") + "~" + forged + "~"
        v = sdjwt.verify(tampered, iss.public_key_b64)
        self.assertTrue(v["verified"])                       # JWS still valid
        self.assertNotIn("admin", v["disclosed_claims"])     # forged claim rejected


class TestCRA(unittest.TestCase):
    """CRA evidence: SBOM binding and vuln-report time honesty (self-asserted vs
    anchored), with the primary-source application dates."""

    def test_sbom_evidence_and_dates(self):
        with tempfile.TemporaryDirectory() as tmp:
            sb = os.path.join(tmp, "sbom.json")
            Path(sb).write_text(json.dumps(
                {"bomFormat": "CycloneDX", "components": [{"name": "a"}, {"name": "b"}]}))
            p = cra.sbom_evidence("prod", "1.0", sb, ledger_path=os.path.join(tmp, "l.jsonl"))
            self.assertEqual(p["sbom_format"], "CycloneDX")
            self.assertEqual(p["top_level_count"], 2)
            self.assertEqual(p["cra_sbom_applies"], "2027-12-11")
            self.assertIn("NOT", p["honest_scope"])

    def test_vuln_report_time_basis(self):
        s = cra.vuln_report_evidence("CVE-2026-1", "prod", "1.0", "2026-09-12T00:00:00Z")
        self.assertEqual(s["time_basis"], "self-asserted")
        self.assertIn("SELF-ASSERTED", s["honest_scope"])
        self.assertEqual(s["cra_reporting_applies"], "2026-09-11")
        a = cra.vuln_report_evidence("CVE-2026-1", "prod", "1.0", "2026-09-12T00:00:00Z",
                                     time_anchored=True)
        # a producer boolean is a CLAIM, not a fact — the caveat is never dropped
        self.assertEqual(a["time_basis"], "producer-claimed-anchored")
        self.assertIn("PRODUCER CLAIM", a["honest_scope"])


class TestPQGate(unittest.TestCase):
    """The KAT gate must reject a broken PQ backend in BOTH directions (accepts
    tampered / rejects valid) — the anti-Goodhart check — and register a sound one."""

    def tearDown(self):
        for a in ("pq-good", "pq-accepts-all", "pq-denies-all"):
            signing.SIG_ALGS.pop(a, None)
            signing.PQ_SIG_ALGS.pop(a, None)

    KAT = [{"public": "PK", "signature": "VALIDSIG", "message_hex": b"hi".hex()}]

    def test_sound_backend_registers(self):
        r = pqgate.register_pq_backend("pq-good", lambda p, s, m: s == "VALIDSIG", self.KAT)
        self.assertTrue(r["registered"])
        self.assertIn("pq-good", signing.PQ_SIG_ALGS)

    def test_backend_accepting_tampered_is_rejected(self):
        r = pqgate.register_pq_backend("pq-accepts-all", lambda p, s, m: True, self.KAT)
        self.assertFalse(r["registered"])
        self.assertIn("tampered", r["reason"])
        self.assertNotIn("pq-accepts-all", signing.PQ_SIG_ALGS)

    def test_backend_rejecting_valid_is_rejected(self):
        r = pqgate.register_pq_backend("pq-denies-all", lambda p, s, m: False, self.KAT)
        self.assertFalse(r["registered"])
        self.assertIn("rejected", r["reason"])

    def test_empty_kat_is_rejected(self):
        r = pqgate.register_pq_backend("pq-good", lambda p, s, m: True, [])
        self.assertFalse(r["registered"])


class TestOpenTimestamps(unittest.TestCase):
    """OTS anchoring: honest pending vs confirmed, fail-soft submit, and never a
    fabricated confirmation. Network is not required for these (deterministic)."""

    def test_submit_rejects_non_32_byte_digest(self):
        with self.assertRaises(ValueError):
            ots.submit("00" * 16)                       # 16 bytes, not 32

    def test_stamp_fail_soft_when_no_calendar_reachable(self):
        with tempfile.TemporaryDirectory() as tmp:
            pp = os.path.join(tmp, "pack.json")
            pack.write_pack(pp, pack.build_pack("demo", {"x": 1},
                                                "ref; NOT a conformity assessment"))
            # unroutable calendar -> fail-soft, no crash, honest status
            side = ots.stamp_pack(pp, calendars=["https://127.0.0.1:1"], timeout=1.0)
            self.assertEqual(side["status"], "no-calendar-reached")
            self.assertTrue(side["calendar_errors"])
            self.assertTrue(Path(pp[:-5] + ".ots.json").exists())

    def test_verify_absent_and_pending_unverified(self):
        with tempfile.TemporaryDirectory() as tmp:
            pp = os.path.join(tmp, "pack.json")
            pack.write_pack(pp, pack.build_pack("demo", {"x": 1},
                                                "ref; NOT a conformity assessment"))
            self.assertEqual(ots.verify(pp)["status"], "absent")   # no sidecar yet
            ots.stamp_pack(pp, calendars=["https://127.0.0.1:1"], timeout=1.0)
            v = ots.verify(pp)
            # without the opentimestamps library, never a false 'confirmed'
            self.assertFalse(v["confirmed"])
            self.assertIn("pending", v["status"])


class TestLTVValidationMaterial(unittest.TestCase):
    """LTV: capture the TSA cert chain + CRL DPs at stamping time. Parser logic is
    tested against a real openssl-generated cert (no network); malformed input is
    handled honestly."""

    def test_split_pem_certs(self):
        from omega_evidence import timestamp as ts
        pem = ("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
               "-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n")
        self.assertEqual(len(ts._split_pem_certs(pem)), 2)

    def test_extract_from_malformed_tsr_is_honest(self):
        from omega_evidence import timestamp as ts
        import shutil as _sh
        if not _sh.which("openssl"):
            self.skipTest("openssl absent")
        m = ts.extract_validation_material(base64.b64encode(b"not a real tsr").decode())
        self.assertFalse(m["available"])          # honest, no crash, no fake certs

    def test_crl_dp_parser_on_real_cert(self):
        import shutil as _sh
        import subprocess as _sp
        from omega_evidence import timestamp as ts
        exe = _sh.which("openssl")
        if not exe:
            self.skipTest("openssl absent")
        with tempfile.TemporaryDirectory() as tmp:
            cpem = os.path.join(tmp, "c.pem"); key = os.path.join(tmp, "k.pem")
            r = _sp.run([exe, "req", "-x509", "-newkey", "rsa:2048", "-keyout", key,
                         "-out", cpem, "-days", "1", "-nodes", "-subj", "/CN=ltv-test",
                         "-addext", "crlDistributionPoints=URI:http://example.com/t.crl"],
                        capture_output=True)
            if r.returncode != 0:
                self.skipTest("openssl req -addext unsupported here")
            pem = Path(cpem).read_text()
            dps = ts._cert_crl_dps(exe, pem, tmp)
            self.assertIn("http://example.com/t.crl", dps)
            der = ts._pem_cert_to_der_b64(exe, pem, tmp)
            self.assertTrue(der and base64.b64decode(der))     # round-trips to DER
            self.assertIn("ltv-test", ts._cert_field(exe, pem, tmp, "-subject"))

    def test_verifier_reports_ltv_material_layer(self):
        # a stamped pack whose sidecar carries LTV material -> informational layer,
        # never changing validity (SKIP).
        with tempfile.TemporaryDirectory() as tmp:
            pp = os.path.join(tmp, "pack.json")
            pack.write_pack(pp, pack.build_pack("demo", {"x": 1},
                                                "ref; NOT a conformity assessment"))
            from omega_evidence.canonical import sha256_bytes
            side = {"digest_sha256": sha256_bytes(Path(pp).read_bytes()),
                    "tsa": "http://tsa.example", "tsr_b64": "",
                    "validation_material": {"available": True, "cert_count": 3,
                                            "crls_b64": [{"url": "u", "crl_b64": "AA"}]}}
            Path(pp[:-5] + ".tsr.json").write_text(json.dumps(side))
            v = verify_pack(pp)
            ltv = [l for l in v["layers"] if l["layer"] == "ltv-material"]
            self.assertTrue(ltv)
            self.assertEqual(ltv[0]["status"], "SKIP")
            self.assertIn("3 cert", ltv[0]["detail"])


class TestNemesisRegressions(unittest.TestCase):
    """Locks the 5 defects NEMESIS confirmed (2026-08-25) so they cannot return."""

    def tearDown(self):
        signing.SIG_ALGS.pop("nem-pq", None)
        signing.PQ_SIG_ALGS.pop("nem-pq", None)

    def test_reattack_binding_needs_dedicated_anchor_field(self):
        # re-attack: pack_sha3 in a JUNK field of an unrelated entry must NOT anchor
        import json
        with tempfile.TemporaryDirectory() as tmp:
            pp = os.path.join(tmp, "p.json")
            pack.write_pack(pp, pack.build_pack("d", {"x": 1}, "ref; NOT x"))
            dg = json.loads(Path(pp).read_text())["pack_sha3"]
            ledger.Ledger(pp[:-5] + ".ledger.jsonl").append({"junk": dg})   # value in junk field
            self.assertFalse(verify_pack(pp)["valid"])
            # dedicated anchor entry (anchor_pack) DOES anchor
            pp2 = os.path.join(tmp, "ok.json")
            pack.write_pack(pp2, pack.build_pack("d", {"y": 2}, "ref; NOT x"))
            pack.anchor_pack(pp2, pp2[:-5] + ".ledger.jsonl")
            self.assertTrue(verify_pack(pp2)["valid"])

    def test_reattack_canonical_rejects_nonstring_keys(self):
        with self.assertRaises(ValueError):
            canonical.sha3({1: "x"})            # int key coerces to '1' -> not injective

    def test_1_anchored_requires_pack_recorded_in_ledger(self):
        with tempfile.TemporaryDirectory() as tmp:
            pp = os.path.join(tmp, "pack.json")
            pack.write_pack(pp, pack.build_pack("d", {"x": 1}, "ref; NOT x"))
            # unrelated / empty ledger must NOT anchor a fabricated pack
            ledger.Ledger(pp[:-5] + ".ledger.jsonl").append({"unrelated": "garbage"})
            self.assertFalse(verify_pack(pp)["valid"])
            # a legitimately anchored pack DOES pass
            pp2 = os.path.join(tmp, "ok.json")
            pack.write_pack(pp2, pack.build_pack("d", {"y": 2}, "ref; NOT x"))
            pack.anchor_pack(pp2, pp2[:-5] + ".ledger.jsonl")
            self.assertTrue(verify_pack(pp2)["valid"])

    def test_1b_hostile_ledger_bytes_are_a_fail_verdict_never_a_traceback(self):
        # 21/09/2026 (propagated from the cra-evidence review): a raw non-UTF-8 byte in the ledger escaped as UnicodeDecodeError
        # from Ledger.__init__ (no verdict, exit 1 traceback) while Go/JS answered FAIL; a raw byte where U+FFFD was hashed
        # must be FAIL (a lossy decoder reads exactly the hashed text and says PASS); "__proto__" added without rehashing = FAIL
        with tempfile.TemporaryDirectory() as tmp:
            def anchored(name):
                pp = os.path.join(tmp, name + ".json")
                pack.write_pack(pp, pack.build_pack("d", {"x": 1}, "ref; NOT x"))
                pack.anchor_pack(pp, pp[:-5] + ".ledger.jsonl")
                self.assertTrue(verify_pack(pp)["valid"])          # positive control: intact = PASS
                return pp, pp[:-5] + ".ledger.jsonl"
            pp, lp = anchored("raw")
            Path(lp).write_bytes(Path(lp).read_bytes().replace(b'"ts"', b'"t\xffs"', 1))
            with self.assertRaises(RuntimeError):      # one exception type out of Ledger for every caller (r2)
                ledger.Ledger(lp)
            r = verify_pack(pp)
            self.assertFalse(r["valid"])
            self.assertEqual([l["status"] for l in r["layers"] if l["layer"] == "ledger-chain"], ["FAIL"])
            pp, lp = anchored("fffd")
            e = json.loads(Path(lp).read_text(encoding="utf-8").splitlines()[0]); e["data"]["note"] = "\ufffd"; e.pop("self_hash")
            e["self_hash"] = ledger._hash_entry(e)
            Path(lp).write_bytes(json.dumps(e, ensure_ascii=False, separators=(",", ":")).encode("utf-8").replace("\ufffd".encode("utf-8"), b"\xff", 1) + b"\n")
            self.assertFalse(verify_pack(pp)["valid"])
            pp, lp = anchored("proto")
            Path(lp).write_text('{"__proto__": {"evil": 1}, ' + Path(lp).read_text(encoding="utf-8")[1:], encoding="utf-8")
            self.assertFalse(verify_pack(pp)["valid"])
            pp, lp = anchored("list")
            Path(lp).write_text("[1]\n", encoding="utf-8")
            self.assertFalse(verify_pack(pp)["valid"])
            # review r1 (Opus): the .tsr.json sidecar was read with the loose json.loads — a float / duplicate key beside a
            # correct digest was PASS in Python alone; a 100000-deep sidecar a RecursionError traceback
            for name, body in (("tsrf", '{"digest_sha256": "%s", "tsa": "x", "tsr_b64": "AA==", "x": 1.5}'),
                               ("tsrd", '{"digest_sha256": "%s", "digest_sha256": "%s", "tsa": "x", "tsr_b64": "AA=="}'),
                               ("tsrdeep", "[" * 100000)):
                pp, lp = anchored(name)
                dg = hashlib.sha256(Path(pp).read_bytes()).hexdigest()
                Path(pp[:-5] + ".tsr.json").write_text(body.replace("%s", dg), encoding="utf-8")
                r = verify_pack(pp)
                self.assertFalse(r["valid"], name)
                self.assertEqual([l["status"] for l in r["layers"] if l["layer"] == "rfc3161"], ["FAIL"], name)
            # review r2 (Opus): the Python reference had no lone-surrogate rule — an anchored pack holding "\\ud800" with a
            # correct hash, and a ledger entry the 0.8.2 producer itself wrote, were PASS here and FAIL in Go/Java/Node
            pp, lp = anchored("lone")
            dd = json.loads(Path(pp).read_text(encoding="utf-8")); dd["s"] = "\ud800"; dd.pop("pack_sha3")
            h = hashlib.sha3_256(json.dumps(dd, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
            dd["pack_sha3"] = h; Path(pp).write_text(json.dumps(dd), encoding="utf-8")
            ledger.Ledger(lp).append({"anchored_pack_sha3": h})
            r = verify_pack(pp); self.assertFalse(r["valid"]); self.assertEqual([l["status"] for l in r["layers"] if l["layer"] == "pack-json"], ["FAIL"])
            with self.assertRaises(ValueError):
                ledger.loads_strict('{"s": "\\ud800"}')
            ledger.loads_strict('{"s": "\\ud83d\\ude00"}')                      # a proper pair is fine
            with self.assertRaises(ValueError):
                ledger.Ledger(os.path.join(tmp, "w.jsonl")).append({"note": "\ud800"})   # the producer refuses it too
            with self.assertRaises(ValueError):
                canonical.sha3({"s": "\udc00"})
            # review r3: LTV material typed (an int was a TypeError traceback); scope regexes ASCII like the three
            pp, lp = anchored("vm"); dg = hashlib.sha256(Path(pp).read_bytes()).hexdigest()
            Path(pp[:-5] + ".tsr.json").write_text('{"digest_sha256": "%s", "tsa": "x", "tsr_b64": "AA==", "validation_material": {"available": true, "crls_b64": 1}}' % dg, encoding="utf-8")
            r = verify_pack(pp); self.assertTrue(r["valid"])   # a verdict (PASS: anchored, timestamp SKIP), never a TypeError
            self.assertTrue(pack._honest_scope_declares_limit("does NOT\u00e9 prove x"))          # ASCII \b: boundary before é
            self.assertTrue(pack._honest_scope_declares_limit("fully cert\u0131fied; does NOT prove x"))   # ı is not i in ASCII folding
            self.assertFalse(pack._honest_scope_declares_limit("fully certified; does NOT prove x"))
            # review r4 (Opus): the anchoring rule reads the ENTRY (top-level or data.anchored_pack_sha3) like the three; a
            # trust-store entry without "data" is a broken store, not a skipped line
            from omega_evidence.ledger import GENESIS, _hash_entry
            def entry(idx, prev, extra):
                e = {"idx": idx, "ts": "2026-09-21T00:00:00+00:00", "prev_hash": prev}; e.update(extra); e["self_hash"] = _hash_entry(e); return e
            for name, extra, want in (("top", lambda H: {"data": {}, "anchored_pack_sha3": H}, True),
                                      ("dd", lambda H: {"data": {"data": {"anchored_pack_sha3": H}}}, False)):
                pp = os.path.join(tmp, name + ".json"); pack.write_pack(pp, pack.build_pack("d", {"x": 1}, "ref; NOT x")); H = json.loads(Path(pp).read_text())["pack_sha3"]
                Path(pp[:-5] + ".ledger.jsonl").write_text(json.dumps(entry(0, GENESIS, extra(H)), separators=(",", ":")) + "\n", encoding="utf-8")
                self.assertEqual(verify_pack(pp)["valid"], want, name)
            idt = signing.Identity("acme"); pp = os.path.join(tmp, "signed2.json"); pack.write_pack(pp, pack.build_pack("d", {"x": 1}, "ref; NOT x")); pack.sign_pack(pp, idt)
            st2 = os.path.join(tmp, "trust2.jsonl"); trust.TrustRegistry(st2).trust("acme", idt.public_key_b64)
            e0 = json.loads(Path(st2).read_text(encoding="utf-8").splitlines()[0])
            Path(st2).write_text(Path(st2).read_text(encoding="utf-8") + json.dumps(entry(1, e0["self_hash"], {}), separators=(",", ":")) + "\n", encoding="utf-8")
            r = verify_pack(pp, trust_store=st2); self.assertFalse(r["valid"]); self.assertFalse(r["authenticated"])
            # review r5: the reserved type-tag key in a pack read from text is data (the three hash it as it is)
            body = {"kind": "d", "honest_scope": "does NOT x", "__omega_reserved_type__": "Decimal", "value": "1"}
            h = hashlib.sha3_256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            pp = os.path.join(tmp, "reserved.json"); Path(pp).write_text(json.dumps(dict(body, pack_sha3=h)), encoding="utf-8")
            ledger.Ledger(pp[:-5] + ".ledger.jsonl").append({"anchored_pack_sha3": h})
            self.assertTrue(verify_pack(pp)["valid"])
            with self.assertRaises(ValueError):
                canonical.sha3(body)                                   # the producer still refuses to forge the tag
            # a trust-store line that is not an object raised AttributeError out of Ledger._load
            pp = os.path.join(tmp, "signed.json"); pack.write_pack(pp, pack.build_pack("d", {"x": 1}, "ref; NOT x"))
            idt = signing.Identity("acme"); pack.sign_pack(pp, idt)
            st = os.path.join(tmp, "trust.jsonl"); trust.TrustRegistry(st).trust("acme", idt.public_key_b64)
            self.assertTrue(verify_pack(pp, trust_store=st)["authenticated"])     # positive control
            Path(st).write_text(Path(st).read_text(encoding="utf-8") + "[1]\n", encoding="utf-8")
            r = verify_pack(pp, trust_store=st)
            self.assertFalse(r["valid"]); self.assertFalse(r["authenticated"])

    def test_1c_cli_value_flags_refuse_empty_and_flag_like_values(self):
        # one CLI grammar in the four verifiers: "" / a flag as value / an abbreviation / a second positional = usage exit 2
        with tempfile.TemporaryDirectory() as tmp:
            pp = os.path.join(tmp, "p.json"); pack.write_pack(pp, pack.build_pack("d", {"x": 1}, "ref; NOT x"))
            for extra in (["--ledger", ""], ["--ledger"], ["--ledger", "--require-pq"], ["--ledg", pp], [pp], ["--no-such-flag"],
                          ["--"], ["--require-pq=false"], ["--help"], ["-h"], ["-ledg", pp], ["-l", pp], ["-r"]):
                out = subprocess.run([sys.executable, "-m", "omega_evidence", pp] + extra, capture_output=True, text=True)
                self.assertEqual(out.returncode, 2, (extra, out.stdout, out.stderr))
                self.assertEqual(out.stdout, "")
            for bad_pack in ("", "-"):     # an unset $PACK is not a path (review r1)
                out = subprocess.run([sys.executable, "-m", "omega_evidence", bad_pack], capture_output=True, text=True)
                self.assertEqual(out.returncode, 2, (bad_pack, out.stdout, out.stderr)); self.assertEqual(out.stdout, "")
            pack.anchor_pack(pp, pp[:-5] + ".ledger.jsonl")     # --flag=value and -flag (one dash) are accepted, as in Go/Java/Node
            for extra in (["--ledger=" + pp[:-5] + ".ledger.jsonl"], ["-ledger", pp[:-5] + ".ledger.jsonl"]):
                out = subprocess.run([sys.executable, "-m", "omega_evidence", pp] + extra, capture_output=True, text=True)
                self.assertEqual(out.returncode, 0, out.stderr); self.assertEqual(json.loads(out.stdout)["verdict"], "PASS")
            out = subprocess.run([sys.executable, "-m", "omega_evidence", pp], capture_output=True, text=True)
            self.assertEqual(out.returncode, 0); self.assertEqual(json.loads(out.stdout)["verdict"], "PASS")   # a well-formed command line: a verdict

    def test_2_classical_cosignature_is_never_pq_protected(self):
        with tempfile.TemporaryDirectory() as tmp:
            pp = os.path.join(tmp, "p.json")
            pack.write_pack(pp, pack.build_pack("d", {"x": 1}, "ref; NOT x"))
            idt = signing.Identity("a"); pack.sign_pack(pp, idt)
            dg = json.loads(Path(pp).read_text())["pack_sha3"]
            pack.add_pq_signature(pp, "ed25519", idt.public_key_b64, idt.sign(dg.encode()))
            pq = [l for l in verify_pack(pp)["layers"] if l["layer"] == "pq-signature"][0]
            self.assertEqual(pq["status"], "SKIP")
            self.assertNotIn("pq-protected", pq["detail"])

    def test_2b_registered_pq_backend_still_reaches_pq_protected(self):
        signing.register_sig_alg("nem-pq", lambda p, s, m: s == "GOOD", post_quantum=True)
        with tempfile.TemporaryDirectory() as tmp:
            pp = os.path.join(tmp, "p.json")
            pack.write_pack(pp, pack.build_pack("d", {"x": 1}, "ref; NOT x"))
            idt = signing.Identity("a"); pack.sign_pack(pp, idt)
            pack.add_pq_signature(pp, "nem-pq", "PK", "GOOD")
            pq = [l for l in verify_pack(pp, expected_pq_public_key_b64="PK")["layers"] if l["layer"] == "pq-signature"][0]
            self.assertEqual(pq["status"], "PASS")      # 0.7.0: reachable when the key is PINNED (never self-declared)

    def test_3_canonical_rejects_forged_type_tag(self):
        from decimal import Decimal
        self.assertTrue(canonical.sha3(Decimal("1.50")))          # genuine typed value OK
        with self.assertRaises(ValueError):                        # forged tag rejected
            canonical.sha3({"__omega_reserved_type__": "Decimal", "value": "1.50"})

    def test_4_revocation_survives_reload_after_trust_append(self):
        with tempfile.TemporaryDirectory() as tmp:
            tp = os.path.join(tmp, "t.jsonl")
            tr = trust.TrustRegistry(tp); k = signing.Identity("s")
            tr.trust("s", k.public_key_b64); tr.revoke("s", "x")
            ledger.Ledger(tp).append({"action": "trust", "signer_id": "s",
                                      "pubkey": k.public_key_b64, "ts": "now"})
            self.assertFalse(trust.TrustRegistry(tp).is_trusted("s", k.public_key_b64))

    def test_5_cra_producer_anchor_claim_keeps_caveat(self):
        p = cra.vuln_report_evidence("CVE-1", "prod", "1.0", "2026-09-12T00:00:00Z",
                                     time_anchored=True)
        self.assertEqual(p["time_basis"], "producer-claimed-anchored")
        self.assertIn("PRODUCER CLAIM", p["honest_scope"])


class TestDoctorSelfExamine(unittest.TestCase):
    def setUp(self):
        self.skipTest('doctor: toolkit completo, non nel subset pubblico')

    """The toolkit self-examines the host and reports what works / what to add."""

    def _SKIPest_examine_reports_backend_and_core_always_available(self):
        env = doctor.examine()
        self.assertIn(env["crypto_backend"], ("cryptography", "pure-python"))
        self.assertIn(env["os"], ("Linux", "Darwin", "Windows"))  # Mac reports 'Darwin'
        caps = env["capabilities"]
        # core capabilities are ALWAYS available, on any machine, stdlib-only
        for core in ("canonical_hashing", "hash_chained_ledger", "evidence_packs",
                     "offline_verifier", "chip_registry", "signing_and_verification"):
            self.assertTrue(caps[core], core)
        self.assertIsInstance(env["recommendations"], list)
        self.assertIn("NOT", env["honest_scope"])   # honest: installs nothing

    def test_render_is_text(self):
        self.assertIn("host self-check", doctor.render(doctor.examine()))


class TestAATInterop(unittest.TestCase):
    """draft-sharif-agent-audit-trail-04: export of an AgentEvidenceLog (one chain per session, genesis lifecycle
    record), chain verification, ES6/JCS numbers, signatures. Negatives first; every positive has its tampered twin."""

    def _log(self, tmp):
        log = agent.AgentEvidenceLog(os.path.join(tmp, "agent.jsonl"), runtime_id="rt-1")
        log.record("bot-7", "sess-a", "tool_call", "https://api.example/x", "rule-1", agent.Decision.ALLOW, agent.Outcome.EXECUTED)
        log.record("bot-7", "sess-a", "file_write", "/tmp/out", "rule-2", agent.Decision.DENY, agent.Outcome.BLOCKED)
        log.record("bot-7", "sess-a", "network", "https://x", "rule-3", agent.Decision.ALLOW_WITH_APPROVAL,
                   agent.Outcome.PENDING_APPROVAL, human_approver="op-9", reason="needs a human")
        return log

    def test_jcs_and_es6_numbers(self):
        from omega_evidence.interop import aat
        self.assertEqual(aat.jcs({"b": 1, "a": [True, None, "é"]}), '{"a":[true,null,"é"],"b":1}'.encode())
        self.assertEqual(aat.jcs({"\u20ac": 1, "a": 2}), aat.jcs({"a": 2, "\u20ac": 1}))
        keys = list(json.loads(aat.jcs({"\U0001F600": 1, "\uFFFD": 2, "\uD7FF": 3}).decode()).keys())
        self.assertEqual(keys, ["\uD7FF", "\U0001F600", "\uFFFD"])                     # ordine per unità UTF-16
        self.assertEqual(aat.jcs({"x": 1.5}), b'{"x":1.5}')
        with self.assertRaises(ValueError):
            aat.jcs({"x": float("nan")})
        with self.assertRaises(ValueError):
            aat.jcs({"x": float("inf")})
        with self.assertRaises(ValueError):
            aat.jcs({"x": 2 ** 53 + 1})                                    # export: perdita di precisione → rifiutato
        self.assertEqual(aat.jcs({"x": 2 ** 53 + 1}, strict=False), b'{"x":9007199254740992}')   # verify: come ES6
        # ES6 Number::toString (RFC 8785 §3.2.2.3 + Appendix B): fissa per 1e-7 <= |x| < 1e21 (round 3)
        for f, exp in ((295147905179352825856.0, "295147905179352830000"), (5e-324, "5e-324"),
                       (1.7976931348623157e308, "1.7976931348623157e+308"), (0.000001, "0.000001"), (1e-7, "1e-7"),
                       (1e21, "1e+21"), (999999999999999900000.0, "999999999999999900000"), (-1.5, "-1.5"), (0.1, "0.1"),
                       (333333333.3333333, "333333333.3333333"), (2.0, "2"), (1e20, "100000000000000000000"),
                       (1e-5, "0.00001"), (-0.0, "0"), (123456789012345680000.0, "123456789012345680000")):
            self.assertEqual(aat._es6_number(f), exp, f)

    def test_export_one_chain_per_session_with_genesis(self):
        from omega_evidence.interop import aat
        import uuid as _u
        with tempfile.TemporaryDirectory() as tmp:
            entries = list(self._log(tmp)._ledger.entries())
            chains = aat.from_omega(entries, agent_version="1.2.3", trust_level="L1")
            self.assertEqual(len(chains), 1)                                        # una catena = una sessione (§3)
            recs = next(iter(chains.values()))
            self.assertEqual(len(recs), 4)                                         # genesi + 3 azioni
            self.assertEqual(recs[0]["action_type"], "lifecycle"); self.assertEqual(recs[0]["action_detail"]["event"], "session_start")
            self.assertIn("synthesised_by", recs[0]["action_detail"])              # dichiarato, non nascosto
            self.assertIsNone(recs[0]["prev_hash"]); self.assertIsNone(recs[0]["parent_record_id"])
            self.assertEqual(recs[1]["prev_hash"], aat.record_hash(recs[0]))
            self.assertEqual([r["outcome"] for r in recs[1:]], ["success", "denied", "escalated"])
            self.assertEqual(recs[3]["human_override"]["operator_id"], "op-9")
            self.assertTrue(recs[1]["agent_id"].startswith("urn:omega:agent:"))
            self.assertEqual(len({r["session_id"] for r in recs}), 1)
            self.assertEqual(chains, aat.from_omega(entries, agent_version="1.2.3", trust_level="L1"))   # deterministico
            self.assertEqual(_u.UUID(recs[1]["record_id"]).version, 4); self.assertEqual(_u.UUID(recs[1]["session_id"]).version, 4)
            v = aat.verify_chain(recs)
            self.assertTrue(v["ok"], v["problems"])
            # manomissioni: riordino, alterazione, genesi mancante, sessioni miste, non UTC, non monotono, id duplicato
            self.assertFalse(aat.verify_chain([recs[0], recs[2], recs[1], recs[3]])["ok"])
            alt = json.loads(json.dumps(recs)); alt[1]["outcome"] = "failure"
            self.assertFalse(aat.verify_chain(alt)["ok"])
            self.assertTrue(any("8.1" in p["why"] for p in aat.verify_chain(recs[1:])["problems"]))
            mix = json.loads(json.dumps(recs)); mix[2]["session_id"] = aat._uuid4_from("other")
            self.assertTrue(any("one session" in p["why"] for p in aat.verify_chain(mix)["problems"]))
            tz = json.loads(json.dumps(recs)); tz[1]["timestamp"] = tz[1]["timestamp"].replace("Z", "+02:00")
            self.assertTrue(any("UTC" in w["why"] for w in aat.verify_chain(tz)["warnings"]))      # §3.1 SHOULD → warning (round 1)
            back = json.loads(json.dumps(recs)); back[2]["timestamp"] = "2000-01-01T00:00:00.000Z"
            self.assertTrue(any("monotonic" in p["why"] for p in aat.verify_chain(back)["problems"]))
            dup = json.loads(json.dumps(recs)); dup[2]["record_id"] = dup[1]["record_id"]
            self.assertTrue(any("duplicate" in p["why"] for p in aat.verify_chain(dup)["problems"]))
            v1 = json.loads(json.dumps(recs)); v1[1]["session_id"] = str(_u.uuid1())
            self.assertTrue(any("v4" in p["why"] for p in aat.verify_chain(v1)["problems"]))
            v2 = json.loads(json.dumps(recs)); v2[1]["record_id"] = "urn:uuid:" + v2[1]["record_id"]
            self.assertTrue(any("canonical" in p["why"] for p in aat.verify_chain(v2)["problems"]))
            self.assertFalse(aat.verify_chain([])["ok"])
            # mai inventare: azione/esito ignoti, timestamp rotto o in formato base, agent_id assente, self_hash assente
            for bad in ({"action": "teleport"}, {"outcome": "meh"}, {"timestamp_utc": "garbage"}, {"timestamp_utc": "20260914T134000Z"}, {"agent_id": None}):
                e2 = json.loads(json.dumps(entries)); e2[0].update(bad)
                with self.assertRaises(ValueError):
                    aat.from_omega(e2, "1.0")
            e3 = json.loads(json.dumps(entries)); e3[0].pop("self_hash", None); e3[0].pop("record_sha3", None)
            with self.assertRaises(ValueError):
                aat.from_omega(e3, "1.0")
            with self.assertRaises(ValueError):
                aat.from_omega(entries, "1.0", session_ids={"sess-a": "not-a-uuid"})
            with self.assertRaises(ValueError):
                aat.from_omega(entries, "1.0", trust_level="L9")
            # catena ESTERNA conforme (float, spiffe URI, genesi lifecycle) deve verificare
            g = {"record_id": aat._uuid4_from("g1"), "timestamp": "2026-09-14T13:40:00.000Z", "agent_id": "spiffe://x/y",
                 "agent_version": "1", "session_id": aat._uuid4_from("s"), "action_type": "lifecycle",
                 "action_detail": {"event": "session_start", "risk": 0.000001, "n": 3}, "outcome": "success", "trust_level": "L2",
                 "record_phase": "concurrent", "parent_record_id": None, "prev_hash": None, "risk_score": 0.75}
            g2 = dict(g, record_id=aat._uuid4_from("g2"), action_type="decision", record_phase="post_execution",
                      action_detail={"decision_type": "route", "risk": 1e-5},
                      parent_record_id=g["record_id"], prev_hash=aat.record_hash(g, strict=False))
            self.assertTrue(aat.verify_chain([g, g2])["ok"], aat.verify_chain([g, g2])["problems"])
            self.assertFalse(aat.verify_chain([g, "junk", dict(g2, parent_record_id=None, prev_hash=None)])["ok"])

    def test_signatures_p256(self):
        from omega_evidence.interop import aat
        try:
            import cryptography  # noqa: F401
        except ImportError:
            self.skipTest("cryptography assente")
        priv, pub = aat.generate_p256_keypair()
        _, pub2 = aat.generate_p256_keypair()
        with tempfile.TemporaryDirectory() as tmp:
            entries = list(self._log(tmp)._ledger.entries())
            recs = next(iter(aat.from_omega(entries, "1.0").values()))
            broken = [aat.sign_record(r, priv) for r in recs]                   # firmare DOPO l export rompe la catena
            self.assertFalse(aat.verify_chain(broken, pubkey_pem=pub)["ok"])
            signed = next(iter(aat.from_omega(entries, "1.0", private_key_pem=priv).values()))
            v = aat.verify_chain(signed, pubkey_pem=pub)
            self.assertTrue(v["ok"], v["problems"]); self.assertEqual(v["signatures_verified"], 4)
            self.assertFalse(aat.verify_chain(signed, pubkey_pem=pub2)["ok"])
            self.assertFalse(aat.verify_chain(recs, pubkey_pem=pub)["ok"])          # non firmati con chiave data
            alt = json.loads(json.dumps(signed)); alt[1]["outcome"] = "failure"
            self.assertFalse(aat.verify_chain(alt, pubkey_pem=pub)["ok"])
            self.assertEqual(len(aat._b64u_dec(signed[0]["signature"])), 64)        # P1363 r||s
            padded = json.loads(json.dumps(signed)); padded[0]["signature"] += "=="
            self.assertFalse(aat.verify_chain(padded, pubkey_pem=pub)["ok"])       # padding rifiutato



def _forge_tombstone(aat, rec, key, original_action_type="lifecycle"):
    """What an attacker (not tombstone()) writes: a tombstone shell over `rec`, signed with `key`."""
    out = {k: rec[k] for k in ("record_id", "timestamp", "agent_id", "agent_version", "session_id", "parent_record_id", "prev_hash",
                               "trust_level", "record_phase") if k in rec}
    if "recording_component" in rec:
        out["recording_component"] = rec["recording_component"]
    out.update({"action_type": "lifecycle", "outcome": "success", "tombstone_hash": aat.record_hash(rec, strict=False),
                "action_detail": {"event": "record_deleted", "deletion_reason": "x", "deleted_at": "2099-01-01T00:00:00Z",
                                  "original_action_type": original_action_type, "original_event": "pause"}})
    return aat.sign_record(out, key)


class TestAAT04(unittest.TestCase):
    """draft -04 (2026-09-15): record_phase and the §4.2 rules, §7 REQUIRED action_detail fields (0.7.0 exports
    violated them), signer_kid (RFC 7638 / AKP thumbprints, KAT from draft-ietf-cose-dilithium-11), ML-DSA-65 and
    hybrid signatures, §5 recording independence, §5.3 fail-safe, nonces, tombstones (§9.3), session close (§8.3),
    §13 closure, Merkle epochs (§6.4) against cryptovalid's RFC 6962 implementation, JSONL/CSV (§10)."""

    def _log(self, tmp):
        log = agent.AgentEvidenceLog(os.path.join(tmp, "agent.jsonl"), runtime_id="rt-1")
        log.record("bot-7", "sess-a", "tool_call", "https://api.example/x", "rule-1", agent.Decision.ALLOW, agent.Outcome.EXECUTED)
        log.record("bot-7", "sess-a", "file_write", "/tmp/out", "rule-2", agent.Decision.DENY, agent.Outcome.BLOCKED)
        log.record("bot-7", "sess-a", "decision", "route", "rule-3", agent.Decision.ALLOW_WITH_APPROVAL,
                   agent.Outcome.PENDING_APPROVAL, human_approver="op-9", reason="needs a human")
        return list(log._ledger.entries())

    def _chain(self, tmp, **kw):
        from omega_evidence.interop import aat
        return next(iter(aat.from_omega(self._log(tmp), "1.0", **kw).values()))

    def test_phases_and_section7_fields(self):
        from omega_evidence.interop import aat
        with tempfile.TemporaryDirectory() as tmp:
            recs = self._chain(tmp, close=True)
            v = aat.verify_chain(recs)
            self.assertTrue(v["ok"], v["problems"])
            self.assertEqual([r["record_phase"] for r in recs], ["concurrent", "post_execution", "pre_execution", "pre_execution", "post_execution"])
            self.assertEqual(recs[1]["action_detail"]["tool_name"], "tool_call")
            self.assertEqual(recs[1]["action_detail"]["parameters_hash"], hashlib.sha256(b'{"resource":"https://api.example/x"}').hexdigest())
            self.assertEqual(recs[3]["action_detail"]["decision_type"], "allow_with_approval")
            self.assertEqual(recs[3]["outcome"], "escalated")
            # §4.2: decision/escalated MUST be pre_execution
            bad = json.loads(json.dumps(recs)); bad[3]["record_phase"] = "post_execution"
            self.assertTrue(any("4.2" in p["why"] for p in aat.verify_chain(bad)["problems"]))
            # -00 chain (no record_phase) refused with the explicit reason
            legacy = json.loads(json.dumps(recs)); [r.pop("record_phase") for r in legacy]
            self.assertTrue(any("re-exported" in p["why"] for p in aat.verify_chain(legacy)["problems"]))
            # §7: a tool_call without parameters_hash; a reserved aat_ key; empty detail
            for mut in (lambda r: r[1]["action_detail"].pop("parameters_hash"), lambda r: r[1]["action_detail"].update({"aat_x": 1}),
                        lambda r: r[1]["action_detail"].clear()):
                m = json.loads(json.dumps(recs)); mut(m)
                self.assertFalse(aat.verify_chain(m)["ok"])
            # §8.3 close: session_hash checked, tampering of an earlier record breaks it even if prev_hashes are recomputed
            self.assertEqual(recs[-1]["action_detail"]["record_count"], 5)
            forged = json.loads(json.dumps(recs)); forged[1]["outcome"] = "failure"
            for k in range(2, 5):
                forged[k]["prev_hash"] = aat.record_hash(forged[k - 1], strict=False)
            self.assertTrue(any("session_hash" in p["why"] for p in aat.verify_chain(forged)["problems"]))
            notlast = json.loads(json.dumps(recs)); notlast.insert(2, notlast.pop())
            self.assertFalse(aat.verify_chain(notlast)["ok"])
            # actions whose §7 fields are not derivable are refused, never guessed
            e = self._log(tmp); e[0]["action"] = "delegation"
            with self.assertRaises(ValueError):
                aat.from_omega(e, "1.0")

    def test_thumbprints_kat(self):
        from omega_evidence.interop import aat
        # draft-ietf-cose-dilithium-11 appendix: ML-DSA-65 JWK with kid = AKP thumbprint (KAT on the pub prefix hash)
        pub = base64.urlsafe_b64decode("QksvJn5Y1bO0TXGs_Gpla7JpUNV8YdsciAvPof6rRD8JQquL2619cIq7w1YHj22ZolInH-YsdAkeuUr7m5JkxQqIjg3-2AzV-yy9NmfmDVOevkSTAhnNT67RXbs0VaJkgCufSbzkLudVD-_91GQqVa3mk4aKRgy-wD9PyZpOMLzP-opHXlOVOWZ067galJN1h4gPbb0nvxxPWp7kPN2LDlOzt_tJxzrfvC1PjFQwNSDCm_l-Ju5X2zQtlXyJOTZSLQlCtB2C7jdyoAVwrftUXBFDkisElvgmoKlwBks23fU0tfjhwc0LVWXqhGtFQx8GGBQ-zol3e7P2EXmtIClf4KbgYq5u7Lwu848qwaItyTt7EmM2IjxVth64wHlVQruy3GXnIurcaGb_qWg764qZmteoPl5uAWwuTDX292Sa071S7GfsHFxue5lydxIYvpVUu6dyfwuExEubCovYMfz_LJd5zNTKMMatdbBJg-Qd6JPuXznqc1UYC3CccEXCLTOgg_auB6EUdG0b_cy-5bkEOHm7Wi4SDipGNig_ShzUkkot5qSqPZnd2I9IqqToi_0ep2nYLBB3ny3teW21Qpccoom3aGPt5Zl7fpzhg7Q8zsJ4sQ2SuHRCzgQ1uxYlFx21VUtHAjnFDSoMOkGyo4gH2wcLR7-z59EPPNl51pljyNefgCnMSkjrBPyz1wiET-uqi23f8Bq2TVk1jmUFxOwdfLsU7SIS30WOzvwD_gMDexUFpMlEQyL1-Y36kaTLjEWGCi2tx1FTULttQx5JpryPW6lW5oKw5RMyGpfRliYCiRyQePYqipZGoxOHpvCWhCZIN4meDY7H0RxWWQEpiyCzRQgWkOtMViwao6Jb7wZWbLNMebwLJeQJXWunk-gTEeQaMykVJobwDUiX-E_E7fSybVRTZXherY1jrvZKh8C5Gi5VADg5Vs319uN8-dVILRyOOlvjjxclmsRcn6HEvTvxd9MS7lKm2gI8BXIqhzgnTdqNGwTpmDHPV8hygqJWxWXCltBSSgY6OkGkioMAmXjZjYq_Ya9o6AE7WU_hUdm-wZmQLExwtJWEIBdDxrUxA9L9JL3weNyQtaGItPjXcheZiNBBbJTUxXwIYLnXtT1M0mHzMqGFFWXVKsN_AIdHyv4yDzY9m-tuQRfbQ_2K7r5eDOL1Tj8DZ-s8yXG74MMBqOUvlglJNgNcbuPKLRPbSDoN0E3BYkfeDgiUrXy34a5-vU-PkAWCsgAh539wJUUBxqw90V1Du7eTHFKDJEMSFYwusbPhEX4ZTwoeTHg--8Ysn4HCFWLQ00pfBCteqvMvMflcWwVfTnogcPsJb1bEFVSc3nTzhk6Ln8J-MplyS0Y5mGBEtVko_WlyeFsoDCWj4hqrgU7L-ww8vsCRSQfskH8lodiLzj0xmugiKjWUXbYq98x1zSnB9dmPy5P3UNwwMQdpebtR38N9I-jup4Bzok0-JsaOe7EORZ8ld7kAgDWa4K7BAxjc2eD540Apwxs-VLGFVkXbQgYYeDNG2tW1Xt20-XezJqZVUl6-IZXsqc7DijwNInO3fT5o8ZAcLKUUlzSlEXe8sIlHaxjLoJ-oubRtlKKUbzWOHeyxmYZSxYqQhSQj4sheedGXJEYWJ-Y5DRqB-xpy-cftxL10fdXIUhe1hWFBAoQU3b5xRY8KCytYnfLhsFF4O49xhnax3vuumLpJbCqTXpLureoKg5PvWfnpFPB0P-ZWQN35mBzqbb3ZV6U0rU55DvyXTuiZOK2Z1TxbaAd1OZMmg0cpuzewgueV-Nh_UubIqNto5RXCd7vqgqdXDUKAiWyYegYIkD4wbGMqIjxV8Oo2ggOcSj9UQPS1rD5u0rLckAzsxyty9Q5JsmKa0w8Eh7Jwe4Yob4xPVWWbJfm916avRgzDxXo5gmY7txdGFYHhlolJKdhBU9h6f0gtKEtbiUzhp4IWsqAR8riHQs7lLVEz6P537a4kL1r5FjfDf_yjJDBQmy_kdWMDqaNln-MlKK8eENjUO-qZGy0Ql4bMZtNbHXjfJUuSzapA-RqYfkqSLKgQUOW8NTDKhUk73yqCU3TQqDEKaGAoTsPscyMm7u_8QrvUK8kbc-XnxrWZ0BZJBjdinzh2w-QvjbWQ5mqFp4OMgY94__tIU8vvCUNJiYA1RdyodlfPfH5-avpxOCvBD6C7ZIDyQ-6huGEQEAb6DP8ydWIZQ8xY603DoEKKXkJWcP6CJo3nHFEdj_vcEbDQ-WESDpcQFa1fRIiGuALj-sEWcjGdSHyE8QATOcuWl4TLVzRPKAf4tCXx1zyvhJbXQu0jf0yfzVpOhPun4n-xqK4SxPBCeuJOkQ2VG9jDXWH4pnjbAcrqjveJqVti7huMXTLGuqU2uoihBw6mGqu_WSlOP2-XTEyRyvxbv2t-z9V6GPt1V9ceBukA0oGwtJqgD-q7NXFK8zhw7desI5PZMXf3nuVgbJ3xdvAlzkmm5f9RoqQS6_hqwPQEcclq1MEZ3yML5hc99TDtZWy9gGkhR0Hs3QJxxgP7bEqGFP-HjTPnJsrGaT6TjKP7qCxJlcFKLUr5AU_kxMULeUysWWtSGJ9mpxBvsyW1Juo" + "=")
        self.assertEqual(len(pub), 1952)
        self.assertEqual(aat.mldsa65_thumbprint(pub), "Suiu29qbfuaBaR4Ats-c6XQBePB_OpAxAwcTR_0KXVM")
        with self.assertRaises(ValueError):
            aat.mldsa65_thumbprint(pub[:-1])
        try:
            import cryptography  # noqa: F401
        except ImportError:
            self.skipTest("cryptography assente")
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        x = int.from_bytes(base64.urlsafe_b64decode("f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU="), "big")
        y = int.from_bytes(base64.urlsafe_b64decode("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0="), "big")
        pem = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        # RFC 7517 Appendix A.1 EC key; thumbprint computed independently with jwcrypto 1.6.1 on 2026-09-19
        self.assertEqual(aat.p256_thumbprint(pem), "oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U")

    def test_signatures_es256_mldsa_hybrid(self):
        from omega_evidence.interop import aat
        from omega_evidence.pqbackends import mldsa
        try:
            import cryptography  # noqa: F401
        except ImportError:
            self.skipTest("cryptography assente")
        priv, pub = aat.generate_p256_keypair()
        priv2, pub2 = aat.generate_p256_keypair()
        with tempfile.TemporaryDirectory() as tmp:
            entries = self._log(tmp)
            es = next(iter(aat.from_omega(entries, "1.0", private_key_pem=priv, close=True).values()))
            kid = aat.p256_thumbprint(pub)
            self.assertTrue(all(r["sig_alg"] == "ES256" and r["signer_kid"] == kid for r in es))
            v = aat.verify_chain(es, keys={kid: pub})
            self.assertTrue(v["ok"], v["problems"]); self.assertEqual(v["signatures_verified"], 5)
            self.assertTrue(aat.verify_chain(es, pubkey_pem=pub)["ok"])                       # fallback resolves by thumbprint
            self.assertFalse(aat.verify_chain(es, keys={kid: pub2})["ok"])                    # wrong key under the right kid
            self.assertFalse(aat.verify_chain(es, keys={"other": pub})["ok"])                 # kid unknown → problem
            self.assertTrue(aat.verify_chain(es, keys={kid: pub}, agent_kid=kid)["ok"])       # self-recording: the agent's key is fine
            swapped = json.loads(json.dumps(es)); swapped[1]["signer_kid"] = aat.p256_thumbprint(pub2)
            self.assertFalse(aat.verify_chain(swapped, keys={kid: pub, aat.p256_thumbprint(pub2): pub2})["ok"])   # kid is signed
            unsigned = next(iter(aat.from_omega(entries, "1.0").values()))
            self.assertFalse(aat.verify_chain(unsigned, require_signatures=True)["ok"])
            self.assertFalse(aat.verify_chain(unsigned, keys={kid: pub})["ok"])               # keys given → every record must be signed (round 2)
            self.assertTrue(aat.verify_chain(unsigned)["ok"])                                  # no key, no claim
            rewritten = json.loads(json.dumps(es))                                             # signed prefix + unsigned continuation = rewrite
            for r in rewritten[2:]:
                for k in ("signature", "sig_alg", "signer_kid"):
                    r.pop(k)
            for k in range(3, 5):
                rewritten[k]["prev_hash"] = aat.record_hash(rewritten[k - 1], strict=False)
            rewritten[-1]["action_detail"]["session_hash"] = hashlib.sha256(b"".join(bytes.fromhex(r["prev_hash"]) for r in rewritten[1:])).hexdigest()
            self.assertFalse(aat.verify_chain(rewritten, keys={kid: pub})["ok"])
            # -03 legacy: signature without sig_alg/signer_kid, verified through the fallback key (warning), not through `keys`
            legacy = []
            for r in unsigned:
                body = {k: v for k, v in r.items()}
                if legacy:
                    body["parent_record_id"] = legacy[-1]["record_id"]; body["prev_hash"] = aat.record_hash(legacy[-1])
                body["signature"], _ = aat._es256_sign(aat._signing_input(body), priv)
                legacy.append(body)
            self.assertFalse(aat.verify_chain(legacy, pubkey_pem=pub)["ok"])                  # §3.3 MUST: a problem by default
            v = aat.verify_chain(legacy, pubkey_pem=pub, allow_legacy_03=True)
            self.assertTrue(v["ok"], v["problems"]); self.assertEqual(v["signatures_verified"], 4)
            self.assertFalse(aat.verify_chain(legacy, keys={kid: pub}, allow_legacy_03=True)["ok"])   # no fallback key → unresolved
            if not mldsa.available():
                self.skipTest("ML-DSA-65 assente (cryptography >= 48)")
            kp = mldsa.MlDsaFileSigner.keygen(os.path.join(tmp, "pq.key")); signer = mldsa.MlDsaFileSigner(os.path.join(tmp, "pq.key"))
            pq_raw = base64.b64decode(kp["public_key_b64"]); pkid = aat.mldsa65_thumbprint(pq_raw)
            pq = next(iter(aat.from_omega(entries, "1.0", pq_signer=signer).values()))
            self.assertTrue(all(r["sig_alg"] == "ML-DSA-65" and r["signer_kid"] == pkid and len(aat._b64u_dec(r["signature"])) == 3309 for r in pq))
            v = aat.verify_chain(pq, keys={pkid: kp["public_key_b64"]})
            self.assertTrue(v["ok"], v["problems"]); self.assertEqual(v["signatures_verified"], 4)
            self.assertFalse(aat.verify_chain(pq, keys={pkid: pub})["ok"])                     # ES256 key under an ML-DSA kid
            alt = json.loads(json.dumps(pq)); alt[2]["outcome"] = "failure"
            self.assertFalse(aat.verify_chain(alt, keys={pkid: pq_raw})["ok"])
            hy = next(iter(aat.from_omega(entries, "1.0", private_key_pem=priv, pq_signer=signer).values()))
            self.assertTrue(all("signature_classical" in r and r["signer_kid_classical"] == kid for r in hy))
            v = aat.verify_chain(hy, keys={pkid: pq_raw, kid: pub})
            self.assertTrue(v["ok"], v["problems"]); self.assertEqual(v["hybrid_verified"], 4)
            self.assertFalse(aat.verify_chain(hy, keys={pkid: pq_raw})["ok"])                 # classical key missing → not hybrid-verified → problem
            bc = json.loads(json.dumps(hy)); bc[1]["signature_classical"] = hy[2]["signature_classical"]
            self.assertFalse(aat.verify_chain(bc, keys={pkid: pq_raw, kid: pub})["ok"])
            # independent recording: recorder's key must differ from the agent's
            ind = next(iter(aat.from_omega(entries, "1.0", private_key_pem=priv2, recording_component="urn:gw:1").values()))
            self.assertEqual(ind[0]["action_detail"]["recording_mode"], "independent")
            self.assertTrue(aat.verify_chain(ind, keys={aat.p256_thumbprint(pub2): pub2}, agent_kid=kid)["ok"])
            self.assertFalse(aat.verify_chain(ind, keys={aat.p256_thumbprint(pub2): pub2}, agent_kid=aat.p256_thumbprint(pub2))["ok"])
            noc = json.loads(json.dumps(ind)); noc[1].pop("recording_component")
            self.assertFalse(aat.verify_chain(noc, keys={aat.p256_thumbprint(pub2): pub2})["ok"])

    def test_tombstone_nonce_failsafe_closure(self):
        from omega_evidence.interop import aat
        with tempfile.TemporaryDirectory() as tmp:
            recs = self._chain(tmp, close=True)
            t = json.loads(json.dumps(recs)); t[1] = aat.tombstone(t[1], "gdpr_art17", "2099-01-01T00:00:00Z")
            v = aat.verify_chain(t)
            self.assertTrue(v["ok"], v["problems"]); self.assertEqual(v["tombstones"], 1)
            self.assertEqual(t[2]["prev_hash"], t[1]["tombstone_hash"])
            th = json.loads(json.dumps(t)); th[1]["tombstone_hash"] = "0" * 64
            self.assertFalse(aat.verify_chain(th)["ok"])
            fake = json.loads(json.dumps(recs)); fake[1]["tombstone_hash"] = aat.record_hash(recs[1])       # not a tombstone
            self.assertFalse(aat.verify_chain(fake)["ok"])
            # nonces: unique within the session
            n = json.loads(json.dumps(recs)); n[1]["nonce"] = "a" * 32; n[2]["nonce"] = "a" * 32
            for k in range(2, 5):
                n[k]["prev_hash"] = aat.record_hash(n[k - 1], strict=False)
            n[-1]["action_detail"]["session_hash"] = hashlib.sha256(b"".join(bytes.fromhex(r["prev_hash"]) for r in n[1:])).hexdigest()
            self.assertTrue(any("nonce" in p["why"] for p in aat.verify_chain(n)["problems"]))
            short = json.loads(json.dumps(recs)); short[1]["nonce"] = "abc"
            self.assertTrue(any("nonce" in p["why"] for p in aat.verify_chain(short)["problems"]))
            # §5.3: delegation below L2 without an attributable downgrade
            g = json.loads(json.dumps(recs[:2])); g[1].update({"action_type": "delegation", "outcome": "success", "trust_level": "L1",
                                                             "action_detail": {"delegate_agent_id": "urn:a:2", "delegate_trust_level": "L1",
                                                                               "task_description_hash": "0" * 64}})
            self.assertTrue(any("5.3" in p["why"] for p in aat.verify_chain(g)["problems"]))
            g[1]["trust_assignment"] = {"classifier_id": "urn:cls:1", "policy_version": "3", "downgraded": True}
            self.assertFalse(any("5.3" in p["why"] for p in aat.verify_chain(g)["problems"]))
            pay = json.loads(json.dumps(recs)); pay[1]["trust_level"] = "L1"
            self.assertTrue(any("5.3" in p["why"] for p in aat.verify_chain(pay, consequential=lambda r: "api.example" in str(r["action_detail"]))["problems"]))
            # §13: reproducible only with a closed attestation
            d = json.loads(json.dumps(recs)); d[3]["reproducibility_class"] = "reproducible"
            self.assertTrue(any("OPEN attestation" in p["why"] for p in aat.verify_chain(d)["problems"]))
            d[3].update({k: "sha256:" + "1" * 64 for k in aat.CLOSURE_DIGESTS})
            d[3]["inference_config"] = {"temperature": 0, "top_k": 1, "top_p": 1, "seed": None, "max_tokens": 10}
            d[3]["environment"] = {"engine": "x", "engine_version": "1", "hardware": "cpu", "batch_size": 1, "num_threads": 1}
            d[3]["content_fingerprint"] = "2" * 64
            self.assertFalse(any("OPEN attestation" in p["why"] for p in aat.verify_chain(d)["problems"]))
            d[3]["margin_reproducible"] = True; d[3]["decision_margin"] = 1.0; d[3]["margin_epsilon"] = 0.6
            self.assertTrue(any("13.8" in p["why"] for p in aat.verify_chain(d)["problems"]))
            # size bound: > 256 KB MUST be rejected
            big = json.loads(json.dumps(recs)); big[1]["action_detail"]["blob"] = "x" * (257 * 1024)
            self.assertTrue(any("256 KB" in p["why"] for p in aat.verify_chain(big)["problems"]))

    def test_round1_tombstone_forgery_crashes_independent(self):
        """Review round 1 (Gemini Pro, Opus, Sonnet, Haiku, 2026-09-19): a forged tombstone in a SIGNED chain must not
        verify; hostile inputs must be problems, never crashes; independent recording must be signed."""
        from omega_evidence.interop import aat
        try:
            import cryptography  # noqa: F401
        except ImportError:
            self.skipTest("cryptography assente")
        priv, pub = aat.generate_p256_keypair(); kid = aat.p256_thumbprint(pub)
        priv2, pub2 = aat.generate_p256_keypair(); kid2 = aat.p256_thumbprint(pub2)
        with tempfile.TemporaryDirectory() as tmp:
            entries = self._log(tmp)
            es = next(iter(aat.from_omega(entries, "1.0", private_key_pem=priv, close=True).values()))
            # attacker with write access: record 2 → tombstone with tombstone_hash := record 3's public prev_hash, stale signature kept
            forged = json.loads(json.dumps(es))
            forged[2] = {**{k: forged[2][k] for k in ("record_id", "timestamp", "agent_id", "agent_version", "session_id", "parent_record_id",
                                                     "prev_hash", "trust_level", "record_phase", "signature", "sig_alg", "signer_kid")},
                         "action_type": "lifecycle", "outcome": "success", "tombstone_hash": forged[3]["prev_hash"],
                         "action_detail": {"event": "record_deleted", "deletion_reason": "attacker", "deleted_at": "2099-01-01T00:00:00Z",
                                           "original_action_type": "tool_call"}}
            for kw in ({"keys": {kid: pub}}, {"keys": {kid: pub}, "require_signatures": True}, {"pubkey_pem": pub}):
                v = aat.verify_chain(forged, **kw)
                self.assertFalse(v["ok"], kw); self.assertTrue(any("signature" in p["why"] for p in v["problems"]))
            unsigned_tomb = json.loads(json.dumps(forged)); [unsigned_tomb[2].pop(k) for k in ("signature", "sig_alg", "signer_kid")]
            self.assertFalse(aat.verify_chain(unsigned_tomb, keys={kid: pub})["ok"])
            self.assertFalse(aat.verify_chain(unsigned_tomb, require_signatures=True)["ok"])
            # legitimate deletion: tombstone signed anew by the deleting authority
            good = json.loads(json.dumps(es)); good[2] = aat.tombstone(good[2], "gdpr_art17", "2099-01-01T00:00:00Z", key=priv2)
            self.assertEqual(good[2]["signer_kid"], kid2); self.assertIn("original_signature", good[2]["action_detail"])
            v = aat.verify_chain(good, keys={kid: pub, kid2: pub2}, require_signatures=True, tombstone_kids=[kid2])
            self.assertTrue(v["ok"], v["problems"]); self.assertEqual(v["tombstones"], 1); self.assertEqual(v["signatures_verified"], 5)
            self.assertFalse(aat.verify_chain(good, keys={kid: pub, kid2: pub2})["ok"])          # not a named deleting authority (round 8: the agent is inferred)
            self.assertFalse(aat.verify_chain(good, keys={kid: pub})["ok"])                       # deleting key unknown → problem
            edited = json.loads(json.dumps(good)); edited[2]["action_detail"]["deletion_reason"] = "other"
            self.assertFalse(aat.verify_chain(edited, keys={kid: pub, kid2: pub2}, tombstone_kids=[kid2])["ok"])   # tombstone content is signed
            # unsigned chain: tombstone accepted with the §9.3 warning
            plain = next(iter(aat.from_omega(entries, "1.0", close=True).values()))
            plain[2] = aat.tombstone(plain[2], "gdpr_art17", "2099-01-01T00:00:00Z")
            v = aat.verify_chain(plain); self.assertTrue(v["ok"], v["problems"]); self.assertTrue(any("unsigned tombstone" in w["why"] for w in v["warnings"]))
            # hostile inputs: problems, never exceptions (also through the CLI path from_jsonl)
            for mut in (lambda r: r[1].update({"action_type": ["tool_call"]}), lambda r: r[1].update({"timestamp": "2026-13-45T25:61:61Z"}),
                        lambda r: r[1].update({"agent_version": "\ud800"}), lambda r: r[1]["action_detail"].update({"deep": json.loads("[" * 600 + "]" * 600)}),
                        lambda r: r[1].update({"decision_margin": True, "margin_epsilon": False, "margin_reproducible": True}),
                        lambda r: r[1].update({"trust_assignment": "x"}), lambda r: r[1].update({"batch": 5}),
                        lambda r: r[1].update({"signer_kid": 5}), lambda r: r[1].update({"external_timestamp": {"tsa_url": 1}})):
                h = json.loads(json.dumps(es)); mut(h)
                v = aat.verify_chain(h, keys={kid: pub}); self.assertFalse(v["ok"])
            with self.assertRaises(ValueError):
                aat.from_jsonl('{"a": NaN}\n')
            with self.assertRaises(ValueError):
                aat.from_jsonl('{"agent_version":"EVIL","agent_version":"1.0"}\n')
            with self.assertRaises(ValueError):
                aat.jcs(json.loads("[" * 600 + "]" * 600))
            # independent recording MUST be signed (§5.2); the agent's key in the classical slot is caught too
            with self.assertRaises(ValueError):
                aat.from_omega(entries, "1.0", recording_component="urn:gw:1")                  # independent MUST be signed: export refuses
            ind = json.loads(json.dumps(next(iter(aat.from_omega(entries, "1.0", private_key_pem=priv2, recording_component="urn:gw:1").values()))))
            for r in ind:
                for k in ("signature", "sig_alg", "signer_kid"):
                    r.pop(k)
            for k in range(1, len(ind)):
                ind[k]["prev_hash"] = aat.record_hash(ind[k - 1])
            self.assertTrue(any("5.2" in p["why"] for p in aat.verify_chain(ind)["problems"]))
            from omega_evidence.pqbackends import mldsa
            if mldsa.available():
                kp = mldsa.MlDsaFileSigner.keygen(os.path.join(tmp, "pq.key")); signer = mldsa.MlDsaFileSigner(os.path.join(tmp, "pq.key"))
                pkid = aat.mldsa65_thumbprint(base64.b64decode(kp["public_key_b64"]))
                hy = next(iter(aat.from_omega(entries, "1.0", private_key_pem=priv, pq_signer=signer, recording_component="urn:gw:1").values()))
                ks = {pkid: kp["public_key_b64"], kid: pub}
                self.assertTrue(aat.verify_chain(hy, keys=ks, agent_kid=kid2)["ok"])
                self.assertFalse(aat.verify_chain(hy, keys=ks, agent_kid=kid)["ok"])              # agent's key used for signature_classical
            # epoch anchor: leaf_count, the index proven by the path, incomplete epochs, TSA never green without a CA
            an = aat.anchor_epoch(es, epoch_id=aat._uuid4_from("e"))
            self.assertFalse(aat.verify_epochs(es, [dict(an, leaf_count=2)])["ok"])
            ve = aat.verify_epochs(es, [an]); self.assertTrue(ve["ok"]); self.assertEqual(ve["incomplete"], {}); self.assertFalse(ve["time_verified"])
            for n in range(1, 21):
                leaves = [hashlib.sha256(bytes([k])).digest() for k in range(n)]
                self.assertEqual([aat.index_from_path(aat.audit_path(leaves, k), n) for k in range(n)], list(range(n)))
            swapped = json.loads(json.dumps(es)); swapped[1]["batch"]["leaf_index"] = 3           # proof still leads to the root
            self.assertTrue(any("proves leaf index" in p["why"] for p in aat.verify_epochs(swapped, [an])["problems"]))
            partial = json.loads(json.dumps(es))[:3]
            ve = aat.verify_epochs(partial, [an]); self.assertTrue(ve["ok"]); self.assertEqual(ve["incomplete"][an["epoch_id"]]["seen"], 3)
            self.assertFalse(aat.verify_epochs(partial, [an], require_complete=True)["ok"])
            stripped = json.loads(json.dumps(es)); stripped[2].pop("batch")
            ve = aat.verify_epochs(stripped, [an]); self.assertIn(an["epoch_id"], ve["incomplete"]); self.assertTrue(any("outside every epoch" in w["why"] for w in ve["warnings"]))
            with_tsa = [dict(an, tsa={"tsa_url": "https://tsa.example", "token": "AAAA", "message_imprint_sha256": hashlib.sha256(bytes.fromhex(an["merkle_root"])).hexdigest()})]
            ve = aat.verify_epochs(es, with_tsa); self.assertFalse(ve["time_verified"]); self.assertTrue(any("NOT verified" in w["why"] for w in ve["warnings"]))
            # truncation of a signed chain is a warning; a hybrid record missing its classical half is a problem
            v = aat.verify_chain(es[:-2], keys={kid: pub}, require_signatures=True)
            self.assertTrue(v["ok"]); self.assertTrue(any("truncated" in w["why"] for w in v["warnings"]))
            self.assertFalse(any("truncated" in w["why"] for w in aat.verify_chain(es, keys={kid: pub})["warnings"]))
            half = json.loads(json.dumps(es)); half[-1]["signer_kid_classical"] = kid2
            self.assertTrue(any("classical half" in p["why"] for p in aat.verify_chain(half, keys={kid: pub})["problems"]))
            v = aat.verify_chain(es, keys={kid: pub, "junk": b"nope"}); self.assertFalse(v["ok"]); self.assertEqual(v["keys_rejected"], ["junk"])
            # RFC 3339 §5.6: lowercase t/z accepted; non-UTC offsets compared as instants
            low = json.loads(json.dumps(es)); low[1]["timestamp"] = low[1]["timestamp"].replace("T", "t").replace("Z", "z")
            self.assertFalse(any("RFC 3339" in p["why"] or "calendar" in p["why"] for p in aat.verify_chain(low)["problems"]))
            self.assertEqual(aat._rfc3339("2026-09-19t20:00:00.5+02:00"), "2026-09-19T18:00:00.500Z")
            # per-record independence: a foreign recording_component without recording_mode still needs the recorder's signature
            sneaky = next(iter(aat.from_omega(entries, "1.0", private_key_pem=priv).values()))
            sneaky = json.loads(json.dumps(sneaky))
            for r in sneaky:
                r["recording_component"] = "urn:gw:evil"
            self.assertTrue(any("5.2" in p["why"] for p in aat.verify_chain(sneaky, keys={kid: pub}, agent_kid=kid)["problems"]))
            # export: time order and size are enforced, never silently produce a red chain
            e2 = json.loads(json.dumps(entries)); e2[1]["timestamp_utc"] = "2000-01-01T00:00:00Z"
            with self.assertRaises(ValueError):
                aat.from_omega(e2, "1.0")
            e3 = json.loads(json.dumps(entries)); e3[1]["reason"] = "x" * (260 * 1024)
            with self.assertRaises(ValueError):
                aat.from_omega(e3, "1.0")

    def test_round2_hostile_epochs_export_never_invents(self):
        """Review round 2 (2026-09-19): verify_epochs and verify_chain never raise on hostile JSON; the export never
        invents (session, outcome, phase, duplicate identity, self-recording labelled independent); legacy -03 never
        applies to an independent recorder; margin_reproducible must be a boolean; anchors must not conflict."""
        from omega_evidence.interop import aat
        try:
            import cryptography  # noqa: F401
        except ImportError:
            self.skipTest("cryptography assente")
        priv, pub = aat.generate_p256_keypair(); kid = aat.p256_thumbprint(pub)
        with tempfile.TemporaryDirectory() as tmp:
            entries = self._log(tmp)
            es = next(iter(aat.from_omega(entries, "1.0", private_key_pem=priv, close=True).values()))
            an = aat.anchor_epoch(es, epoch_id=aat._uuid4_from("e"))
            hostile = [lambda r, a: r.__setitem__(1, "junk"), lambda r, a: r[1]["batch"].__setitem__("epoch_id", ["x"]),
                       lambda r, a: a[0].pop("epoch_id"), lambda r, a: r[1]["action_detail"].__setitem__("x", float("nan")),
                       lambda r, a: r[1]["action_detail"].__setitem__("deep", json.loads("[" * 600 + "]" * 600)),
                       lambda r, a: a[0].__setitem__("leaf_count", "5"), lambda r, a: a[0].__setitem__("tsa", {"token": 5}),
                       lambda r, a: a.append(dict(a[0], merkle_root="0" * 64))]
            for mut in hostile:
                rr = json.loads(json.dumps(es)); aa = json.loads(json.dumps([an])); mut(rr, aa)
                self.assertFalse(aat.verify_epochs(rr, aa)["ok"])
            self.assertTrue(any("conflicting anchors" in p["why"] for p in aat.verify_epochs(es, [an, dict(an, merkle_root="0" * 64)])["problems"]))
            ve = aat.verify_epochs(es[:1], [an, dict(an, epoch_id=aat._uuid4_from("other"))])
            self.assertTrue(any("unaccounted" in w["why"] for w in ve["warnings"]))
            for mut in (lambda r: r[1].update({"action_type": "lifecycle", "action_detail": "abc"}),
                        lambda r: r[-1].update({"action_type": "lifecycle", "action_detail": True}),
                        lambda r: r[1].update({"latency_ms": int("1" + "0" * 400)}),
                        lambda r: r[1].update({"batch": {"epoch_id": "not-a-uuid", "merkle_root": "0" * 64, "leaf_index": 0}}),
                        lambda r: r[1].update({"batch": {"epoch_id": aat._uuid4_from("e"), "merkle_root": "0" * 64, "leaf_index": 0, "inclusion_proof": [{"hash": "zz", "side": "up"}]}}),
                        lambda r: r[3].update({"margin_reproducible": "false", "decision_margin": 5, "margin_epsilon": 1})):
                h = json.loads(json.dumps(es)); mut(h)
                self.assertFalse(aat.verify_chain(h, keys={kid: pub})["ok"])
            plain = next(iter(aat.from_omega(entries, "1.0", close=True).values()))            # unsigned: the rule itself, not the signature, must fire
            pm = json.loads(json.dumps(plain)); pm[3].update({"margin_reproducible": "false", "decision_margin": 5, "margin_epsilon": 1})
            self.assertTrue(any("must be a boolean" in p["why"] for p in aat.verify_chain(pm)["problems"]))
            pb = json.loads(json.dumps(plain)); pb[1]["batch"] = {"epoch_id": "not-a-uuid", "merkle_root": "0" * 64, "leaf_index": 0}
            self.assertTrue(any("UUID v4" in p["why"] for p in aat.verify_chain(pb)["problems"]))
            pl = json.loads(json.dumps(plain)); pl[1]["action_type"] = "lifecycle"; pl[1]["action_detail"] = "abc"
            self.assertTrue(any("not an object" in p["why"] for p in aat.verify_chain(pl)["problems"]))
            with self.assertRaises(ValueError):
                aat.jcs({"x": int("1" + "0" * 400)}, strict=False)
            # export never invents
            for bad in ({"session_id": None}, {"outcome": "denied"}, {"outcome": "success"}):
                e2 = json.loads(json.dumps(entries)); e2[0].update(bad)
                with self.assertRaises(ValueError):
                    aat.from_omega(e2, "1.0")
            e3 = json.loads(json.dumps(entries)); e3[1]["record_sha3"] = e3[0]["record_sha3"]
            with self.assertRaises(ValueError):
                aat.from_omega(e3, "1.0")
            with self.assertRaises(ValueError):
                aat.from_omega(entries, "1.0", recording_component="urn:omega:agent:bot-7")
            with self.assertRaises(ValueError):
                aat.close_record(es[:-1], timestamp="2000-01-01T00:00:00Z")
            # -03 fallback never applies to an independent recorder; independence declared with own component is a problem
            ind = next(iter(aat.from_omega(entries, "1.0", private_key_pem=priv, recording_component="urn:gw:1").values()))
            legacy = []
            for r in ind:
                body = {k: v for k, v in r.items() if k not in ("signature", "sig_alg", "signer_kid")}
                if legacy:
                    body["parent_record_id"] = legacy[-1]["record_id"]; body["prev_hash"] = aat.record_hash(legacy[-1])
                body["signature"], _ = aat._es256_sign(aat._signing_input(body), priv)
                legacy.append(body)
            self.assertFalse(aat.verify_chain(legacy, pubkey_pem=pub, agent_kid=kid, allow_legacy_03=True)["ok"])
            own = json.loads(json.dumps(es))
            own[0]["action_detail"].update({"recording_mode": "independent", "recording_component_id": own[0]["agent_id"]})
            for r in own:
                r["recording_component"] = r["agent_id"]
            self.assertTrue(any("equals agent_id" in p["why"] for p in aat.verify_chain(own)["problems"]))
            # leap second and 7-digit fractions are foreign-valid instants
            leap = json.loads(json.dumps(es)); leap[-2]["timestamp"] = "2026-12-31T23:59:59.1234567Z"; leap[-1]["timestamp"] = "2026-12-31T23:59:60Z"
            self.assertFalse(any("calendar" in p["why"] or "monotonic" in p["why"] for p in aat.verify_chain(leap)["problems"]))

    def test_round3_attribution_regex_fraction_specific_messages(self):
        """Review round 3 (2026-09-19): one agent per chain, the agent's key for self-recorded records (§6.3 3a),
        leaf_count mandatory in anchors, fullmatch on every format check, fractions of any length (Python 3.9 parses only
        3 or 6 digits), a synthesised close never claims task_complete, and the guards the earlier tests masked behind
        prev_hash are asserted by their own message on the LAST record."""
        from omega_evidence.interop import aat
        try:
            import cryptography  # noqa: F401
        except ImportError:
            self.skipTest("cryptography assente")
        priv, pub = aat.generate_p256_keypair(); kid = aat.p256_thumbprint(pub)
        priv2, pub2 = aat.generate_p256_keypair(); kid2 = aat.p256_thumbprint(pub2)
        with tempfile.TemporaryDirectory() as tmp:
            entries = self._log(tmp)
            es = next(iter(aat.from_omega(entries, "1.0", private_key_pem=priv, close=True).values()))
            self.assertEqual(es[-1]["action_detail"]["trigger"], "export"); self.assertIn("close_basis", es[-1]["action_detail"])
            self.assertNotIn("task_complete", json.dumps(es))
            # one agent per chain (verify) and per session (export)
            two = json.loads(json.dumps(es)); two[2]["agent_id"] = "urn:omega:agent:someone-else"
            self.assertTrue(any("one agent" in p["why"] for p in aat.verify_chain(two)["problems"]))
            e2 = json.loads(json.dumps(entries)); e2[1]["agent_id"] = "bot-8"
            with self.assertRaises(ValueError):
                aat.from_omega(e2, "1.0")
            # self-recorded chain signed by a non-agent key in the key set: problem when agent_kid is given
            other = next(iter(aat.from_omega(entries, "1.0", private_key_pem=priv2, close=True).values()))
            self.assertTrue(aat.verify_chain(other, keys={kid: pub, kid2: pub2})["ok"])
            self.assertTrue(any("6.3 step 3a" in p["why"] for p in aat.verify_chain(other, keys={kid: pub, kid2: pub2}, agent_kid=kid)["problems"]))
            self.assertTrue(aat.verify_chain(es, keys={kid: pub, kid2: pub2}, agent_kid=kid)["ok"])
            # anchors without leaf_count are malformed (a dropped record would otherwise hide)
            an = aat.anchor_epoch(es, epoch_id=aat._uuid4_from("e"))
            nolc = {k: v for k, v in an.items() if k != "leaf_count"}
            self.assertTrue(any("anchor malformed" in p["why"] for p in aat.verify_epochs(es[:3], [nolc])["problems"]))
            # fullmatch: a trailing newline is not a hex digest / nonce / country code
            plain = next(iter(aat.from_omega(entries, "1.0", close=True).values()))
            for mut, word in ((lambda r: r[-1]["action_detail"].update({"session_hash": r[-1]["action_detail"]["session_hash"] + "\n"}), "session_hash"),
                              (lambda r: r[-1].update({"nonce": "b" * 32 + "\n"}), "nonce"),
                              (lambda r: r[-1].update({"jurisdiction": "IT\n"}), "jurisdiction"),
                              (lambda r: r[-1]["action_detail"].update({"aat_x": 1}), "aat_ prefix")):
                m = json.loads(json.dumps(plain)); mut(m)
                self.assertTrue(any(word in p["why"] for p in aat.verify_chain(m)["problems"]), word)
            # fractions of 1, 2, 7 and 12 digits parse (and compare) on every supported Python
            for frac in (".5", ".12", ".1234567", ".123456789012"):
                self.assertEqual(aat._parse_ts("2026-09-19T20:00:00" + frac + "Z").year, 2026)
            self.assertEqual(aat._rfc3339("0999-01-01T00:00:00Z"), "0999-01-01T00:00:00.000Z")
            # guards asserted by their own message on the last record (no prev_hash to mask them)
            last = json.loads(json.dumps(es))
            sig = last[-1]["signature"]; raw = aat._b64u_dec(sig); pad = "=" * (-len(sig) % 4)
            alt = next(c for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                       if c != sig[-1] and base64.urlsafe_b64decode(sig[:-1] + c + pad) == raw)          # same bytes, non-canonical tail
            last[-1]["signature"] = sig[:-1] + alt
            self.assertTrue(any("not canonical" in p["why"] for p in aat.verify_chain(last, keys={kid: pub})["problems"]))
            from omega_evidence.pqbackends import mldsa
            if mldsa.available():
                kp = mldsa.MlDsaFileSigner.keygen(os.path.join(tmp, "pq.key")); signer = mldsa.MlDsaFileSigner(os.path.join(tmp, "pq.key"))
                pkid = aat.mldsa65_thumbprint(base64.b64decode(kp["public_key_b64"]))
                hy = next(iter(aat.from_omega(entries, "1.0", private_key_pem=priv, pq_signer=signer).values()))
                bc = json.loads(json.dumps(hy)); bc[-1]["signature_classical"] = hy[-2]["signature_classical"]
                self.assertTrue(any("signature_classical invalid" in p["why"] for p in aat.verify_chain(bc, keys={pkid: kp["public_key_b64"], kid: pub})["problems"]))
                v = aat.verify_chain(hy, keys={pkid: pub, kid: pub}); self.assertFalse(v["ok"]); self.assertEqual(v["keys_rejected"], [pkid])   # ES256 key under the PQ kid: not its thumbprint
            # §13 fields only on decision records; L2+ self-recorded is a warning
            wrong = json.loads(json.dumps(plain)); wrong[1]["reproducibility_class"] = "reconstructable"
            self.assertTrue(any("decision records only" in p["why"] for p in aat.verify_chain(wrong)["problems"]))
            l2 = next(iter(aat.from_omega(entries, "1.0", trust_level="L2", close=True).values()))
            self.assertTrue(any("5.2 SHOULD" in w["why"] for w in aat.verify_chain(l2)["warnings"]))

    def test_round4_session_independence_epochs_paths(self):
        """Review round 4 (2026-09-19): independence is a session property (a record cannot opt out by omitting
        recording_component); whole-epoch truncation under require_complete; a TSA token over an epoch root counts only
        when the record's inclusion proof leads to that root; bottom-up audit paths equal the recursive ones; uppercase
        session ids are the same session; keys={} still means every record must be signed."""
        from omega_evidence.interop import aat
        try:
            import cryptography  # noqa: F401
        except ImportError:
            self.skipTest("cryptography assente")
        priv, pub = aat.generate_p256_keypair(); kid = aat.p256_thumbprint(pub)
        privR, pubR = aat.generate_p256_keypair(); kidR = aat.p256_thumbprint(pubR)
        with tempfile.TemporaryDirectory() as tmp:
            entries = self._log(tmp)
            ind = next(iter(aat.from_omega(entries, "1.0", private_key_pem=privR, recording_component="urn:gw:x").values()))
            nomode = json.loads(json.dumps(ind))
            for k in ("recording_mode", "recording_component_id"):
                nomode[0]["action_detail"].pop(k)
            nomode[0] = aat.sign_record({k: v for k, v in nomode[0].items() if k not in ("signature", "sig_alg", "signer_kid")}, privR)
            for k in range(1, len(nomode)):
                nomode[k]["prev_hash"] = aat.record_hash(nomode[k - 1])
                nomode[k] = aat.sign_record({kk: v for kk, v in nomode[k].items() if kk not in ("signature", "sig_alg", "signer_kid")}, privR)
            ks = {kid: pub, kidR: pubR}
            self.assertTrue(aat.verify_chain(nomode, keys=ks, agent_kid=kid)["ok"])
            # the agent tombstones record 1 with its own key and drops recording_component: still an independent session
            t = json.loads(json.dumps(nomode)); t[1] = aat.tombstone(t[1], "x", "2099-01-01T00:00:00Z", key=priv); t[1].pop("recording_component", None)
            self.assertTrue(any("5.2" in p["why"] for p in aat.verify_chain(t, keys=ks, agent_kid=kid)["problems"]))
            # the agent appends a self-signed tail record without recording_component
            tail = json.loads(json.dumps(nomode)); extra = {k: v for k, v in tail[-1].items() if k not in ("signature", "sig_alg", "signer_kid", "recording_component")}
            extra.update({"record_id": aat._uuid4_from("x"), "parent_record_id": tail[-1]["record_id"], "prev_hash": aat.record_hash(tail[-1])})
            tail.append(aat.sign_record(extra, priv))
            self.assertTrue(any("5.2" in p["why"] for p in aat.verify_chain(tail, keys=ks, agent_kid=kid)["problems"]))
            # two recorders in one session
            two = json.loads(json.dumps(ind)); two[1]["recording_component"] = "urn:gw:other"
            self.assertTrue(any("second recording component" in p["why"] and p["i"] == 1 for p in aat.verify_chain(two, keys=ks)["problems"]))
            # audit paths: bottom-up == recursive; anchoring 4000 records stays fast
            for n in range(1, 65):
                leaves = [hashlib.sha256(bytes([n, k])).digest() for k in range(n)]
                self.assertEqual(aat.audit_paths(leaves), [aat.audit_path(leaves, k) for k in range(n)], n)
                self.assertEqual(aat.merkle_levels(leaves)[-1][0], aat.merkle_root(leaves))
            import time as _t
            big = [{"record_id": aat._uuid4_from(str(k)), "n": k} for k in range(4000)]
            t0 = _t.monotonic(); aat.anchor_epoch(big, epoch_id=aat._uuid4_from("big")); self.assertLess(_t.monotonic() - t0, 5.0)
            with self.assertRaises(ValueError):
                aat.anchor_epoch([{"n": 2 ** 53 + 1}], epoch_id=aat._uuid4_from("b"))            # export refuses lossy integers
            # whole-epoch truncation: a warning by default, a problem with require_complete
            es = next(iter(aat.from_omega(entries, "1.0", private_key_pem=priv, close=True).values()))
            a1 = aat.anchor_epoch(es[:3], epoch_id=aat._uuid4_from("e1")); a2 = aat.anchor_epoch(es[3:], epoch_id=aat._uuid4_from("e2"))
            self.assertTrue(aat.verify_epochs(es, [a1, a2], require_complete=True)["ok"])
            ve = aat.verify_epochs(es[:3], [a1, a2], require_complete=True)
            self.assertFalse(ve["ok"]); self.assertEqual(ve["incomplete"][a2["epoch_id"]]["seen"], 0)
            self.assertFalse(aat.verify_epochs(es, "junk")["ok"])
            # external_timestamp: verified over the record's own digest only; a token over some root (a forged batch, or a
            # genuine old epoch token) never counts for a record (round 4: the record's leaf hash changes once the token is in)
            from omega_evidence import timestamp as _tsmod
            c = json.loads(json.dumps(es)); c[2]["external_timestamp"] = {"tsa_url": "https://tsa", "token": "AAAA", "anchored_at": "2020-01-01T00:00:00Z"}
            own = hashlib.sha256(aat.jcs({k: v for k, v in c[2].items() if k not in ("signature", "signature_classical", "batch", "external_timestamp")}, strict=False)).hexdigest()
            root_imprint = hashlib.sha256(bytes.fromhex(c[2]["batch"]["merkle_root"])).hexdigest()
            for imprint, expect in ((own, True), (root_imprint, False)):
                with unittest.mock.patch.object(_tsmod, "verify", lambda tok, im, ca_file=None, **kw: {"verified": im == imprint}):
                    v = aat.verify_chain(c, external_timestamp_ca_file="/x/ca.pem")
                self.assertEqual(not any("external_timestamp token not verified" in p["why"] for p in v["problems"]), expect)
            # uppercase session id = same session; keys={} = every record must be signed; deleted_at before the record
            up = json.loads(json.dumps(entries)); sid4 = aat._uuid4_from("s4"); up[0]["session_id"] = sid4.upper(); up[1]["session_id"] = sid4; up[2]["session_id"] = "{" + sid4 + "}"
            self.assertEqual(list(aat.from_omega(up, "1.0").keys()), [sid4])
            plain = next(iter(aat.from_omega(entries, "1.0", close=True).values()))
            self.assertFalse(aat.verify_chain(plain, keys={})["ok"]); self.assertTrue(aat.verify_chain(plain)["ok"])
            early = json.loads(json.dumps(plain)); early[1] = aat.tombstone(early[1], "x", "2020-01-01T00:00:00Z")
            self.assertTrue(any("deleted_at earlier" in p["why"] for p in aat.verify_chain(early)["problems"]))
            # inclusion_proof is OPTIONAL: a complete epoch rebuilds without them (warning); an incomplete one cannot (problem)
            np_ = json.loads(json.dumps(es)); a_all = aat.anchor_epoch(np_, epoch_id=aat._uuid4_from("all"))
            for r in np_:
                r["batch"].pop("inclusion_proof")
            ve = aat.verify_epochs(np_, [a_all]); self.assertTrue(ve["ok"], ve["problems"]); self.assertTrue(any("rebuilding" in w["why"] for w in ve["warnings"]))
            self.assertFalse(aat.verify_epochs(np_[:3], [a_all])["ok"])
            with self.assertRaises(ValueError):
                aat.from_omega(entries, "")
            e_leap = json.loads(json.dumps(entries)); e_leap[0]["timestamp_utc"] = "2026-09-19T23:59:60Z"
            with self.assertRaises(ValueError):
                aat.from_omega(e_leap, "1.0")
            neg = json.loads(json.dumps(plain)); neg[3].update({"margin_reproducible": True, "decision_margin": 0.001, "margin_epsilon": -1000})
            self.assertTrue(any("cannot be negative" in p["why"] for p in aat.verify_chain(neg)["problems"]))

    def test_round5_self_certifying_kids_low_s_s13_placement_csv(self):
        """Review round 5 (2026-09-19): a key set entry whose kid is not the thumbprint of its key is rejected (a poisoned
        map cannot relabel keys); ES256 signatures are emitted in low-S form and a high-S (malleable) form is reported;
        §13 field NAMES inside action_detail of a non-decision record are preserved (warning), at the top level a problem;
        environment_attestation has a shape; CSV cells cannot start a spreadsheet formula."""
        from omega_evidence.interop import aat
        try:
            import cryptography  # noqa: F401
        except ImportError:
            self.skipTest("cryptography assente")
        priv, pub = aat.generate_p256_keypair(); kid = aat.p256_thumbprint(pub)
        priv2, pub2 = aat.generate_p256_keypair(); kid2 = aat.p256_thumbprint(pub2)
        with tempfile.TemporaryDirectory() as tmp:
            entries = self._log(tmp)
            byB = next(iter(aat.from_omega(entries, "1.0", private_key_pem=priv2, close=True).values()))
            relabel = json.loads(json.dumps(byB))
            for r in relabel:
                r["signer_kid"] = kid                                   # claims the agent's kid (breaks the signature, but the map is the point)
            v = aat.verify_chain(byB, keys={kid: pub2}, agent_kid=kid)  # poisoned map: agent's kid → B's key
            self.assertFalse(v["ok"]); self.assertEqual(v["keys_rejected"], [kid])
            self.assertTrue(aat.verify_chain(byB, keys={kid2: pub2})["ok"])
            # low-S: every emitted signature has s <= n/2; the (r, n-s) twin verifies with a warning, never silently
            for r in byB:
                sig = aat._b64u_dec(r["signature"]); self.assertLessEqual(int.from_bytes(sig[32:], "big"), aat.P256_ORDER // 2)
            hi = json.loads(json.dumps(byB)); sig = aat._b64u_dec(hi[-1]["signature"])
            s_hi = aat.P256_ORDER - int.from_bytes(sig[32:], "big")
            hi[-1]["signature"] = aat._b64u(sig[:32] + s_hi.to_bytes(32, "big"))
            v = aat.verify_chain(hi, keys={kid2: pub2})
            self.assertTrue(v["ok"], v["problems"]); self.assertTrue(any("high-S" in w["why"] for w in v["warnings"]))
            self.assertNotEqual(aat.record_hash(hi[-1]), aat.record_hash(byB[-1]))    # the malleated twin has another hash: declared
            # §13 names inside a tool_call's action_detail: preserved, warning only; at the top level: problem
            plain = next(iter(aat.from_omega(entries, "1.0", close=True).values()))
            open_ = next(iter(aat.from_omega(entries, "1.0").values()))                    # no close: the LAST record can be edited freely
            det = json.loads(json.dumps(open_)); det[-1]["action_detail"]["environment"] = "production"
            self.assertEqual(det[-1]["action_type"], "decision")                             # a decision: §13 names are checked, not just warned
            det[1]["action_detail"]["environment"] = "production"; det[2]["prev_hash"] = aat.record_hash(det[1]); det[3]["prev_hash"] = aat.record_hash(det[2])
            v = aat.verify_chain(det); self.assertTrue(any("§13 field names" in w["why"] for w in v["warnings"]))
            self.assertTrue(v["ok"], v["problems"])
            top = json.loads(json.dumps(open_)); top[-1]["action_type"] = "tool_call"; top[-1]["action_detail"] = {"tool_name": "t", "parameters_hash": "0" * 64}
            top[-1]["decision_margin"] = 1.0; top[-1]["margin_epsilon"] = 0.4; top[-1]["margin_reproducible"] = True
            self.assertTrue(any("decision records only" in p["why"] for p in aat.verify_chain(top)["problems"]))
            ea = json.loads(json.dumps(open_)); ea[-1]["environment_attestation"] = 5
            self.assertTrue(any("environment_attestation" in p["why"] for p in aat.verify_chain(ea)["problems"]))
            ea[-1]["environment_attestation"] = "https://attest.example/quote/1"
            self.assertFalse(any("environment_attestation" in p["why"] for p in aat.verify_chain(ea)["problems"]))
            # CSV injection
            inj = json.loads(json.dumps(plain)); inj[1]["agent_version"] = "=cmd|'/c calc'!A0"
            line = aat.to_csv(inj).splitlines()[2]
            self.assertIn("'=cmd", line); self.assertNotIn(",=cmd", line)

    def test_round6_epoch_membership_tsa_failure_phase_basis_double_tombstone(self):
        """Review round 6 (Opus): a copied record with the same record_id/leaf_index and altered content is not a member;
        TSA anchoring that fails raises (no anchor without a token) and an anchor declaring a TSA without a token is
        malformed; an omega entry with consistent=false is refused; a tombstone of a tombstone keeps the original hash."""
        from omega_evidence.interop import aat
        with tempfile.TemporaryDirectory() as tmp:
            entries = self._log(tmp)
            plain = next(iter(aat.from_omega(entries, "1.0", close=True).values()))
            an = aat.anchor_epoch(plain, epoch_id=aat._uuid4_from("e"))
            forged = json.loads(json.dumps(plain))
            fake = json.loads(json.dumps(forged[3])); fake["action_detail"]["resource"] = "/etc/passwd"; fake.pop("batch"); fake["batch"] = {k: v for k, v in forged[3]["batch"].items() if k != "inclusion_proof"}
            forged.insert(3, fake)
            ve = aat.verify_epochs(forged, [an]); self.assertFalse(ve["ok"]); self.assertTrue(any("NOT the leaf" in p["why"] or "DIFFERENT records" in p["why"] for p in ve["problems"]))
            with self.assertRaises(RuntimeError):
                aat.anchor_epoch(json.loads(json.dumps(plain)), epoch_id=aat._uuid4_from("t"), tsa_url="https://127.0.0.1:9/tsa")
            self.assertFalse(aat.verify_epochs(plain, [dict(an, tsa={"tsa_url": "https://tsa", "token": None})])["ok"])
            e2 = json.loads(json.dumps(entries)); e2[0]["consistent"] = False
            with self.assertRaises(ValueError):
                aat.from_omega(e2, "1.0")
            self.assertIn("DERIVED by the exporter", plain[1]["action_detail"]["record_phase_basis"])
            t1 = json.loads(json.dumps(plain)); t1[1] = aat.tombstone(t1[1], "gdpr", "2099-01-01T00:00:00Z")
            t2 = json.loads(json.dumps(t1)); t2[1] = aat.tombstone(t2[1], "gdpr (corrected reason)", "2099-01-01T00:30:00Z")
            self.assertEqual(t2[1]["tombstone_hash"], t1[1]["tombstone_hash"]); self.assertEqual(t2[1]["action_detail"]["original_action_type"], "tool_call")
            self.assertTrue(aat.verify_chain(t2)["ok"], aat.verify_chain(t2)["problems"])
            with self.assertRaises(ValueError):
                aat.close_record(["junk"])
            bad_uri = json.loads(json.dumps(plain)); bad_uri[-1]["agent_id"] = "urn:x y"
            self.assertTrue(any("agent_id is not a URI" in p["why"] for p in aat.verify_chain(bad_uri)["problems"]))

    def test_round6_guards_asserted_by_message(self):
        """Review round 6 (Opus p3/p4): every guard the earlier tests reached only through prev_hash or the signature is
        asserted by its own message; deleting authorities are pinned (agent_kid / tombstone_kids); the synthesised close
        states session_outcome unknown; hostile CLI/JSON inputs are verdicts, not tracebacks."""
        from omega_evidence.interop import aat
        try:
            import cryptography  # noqa: F401
        except ImportError:
            self.skipTest("cryptography assente")
        priv, pub = aat.generate_p256_keypair(); kid = aat.p256_thumbprint(pub)
        privR, pubR = aat.generate_p256_keypair(); kidR = aat.p256_thumbprint(pubR)
        privX, pubX = aat.generate_p256_keypair(); kidX = aat.p256_thumbprint(pubX)
        ks = {kid: pub, kidR: pubR, kidX: pubX}

        def resign(chain, key, start=1):
            out = json.loads(json.dumps(chain))
            for k in range(start, len(out)):
                body = {kk: v for kk, v in out[k].items() if kk not in ("signature", "sig_alg", "signer_kid", "signature_classical", "signer_kid_classical")}
                if k > 0:
                    body["parent_record_id"] = out[k - 1]["record_id"]; body["prev_hash"] = aat.record_hash(out[k - 1])
                out[k] = aat.sign_record(body, key)
            return out
        with tempfile.TemporaryDirectory() as tmp:
            entries = self._log(tmp)
            ind = next(iter(aat.from_omega(entries, "1.0", private_key_pem=privR, recording_component="urn:gw:x").values()))
            # 1. omission of recording_component, re-signed by the recorder itself: the omission rule, by message
            om = json.loads(json.dumps(ind)); om[2].pop("recording_component"); om = resign(om, privR, start=2)
            self.assertTrue(any("every record MUST carry recording_component" in p["why"] for p in aat.verify_chain(om, keys=ks, agent_kid=kid)["problems"]))
            # 2. session_end not last, chain re-linked: §8.3 rule by message
            es = next(iter(aat.from_omega(entries, "1.0", private_key_pem=priv, close=True).values()))
            moved = json.loads(json.dumps(es)); moved.insert(2, moved.pop()); moved = resign(moved, priv, start=1)
            self.assertTrue(any("session_end is not the last record" in p["why"] for p in aat.verify_chain(moved, keys=ks)["problems"]))
            # 3. deleting authorities: a foreign key in `keys` cannot tombstone a self-recorded record when agent_kid is pinned
            t = json.loads(json.dumps(es)); t[2] = aat.tombstone(t[2], "x", "2099-01-01T00:00:00Z", key=privX)
            v = aat.verify_chain(t, keys=ks, agent_kid=kid); self.assertTrue(any("not a deleting authority" in p["why"] for p in v["problems"]))
            self.assertTrue(aat.verify_chain(t, keys=ks, agent_kid=kid, tombstone_kids=[kidX])["ok"])
            v = aat.verify_chain(t, keys=ks); self.assertFalse(v["ok"])                          # round 8: the genesis signer is the inferred agent, X is not an authority
            self.assertTrue(any("agent key not pinned" in w["why"] for w in v["warnings"]))
            ta = json.loads(json.dumps(es)); ta[2] = aat.tombstone(ta[2], "x", "2099-01-01T00:00:00Z", key=priv)
            self.assertTrue(aat.verify_chain(ta, keys=ks, agent_kid=kid)["ok"])                    # the agent may delete its own
            # 4. key algorithm mismatch by message: a record claiming ML-DSA-65 under a P-256 kid
            alg = json.loads(json.dumps(es)); alg[-1]["sig_alg"] = "ML-DSA-65"
            self.assertTrue(any("record says ML-DSA-65" in p["why"] for p in aat.verify_chain(alg, keys=ks)["problems"]))
            # 5. signer_kid_classical == signer_kid on an unsigned-classical path; tombstoned genesis; close states unknown
            same = json.loads(json.dumps(es)); same[-1]["signer_kid_classical"] = same[-1]["signer_kid"]; same[-1]["signature_classical"] = same[-1]["signature"]; same[-1]["sig_alg"] = "ML-DSA-65"
            self.assertTrue(any("two DISTINCT keys" in p["why"] for p in aat.verify_chain(same, keys=ks)["problems"]))
            with self.assertRaises(ValueError):
                aat.tombstone(es[0], "x", "2099-01-01T00:00:00Z", key=priv)                 # tombstone() never deletes lifecycle records
            g = json.loads(json.dumps(es)); g[0] = _forge_tombstone(aat, g[0], priv)
            self.assertTrue(any("8.1" in p["why"] for p in aat.verify_chain(g, keys=ks)["problems"]))
            self.assertEqual(es[-1]["action_detail"]["session_outcome"], "unknown")
            from omega_evidence.pqbackends import mldsa
            if mldsa.available():
                kp = mldsa.MlDsaFileSigner.keygen(os.path.join(tmp, "pq.key")); signer = mldsa.MlDsaFileSigner(os.path.join(tmp, "pq.key"))
                pkid = aat.mldsa65_thumbprint(base64.b64decode(kp["public_key_b64"]))
                pq = next(iter(aat.from_omega(entries, "1.0", pq_signer=signer).values()))
                short = json.loads(json.dumps(pq)); short[-1]["signature"] = short[-1]["signature"][:-8]
                self.assertTrue(any("3309" in p["why"] or "not canonical" in p["why"] for p in aat.verify_chain(short, keys={pkid: kp["public_key_b64"]})["problems"]))
            # 6. hostile verifier-side inputs are verdicts
            self.assertFalse(aat.verify_chain(es, keys=[1, 2])["ok"])
            v = aat.verify_chain(es, pubkey_pem=b"junk"); self.assertFalse(v["ok"]); self.assertTrue(any("pubkey_pem" in k for k in v["keys_rejected"]))
            with self.assertRaises(ValueError):
                aat.from_jsonl('{"a": 1e999}\n')
            import subprocess, sys as _sys
            open(os.path.join(tmp, "c.jsonl"), "w").write(aat.to_jsonl(es)); open(os.path.join(tmp, "deep.json"), "w").write("[" * 100000)
            r = subprocess.run([_sys.executable, "-m", "omega_evidence.interop.aat", "verify", os.path.join(tmp, "c.jsonl"), "--epochs", os.path.join(tmp, "deep.json")],
                               capture_output=True, text=True, cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            self.assertEqual(r.returncode, 2); self.assertIn('"ok": false', r.stdout); self.assertNotIn("Traceback", r.stderr)

    def test_round7_recorder_pin_legacy_effective_kid_close_tombstone(self):
        """Review round 7 (Opus/Sonnet, 2026-09-20): the recorder of an independent session is pinned (recorder_kid, or the
        first signing key) so a deleting-only key cannot rewrite the tail; the -03 fallback key is judged by its thumbprint
        like any other; a list-valued signer_kid_classical on a tombstone is a verdict, not a TypeError; tombstone_kids is
        typed; a tombstoned session close is refused; tool_response.parent_call_id must name an earlier tool_call."""
        from omega_evidence.interop import aat
        try:
            import cryptography  # noqa: F401
        except ImportError:
            self.skipTest("cryptography assente")
        privA, pubA = aat.generate_p256_keypair(); kidA = aat.p256_thumbprint(pubA)
        privR, pubR = aat.generate_p256_keypair(); kidR = aat.p256_thumbprint(pubR)
        privD, pubD = aat.generate_p256_keypair(); kidD = aat.p256_thumbprint(pubD)
        ks = {kidA: pubA, kidR: pubR, kidD: pubD}

        def resign(chain, key, start):
            out = json.loads(json.dumps(chain))
            for k in range(start, len(out)):
                body = {kk: v for kk, v in out[k].items() if kk not in ("signature", "sig_alg", "signer_kid", "signature_classical", "signer_kid_classical")}
                body["parent_record_id"] = out[k - 1]["record_id"]; body["prev_hash"] = aat.record_hash(out[k - 1])
                out[k] = aat.sign_record(body, key)
            return out
        with tempfile.TemporaryDirectory() as tmp:
            entries = self._log(tmp)
            ind = next(iter(aat.from_omega(entries, "1.0", private_key_pem=privR, recording_component="urn:recorder:R", close=True).values()))
            v = aat.verify_chain(ind, keys=ks, agent_kid=kidA, tombstone_kids=[kidD]); self.assertTrue(v["ok"], v["problems"])
            self.assertTrue(any("recorder key not pinned" in w["why"] for w in v["warnings"]))
            self.assertFalse(any("recorder key not pinned" in w["why"] for w in aat.verify_chain(ind, keys=ks, agent_kid=kidA, recorder_kid=kidR)["warnings"]))
            # the deleting-only key D rewrites record 2 and the tail: refused, with and without tombstone_kids / recorder_kid
            rw = json.loads(json.dumps(ind)); rw[2]["action_detail"]["resource"] = "/etc/passwd"; rw = resign(rw, privD, 2)
            for kw in ({"tombstone_kids": [kidD]}, {}, {"recorder_kid": kidR}):
                v = aat.verify_chain(rw, keys=ks, agent_kid=kidA, **kw)
                self.assertTrue(any("second signing key" in p["why"] or "not the session's recorder" in p["why"] for p in v["problems"]), kw)
            # D may tombstone (named authority), the recorder may tombstone, A (the agent) may not in an independent session
            td = json.loads(json.dumps(ind)); td[2] = aat.tombstone(td[2], "x", "2099-01-01T00:00:00Z", key=privD)
            self.assertTrue(aat.verify_chain(td, keys=ks, agent_kid=kidA, recorder_kid=kidR, tombstone_kids=[kidD])["ok"])
            self.assertTrue(any("not a deleting authority" in p["why"] for p in aat.verify_chain(td, keys=ks, agent_kid=kidA, recorder_kid=kidR)["problems"]))
            tr = json.loads(json.dumps(ind)); tr[2] = aat.tombstone(tr[2], "x", "2099-01-01T00:00:00Z", key=privR)
            self.assertTrue(aat.verify_chain(tr, keys=ks, agent_kid=kidA, recorder_kid=kidR)["ok"])
            # hostile: signer_kid_classical as a list on a tombstone → verdict, no TypeError; tombstone_kids typed
            bad = json.loads(json.dumps(td)); bad[2]["signer_kid_classical"] = []
            v = aat.verify_chain(bad, keys=ks, agent_kid=kidA, recorder_kid=kidR); self.assertFalse(v["ok"])
            v = aat.verify_chain(ind, keys=ks, tombstone_kids=5); self.assertTrue(any("tombstone_kids" in p["why"] for p in v["problems"]))
            # -03 fallback: the fallback key is judged by its thumbprint (agent_kid pin holds; deleting authority holds)
            byB = next(iter(aat.from_omega(entries, "1.0").values()))            # no close: the close's session_hash would not survive re-signing
            legacy = []
            for r in byB:
                body = dict(r)
                if legacy:
                    body["parent_record_id"] = legacy[-1]["record_id"]; body["prev_hash"] = aat.record_hash(legacy[-1])
                body["signature"], _ = aat._es256_sign(aat._signing_input(body), privD)
                legacy.append(body)
            self.assertTrue(aat.verify_chain(legacy, pubkey_pem=pubD, allow_legacy_03=True)["ok"])
            self.assertTrue(any("6.3 step 3a" in p["why"] for p in aat.verify_chain(legacy, pubkey_pem=pubD, agent_kid=kidA, allow_legacy_03=True)["problems"]))
            # a tombstoned session close is refused; parent_call_id must resolve
            es = next(iter(aat.from_omega(entries, "1.0", private_key_pem=privA, close=True).values()))
            tc = json.loads(json.dumps(es)); tc[-1] = _forge_tombstone(aat, tc[-1], privA)
            self.assertTrue(any("tombstone of a lifecycle record" in p["why"] for p in aat.verify_chain(tc, keys=ks, agent_kid=kidA)["problems"]))
            plain = next(iter(aat.from_omega(entries, "1.0").values()))
            resp = json.loads(json.dumps(plain)); resp[-1].update({"action_type": "tool_response", "record_phase": "post_execution",
                                                                   "action_detail": {"tool_name": "t", "response_hash": "0" * 64, "parent_call_id": aat._uuid4_from("nope")}})
            self.assertTrue(any("parent_call_id" in p["why"] for p in aat.verify_chain(resp)["problems"]))
            resp[-1]["action_detail"]["parent_call_id"] = plain[1]["record_id"]
            self.assertFalse(any("parent_call_id" in p["why"] for p in aat.verify_chain(resp)["problems"]))

    def test_round8_close_reopen_self_recorded_rewrite_s13_types(self):
        """Review round 8 (Opus/Haiku, 2026-09-20): a tombstoned close followed by appends is refused anywhere in the chain;
        a self-recorded session without agent_kid pins the genesis signer as the agent (a second key in the key set cannot
        rewrite the tail); §13 inference_config / environment values are typed."""
        from omega_evidence.interop import aat
        try:
            import cryptography  # noqa: F401
        except ImportError:
            self.skipTest("cryptography assente")
        privA, pubA = aat.generate_p256_keypair(); kidA = aat.p256_thumbprint(pubA)
        privD, pubD = aat.generate_p256_keypair(); kidD = aat.p256_thumbprint(pubD)
        ks = {kidA: pubA, kidD: pubD}
        with tempfile.TemporaryDirectory() as tmp:
            entries = self._log(tmp)
            es = next(iter(aat.from_omega(entries, "1.0", private_key_pem=privA, close=True).values()))
            # tombstone the close, append a wire_transfer and a new close, all signed by the agent: refused
            re = json.loads(json.dumps(es)); re[-1] = _forge_tombstone(aat, re[-1], privA)       # deleter writes original_event: "pause"
            extra = {k: v for k, v in es[1].items() if k not in ("signature", "sig_alg", "signer_kid")}
            extra.update({"record_id": aat._uuid4_from("wire"), "parent_record_id": re[-1]["record_id"], "prev_hash": aat.record_hash(re[-1]),
                          "timestamp": "2099-01-02T00:00:00Z", "action_detail": {"tool_name": "wire_transfer", "parameters_hash": "0" * 64}})
            re.append(aat.sign_record(extra, privA)); re.append(aat.sign_record(aat.close_record(re, synthesised=True), privA))
            v = aat.verify_chain(re, keys=ks, agent_kid=kidA, require_signatures=True)
            self.assertTrue(any("tombstone of a lifecycle record" in p["why"] for p in v["problems"]), v["problems"])
            # a phantom tombstone appended at the tail (nothing follows, tombstone_hash bound to nothing) is a problem
            ph = json.loads(json.dumps(es))[:-1]; ph.append(_forge_tombstone(aat, dict(ph[-1], record_id=aat._uuid4_from("ph"), parent_record_id=ph[-1]["record_id"],
                                                                                    prev_hash=aat.record_hash(ph[-1])), privA, original_action_type="tool_call"))
            self.assertTrue(any("tombstone as the last record" in p["why"] for p in aat.verify_chain(ph, keys=ks, agent_kid=kidA)["problems"]))
            # re-tombstoning keeps the ORIGINAL record's signature as evidence and lists the deleters' signatures
            t1 = json.loads(json.dumps(es)); t1[2] = aat.tombstone(t1[2], "gdpr", "2099-01-01T00:00:00Z", key=privA)
            t2 = json.loads(json.dumps(t1)); t2[2] = aat.tombstone(t2[2], "gdpr (corrected)", "2099-01-01T00:30:00Z", key=privA)
            self.assertEqual(t2[2]["action_detail"]["original_signature"]["signature"], es[2]["signature"])
            self.assertEqual(t2[2]["action_detail"]["deleter_signatures"][0]["signature"], t1[2]["signature"])
            self.assertTrue(aat.verify_chain(t2, keys=ks, agent_kid=kidA)["ok"])
            # hybrid: the PRIMARY signer is judged — the agent's key in the classical slot of a foreign primary is not the agent
            from omega_evidence.pqbackends import mldsa
            if mldsa.available():
                kp = mldsa.MlDsaFileSigner.keygen(os.path.join(tmp, "pq.key")); signer = mldsa.MlDsaFileSigner(os.path.join(tmp, "pq.key"))
                pkid = aat.mldsa65_thumbprint(base64.b64decode(kp["public_key_b64"]))
                hy = json.loads(json.dumps(es))[:-1]
                body = {k: v for k, v in hy[-1].items() if k not in ("signature", "sig_alg", "signer_kid")}
                hy[-1] = aat.sign_record_hybrid(body, signer, privA)                       # primary = PQ key, classical = the agent's
                self.assertTrue(any("6.3 step 3a" in p["why"] for p in aat.verify_chain(hy, keys={**ks, pkid: kp["public_key_b64"]}, agent_kid=kidA)["problems"]))
                th = json.loads(json.dumps(es)); th[2] = aat.tombstone(th[2], "x", "2099-01-01T00:00:00Z", key=signer, classical_private_key_pem=privA)
                self.assertTrue(any("not a deleting authority" in p["why"] for p in aat.verify_chain(th, keys={**ks, pkid: kp["public_key_b64"]}, agent_kid=kidA)["problems"]))
            # self-recorded without agent_kid: D (in the key set) rewrites the tail → problem; the honest chain warns only
            rw = json.loads(json.dumps(es)); rw[2]["action_detail"]["resource"] = "/etc/passwd"
            for k in range(2, len(rw)):
                body = {kk: v for kk, v in rw[k].items() if kk not in ("signature", "sig_alg", "signer_kid")}
                body["parent_record_id"] = rw[k - 1]["record_id"]; body["prev_hash"] = aat.record_hash(rw[k - 1])
                rw[k] = aat.sign_record(body, privD)
            v = aat.verify_chain(rw, keys=ks, require_signatures=True)
            self.assertTrue(any("6.3 step 3a" in p["why"] for p in v["problems"]))
            v = aat.verify_chain(es, keys=ks, require_signatures=True)
            self.assertTrue(v["ok"], v["problems"]); self.assertTrue(any("agent key not pinned" in w["why"] for w in v["warnings"]))
            # §13 typed values
            plain = next(iter(aat.from_omega(entries, "1.0").values()))
            d = json.loads(json.dumps(plain)); d[-1]["reproducibility_class"] = "reproducible"
            d[-1].update({k: "sha256:" + "1" * 64 for k in aat.CLOSURE_DIGESTS}); d[-1]["content_fingerprint"] = "2" * 64
            d[-1]["inference_config"] = {"temperature": "high", "top_k": 1, "top_p": 1, "seed": None, "max_tokens": 10}
            d[-1]["environment"] = {"engine": "x", "engine_version": "1", "hardware": "cpu", "batch_size": 1, "num_threads": 1}
            self.assertTrue(any("OPEN attestation" in p["why"] for p in aat.verify_chain(d)["problems"]))
            d[-1]["inference_config"]["temperature"] = 0
            self.assertFalse(any("OPEN attestation" in p["why"] for p in aat.verify_chain(d)["problems"]))
            d[-1]["environment"]["batch_size"] = "1"
            self.assertTrue(any("OPEN attestation" in p["why"] for p in aat.verify_chain(d)["problems"]))
            d[-1]["environment"]["batch_size"] = 1; d[-1]["inference_config"]["seed"] = "x"
            self.assertTrue(any("OPEN attestation" in p["why"] for p in aat.verify_chain(d)["problems"]))
            d[-1]["inference_config"].pop("seed")
            self.assertTrue(any("OPEN attestation" in p["why"] for p in aat.verify_chain(d)["problems"]))

    def test_merkle_epochs_against_cryptovalid_and_exports(self):
        from omega_evidence.interop import aat
        with tempfile.TemporaryDirectory() as tmp:
            recs = self._chain(tmp, close=True)
            plain = json.loads(json.dumps(recs))
            anchor = aat.anchor_epoch(recs, epoch_id=aat._uuid4_from("epoch-1"))
            self.assertEqual(anchor["leaf_count"], 5)
            self.assertTrue(all(r["batch"]["merkle_root"] == anchor["merkle_root"] for r in recs))
            self.assertTrue(aat.verify_chain(recs)["ok"])                                  # batch is detached: chain hashes unchanged
            self.assertEqual([aat.record_hash(r) for r in recs], [aat.record_hash(r) for r in plain])
            ve = aat.verify_epochs(recs, [anchor]); self.assertTrue(ve["ok"], ve["problems"])
            # oracle: cryptovalid's RFC 6962 roots and audit paths for 1..20 leaves, VENDORED as vectors (tests/fixtures) so the
            # claim reproduces in any clone; the live implementation is used too when this machine has it
            vec = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "rfc6962_cryptovalid_vectors.json")))
            self.assertEqual(len(vec["trees"]), 20)
            for t in vec["trees"]:
                n = t["n"]; datas = [bytes([i]) * 3 for i in range(n)]; leaves = [hashlib.sha256(b"\x00" + d).digest() for d in datas]
                self.assertEqual(aat.merkle_root(leaves).hex(), t["root"], n)
                for i in range(n):
                    self.assertEqual([st["hash"] for st in aat.audit_path(leaves, i)], t["paths"][i], (n, i))
            import importlib.util, sys as _sys
            cv = os.path.join(os.path.expanduser("~"), "omega", "omega_package", "opencore", "cryptovalid_merkle.py")
            if os.path.exists(cv):
                spec = importlib.util.spec_from_file_location("cryptovalid_merkle", cv); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
                self.assertTrue(hasattr(m, "mth") and hasattr(m, "inclusion_proof"))
                for n in range(1, 21):
                    datas = [bytes([i]) * 3 for i in range(n)]
                    leaves = [hashlib.sha256(b"\x00" + d).digest() for d in datas]
                    self.assertEqual(aat.merkle_root(leaves).hex(), m.mth(datas).hex(), n)                 # RFC 6962 MTH
                    for i in range(n):
                        self.assertEqual([st["hash"] for st in aat.audit_path(leaves, i)], [h.hex() for h in m.inclusion_proof(i, datas)], (n, i))
                        self.assertEqual(aat.root_from_path(leaves[i], aat.audit_path(leaves, i)), aat.merkle_root(leaves))
                    # the draft's wording ("odd last node promoted unchanged") gives the same root as RFC 6962's MTH
                    level = list(leaves)
                    while len(level) > 1:
                        level = [aat._node(level[j], level[j + 1]) if j + 1 < len(level) else level[j] for j in range(0, len(level), 2)]
                    self.assertEqual(level[0], aat.merkle_root(leaves), n)
            # (no live cryptovalid on this host: the vendored vectors above already carried the comparison)
            bad = json.loads(json.dumps(recs)); bad[2]["batch"]["inclusion_proof"][0]["hash"] = "0" * 64
            self.assertFalse(aat.verify_epochs(bad, [anchor])["ok"])
            dupidx = json.loads(json.dumps(recs)); dupidx[2]["batch"]["leaf_index"] = 1
            self.assertFalse(aat.verify_epochs(dupidx, [anchor])["ok"])
            self.assertFalse(aat.verify_epochs(recs, [dict(anchor, merkle_root="0" * 64)])["ok"])
            self.assertFalse(aat.verify_epochs(recs, [])["ok"])
            # JSONL round trip keeps the hashes; CSV is the draft's header, lossy and declared
            back = aat.from_jsonl(aat.to_jsonl(recs))
            self.assertEqual([aat.record_hash(r) for r in back], [aat.record_hash(r) for r in recs])
            self.assertTrue(aat.verify_chain(back)["ok"])
            csv_text = aat.to_csv(recs)
            self.assertTrue(csv_text.startswith("record_id,timestamp,agent_id,agent_version,session_id,action_type,outcome,trust_level,record_phase,parent_record_id,prev_hash,action_detail\r\n"))
            self.assertEqual(csv_text.count("\r\n"), 6)
            with self.assertRaises(ValueError):
                aat.from_jsonl('{"a":1}\n[1,2]\n')


class TestMlDsaHybrid(unittest.TestCase):
    """0.7.0 — ML-DSA-65 (FIPS 204) co-signature, the cryptovalid 0.13.0 rules: KAT-gated backend on NIST vectors,
    empty context, strict decoders, pinned tri-state (true only against the caller's or the registry's PQ key),
    a required layer that is missing / foreign / unverifiable is FAIL, self-verify after signing, AWS KMS signer shape."""

    def setUp(self):
        from omega_evidence.pqbackends import mldsa, autoload
        self.m = mldsa
        if not mldsa.available():
            self.skipTest("cryptography >= 48 (ML-DSA) absent")
        self.assertTrue(autoload()["mldsa"]["registered"], autoload())

    def _hybrid(self, tmp):
        pp = os.path.join(tmp, "p.json")
        pack.write_pack(pp, pack.build_pack("d", {"x": 1}, "ref; NOT x"))
        idt = signing.Identity("acme"); pack.sign_pack(pp, idt)
        kf = os.path.join(tmp, "pq.key"); kg = self.m.MlDsaFileSigner.keygen(kf)
        self.assertEqual(oct(os.stat(kf).st_mode & 0o777), "0o600")
        signer = self.m.MlDsaFileSigner(kf)
        side = pack.pq_cosign(pp, signer)
        self.assertEqual(side["pq_sig_alg"], "ml-dsa-65"); self.assertEqual(side["pq_public_key_b64"], kg["public_key_b64"])
        return pp, idt, signer

    def test_file_signer_pinned_tri_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            pp, idt, signer = self._hybrid(tmp)
            self.assertIsNone(verify_pack(pp)["pq_protected"])                                          # unpinned -> null
            v = verify_pack(pp, expected_pq_public_key_b64=signer.public_key_b64)
            self.assertTrue(v["valid"]); self.assertIs(v["pq_protected"], True)
            store = os.path.join(tmp, "trust.jsonl")
            trust.TrustRegistry(store).trust("acme", idt.public_key_b64, pq_pubkey=signer.public_key_b64)
            v = verify_pack(pp, trust_store=store, require_pq=True)
            self.assertTrue(v["valid"]); self.assertIs(v["pq_protected"], True); self.assertTrue(v["authenticated"])
            other = self.m.MlDsaFileSigner.keygen(os.path.join(tmp, "o.key"))["public_key_b64"]
            v = verify_pack(pp, expected_pq_public_key_b64=other)                                       # foreign key
            self.assertFalse(v["valid"]); self.assertIs(v["pq_protected"], False)

    def test_stripped_and_tampered_layer(self):
        with tempfile.TemporaryDirectory() as tmp:
            pp, idt, signer = self._hybrid(tmp)
            side_path = pp[:-5] + ".sig.json"; side = json.load(open(side_path)); good = dict(side)
            for k in ("pq_sig_alg", "pq_public_key_b64", "pq_signature_b64"):
                side.pop(k)
            json.dump(side, open(side_path, "w"))
            self.assertTrue(verify_pack(pp)["valid"])                                                   # classical still fine
            v = verify_pack(pp, expected_pq_public_key_b64=signer.public_key_b64)                       # required -> stripped = FAIL
            self.assertFalse(v["valid"]); self.assertIs(v["pq_protected"], False)
            raw = bytearray(base64.b64decode(good["pq_signature_b64"])); raw[7] ^= 1
            json.dump(dict(good, pq_signature_b64=base64.b64encode(bytes(raw)).decode()), open(side_path, "w"))
            self.assertFalse(verify_pack(pp)["valid"])                                                  # present but invalid = FAIL
            json.dump(dict(good, pq_signature_b64=good["pq_signature_b64"][:10] + " " + good["pq_signature_b64"][10:]), open(side_path, "w"))
            self.assertFalse(verify_pack(pp)["valid"])                                                  # lenient base64 refused

    def test_kms_signer_shape_with_stub(self):
        from cryptography.hazmat.primitives import serialization as ser
        with tempfile.TemporaryDirectory() as tmp:
            kf = os.path.join(tmp, "pq.key"); self.m.MlDsaFileSigner.keygen(kf); fs = self.m.MlDsaFileSigner(kf)
            spki = fs._sk.public_key().public_bytes(ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo)
            self.assertEqual(len(spki), 1974)
            class Stub:
                def get_public_key(self, KeyId): return {"PublicKey": spki, "KeyId": "arn:x"}
                def sign(self, KeyId, Message, MessageType, SigningAlgorithm):
                    assert (MessageType, SigningAlgorithm) == ("RAW", "ML_DSA_SHAKE_256"); return {"Signature": fs.sign(Message), "KeyId": "arn:x", "SigningAlgorithm": SigningAlgorithm}
            ks = self.m.AwsKmsMlDsaSigner("alias/x", client=Stub())
            self.assertEqual(ks.public_key_b64, fs.public_key_b64); self.assertFalse(ks.describe()["key_in_process_memory"])
            pp = os.path.join(tmp, "p.json"); pack.write_pack(pp, pack.build_pack("d", {"x": 1}, "ref; NOT x"))
            pack.sign_pack(pp, signing.Identity("a")); pack.pq_cosign(pp, ks)
            self.assertIs(verify_pack(pp, expected_pq_public_key_b64=ks.public_key_b64)["pq_protected"], True)
            class Repointed(Stub):
                def sign(self, KeyId, Message, MessageType, SigningAlgorithm):
                    return {"Signature": fs.sign(Message), "KeyId": "arn:OTHER", "SigningAlgorithm": SigningAlgorithm}
            with self.assertRaises(RuntimeError):
                self.m.AwsKmsMlDsaSigner("alias/x", client=Repointed()).sign(b"m")
            wrong = self.m.MlDsaFileSigner(self.m.MlDsaFileSigner.keygen(os.path.join(tmp, "w.key"))["path"])
            class WrongKey:
                public_key_b64 = fs.public_key_b64
                alg = "ml-dsa-65"
                def sign(self, m): return wrong.sign(m)
            with self.assertRaises(RuntimeError):                                                        # self-verify refuses
                pack.pq_cosign(pp, WrongKey())

    def test_pq_alone_is_not_hybrid_and_classical_alg_never_pq(self):
        with tempfile.TemporaryDirectory() as tmp:
            pp = os.path.join(tmp, "p.json"); pack.write_pack(pp, pack.build_pack("d", {"x": 1}, "ref; NOT x"))
            kf = os.path.join(tmp, "pq.key"); self.m.MlDsaFileSigner.keygen(kf)
            with self.assertRaises(RuntimeError):                                                        # no classical sidecar
                pack.pq_cosign(pp, self.m.MlDsaFileSigner(kf))
            idt = signing.Identity("a"); pack.sign_pack(pp, idt)
            pack.add_pq_signature(pp, "ed25519", idt.public_key_b64, json.load(open(pp[:-5] + ".sig.json"))["signature_b64"])
            v = verify_pack(pp, expected_pq_public_key_b64=idt.public_key_b64)
            self.assertFalse(v["valid"]); self.assertIsNot(v["pq_protected"], True)

    # ── council 16/09 r1 (Fable 5.1 + Opus + Sonnet + Haiku on the real files) ─────────────────────────────────
    def _layer(self, v, name):
        return next(ly for ly in v["layers"] if ly["layer"] == name)

    def test_pq_alg_never_accepted_as_classical_layer_even_when_loaded(self):
        """A sidecar declaring sig_alg ml-dsa-65 and no Ed25519 at all was PASSing 'producer-signature' once the
        backend had been autoloaded (register_sig_alg put it in SIG_ALGS). Now: unsupported → SKIP, never signed."""
        self.assertNotIn("ml-dsa-65", signing.SIG_ALGS); self.assertIn("ml-dsa-65", signing.PQ_SIG_ALGS)
        with tempfile.TemporaryDirectory() as tmp:
            pp, idt, signer = self._hybrid(tmp)
            sp = pp[:-5] + ".sig.json"; side = json.load(open(sp))
            digest = side["signed_pack_sha3"]
            pq_only = {"signer_id": "acme", "sig_alg": "ml-dsa-65", "signed_pack_sha3": digest,
                       "public_key_b64": side["pq_public_key_b64"], "signature_b64": side["pq_signature_b64"]}
            json.dump(pq_only, open(sp, "w"))
            v = verify_pack(pp)
            self.assertEqual(self._layer(v, "producer-signature")["status"], "SKIP")
            self.assertFalse(v["authenticated"]); self.assertFalse(v["valid"])
            for bad in (5, ["x"], None, {"a": 1}):                                                        # not a string → malformed
                json.dump(dict(side, sig_alg=bad), open(sp, "w"))
                v = verify_pack(pp)
                self.assertEqual(self._layer(v, "producer-signature")["status"], "FAIL"); self.assertFalse(v["authenticated"])
            json.dump(dict(side, sig_alg="rsa-pss"), open(sp, "w"))                                      # unknown string + odd pack_sha3: no crash
            body = json.load(open(pp)); body["pack_sha3"] = 5; json.dump(body, open(pp, "w"))
            v = verify_pack(pp); self.assertFalse(v["valid"]); self.assertIs(v["pq_protected"], False)

    def test_foreign_classical_key_under_trusted_id_is_not_pq_protected(self):
        """Mallory's Ed25519 key with signer_id 'acme' + acme's real ML-DSA co-signature: the registry's PQ pin is
        NOT borrowed; pq_protected is null (unpinned) / false when required, never true; never authenticated."""
        with tempfile.TemporaryDirectory() as tmp:
            pp, idt, signer = self._hybrid(tmp)
            store = os.path.join(tmp, "trust.jsonl")
            trust.TrustRegistry(store).trust("acme", idt.public_key_b64, pq_pubkey=signer.public_key_b64)
            mallory = signing.Identity("acme"); pack.sign_pack(pp, mallory); pack.pq_cosign(pp, signer)
            v = verify_pack(pp, trust_store=store)
            self.assertFalse(v["valid"]); self.assertIsNone(v["pq_protected"]); self.assertFalse(v["authenticated"])
            self.assertEqual(self._layer(v, "trusted-signer")["status"], "FAIL")
            v = verify_pack(pp, trust_store=store, require_pq=True)
            self.assertIs(v["pq_protected"], False); self.assertFalse(v["authenticated"])
            # a revoked hybrid signer: never pq-protected through the registry, never authenticated
            pack.sign_pack(pp, idt); pack.pq_cosign(pp, signer)
            trust.TrustRegistry(store).revoke("acme", "compromised")
            v = verify_pack(pp, trust_store=store, require_pq=True)
            self.assertFalse(v["valid"]); self.assertIs(v["pq_protected"], False); self.assertFalse(v["authenticated"])

    def test_trust_store_replayed_only_from_a_strict_verified_chain(self):
        """A broken chain is 'trusted-signer FAIL', not a crash; a line with a duplicated 'pubkey' key (last-wins
        for a lenient parser, self_hash made consistent) is refused, never a pin."""
        with tempfile.TemporaryDirectory() as tmp:
            pp, idt, signer = self._hybrid(tmp)
            store = os.path.join(tmp, "trust.jsonl"); trust.TrustRegistry(store).trust("acme", idt.public_key_b64, pq_pubkey=signer.public_key_b64)
            good = open(store).read()
            ln = json.loads(good.splitlines()[0]); ln["ts"] = "1999-01-01T00:00:00Z"; open(store, "w").write(json.dumps(ln, separators=(",", ":")) + "\n")
            v = verify_pack(pp, trust_store=store, require_pq=True)
            self.assertFalse(v["valid"]); self.assertFalse(v["authenticated"]); self.assertIs(v["pq_protected"], False)
            self.assertIn("trust store", self._layer(v, "trusted-signer")["detail"])
            with self.assertRaises(ValueError):
                trust.TrustRegistry(store)
            mallory = signing.Identity("acme")
            txt = good.replace('"pubkey":"' + idt.public_key_b64 + '"', '"pubkey":"' + idt.public_key_b64 + '","pubkey":"' + mallory.public_key_b64 + '"', 1)
            e = json.loads(txt); e2 = {k: v for k, v in e.items() if k != "self_hash"}
            import hashlib as _h; fixed = _h.sha256(json.dumps(e2, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            open(store, "w").write(txt.replace(json.loads(good)["self_hash"], fixed))
            pack.sign_pack(pp, mallory); pack.pq_cosign(pp, signer)
            v = verify_pack(pp, trust_store=store)
            self.assertFalse(v["authenticated"]); self.assertEqual(self._layer(v, "trusted-signer")["status"], "FAIL")

    def test_rotation_keeps_the_pq_pin_unless_dropped_and_keys_are_validated(self):
        with tempfile.TemporaryDirectory() as tmp:
            pp, idt, signer = self._hybrid(tmp); K = signer.public_key_b64
            store = os.path.join(tmp, "trust.jsonl"); tr = trust.TrustRegistry(store)
            old = signing.Identity("acme"); tr.trust("acme", old.public_key_b64, pq_pubkey=K)
            r = tr.rotate("acme", idt.public_key_b64)                                                    # classical-only rotation
            self.assertTrue(r["pq_pubkey_kept"]); self.assertEqual(tr.pq_pubkey("acme"), K)
            self.assertEqual(trust.TrustRegistry(store).pq_pubkey("acme"), K)                            # and on replay (recorded)
            self.assertEqual(json.loads(open(store).read().splitlines()[-1])["data"]["pq_pubkey"], K)
            self.assertIs(verify_pack(pp, trust_store=store, require_pq=True)["pq_protected"], True)
            tr.rotate("acme", idt.public_key_b64, drop_pq=True)
            self.assertIsNone(tr.pq_pubkey("acme")); self.assertIsNone(trust.TrustRegistry(store).pq_pubkey("acme"))
            self.assertIs(verify_pack(pp, trust_store=store, require_pq=True)["pq_protected"], False)
            for bad in ("", " x", 5, b"k"):
                with self.assertRaises(ValueError):
                    tr.trust("bob", idt.public_key_b64, pq_pubkey=bad)
            with self.assertRaises(ValueError):
                tr.trust("bob", "")

    def test_kat_gate_covers_the_registered_empty_context_function(self):
        """The registered verifier (empty context) must itself pass a NIST known answer: two ACVP sigGen ML-DSA-65
        external/pure signatures with the EMPTY context ship in the vector file; the with-context sigVer vectors are
        bound by (key, signature, message). A gate without an empty-context vector refuses to register."""
        kat = self.m.load_kat()
        empty = [v for v in kat if not v["context_hex"]]
        self.assertGreaterEqual(len(empty), 2); self.assertGreaterEqual(len(kat) - len(empty), 3)
        from omega_evidence.pqbackends import gate
        self.assertTrue(gate.run_kat(self.m.verify_fn, empty)["passed"])
        for v in empty:                                                                                   # and a context breaks them
            self.assertFalse(self.m._kat_verify(v["public"], v["signature"], bytes.fromhex(v["message_hex"]), "00"))
        r = self.m.try_load(); self.assertTrue(r["registered"]); self.assertIn("2 with the empty context", r["reason"])
        with unittest.mock.patch.object(self.m, "load_kat", lambda: [v for v in kat if v["context_hex"]]):
            self.assertFalse(self.m.try_load()["registered"])

    def test_pq_cosign_recomputes_the_digest_from_the_pack_body(self):
        with tempfile.TemporaryDirectory() as tmp:
            pp, idt, signer = self._hybrid(tmp)
            body = json.load(open(pp)); body["x"] = 2; json.dump(body, open(pp, "w"))                      # stale pack_sha3 + sidecar
            with self.assertRaises(RuntimeError):
                pack.pq_cosign(pp, signer)

    def test_spki_parse_is_structural(self):
        from cryptography.hazmat.primitives import serialization as ser
        sk = self.m._mldsa().MLDSA65PrivateKey.generate(); pk = sk.public_key()
        spki = pk.public_bytes(ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo)
        self.assertEqual(self.m._mldsa65_raw_from_spki(spki), pk.public_bytes_raw())
        # the key bytes themselves are opaque (any 1952 bytes are a well-formed ML-DSA-65 public key): what the
        # structural parse adds over the old byte-offset check is the FRAMING — same length, OID still in the first
        # 32 bytes, unused-bits byte still 0, but the BIT STRING tag (offset 17) replaced: refused now, accepted before
        bad = bytearray(spki); bad[17] = 0x04                                                             # OCTET STRING, not BIT STRING
        self.assertEqual(len(bad), self.m.MLDSA65_SPKI_LEN); self.assertIn(self.m.MLDSA65_SPKI_OID, bytes(bad[:32])); self.assertEqual(bad[-1953], 0)
        with self.assertRaises(RuntimeError):
            self.m._mldsa65_raw_from_spki(bytes(bad))
        with self.assertRaises(RuntimeError):
            self.m._mldsa65_raw_from_spki(spki[:-1])

    # ── council 16/09 r2 (five minds incl. Gemini Pro) ────────────────────────────────────────────────────────
    def test_authenticated_requires_integrity(self):
        """Body mutated after signing, pack_sha3 and sidecar intact: valid false AND authenticated false."""
        with tempfile.TemporaryDirectory() as tmp:
            pp, idt, signer = self._hybrid(tmp)
            store = os.path.join(tmp, "trust.jsonl"); trust.TrustRegistry(store).trust("acme", idt.public_key_b64, pq_pubkey=signer.public_key_b64)
            body = json.load(open(pp)); body["x"] = 2; json.dump(body, open(pp, "w"))
            v = verify_pack(pp, trust_store=store, require_pq=True)
            self.assertFalse(v["valid"]); self.assertFalse(v["authenticated"])
            self.assertEqual(self._layer(v, "trusted-signer")["status"], "PASS")                       # identity held, content did not

    def test_signer_id_must_be_a_non_empty_string(self):
        with tempfile.TemporaryDirectory() as tmp:
            pp, idt, signer = self._hybrid(tmp)
            store = os.path.join(tmp, "trust.jsonl"); trust.TrustRegistry(store).trust("acme", idt.public_key_b64)
            sp = pp[:-5] + ".sig.json"; side = json.load(open(sp))
            for bad in (["acme"], "", 5, None):
                sd = dict(side); sd["signer_id"] = bad; json.dump(sd, open(sp, "w"))
                v = verify_pack(pp, trust_store=store)
                self.assertEqual(self._layer(v, "producer-signature")["status"], "FAIL"); self.assertFalse(v["authenticated"])
            json.dump({k: v for k, v in side.items() if k != "signer_id"}, open(sp, "w"))
            v = verify_pack(pp, trust_store=store); self.assertEqual(self._layer(v, "producer-signature")["status"], "FAIL")
            os.chmod(sp, 0)                                                                              # unreadable: FAIL, not a crash
            try:
                v = verify_pack(pp, trust_store=store); self.assertEqual(self._layer(v, "producer-signature")["status"], "FAIL")
            finally:
                os.chmod(sp, 0o600)

    def test_trust_store_malformed_records_are_a_broken_store(self):
        from omega_evidence.ledger import _hash_entry
        with tempfile.TemporaryDirectory() as tmp:
            pp, idt, signer = self._hybrid(tmp)
            store = os.path.join(tmp, "trust.jsonl"); trust.TrustRegistry(store).trust("acme", idt.public_key_b64, pq_pubkey=signer.public_key_b64)
            good = json.loads(open(store).read().splitlines()[0])
            for edit in (lambda e: e.__setitem__("data", [1]), lambda e: e["data"].__setitem__("signer_id", ["acme"]),
                         lambda e: e["data"].__setitem__("pubkey", 5), lambda e: e["data"].__setitem__("pq_pubkey", "")):
                e = json.loads(json.dumps(good)); edit(e); e["self_hash"] = _hash_entry(e)
                open(store, "w").write(json.dumps(e, separators=(",", ":")) + "\n")
                with self.assertRaises(ValueError):
                    trust.TrustRegistry(store)
                v = verify_pack(pp, trust_store=store, require_pq=True)
                self.assertFalse(v["valid"]); self.assertFalse(v["authenticated"]); self.assertIs(v["pq_protected"], False)
                self.assertIn("trust store", self._layer(v, "trusted-signer")["detail"])

    def test_rotate_after_revocation_decides_the_pq_key_explicitly(self):
        with tempfile.TemporaryDirectory() as tmp:
            pp, idt, signer = self._hybrid(tmp); K = signer.public_key_b64
            store = os.path.join(tmp, "trust.jsonl"); tr = trust.TrustRegistry(store)
            tr.trust("acme", idt.public_key_b64, pq_pubkey=K); tr.revoke("acme", "HSM breach")
            with self.assertRaises(ValueError):                                                          # no silent resurrection
                tr.rotate("acme", signing.Identity("acme").public_key_b64)
            self.assertIsNone(tr.pq_pubkey("acme"))
            with self.assertRaises(ValueError):                                                          # contradictory arguments
                tr.rotate("acme", idt.public_key_b64, pq_pubkey=K, drop_pq=True)
            tr.rotate("acme", idt.public_key_b64, drop_pq=True); self.assertIsNone(tr.pq_pubkey("acme"))
            self.assertIs(verify_pack(pp, trust_store=store, require_pq=True)["pq_protected"], False)
            K2 = self.m.MlDsaFileSigner.keygen(os.path.join(tmp, "n.key"))["public_key_b64"]
            tr.rotate("acme", idt.public_key_b64, pq_pubkey=K2); self.assertEqual(trust.TrustRegistry(store).pq_pubkey("acme"), K2)

    def test_kat_context_binding_survives_the_gates_negative(self):
        """The with-context vectors are bound by (key, message): the gate's tampered-signature negative still runs with
        the right context; a duplicated (key, message) pair in the vector file is refused."""
        kat = self.m.load_kat(); ctxed = [v for v in kat if v["context_hex"]]
        seen = {}
        def spy(p, s, m):
            seen[(p, m.hex())] = seen.get((p, m.hex()), 0) + 1
            return self.m._kat_verify(p, s, m, next(v["context_hex"] for v in ctxed if v["public"] == p and v["message_hex"] == m.hex()))
        from omega_evidence.pqbackends import gate
        self.assertTrue(gate.run_kat(spy, ctxed)["passed"]); self.assertTrue(all(n == 2 for n in seen.values()))   # positive + negative, both with ctx
        with unittest.mock.patch.object(self.m, "KAT_FILE", os.path.join(tempfile.gettempdir(), "dup_kat.txt")):
            ln = [l for l in open(os.path.join(os.path.dirname(self.m.__file__), "vectors", "acvp_mldsa65_sigver.txt")) if not l.startswith("#") and l.strip()][0]
            open(self.m.KAT_FILE, "w").write(ln + ln)
            with self.assertRaises(ValueError):
                self.m.load_kat()

    def test_try_load_never_crashes_on_a_broken_vector_file(self):
        with unittest.mock.patch.object(self.m, "KAT_FILE", os.path.join(tempfile.gettempdir(), "no_such_kat.txt")):
            r = self.m.try_load(); self.assertFalse(r["registered"]); self.assertIn("unusable", r["reason"])

    def test_timestamp_sidecar_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            pp, idt, signer = self._hybrid(tmp)
            open(pp[:-5] + ".tsr.json", "w").write("[1]")
            v = verify_pack(pp); self.assertEqual(self._layer(v, "rfc3161")["status"], "FAIL"); self.assertFalse(v["valid"])

if __name__ == "__main__":
    unittest.main(verbosity=2)
