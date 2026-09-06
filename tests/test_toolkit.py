# Copyright 2026 Roberto Locatelli — Apache-2.0
"""End-to-end tests for the omega_evidence open toolkit.

Self-contained: imports only omega_evidence + stdlib. Positive and negative
controls for every property; a fabricated pack must not pass."""

import base64
import json
import os
import sys
import tempfile
import unittest
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
            v = verify_pack(pp, trust_store=store)
            pq = [l for l in v["layers"] if l["layer"] == "pq-signature"][0]
            self.assertEqual(pq["status"], "PASS")
            self.assertIn("pq-protected", pq["detail"])
            self.assertTrue(v["valid"])

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
            pq = [l for l in verify_pack(pp)["layers"] if l["layer"] == "pq-signature"][0]
            self.assertEqual(pq["status"], "PASS")

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
