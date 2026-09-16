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
    """draft-sharif-agent-audit-trail-00: export of an AgentEvidenceLog (one chain per session, genesis lifecycle
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
            self.assertTrue(any("6.1" in p["why"] for p in aat.verify_chain(recs[1:])["problems"]))
            mix = json.loads(json.dumps(recs)); mix[2]["session_id"] = aat._uuid4_from("other")
            self.assertTrue(any("one session" in p["why"] for p in aat.verify_chain(mix)["problems"]))
            tz = json.loads(json.dumps(recs)); tz[1]["timestamp"] = tz[1]["timestamp"].replace("Z", "+02:00")
            self.assertTrue(any("UTC" in p["why"] for p in aat.verify_chain(tz)["problems"]))
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
                 "parent_record_id": None, "prev_hash": None, "risk_score": 0.75}
            g2 = dict(g, record_id=aat._uuid4_from("g2"), action_type="decision", action_detail={"risk": 1e-5},
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

    def test_timestamp_sidecar_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            pp, idt, signer = self._hybrid(tmp)
            open(pp[:-5] + ".tsr.json", "w").write("[1]")
            v = verify_pack(pp); self.assertEqual(self._layer(v, "rfc3161")["status"], "FAIL"); self.assertFalse(v["valid"])

if __name__ == "__main__":
    unittest.main(verbosity=2)
