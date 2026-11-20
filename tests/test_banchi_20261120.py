# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""Defects found on 0.12.0 by two review benches on 20 November 2026 and still present on 0.13.0 (6176841), each
reproduced before it was fixed.

(1) `pack.sign_pack` signed, and `pack.anchor_pack` recorded, the DECLARED `pack_sha3` as read: a pack file whose field
    named another pack's body got the producer's signature (or the ledger anchor) over that other pack.
(2) `TrustRegistry` replay (and the Go, Java and Node verifiers) took a `trust` line for an already trusted signer with
    ANOTHER key as the new key — `trust()` refuses it live — and a `trust` line without `pq_pubkey` dropped the pinned
    post-quantum key, which `trust()` leaves in place.
(3) `interop.dsse.from_dsse` read any `_type` as a Statement v1, handed back the predicate of any `predicateType` as
    `pack`, and took the last of two members with one name.
(4) `preservation.verify_evidence_record` read a `time_source` other than rfc3161 / asserted (or none) as asserted.
    The class of (1) in the same module: `build_evidence_record`, `renew_hash_tree` and the `data-objects-bound` layer
    of `verify_evidence_record` took the DECLARED `pack_sha3` of each pack file (found on 35e8c40).
(5) `interop.aat.verify_chain` left `agent_kid` / `recorder_kid` / `tombstone_kids` uncompared on unsigned records (ok
    True), and its RFC 3339 pattern took any Unicode decimal digit.

Positive control: on 6176841 the tests whose docstring says "fails on 6176841" fail; the others hold what must not
change and pass there too.
"""
import base64
import copy
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unicodedata
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)

from omega_evidence import agent, pack as P, preservation as PR, trust as TR  # noqa: E402
from omega_evidence.ledger import Ledger  # noqa: E402
from omega_evidence.signing import Identity  # noqa: E402
from omega_evidence.verifier import verify_pack  # noqa: E402
from omega_evidence.interop import aat, dsse  # noqa: E402

SCOPE = "test only, NOT a conformity assessment"
NODE = shutil.which("node")
JS = os.path.join(ROOT, "verifiers", "js", "oeverify.mjs")


def _tmp(test):
    d = tempfile.mkdtemp(prefix="oe-banchi-")
    test.addCleanup(shutil.rmtree, d, ignore_errors=True)
    return d


def _pack(d, name, body=None):
    p = os.path.join(d, name + ".json")
    P.write_pack(p, P.build_pack("x", body if body is not None else {"amount": "10"}, SCOPE))
    return p


def _rj(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _wj(path, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f)


def _wt(path, text):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def _layer(r, name):
    return next((x for x in r["layers"] if x["layer"] == name), {})


class TestSignAndAnchorTheBodysDigest(unittest.TestCase):
    def test_intact_pack_is_signed_and_anchored_as_before(self):
        d = _tmp(self)
        p = _pack(d, "a")
        side = P.sign_pack(p, Identity("producer"))
        e = P.anchor_pack(p, os.path.join(d, "a.ledger.jsonl"))
        digest = _rj(p)["pack_sha3"]
        self.assertEqual((side["signed_pack_sha3"], e["anchored_pack_sha3"]), (digest, digest))
        r = verify_pack(p)   # signed and anchored: PASS; `authenticated` needs a trust registry (Unreleased, Decision 1)
        self.assertEqual((r["valid"], next(ly for ly in r["layers"] if ly["layer"] == "producer-signature")["status"]), (True, "PASS"))

    def test_declared_digest_of_another_pack_is_neither_signed_nor_anchored(self):
        """fails on 6176841: the other pack's digest was signed and anchored"""
        d = _tmp(self)
        a, b = _pack(d, "a"), _pack(d, "b", {"amount": "999999"})
        pa = _rj(a); pa["pack_sha3"] = _rj(b)["pack_sha3"]; _wj(a, pa)
        led = os.path.join(d, "a.ledger.jsonl")
        with self.assertRaisesRegex(ValueError, "not the digest of the pack body"):
            P.sign_pack(a, Identity("producer"))
        with self.assertRaisesRegex(ValueError, "not the digest of the pack body"):
            P.anchor_pack(a, led)
        self.assertFalse(os.path.exists(a[:-5] + ".sig.json"))
        self.assertFalse(os.path.exists(led))

    def test_generated_mismatches_are_never_signed(self):
        """fails on 6176841: every generated mismatch was signed. Body changed without rehash, digest respelled (upper case,
        cut, padded, another pack's), field removed or of another type, a new top-level key: each is refused, nothing is
        written; the untouched pack (control) is signed in every round."""
        rng = random.Random(20261120)
        d = _tmp(self)
        other = _rj(_pack(d, "other", {"amount": "1"}))["pack_sha3"]
        muts = [lambda x: x.__setitem__("amount", "11"), lambda x: x.__setitem__("pack_sha3", x["pack_sha3"].upper()),
                lambda x: x.__setitem__("pack_sha3", x["pack_sha3"][:-1]), lambda x: x.__setitem__("pack_sha3", x["pack_sha3"] + "0"),
                lambda x: x.__setitem__("pack_sha3", other), lambda x: x.pop("pack_sha3"),
                lambda x: x.__setitem__("pack_sha3", None), lambda x: x.__setitem__("pack_sha3", 7),
                lambda x: x.__setitem__("x_new_%d" % rng.randrange(10**6), rng.choice(["", 0, [], {}, "v"])),
                lambda x: x.__setitem__("honest_scope", x["honest_scope"] + " "), lambda x: x.pop("kind")]
        for n in range(60):
            p = _pack(d, f"g{n}", {"amount": str(rng.randrange(10**9))})
            P.sign_pack(p, Identity("producer"))                         # control
            os.remove(p[:-5] + ".sig.json")
            x = _rj(p)
            rng.choice(muts)(x)
            _wj(p, x)
            with self.subTest(n=n):
                with self.assertRaises(ValueError):
                    P.sign_pack(p, Identity("producer"))
                self.assertFalse(os.path.exists(p[:-5] + ".sig.json"))

    def test_a_body_the_verifier_reads_is_signed_like_the_verifier_hashes_it(self):
        """the digest is computed as the verifier computes it (text side): a pack whose body carries the canonical module's
        reserved tag key, written as text with the digest the verifier computes, verifies — and is signed (control of the
        reading side: a producer-side hash would refuse it)"""
        from omega_evidence import canonical
        d = _tmp(self)
        p = os.path.join(d, "t.json")
        body = {"kind": "x", "generated_utc": "2026-11-20T00:00:00+00:00", "honest_scope": SCOPE,
                "v": {canonical._TAG: "Decimal", "value": "1.5"}}
        body["pack_sha3"] = canonical.sha3(body, from_text=True)
        _wt(p, json.dumps(body))
        self.assertEqual(_layer(verify_pack(p), "pack-sha3")["status"], "PASS")
        P.sign_pack(p, Identity("producer"))
        r = verify_pack(p)   # signed and anchored: PASS; `authenticated` needs a trust registry (Unreleased, Decision 1)
        self.assertEqual((r["valid"], next(ly for ly in r["layers"] if ly["layer"] == "producer-signature")["status"]), (True, "PASS"))

    def test_a_pack_the_verifier_refuses_to_read_is_not_signed(self):
        """the file is read as the verifier reads it: a member name twice, or a float, is refused by the verifier and
        is not signed either, although the declared digest is the one a last-wins reading would compute"""
        from omega_evidence import canonical
        d = _tmp(self)
        base = {"kind": "x", "generated_utc": "2026-11-20T00:00:00+00:00", "honest_scope": SCOPE}
        digest = canonical.sha3(dict(base, a=2))
        texts = {"dup": json.dumps(dict(base, a=1))[:-1] + ', "a": 2, "pack_sha3": "%s"}' % digest,
                 "float": json.dumps(dict(base, a=1.5, pack_sha3=digest))}
        for name, text in texts.items():
            p = os.path.join(d, name + ".json")
            _wt(p, text)
            with self.subTest(case=name):
                self.assertNotEqual(_layer(verify_pack(p), "pack-sha3").get("status"), "PASS")
                with self.assertRaisesRegex(ValueError, "cannot be read as the verifier reads it"):
                    P.sign_pack(p, Identity("producer"))
                with self.assertRaisesRegex(ValueError, "cannot be read as the verifier reads it"):
                    P.anchor_pack(p, os.path.join(d, name + ".ledger.jsonl"))
                self.assertFalse(os.path.exists(p[:-5] + ".sig.json"))

    def test_a_file_that_is_not_a_pack_object_is_a_value_error(self):
        """fails on 6176841: "[]" raised AttributeError, the float and the duplicate key were signed"""
        d = _tmp(self)
        for text in ("[]", "{", '{"a": 1.5, "pack_sha3": "x"}', '{"a": 1, "a": 2}', ""):
            p = os.path.join(d, "n.json"); _wt(p, text)
            with self.subTest(text=text), self.assertRaises(ValueError):
                P.sign_pack(p, Identity("producer"))


class TestTrustReplayChangesNoKey(unittest.TestCase):
    def _store(self, d, *lines, pq=None):
        real = Identity("bank")
        ts = os.path.join(d, "trust.jsonl")
        TR.TrustRegistry(ts).trust("bank", real.public_key_b64, pq_pubkey=pq)
        for ln in lines:
            Ledger(ts).append(dict({"action": "trust", "signer_id": "bank", "ts": "2026-11-20T00:00:00+00:00"}, **ln))
        return ts, real

    def test_trust_line_with_another_key_is_a_broken_store(self):
        """fails on 6176841: the appended key became the trusted one, trusted-signer PASS, authenticated True"""
        d = _tmp(self)
        evil = Identity("bank")
        ts, _ = self._store(d, {"pubkey": evil.public_key_b64})
        with self.assertRaisesRegex(ValueError, "changes the key"):
            TR.TrustRegistry(ts)
        p = _pack(d, "p"); P.sign_pack(p, evil)
        r = verify_pack(p, trust_store=ts)
        self.assertEqual(_layer(r, "trusted-signer")["status"], "FAIL")
        self.assertIn("broken", _layer(r, "trusted-signer")["detail"])
        self.assertFalse(r["authenticated"])

    def test_live_trust_refuses_the_same_line(self):   # holds on 6176841 too: the replay now agrees with it
        d = _tmp(self)
        ts, _ = self._store(d)
        with self.assertRaisesRegex(ValueError, "different key"):
            TR.TrustRegistry(ts).trust("bank", Identity("bank").public_key_b64)

    def test_the_same_key_again_is_read_as_before(self):   # control, passes on 6176841 too
        d = _tmp(self)
        real = Identity("bank")
        ts = os.path.join(d, "trust.jsonl")
        TR.TrustRegistry(ts).trust("bank", real.public_key_b64)
        Ledger(ts).append({"action": "trust", "signer_id": "bank", "pubkey": real.public_key_b64, "ts": "2026-11-20T00:00:00+00:00"})
        p = _pack(d, "p"); P.sign_pack(p, real)
        self.assertTrue(verify_pack(p, trust_store=ts)["authenticated"])

    def test_a_line_without_pq_keeps_the_pinned_pq_key_and_another_pq_is_broken(self):
        """fails on 6176841: the line without pq_pubkey dropped the pin; a line with another pq_pubkey replaced it"""
        d = _tmp(self)
        real = Identity("bank")
        ts = os.path.join(d, "trust.jsonl")
        TR.TrustRegistry(ts).trust("bank", real.public_key_b64, pq_pubkey="UFEtS0VZLTE=")
        Ledger(ts).append({"action": "trust", "signer_id": "bank", "pubkey": real.public_key_b64, "ts": "2026-11-20T00:00:00+00:00"})
        self.assertEqual(TR.TrustRegistry(ts).pq_pubkey("bank"), "UFEtS0VZLTE=")
        Ledger(ts).append({"action": "trust", "signer_id": "bank", "pubkey": real.public_key_b64, "pq_pubkey": "UFEtS0VZLTI=",
                           "ts": "2026-11-20T00:00:00+00:00"})
        with self.assertRaisesRegex(ValueError, "post-quantum key"):
            TR.TrustRegistry(ts)

    def test_rotate_revoke_and_the_api_sequences_replay_to_the_live_state(self):
        """fails on 6176841: the appended key replaced the trusted one. Generated: 200 sequences of trust / rotate / revoke
        through the API; the replayed registry equals the live one, and a trust line with another key appended after them
        is always a broken store"""
        rng = random.Random(7)
        for n in range(200):
            d = _tmp(self)
            ts = os.path.join(d, "t.jsonl")
            live = TR.TrustRegistry(ts)
            keys = [Identity("k").public_key_b64 for _ in range(3)]
            for _ in range(rng.randrange(1, 8)):
                op, sid, k = rng.choice(["trust", "rotate", "revoke"]), rng.choice(["a", "b"]), rng.choice(keys)
                try:
                    {"trust": lambda: live.trust(sid, k), "rotate": lambda: live.rotate(sid, k),
                     "revoke": lambda: live.revoke(sid, "r")}[op]()
                except (ValueError, KeyError):   # what the API refuses is not written
                    pass
            again = TR.TrustRegistry(ts)
            for sid in ("a", "b"):
                self.assertEqual(again.status(sid), live.status(sid), (n, sid))
            trusted = [s for s in ("a", "b") if live.status(s).get("known") and not live.status(s).get("revoked")]
            if trusted:
                sid = rng.choice(trusted)
                Ledger(ts).append({"action": "trust", "signer_id": sid, "pubkey": Identity("x").public_key_b64, "ts": "2026-11-20T00:00:00+00:00"})
                with self.subTest(n=n), self.assertRaisesRegex(ValueError, "changes the key"):
                    TR.TrustRegistry(ts)

    def _verifier_says(self, cmd, pack, ts):
        r = subprocess.run(cmd + ["--trust-store", ts, pack], capture_output=True, text=True, timeout=120)
        return r.returncode, json.loads(r.stdout)

    def _other_verifiers(self):
        out = []
        if NODE:
            out.append(("node", [NODE, JS]))
        if os.environ.get("OEVERIFY_GO"):
            out.append(("go", [os.environ["OEVERIFY_GO"]]))
        if os.environ.get("OEVERIFY_JAVA"):
            out.append(("java", os.environ["OEVERIFY_JAVA"].split()))
        return out

    def test_the_other_verifiers_agree(self):
        """fails on 6176841 (Node always; Go and Java with OEVERIFY_GO / OEVERIFY_JAVA): verdict PASS with the appended key"""
        vs = self._other_verifiers()
        if not vs:
            self.skipTest("no node, no OEVERIFY_GO, no OEVERIFY_JAVA")
        d = _tmp(self)
        evil = Identity("bank")
        ts, real = self._store(d, {"pubkey": evil.public_key_b64})
        p = _pack(d, "p"); P.sign_pack(p, evil)
        q = _pack(d, "q"); P.sign_pack(q, real)
        ts2 = os.path.join(d, "same.jsonl")
        TR.TrustRegistry(ts2).trust("bank", real.public_key_b64)
        Ledger(ts2).append({"action": "trust", "signer_id": "bank", "pubkey": real.public_key_b64, "ts": "2026-11-20T00:00:00+00:00"})
        stores = []
        for pq_line in ("UFEtS0VZLTI=", None):
            t = os.path.join(d, f"pq{len(stores)}.jsonl")
            TR.TrustRegistry(t).trust("bank", real.public_key_b64, pq_pubkey="UFEtS0VZLTE=")
            Ledger(t).append(dict({"action": "trust", "signer_id": "bank", "pubkey": real.public_key_b64, "ts": "2026-11-20T00:00:00+00:00"},
                                  **({"pq_pubkey": pq_line} if pq_line else {})))
            stores.append(t)
        ts3, ts4 = stores
        ts5 = os.path.join(d, "plain.jsonl")
        TR.TrustRegistry(ts5).trust("bank", real.public_key_b64)
        for name, cmd in [("python", [sys.executable, "-I", "-c", "import sys; sys.path.insert(0, sys.argv.pop(1)); from omega_evidence.verifier "
                                                "import main; raise SystemExit(main(sys.argv[1:]))", ROOT])] + vs:
            with self.subTest(verifier=name):
                rc, out = self._verifier_says(cmd, p, ts)
                self.assertEqual((rc, out["verdict"], out["authenticated"]), (1, "FAIL", False))
                rc, out = self._verifier_says(cmd, q, ts2)                       # control: the same key twice
                self.assertEqual((rc, out["verdict"], out["authenticated"]), (0, "PASS", True))
                rc, out = self._verifier_says(cmd, q, ts3)                       # another PQ key in a trust line: broken
                self.assertEqual((rc, out["verdict"], out["authenticated"]), (1, "FAIL", False))
                rc, out = self._verifier_says(cmd, q, ts4)                       # no pq_pubkey: the pin stays, and a pinned
                self.assertEqual((rc, out["verdict"], out["pq_protected"]), (1, "FAIL", False))   # PQ layer is then required
                rc, out = self._verifier_says(cmd, q, ts5)                       # control: no pin, classical pack
                self.assertEqual((rc, out["verdict"]), (0, "PASS"))


class TestDsseStatement(unittest.TestCase):
    def setUp(self):
        self.i = Identity("anyone")

    def _env(self, payload: bytes):
        return {"payload": base64.b64encode(payload).decode(), "payloadType": dsse.PAYLOAD_TYPE,
                "signatures": [{"keyid": "", "sig": self.i.sign(dsse.pae(dsse.PAYLOAD_TYPE, payload))}]}

    def _from(self, payload: bytes):
        return dsse.from_dsse(self._env(payload), public_key_b64=self.i.public_key_b64)

    def test_own_statement_verifies_as_before(self):   # control, passes on 6176841 too
        pk = {"kind": "x", "pack_sha3": "0" * 64}
        r = dsse.from_dsse(dsse.to_dsse(pk, self.i), public_key_b64=self.i.public_key_b64)
        self.assertIs(r["verified"], True)
        self.assertEqual(r["pack"], pk)

    def test_type_other_than_statement_v1_is_refused(self):
        """fails on 6176841: verified True for every one of these"""
        for t in ("https://in-toto.io/Statement/v0.1", "https://in-toto.io/Statement/v1 ", "x", "", None, 1, ["x"]):
            st = dsse.build_statement({"kind": "x", "pack_sha3": "0" * 64}); st["_type"] = t
            r = self._from(json.dumps(st).encode())
            with self.subTest(t=t):
                self.assertIs(r["verified"], False)
                self.assertIn("_type", r["error"])
        st = dsse.build_statement({"kind": "x", "pack_sha3": "0" * 64}); del st["_type"]
        self.assertIs(self._from(json.dumps(st).encode())["verified"], False)

    def test_what_the_docstring_says_is_not_read(self):   # holds on 6176841 too: the limit from_dsse states
        st = {"_type": dsse.STATEMENT_TYPE}
        r = self._from(json.dumps(st).encode())
        self.assertEqual((r["verified"], r["pack"]), (True, None))
        for more in ({"subject": 7}, {"subject": [{"name": "no digest"}]}, {"predicateType": 7}):
            self.assertIs(self._from(json.dumps(dict(st, **more)).encode())["verified"], True, more)
        r = self._from(json.dumps(dict(st, predicateType=dsse.PREDICATE_TYPE, predicate=7)).encode())
        self.assertEqual((r["verified"], r["pack"]), (True, 7))

    def test_pack_only_for_the_omega_predicate_type(self):
        """fails on 6176841: the predicate of an SLSA provenance came back as `pack`"""
        for pt in ("https://slsa.dev/provenance/v1", dsse.PREDICATE_TYPE + "x", None):
            st = dsse.build_statement({"kind": "x", "pack_sha3": "0" * 64})
            if pt is None:
                del st["predicateType"]
            else:
                st["predicateType"] = pt
            r = self._from(json.dumps(st).encode())
            with self.subTest(pt=pt):
                self.assertIs(r["verified"], True)
                self.assertIsNone(r["pack"])
                self.assertEqual(r["statement"]["predicate"], {"kind": "x", "pack_sha3": "0" * 64})

    def test_generated_duplicate_member_names_are_refused_at_every_level(self):
        """fails on 6176841: the last member won and the envelope verified. A member repeated at the top, in the predicate,
        in a subject and in a digest, with the same or another value: refused with the reason."""
        rng = random.Random(3)
        base = json.dumps(dsse.build_statement({"kind": "x", "pack_sha3": "0" * 64}), separators=(",", ":"))
        anchors = ['{"_type":', '"predicate":{', '"subject":[{', '"digest":{']
        for n in range(80):
            a = rng.choice(anchors)
            i = base.index(a) + len(a) - (len('"_type":') if a == '{"_type":' else 0)
            name = rng.choice(["_type", "kind", "name", "sha3-256", "predicateType", "x"])
            val = rng.choice(['"https://in-toto.io/Statement/v1"', '"y"', "1", "{}", "[]"])
            text = base[:i] + f'"{name}":{val},"{name}":{val},' + base[i:]
            r = self._from(text.encode())
            with self.subTest(n=n, text=text[:120]):
                self.assertIs(r["verified"], False)
                self.assertIn("appears twice", r["error"])


class TestPreservationTimeSource(unittest.TestCase):
    def test_only_rfc3161_or_asserted(self):
        """fails on 6176841 (except the two controls): any other time_source, or none, was an asserted SKIP, valid True"""
        d = _tmp(self)
        rec = PR.build_evidence_record([_pack(d, "p")])
        self.assertIs(PR.verify_evidence_record(rec)["valid"], True)                               # control: asserted
        for ts in ({"time_source": "bogus"}, {}, {"time_source": "RFC3161", "tsr_b64": "x"}, {"time_source": None},
                   {"time_source": 1}, {"time_source": "asserted "}, {"time_source": "Asserted"}):
            r2 = copy.deepcopy(rec)
            r2["archive_timestamps"][0]["timestamp"] = ts
            r2 = PR._finalize(r2)
            with self.subTest(ts=ts):
                r = PR.verify_evidence_record(r2)
                self.assertIs(r["valid"], False)
                self.assertEqual(_layer(r, "time[0]-source")["status"], "FAIL")
        r2 = PR.renew_timestamp(copy.deepcopy(rec))                                                # control: renewal
        self.assertIs(PR.verify_evidence_record(r2)["valid"], True)


class TestPreservationBindsTheBodysDigest(unittest.TestCase):
    """The class of (1) in `preservation` (measured on 35e8c40, where sign_pack and anchor_pack were already fixed)."""

    def _forged(self, d):
        a, b = _pack(d, "a"), _pack(d, "b", {"amount": "999999"})
        f = os.path.join(d, "f.json")
        pf = _rj(b); pf["pack_sha3"] = _rj(a)["pack_sha3"]; _wj(f, pf)      # the body of b under the digest of a
        return a, b, f

    def test_a_pack_under_another_packs_digest_is_not_bound_to_the_record(self):
        """fails on 6176841 and on 35e8c40: data-objects-bound PASS, "packs match the record's data objects" """
        d = _tmp(self)
        a, b, f = self._forged(d)
        rec = PR.build_evidence_record([a])
        self.assertEqual(_layer(PR.verify_evidence_record(rec, pack_paths=[a]), "data-objects-bound")["status"], "PASS")
        self.assertEqual(_layer(PR.verify_evidence_record(rec, pack_paths=[b]), "data-objects-bound")["status"], "FAIL")
        r = PR.verify_evidence_record(rec, pack_paths=[f])
        self.assertIs(r["valid"], False)
        self.assertEqual(_layer(r, "data-objects-bound")["status"], "FAIL")
        self.assertIn("not the digest of the pack body", _layer(r, "data-objects-bound")["detail"])

    def test_a_pack_under_another_packs_digest_is_neither_preserved_nor_renewed(self):
        """fails on 6176841 and on 35e8c40: the record carried the other pack's digest"""
        d = _tmp(self)
        a, b, f = self._forged(d)
        with self.assertRaisesRegex(ValueError, "not the digest of the pack body"):
            PR.build_evidence_record([f])
        rec = PR.build_evidence_record([a])
        with self.assertRaisesRegex(ValueError, "not the digest of the pack body"):
            PR.renew_hash_tree(rec, [f], "sha3_512")
        self.assertEqual(PR.renew_hash_tree(rec, [a], "sha3_512")["data_objects"], rec["data_objects"])   # control


def _chain(n_calls=2, close=True):
    d = tempfile.mkdtemp(prefix="oe-banchi-aat-")
    try:
        log = agent.AgentEvidenceLog(os.path.join(d, "agent.jsonl"), runtime_id="rt-1")
        for k in range(n_calls):
            log.record("bot-7", "sess-a", "tool_call", f"https://api.example/{k}", "rule-1", agent.Decision.ALLOW, agent.Outcome.EXECUTED)
        return next(iter(aat.from_omega(list(log._ledger.entries()), "1.0", close=close).values()))
    finally:
        shutil.rmtree(d, ignore_errors=True)


class TestAatPinsAndDigits(unittest.TestCase):
    def test_unsigned_chain_without_pins_is_as_before(self):   # control, passes on 6176841 too
        self.assertIs(aat.verify_chain(_chain())["ok"], True)

    def test_a_pin_on_an_unsigned_record_is_a_problem(self):
        """fails on 6176841: ok True with each pin never compared"""
        recs = _chain()
        recs[1] = aat.tombstone(recs[1], "GDPR art. 17", recs[1]["timestamp"])
        for kw in ({"agent_kid": "a" * 43}, {"recorder_kid": "b" * 43}, {"tombstone_kids": ["c" * 43]}):
            r = aat.verify_chain(recs, **kw)
            with self.subTest(kw=list(kw)):
                self.assertIs(r["ok"], False)
                self.assertTrue(any("while a signer was pinned" in p["why"] for p in r["problems"]))
        r = aat.verify_chain(_chain(), tombstone_kids=["c" * 43])    # no tombstone: tombstone_kids pins nothing here
        self.assertIs(r["ok"], True)

    def test_signed_chain_with_its_agent_pinned_is_ok(self):   # control, passes on 6176841 too
        try:
            priv, pub = aat.generate_p256_keypair()
        except Exception:  # noqa: BLE001 — no cryptography here
            self.skipTest("cryptography absent")
        d = tempfile.mkdtemp(prefix="oe-banchi-aat-"); self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        log = agent.AgentEvidenceLog(os.path.join(d, "agent.jsonl"), runtime_id="rt-1")
        log.record("bot-7", "sess-a", "tool_call", "https://api.example/x", "rule-1", agent.Decision.ALLOW, agent.Outcome.EXECUTED)
        recs = next(iter(aat.from_omega(list(log._ledger.entries()), "1.0", private_key_pem=priv, close=True).values()))
        r = aat.verify_chain(recs, pubkey_pem=pub, agent_kid=aat.p256_thumbprint(pub))
        self.assertIs(r["ok"], True, r["problems"])

    def test_every_unicode_decimal_digit_other_than_ascii_is_refused(self):
        """fails on 6176841: the pattern took every Nd digit; in a record timestamp and in deleted_at it then passed. All
        Unicode Nd characters (unicodedata of this Python), each at every one of the 17 digit positions of a timestamp
        with a three-digit fraction."""
        nd = [chr(c) for c in range(0x110000) if unicodedata.category(chr(c)) == "Nd" and not "0" <= chr(c) <= "9"]
        self.assertGreater(len(nd), 600)
        base = "2026-11-20T16:22:05.123Z"
        pos = [i for i, ch in enumerate(base) if ch.isdigit()]
        self.assertEqual(len(pos), 17)
        for ch in nd:
            for i in pos:
                t = base[:i] + ch + base[i + 1:]
                self.assertIsNone(aat._RFC3339.match(t), t)
        self.assertTrue(aat._RFC3339.match(base))                                                   # control
        recs = _chain(1, close=False)
        bad = "２０２６" + recs[1]["timestamp"][4:]
        tomb = aat.tombstone(recs[1], "GDPR art. 17", recs[1]["timestamp"])
        tomb["action_detail"]["deleted_at"] = bad
        r = aat.verify_chain([recs[0], tomb])
        self.assertTrue(any("deleted_at" in p["why"] for p in r["problems"]))
        r = aat.verify_chain([dict(recs[0], timestamp=bad)])
        self.assertTrue(any("timestamp is not RFC 3339" in p["why"] for p in r["problems"]))


if __name__ == "__main__":
    unittest.main()
