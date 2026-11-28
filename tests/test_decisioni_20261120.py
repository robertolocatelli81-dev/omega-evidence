# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""The six decisions of 20 November 2026 on behaviours that 0.13.0 documented and that two review benches flagged
(each measured on 404b60b before it was changed; the tests marked "fails on 404b60b" fail there).

(D1) `authenticated` was true for a signature by any key under any `signer_id` with no trust registry, and a trust
     registry given did not require a signature (no sidecar, or an unknown algorithm: exit 0).
(D2) The timestamp sidecar: any `tsr_b64` (text, or none) was a SKIP "token recorded", and `validation_material` was
     read as found (`cert_count: "lots"` printed as a count). Now the token's form and a closed material, FAIL.
(D3) `interop.dsse.from_dsse` verified an envelope with the key the envelope itself carries (`verified: True` for anyone's
     envelope), read neither `subject` nor `predicateType`, and `build_statement` wrote a declared `pack_sha3` as read.
(D4) `preservation`: an `asserted` time beside `tsa_ca_file` was a SKIP and the record valid; the Merkle root had no
     domain separation and duplicated an odd node. Now FAIL, and record version 2 with the RFC 6962 Merkle Tree Hash.
(D5) `sigstore.verify_bundle(tsa_ca_file=...)` on a bundle with no token, and `sdjwt.verify(expected_aud / expected_nonce)`
     on a credential without `cnf`, verified true without the proof the argument asks for.
(D6) `chip_registry`: an older signed update applied after a newer one put the old mapping back.
Also (21/11/2026): the differential oracle left its cases in /tmp when it stopped early, and test_toolkit left files.
"""
import base64
import hashlib
import itertools
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)

from omega_evidence import pack as P, trust as TR  # noqa: E402
from omega_evidence.ledger import Ledger  # noqa: E402
from omega_evidence.signing import Identity  # noqa: E402
from omega_evidence import verifier as V  # noqa: E402
from omega_evidence.verifier import verify_pack  # noqa: E402

SCOPE = "test only, NOT a conformity assessment"
NODE = shutil.which("node")
JS = os.path.join(ROOT, "verifiers", "js", "oeverify.mjs")


def _tmp(test):
    d = tempfile.mkdtemp(prefix="oe-decisioni-")
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


def _layer(r, name):
    return next((ly for ly in r["layers"] if ly["layer"] == name), {})


def _cli_verdicts(pack, flags):
    """(verdict, authenticated) from the Python CLI and, when Node is installed, from the Node verifier"""
    out = {}
    cmds = [("python", [sys.executable, "-I", "-c", "import sys; sys.path.insert(0, sys.argv[1]); "
                        "from omega_evidence.verifier import main; raise SystemExit(main(sys.argv[2:]))", ROOT])]
    if NODE:
        cmds.append(("node", [NODE, JS]))
    for name, cmd in cmds:
        r = subprocess.run(cmd + [pack] + flags, capture_output=True, text=True, timeout=120)
        j = json.loads(r.stdout)
        out[name] = (j["verdict"], j["authenticated"], r.returncode)
    return out


class D1AuthenticatedIsTrustedSigned(unittest.TestCase):
    def test_signed_without_registry_is_not_authenticated(self):
        """fails on 404b60b: authenticated True for a fresh key under signer_id 'bank-official', no registry"""
        d = _tmp(self)
        p = _pack(d, "p")
        P.sign_pack(p, Identity("bank-official"))
        r = verify_pack(p)
        self.assertTrue(r["valid"])                                     # the signed tier stays a PASS
        self.assertIs(r["authenticated"], False)
        self.assertIn("NOT checked against a registry", _layer(r, "authenticity")["detail"])
        self.assertIn("not covered", _layer(r, "producer-signature")["detail"])

    def test_trusted_signed_is_authenticated(self):
        """control (passes on 404b60b too): the registry binds signer_id to the key"""
        d = _tmp(self)
        p = _pack(d, "p")
        ident = Identity("bank")
        P.sign_pack(p, ident)
        ts = os.path.join(d, "trust.jsonl")
        TR.TrustRegistry(ts).trust("bank", ident.public_key_b64)
        r = verify_pack(p, trust_store=ts)
        self.assertEqual((r["valid"], r["authenticated"], _layer(r, "authenticity")["detail"]), (True, True, "trusted-signed"))

    def test_trust_store_requires_a_signature(self):
        """fails on 404b60b: an anchored unsigned pack, and an anchored pack with an unknown sig_alg, were valid beside a
        trust store"""
        d = _tmp(self)
        ts = os.path.join(d, "trust.jsonl")
        TR.TrustRegistry(ts).trust("bank", Identity("bank").public_key_b64)
        p = _pack(d, "unsigned")
        P.anchor_pack(p, p[:-5] + ".ledger.jsonl")
        self.assertTrue(verify_pack(p)["valid"])                         # control: the anchored tier without a store
        r = verify_pack(p, trust_store=ts)
        self.assertEqual((r["valid"], _layer(r, "producer-signature")["status"]), (False, "FAIL"))
        q = _pack(d, "alg")
        P.anchor_pack(q, q[:-5] + ".ledger.jsonl")
        P.sign_pack(q, Identity("x"))
        sp = q[:-5] + ".sig.json"
        side = _rj(sp)
        side["sig_alg"] = "x-unknown"
        _wj(sp, side)
        self.assertTrue(verify_pack(q)["valid"])                         # control: SKIP and the anchored tier, no store
        r = verify_pack(q, trust_store=ts)
        self.assertEqual((r["valid"], _layer(r, "producer-signature")["status"]), (False, "FAIL"))

    def test_generated_space(self):
        """every combination of signature (none / valid / unknown algorithm), anchor, registry (none / trusts the signer /
        trusts another key / revoked) and --require-signed: authenticated iff trusted-signed with an intact body; with a
        registry, valid only for trusted-signed. Python and, where installed, Node give the same pair."""
        d = _tmp(self)
        rnd = random.Random(20261120)
        ident, other = Identity("acme"), Identity("acme")
        stores = {"none": None}
        for nm in ("trusts", "other", "revoked"):
            stores[nm] = os.path.join(d, nm + ".jsonl")
        TR.TrustRegistry(stores["trusts"]).trust("acme", ident.public_key_b64)
        TR.TrustRegistry(stores["other"]).trust("acme", other.public_key_b64)
        rv = TR.TrustRegistry(stores["revoked"])
        rv.trust("acme", ident.public_key_b64)
        rv.revoke("acme", "test")
        n = 0
        for sig, anchored, store, req in itertools.product(("none", "valid", "unknown", "tampered"), (False, True),
                                                          stores, (False, True)):
            n += 1
            p = _pack(d, f"c{n}", {"amount": str(rnd.randrange(10 ** 6))})
            if anchored:
                P.anchor_pack(p, p[:-5] + ".ledger.jsonl")
            if sig != "none":
                P.sign_pack(p, ident)
            if sig == "unknown":
                sp = p[:-5] + ".sig.json"
                side = _rj(sp)
                side["sig_alg"] = rnd.choice(["rsa-pss", "x-" + str(rnd.randrange(999)), "ml-dsa-65"])
                _wj(sp, side)
            if sig == "tampered":
                body = _rj(p)
                body["amount"] = "tampered"
                _wj(p, body)
            r = verify_pack(p, trust_store=stores[store], require_signed=req)
            trusted_signed = sig == "valid" and store == "trusts"
            self.assertIs(r["authenticated"], trusted_signed, (sig, anchored, store, req))
            if store != "none" or req:
                self.assertIs(r["valid"], trusted_signed or (sig == "valid" and store == "none"), (sig, anchored, store, req))
            if n % 7 == 0:   # a sample through the CLIs (the four agree on the full set in verifiers/differential_oracle.py)
                flags = (["--trust-store", stores[store]] if stores[store] else []) + (["--require-signed"] if req else [])
                got = _cli_verdicts(p, flags)
                self.assertEqual(len(set(got.values())), 1, got)
                self.assertIs(got["python"][1], trusted_signed)
        self.assertEqual(n, 64)



def _der(n, extra=b""):
    """one DER SEQUENCE holding an OCTET STRING of n zero bytes (shortest length forms)"""
    def ln(k):
        if k < 0x80:
            return bytes([k])
        b = k.to_bytes((k.bit_length() + 7) // 8, "big")
        return bytes([0x80 | len(b)]) + b
    body = b"\x04" + ln(n) + b"\x00" * n
    return b"\x30" + ln(len(body)) + body + extra


class D2TimestampSidecarForm(unittest.TestCase):
    def _stamped(self, d, name, side_extra):
        p = _pack(d, name)
        P.anchor_pack(p, p[:-5] + ".ledger.jsonl")
        with open(p, "rb") as f:
            digest = hashlib.sha256(f.read()).hexdigest()
        side = {"digest_sha256": digest, "tsa": "x", "tsr_b64": base64.b64encode(_der(300)).decode(),
                "stamped_utc": "2026-11-20T00:00:00+00:00"}
        side.update(side_extra)
        side = {k: v for k, v in side.items() if v is not ...}
        _wj(p[:-5] + ".tsr.json", side)
        return verify_pack(p)

    def test_a_token_that_is_not_one_der_sequence_fails(self):
        """fails on 404b60b: "not a token at all!!" was rfc3161 SKIP and the anchored pack valid"""
        d = _tmp(self)
        self.assertTrue(self._stamped(d, "ok", {})["valid"])                        # control: a well-formed token
        for nm, tok in (("garbage", "not a token at all!!"), ("absent", ...), ("int", 7), ("empty", ""),
                        ("integer-not-sequence", base64.b64encode(b"\x02\x01\x00").decode()),
                        ("trailing", base64.b64encode(_der(10, b"\x00")).decode()),
                        ("indefinite", base64.b64encode(b"\x30\x80\x00\x00").decode())):
            with self.subTest(nm):
                r = self._stamped(d, nm, {"tsr_b64": tok})
                self.assertEqual((r["valid"], _layer(r, "rfc3161")["status"], _layer(r, "rfc3161")["detail"]),
                                 (False, "FAIL", V.TSR_FORM_MSG))

    def test_validation_material_is_closed(self):
        """fails on 404b60b: an unknown member and cert_count "lots" were read (ltv-material SKIP "captured: lots cert(s)")"""
        d = _tmp(self)
        cert = base64.b64encode(_der(200)).decode()
        good = {"available": True, "certs_der_b64": [cert], "cert_count": 1, "subjects": ["CN=t"], "crl_distribution_points": []}
        self.assertTrue(self._stamped(d, "good", {"validation_material": good})["valid"])
        self.assertTrue(self._stamped(d, "na", {"validation_material": {"available": False, "note": "openssl absent"}})["valid"])
        for nm, vm in (("open", {"available": True, "anything": {"evil": 1}, "cert_count": "lots"}),
                       ("lots", dict(good, cert_count="lots")), ("lie", dict(good, cert_count=5)),
                       ("not-der", dict(good, certs_der_b64=["AAAA"])), ("null", None)):
            with self.subTest(nm):
                r = self._stamped(d, nm, {"validation_material": vm})
                self.assertFalse(r["valid"])
                self.assertTrue(_layer(r, "rfc3161")["detail"].startswith("malformed sidecar: validation_material: "))

    def test_a_crl_entry_needs_a_url_string(self):
        """the type of `url` in a crls_b64 entry (a mutant that dropped it passed every Python suite, 21/11/2026)"""
        good = {"available": True, "certs_der_b64": [], "cert_count": 0, "subjects": [], "crl_distribution_points": []}
        self.assertEqual(V._vm_problem(dict(good, crls_b64=[{"url": "http://c", "error": "x"}])), "")          # control
        for url in (5, None, ["http://c"], True):
            for entry in ({"url": url, "error": "x"}, {"url": url, "crl_b64": "AAAA", "bytes": 3}):
                self.assertEqual(V._vm_problem(dict(good, crls_b64=[entry])),
                                 "a crls_b64 entry is not an object with a url string", entry)
        # chain_certificates is a count: zero is one, a negative number is not
        self.assertEqual(V._vm_problem(dict(good, crl_fetch={"fetched": True, "chain_certificates": 0})), "")
        self.assertEqual(V._vm_problem(dict(good, crl_fetch={"fetched": True, "chain_certificates": -1})),
                         "crl_fetch.chain_certificates is not a non-negative integer")

    def test_shapes_every_release_wrote(self):
        """the members extract_validation_material and stamp_pack wrote from 0.5.0 to 0.13.0 (read from each tag's source),
        and tokens of the size real TSAs return (4 645 and 4 894 bytes, three real sidecars measured 20/11/2026)"""
        for n in (4600, 4850):
            self.assertTrue(V._der_one_sequence(_der(n)))
        vm_old = {"available": True, "certs_der_b64": [], "cert_count": 0, "subjects": [], "crl_distribution_points": [],
                  "crls_b64": [{"url": "http://c", "crl_b64": "AAAA", "bytes": 3}, {"url": "http://d", "error": "URLError: x"}]}
        vm_new = dict(vm_old, token_verified=None, note="n", crl_fetch={"fetched": False, "reason": "r"}, tsa_transport="http")
        for vm in (vm_old, vm_new, {"available": False, "note": "could not extract token from TSR"}):
            self.assertEqual(V._vm_problem(vm), "", vm)

    def test_der_and_base64_generated(self):
        """random lengths: the exact encoding is accepted; one byte more or less, another tag, a long form for a short
        length, a leading zero length octet, five length octets, a non-canonical base64 spelling are refused"""
        rnd = random.Random(20261120)
        for _ in range(400):
            n = rnd.choice([rnd.randrange(0, 130), rnd.randrange(0, 70000)])
            b = _der(n)
            self.assertTrue(V._der_one_sequence(b), n)
            self.assertFalse(V._der_one_sequence(b + bytes([rnd.randrange(256)])))
            self.assertFalse(V._der_one_sequence(b[:-1]))
            self.assertFalse(V._der_one_sequence(bytes([rnd.choice([0x31, 0x04, 0x02, 0xA0])]) + b[1:]))
            t = base64.b64encode(b).decode()
            self.assertEqual(V._b64_canon(t), b)
            i = rnd.randrange(len(t))
            for bad in (t[:i] + " " + t[i:], t.replace("+", "-").replace("/", "_") if ("+" in t or "/" in t) else t + "\n",
                        t.rstrip("=") if t.endswith("=") else t + "==", t[:i] + "*" + t[i + 1:]):
                self.assertIsNone(V._b64_canon(bad), bad[:20])
        for short in range(0x80):
            self.assertFalse(V._der_one_sequence(b"\x30\x81" + bytes([short]) + b"\x00" * short))
        self.assertFalse(V._der_one_sequence(b"\x30\x82\x00\x81" + b"\x00" * 0x81))
        self.assertFalse(V._der_one_sequence(b"\x30\x85\x00\x00\x00\x00\x01\x00"))
        self.assertIsNone(V._b64_canon("MAMEAQB="))          # non-zero pad bits: decodes, does not re-encode the same
        # every cut of a header is a verdict, never an IndexError (30 80 alone: the indefinite form with nothing after it)
        for head in (b"", b"\x30", b"\x30\x80", b"\x30\x81", b"\x30\x82\x01", b"\x30\x84\x00\x00\x00", b"\x30\x80\x00\x00"):
            self.assertIs(V._der_one_sequence(head), False, head)

    def test_generated_validation_material_mutations(self):
        """each member of a good material replaced by a value of another type or removed, and a new member added at each
        level: refused, except where the closed list allows it (absent optional members, empty arrays, a string note)"""
        cert = base64.b64encode(_der(64)).decode()
        good = {"available": True, "certs_der_b64": [cert], "cert_count": 1, "subjects": ["CN=t"], "crl_distribution_points": ["u"],
                "crls_b64": [{"url": "u", "crl_b64": "AAAA", "bytes": 3}], "crl_fetch": {"fetched": True, "chain_certificates": 1},
                "token_verified": True, "note": "n", "tsa_transport": "https"}
        self.assertEqual(V._vm_problem(good), "")
        optional = {"crls_b64", "crl_fetch", "token_verified", "note", "tsa_transport"}
        others = [None, True, 0, -1, 2 ** 53 - 1, "", "x", [], [1], {}, {"x": 1}]
        n = 0
        for k in good:
            removed = {kk: vv for kk, vv in good.items() if kk != k}
            self.assertEqual(V._vm_problem(removed) == "", k in optional, k)
            for o in others:
                ok = V._vm_problem(dict(good, **{k: o})) == ""
                allowed = ((o == good[k] and type(o) is type(good[k]))
                           or (k == "token_verified" and (o is None or o is True))
                           or (k == "note" and isinstance(o, str))
                           or (k in ("crls_b64", "crl_distribution_points", "subjects") and o == []))
                self.assertEqual(ok, allowed, (k, o))
                n += 1
        for path in ((), ("crl_fetch",), ("crls_b64", 0)):
            bad = json.loads(json.dumps(good))
            tgt = bad
            for step in path:
                tgt = tgt[step]
            tgt["unexpected"] = 1
            self.assertNotEqual(V._vm_problem(bad), "", path)
        self.assertEqual(n, len(good) * len(others))


class D3DsseKeyOfTheCaller(unittest.TestCase):
    def setUp(self):
        from omega_evidence.interop import dsse
        self.dsse = dsse
        self.ident = Identity("producer")
        self.pk = P.build_pack("x", {"amount": "10"}, SCOPE)
        self.env = dsse.to_dsse(self.pk, self.ident)

    def test_no_caller_key_is_not_verified(self):
        """fails on 404b60b: verified True with the envelope's own publicKeyB64, no key given"""
        r = self.dsse.from_dsse(self.env)
        self.assertEqual((r["verified"], r["identity_verified"]), (False, False))
        self.assertIn("not one the caller trusts", r["error"])

    def test_embedded_key_only_when_asked_and_never_identity(self):
        r = self.dsse.from_dsse(self.env, allow_embedded_key=True)
        self.assertEqual((r["verified"], r["identity_verified"], r["pack"]), (True, False, self.pk))
        self.assertIn("integrity, not identity", r["key_source"])
        r = self.dsse.from_dsse(self.env, public_key_b64=self.ident.public_key_b64)
        self.assertEqual((r["verified"], r["identity_verified"]), (True, True))
        other = Identity("other")
        r = self.dsse.from_dsse(self.env, public_key_b64=other.public_key_b64)
        self.assertEqual((r["verified"], r["identity_verified"]), (False, False))

    def test_identity_verified_is_in_every_result(self):
        for env in (self.env, {}, [], dict(self.env, payloadType="x"), dict(self.env, signatures=[])):
            for kw in ({}, {"allow_embedded_key": True}, {"public_key_b64": self.ident.public_key_b64}):
                r = self.dsse.from_dsse(env, **kw)
                self.assertIn(r["identity_verified"], (True, False))
                self.assertTrue(r["identity_verified"] is False or (r["verified"] is True and "public_key_b64" in kw))

    def test_statement_members_are_read(self):
        """fails on 404b60b: a Statement with only _type, a subject without digest, a predicateType that is not a string
        were verified True; an OMEGA predicate that is not an object came back as `pack`"""
        import base64 as b64
        ok = {"_type": self.dsse.STATEMENT_TYPE, "subject": [{"name": "a", "digest": {"sha256": "00" * 32}}],
              "predicateType": self.dsse.PREDICATE_TYPE, "predicate": {"k": 1}}

        def check(st):
            payload = json.dumps(st).encode()
            env = {"payload": b64.b64encode(payload).decode(), "payloadType": self.dsse.PAYLOAD_TYPE,
                   "signatures": [{"sig": self.ident.sign(self.dsse.pae(self.dsse.PAYLOAD_TYPE, payload))}]}
            return self.dsse.from_dsse(env, public_key_b64=self.ident.public_key_b64)
        r = check(ok)
        self.assertEqual((r["verified"], r["pack"]), (True, {"k": 1}))                          # control
        for bad in ({"subject": 7}, {"subject": [{"name": "x"}]}, {"subject": [{"digest": {}}]}, {"predicateType": 7},
                    {"predicateType": ""}):
            r = check(dict(ok, **bad))
            self.assertIs(r["verified"], False, bad)
        st = {k: v for k, v in ok.items() if k != "predicateType"}
        self.assertIs(check(st)["verified"], False)
        for pred in (7, [1], "x", None):
            r = check(dict(ok, predicate=pred))
            self.assertEqual((r["verified"], r["pack"]), (True, None), pred)

    def test_build_statement_recomputes_the_digest(self):
        """fails on 404b60b: a pack_sha3 naming another body was written into the signed subject"""
        other = P.build_pack("x", {"amount": "999"}, SCOPE)
        forged = dict(self.pk, pack_sha3=other["pack_sha3"])
        with self.assertRaises(ValueError):
            self.dsse.build_statement(forged)
        with self.assertRaises(ValueError):
            self.dsse.to_dsse(forged, self.ident)
        st = self.dsse.build_statement(self.pk)
        self.assertEqual(st["subject"][0]["digest"]["sha3_256"], self.pk["pack_sha3"])


class D4PreservationRecord(unittest.TestCase):
    def _ca(self, d):
        ca = os.path.join(d, "ca.pem")
        with open(ca, "w") as f:
            f.write("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n")
        return ca

    def test_asserted_time_beside_a_trust_anchor_fails(self):
        """fails on 404b60b: valid True with time[0]-asserted SKIP though tsa_ca_file was given"""
        from omega_evidence import preservation as PR
        d = _tmp(self)
        rec = PR.build_evidence_record([_pack(d, "p")])
        self.assertTrue(PR.verify_evidence_record(rec)["valid"])                     # control: no anchor, SKIP
        r = PR.verify_evidence_record(rec, tsa_ca_file=self._ca(d))
        self.assertFalse(r["valid"])
        self.assertEqual(_layer(r, "time[0]-asserted")["status"], "FAIL")

    def test_a_trust_anchor_given_and_empty_is_not_read_as_absent(self):
        """fails on 1e2896e: tsa_ca_file="" (an unset variable) was an asserted time SKIP and the record valid"""
        from omega_evidence import preservation as PR
        d = _tmp(self)
        rec = PR.build_evidence_record([_pack(d, "a")])
        self.assertIs(PR.verify_evidence_record(rec)["valid"], True)                    # control: no anchor asked
        for bad in ("", 0, False, b"", [], b"ca.pem"):
            r = PR.verify_evidence_record(rec, tsa_ca_file=bad)
            self.assertIs(r["valid"], False, repr(bad))
            self.assertEqual([(ly["layer"], ly["status"]) for ly in r["layers"]], [("tsa-ca-file", "FAIL")], repr(bad))

    def test_renew_timestamp_refuses_an_unknown_version(self):
        """fails on 1e2896e: renew_timestamp wrote a renewal on a record of version 7 (renew_hash_tree refused it)"""
        from omega_evidence import preservation as PR
        d = _tmp(self)
        p = _pack(d, "a")
        rec = PR.build_evidence_record([p])
        self.assertEqual(len(PR.renew_timestamp(dict(rec, archive_timestamps=list(rec["archive_timestamps"])))["archive_timestamps"]), 2)   # control
        rec["record_version"] = 7
        with self.assertRaises(ValueError):
            PR.renew_timestamp(rec)
        with self.assertRaises(ValueError):
            PR.renew_hash_tree(rec, [p], "sha3_512")
        self.assertEqual(len(rec["archive_timestamps"]), 1)

    def test_a_token_not_checkable_here_beside_a_trust_anchor_fails(self):
        """fails on 404b60b: timestamp.verify answering verified None (no openssl) with tsa_ca_file gave SKIP, valid True"""
        from unittest import mock
        from omega_evidence import preservation as PR, timestamp as T
        d = _tmp(self)
        rec = PR.build_evidence_record([_pack(d, "p")])
        rec["archive_timestamps"][0]["timestamp"] = {"time_source": "rfc3161", "tsa": "t", "tsr_b64": "MAMCAQA=",
                                                     "stamped_utc": "2026-11-21T00:00:00+00:00"}
        rec = PR._finalize(rec)
        with mock.patch.object(T, "verify", return_value={"verified": None, "note": "openssl absent"}):
            self.assertTrue(PR.verify_evidence_record(rec)["valid"])                       # control: SKIP without anchor
            r = PR.verify_evidence_record(rec, tsa_ca_file=self._ca(d))
        self.assertFalse(r["valid"])
        self.assertEqual(_layer(r, "time[0]-rfc3161")["status"], "FAIL")

    def test_version_2_is_rfc6962(self):
        """fails on 404b60b: root[a,b,c] == root[a,b,c,c] and root[l1,l2] == root[H(l1||l2)]; new records are version 2"""
        import hashlib as H
        from omega_evidence import preservation as PR
        l3 = PR._leaves(["a", "b", "c"], "sha256")
        l4 = PR._leaves(["a", "b", "c", "c"], "sha256")
        self.assertNotEqual(PR._root(l3, "sha256", 2), PR._root(l4, "sha256", 2))
        inner = H.sha256(bytes.fromhex(l3[0]) + bytes.fromhex(l3[1])).hexdigest()
        self.assertNotEqual(PR._root(l3[:2], "sha256", 2), PR._root([inner], "sha256", 2))
        # the RFC 6962 vectors this repository already holds (cryptovalid-opencore 0.14.0, leaf data = bytes([i]) * 3)
        with open(os.path.join(ROOT, "tests", "fixtures", "rfc6962_cryptovalid_vectors.json")) as f:
            vec = json.load(f)
        for t in vec["trees"]:
            self.assertEqual(PR._root([(bytes([i]) * 3).hex() for i in range(t["n"])], "sha256", 2), t["root"], t["n"])
        self.assertEqual(PR._root([], "sha256", 2), H.sha256(b"").hexdigest())
        d = _tmp(self)
        rec = PR.build_evidence_record([_pack(d, "p"), _pack(d, "q", {"amount": "2"})])
        self.assertEqual(rec["record_version"], 2)
        self.assertTrue(PR.verify_evidence_record(rec)["valid"])

    def test_version_1_records_still_verify_and_unknown_versions_fail(self):
        from omega_evidence import preservation as PR
        d = _tmp(self)
        paths = [_pack(d, f"p{i}", {"amount": str(i)}) for i in range(3)]
        rec = PR.build_evidence_record(paths)
        v1 = {k: v for k, v in json.loads(json.dumps(rec)).items() if k != "record_version"}   # as 0.13.0 wrote it
        a0 = v1["archive_timestamps"][0]
        a0["merkle_root"] = PR._merkle_root(a0["leaves"], a0["hash_alg"])
        v1 = PR._finalize(v1)
        self.assertTrue(PR.verify_evidence_record(v1, pack_paths=paths)["valid"])
        v1r = PR.renew_hash_tree(json.loads(json.dumps(v1)), paths, "sha3_256")
        self.assertNotIn("record_version", v1r)
        self.assertTrue(PR.verify_evidence_record(v1r, pack_paths=paths)["valid"])
        v2r = PR.renew_hash_tree(PR.renew_timestamp(json.loads(json.dumps(rec))), paths, "sha512")
        self.assertTrue(PR.verify_evidence_record(v2r, pack_paths=paths)["valid"])
        for bad in (2.0, True, 1, "2"):
            with self.assertRaises(ValueError):
                PR._version_of({"record_version": bad})
        for bad in (1, 3, 0, "2", True, None, [2]):   # a float cannot be canonicalised into a record at all
            r2 = PR._finalize(dict(json.loads(json.dumps(rec)), record_version=bad))
            r = PR.verify_evidence_record(r2)
            self.assertFalse(r["valid"], bad)
            self.assertEqual(_layer(r, "record-version")["status"], "FAIL", bad)
        # a version 1 root under a version 2 label (and the reverse) is refused
        swap = PR._finalize(dict(json.loads(json.dumps(v1)), record_version=2))
        self.assertFalse(PR.verify_evidence_record(swap)["valid"])
        # under a version nobody defined no root is recomputed: the Merkle layers are FAIL whatever root the record carries
        for base in (v1r, v2r):
            unk = PR._finalize(dict(json.loads(json.dumps(base)), record_version=7))
            r = PR.verify_evidence_record(unk)
            self.assertEqual([_layer(r, n)["status"] for n in ("record-version", "initial-merkle-root")], ["FAIL", "FAIL"])
            tree = [ly["status"] for ly in r["layers"] if ly["layer"].endswith("-hash-tree")]
            self.assertEqual(tree, ["FAIL"], r["layers"])

    def test_generated_trees(self):
        """random lists of 0..70 leaves and every hash_alg: version 2 equals an independent RFC 6962 implementation (the
        one of interop.aat for sha256), a duplicated last leaf and an inner node as a leaf never give the same root"""
        import hashlib as H
        from omega_evidence import preservation as PR
        from omega_evidence.interop import aat
        rnd = random.Random(6962)
        for _ in range(150):
            alg = rnd.choice(PR._SUPPORTED_HASH)
            n = rnd.randrange(0, 70)
            leaves = [PR._digest(alg, str(rnd.random()).encode()) for _ in range(n)]
            root = PR._root(leaves, alg, 2)
            if alg == "sha256" and n:
                ref = aat.merkle_root([H.sha256(b"\x00" + bytes.fromhex(x)).digest() for x in leaves]).hex()
                self.assertEqual(root, ref, n)
            if n:
                self.assertNotEqual(root, PR._root(leaves + [leaves[-1]], alg, 2))
            if n >= 2:
                h = PR._hnew(alg)
                h.update(bytes.fromhex(leaves[0]) + bytes.fromhex(leaves[1]))
                self.assertNotEqual(PR._root(leaves[:2], alg, 2), PR._root([h.hexdigest()], alg, 2))


class D5ArgumentsThatAskForAProof(unittest.TestCase):
    def test_sdjwt_aud_or_nonce_given_requires_key_binding(self):
        """fails on 404b60b: verified True, key_binding "not_required" with expected_aud and expected_nonce, no cnf"""
        from omega_evidence.interop import sdjwt
        ident = Identity("issuer")
        t = sdjwt.issue({"given_name": "A"}, ident, {"iss": "https://i.example", "vct": "x"})
        self.assertEqual(sdjwt.verify(t, ident.public_key_b64)["key_binding"], "not_required")      # control
        for kw in ({"expected_aud": "https://v.example", "expected_nonce": "n"}, {"expected_aud": "https://v.example"},
                   {"expected_nonce": "n"}):
            r = sdjwt.verify(t, ident.public_key_b64, **kw)
            self.assertIs(r["verified"], False, kw)
            self.assertIn("Key Binding is required", r["error"])
        r = sdjwt.verify(t, ident.public_key_b64, expected_aud="https://v.example", expected_nonce="n",
                         require_key_binding=False)
        self.assertEqual((r["verified"], r["key_binding"]), (True, "not_required"))   # an explicit policy still wins

    def test_sigstore_trust_anchor_and_no_token(self):
        """fails on 404b60b: verified True, checks without rfc3161, though tsa_ca_file was given"""
        try:
            from cryptography import x509
        except ImportError:
            self.skipTest("cryptography not installed")
        import datetime as dt
        import hashlib as H
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from omega_evidence.interop import dsse, sigstore
        k = ec.generate_private_key(ec.SECP256R1())
        n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "t")])
        now = dt.datetime.now(dt.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key()).serial_number(1)
                .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=1)).sign(k, hashes.SHA256()))
        st = {"_type": dsse.STATEMENT_TYPE, "predicateType": "x", "predicate": {},
              "subject": [{"name": "a", "digest": {"sha256": H.sha256(b"artifact").hexdigest()}}]}
        payload = json.dumps(st).encode()
        sig = k.sign(dsse.pae(dsse.PAYLOAD_TYPE, payload), ec.ECDSA(hashes.SHA256()))
        b = {"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
             "verificationMaterial": {"certificate": {"rawBytes": base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()}},
             "dsseEnvelope": {"payload": base64.b64encode(payload).decode(), "payloadType": dsse.PAYLOAD_TYPE,
                              "signatures": [{"sig": base64.b64encode(sig).decode()}]}}
        self.assertIs(sigstore.verify_bundle(b, artifact=b"artifact")["verified"], True)              # control
        d = _tmp(self)
        ca = os.path.join(d, "tsa.pem")
        with open(ca, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        r = sigstore.verify_bundle(b, artifact=b"artifact", tsa_ca_file=ca)
        self.assertEqual((r["verified"], r["checks"].get("rfc3161")), (False, False))
        self.assertIn("no RFC 3161 token", r["error"])


class D6ChipRegistryOrder(unittest.TestCase):
    def _setup(self, d):
        from omega_evidence import chip_registry as CR
        ident = Identity("chip-authority")
        ts = os.path.join(d, "trust.jsonl")
        TR.TrustRegistry(ts).trust("chip-authority", ident.public_key_b64)
        return CR, ident, ts

    def test_an_older_update_is_not_applied_after_a_newer_one(self):
        """fails on 404b60b (there the kind had no update_seq): the old mapping came back"""
        d = _tmp(self)
        CR, ident, ts = self._setup(d)
        old, new = os.path.join(d, "old.json"), os.path.join(d, "new.json")
        CR.publish_signed_update(old, {"vendor-x-v1": "service-OLD"}, ident, update_seq=1)
        CR.publish_signed_update(new, {"vendor-x-v1": "service-NEW"}, ident, update_seq=2)
        reg = CR.ChipRegistry()
        self.assertTrue(reg.apply_signed_update(new, ts)["applied"])
        r = reg.apply_signed_update(old, ts)
        self.assertFalse(r["applied"])
        self.assertIn("not after the last applied", r["reason"])
        self.assertEqual(reg.service_for("vendor-x-v1"), "service-NEW")
        self.assertFalse(reg.apply_signed_update(new, ts)["applied"])                # the same update again
        reg2 = CR.ChipRegistry(last_seq=reg.last_seq())                               # across a restart
        self.assertFalse(reg2.apply_signed_update(old, ts)["applied"])
        self.assertEqual(CR.ChipRegistry().apply_signed_update(old, ts)["applied"], True)   # in order: applied

    def test_unsequenced_and_malformed_sequences_are_refused(self):
        d = _tmp(self)
        CR, ident, ts = self._setup(d)
        reg = CR.ChipRegistry()
        cases = {"v1-kind": (CR.UPDATE_KIND_V1, {}), "missing": (CR.UPDATE_KIND, {}), "zero": (CR.UPDATE_KIND, {"update_seq": 0}),
                 "negative": (CR.UPDATE_KIND, {"update_seq": -1}), "string": (CR.UPDATE_KIND, {"update_seq": "2"}),
                 "bool": (CR.UPDATE_KIND, {"update_seq": True}), "list": (CR.UPDATE_KIND, {"update_seq": [2]}),
                 "beyond": (CR.UPDATE_KIND, {"update_seq": 2 ** 53})}
        for nm, (kind, extra) in cases.items():
            p = os.path.join(d, nm + ".json")
            try:
                pk = P.build_pack(kind, dict({"chip_classes": {"vendor-" + nm: "svc"}}, **extra), "a mapping, NOT more")
                P.write_pack(p, pk)
                P.sign_pack(p, ident)
            except ValueError:
                continue                                       # a value the strict profile does not write (2^53)
            r = reg.apply_signed_update(p, ts)
            self.assertFalse(r["applied"], nm)
            if nm == "v1-kind":
                self.assertIn("unsequenced update", r["reason"])
            self.assertFalse(reg.is_known("vendor-" + nm), nm)
        for bad in (0, -1, True, "1", 2 ** 53, None):
            with self.assertRaises((ValueError, TypeError)):
                CR.publish_signed_update(os.path.join(d, "x.json"), {"v": "s"}, ident, update_seq=bad)
        with self.assertRaises(ValueError):
            CR.ChipRegistry(last_seq={"x": -1})

    def test_the_order_is_per_signing_key_not_per_label(self):
        """fails on 1e2896e: signer_id is a label the signature does not cover; with one key under two labels in the
        trust store, the older update re-labelled was applied after the newer one (service-OLD came back)"""
        d = _tmp(self)
        from omega_evidence import chip_registry as CR
        ident = Identity("cur-a")
        ts = os.path.join(d, "trust.jsonl")
        tr = TR.TrustRegistry(ts)
        tr.trust("cur-a", ident.public_key_b64)
        tr.trust("cur-b", ident.public_key_b64)
        old, new = os.path.join(d, "old.json"), os.path.join(d, "new.json")
        CR.publish_signed_update(old, {"vendor-x-v1": "service-OLD"}, ident, update_seq=1)
        CR.publish_signed_update(new, {"vendor-x-v1": "service-NEW"}, ident, update_seq=2)
        reg = CR.ChipRegistry()
        self.assertTrue(reg.apply_signed_update(new, ts)["applied"])
        side = _rj(old[:-5] + ".sig.json")
        side["signer_id"] = "cur-b"
        _wj(old[:-5] + ".sig.json", side)
        self.assertEqual(verify_pack(old, trust_store=ts)["authenticated"], True)      # control: trusted-signed as cur-b
        r = reg.apply_signed_update(old, ts)
        self.assertFalse(r["applied"], r)
        self.assertIn("not after the last applied", r["reason"])
        self.assertEqual(reg.service_for("vendor-x-v1"), "service-NEW")
        self.assertEqual(reg.last_seq(), {ident.public_key_b64: 2})                    # keyed by the key that verified
        reg.last_seq()[ident.public_key_b64] = 0                                       # a copy: the registry's own is not touched
        self.assertEqual(reg.last_seq(), {ident.public_key_b64: 2})
        reg2 = CR.ChipRegistry(last_seq=reg.last_seq())                                # across a restart
        self.assertFalse(reg2.apply_signed_update(old, ts)["applied"])
        for bad in ([("k", 1)], "k", 5, {"k": "1"}, {"k": 1.0}, {1: 1}, {"k": True}, {"k": 2 ** 53}):
            with self.assertRaises(ValueError, msg=repr(bad)):
                CR.ChipRegistry(last_seq=bad)

    def test_generated_orders(self):
        """random orders of 8 updates from 2 signers: what is applied for each signer is strictly increasing, and the
        mapping left is the one of the highest update_seq seen per signer"""
        d = _tmp(self)
        from omega_evidence import chip_registry as CR
        rnd = random.Random(13)
        ids = [Identity("cur-a"), Identity("cur-b")]
        ts = os.path.join(d, "trust.jsonl")
        tr = TR.TrustRegistry(ts)
        for i in ids:
            tr.trust(i.name, i.public_key_b64)
        ups = []
        for i in ids:
            for seq in range(1, 5):
                p = os.path.join(d, f"{i.name}-{seq}.json")
                CR.publish_signed_update(p, {f"cls-{i.name}": f"svc-{seq}"}, i, update_seq=seq)
                ups.append((i.name, seq, p))
        for _ in range(6):
            reg = CR.ChipRegistry()
            order = ups[:]
            rnd.shuffle(order)
            best = {}
            for name, seq, p in order:
                r = reg.apply_signed_update(p, ts)
                self.assertEqual(r["applied"], seq > best.get(name, 0), (name, seq, best))
                best[name] = max(best.get(name, 0), seq)
            for name, seq in best.items():
                self.assertEqual(reg.service_for(f"cls-{name}"), f"svc-{seq}")


class TemporaryFilesAreRemoved(unittest.TestCase):
    """Measured 21/11/2026: a run of the differential oracle that stopped on an exception left its ~450 MB of cases in
    /tmp (the removal was its last line), and the CI test line left 6 entries (284 KB) in the temporary directory."""

    def _fresh_tmp(self):
        d = tempfile.mkdtemp(prefix="oe-leakprobe-")
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        return d

    def test_oracle_removes_its_directory_on_an_exception_and_on_sigterm(self):
        """fails on 56de8cb: the directory stays"""
        probe = self._fresh_tmp()
        script = (
            "import os, sys, tempfile, time\n"
            "sys.path.insert(0, os.path.join(sys.argv[1], 'verifiers'))\n"
            "tempfile.tempdir = sys.argv[2]\n"
            "import differential_oracle as O\n"
            "def fake(tmp):\n"
            "    for i in range(3000 if sys.argv[3] == 'many' else 1):\n"
            "        open(os.path.join(tmp, 'case%d.json' % i), 'w').write('x' * 1000)\n"
            "    print('ready', flush=True)\n"
            "    if sys.argv[3] == 'raise':\n"
            "        raise RuntimeError('stopped')\n"
            "    for _ in range(600):\n"          # short sleeps: on Windows time.sleep wakes for Ctrl-C only, not for
            "        time.sleep(0.1)\n"           # SIGBREAK, so its handler would run after the whole sleep
            "O._main = fake\n"
            "O.main()\n")
        r = subprocess.run([sys.executable, "-c", script, ROOT, probe, "raise"], capture_output=True, text=True, timeout=60)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("RuntimeError", r.stderr)
        self.assertEqual(os.listdir(probe), [])
        import signal
        import time
        # Windows: terminate() is TerminateProcess, which no process can handle (SIGKILL); the stop a process can handle
        # there is Ctrl-Break (SIGBREAK), sent to a child started in its own process group. Windows has no SIGHUP.
        stop, group = ((signal.CTRL_BREAK_EVENT, subprocess.CREATE_NEW_PROCESS_GROUP) if os.name == "nt" else
                       (signal.SIGTERM, 0))
        p = subprocess.Popen([sys.executable, "-c", script, ROOT, probe, "sleep"], stdout=subprocess.PIPE, text=True,
                             creationflags=group)
        self.assertEqual(p.stdout.readline().strip(), "ready")
        self.assertEqual(len(os.listdir(probe)), 1)                    # control: the cases are there while it runs
        p.send_signal(stop)
        p.wait(timeout=30)
        p.stdout.close()
        self.assertEqual(os.listdir(probe), [])
        # fails on 1e2896e: SIGHUP, and a second SIGTERM while the directory is being removed, left it
        cases = ([[stop], [stop, stop]] if os.name == "nt" else
                 [[signal.SIGHUP], [signal.SIGTERM, signal.SIGTERM], [signal.SIGTERM, signal.SIGINT]])
        for sigs in cases:
            p = subprocess.Popen([sys.executable, "-c", script, ROOT, probe, "many"], stdout=subprocess.PIPE, text=True,
                                 creationflags=group)
            self.assertEqual(p.stdout.readline().strip(), "ready")
            self.assertEqual(len(os.listdir(probe)), 1)
            for n, s in enumerate(sigs):
                if n:
                    time.sleep(0.02)
                p.send_signal(s)
            p.wait(timeout=60)
            p.stdout.close()
            self.assertEqual(os.listdir(probe), [], sigs)

    def test_the_toolkit_suite_leaves_nothing_in_the_temporary_directory(self):
        """fails on 56de8cb: 4 directories of r.json, one of .ots.json files and dup_kat.jsonl stayed"""
        probe = self._fresh_tmp()
        env = dict(os.environ, TMPDIR=probe)
        env.pop("PYTHONPATH", None)
        r = subprocess.run([sys.executable, os.path.join(ROOT, "tests", "test_toolkit.py")], capture_output=True,
                           text=True, timeout=900, env=env, cwd=ROOT)
        self.assertEqual(r.returncode, 0, r.stderr[-500:])
        self.assertEqual(sorted(os.listdir(probe)), [])


    def test_the_fuzzer_leaves_nothing_in_the_temporary_directory(self):
        """fails on d5340a3: with --findings-dir (as CI runs it) or --ablate the corpus directory stayed (48 KB a run)"""
        probe = self._fresh_tmp()
        out = self._fresh_tmp()
        env = dict(os.environ, TMPDIR=probe)
        env.pop("PYTHONPATH", None)
        for extra in (["--findings-dir", os.path.join(out, "f")], ["--ablate", "pack-sha3", "--findings-dir", os.path.join(out, "a")], []):
            r = subprocess.run([sys.executable, os.path.join(ROOT, "tests", "fuzz_toolkit.py"), "--seed", "20260928",
                                "--iterations", "60"] + extra, capture_output=True, text=True, timeout=600, env=env, cwd=ROOT)
            self.assertIn(r.returncode, (0, 1), r.stderr[-300:])
            self.assertEqual(sorted(os.listdir(probe)), [], extra)
        # fails on 1e2896e: a run stopped by SIGTERM or SIGHUP left the corpus directory
        import signal
        import time
        win = os.name == "nt"   # Windows: Ctrl-Break (SIGBREAK) to its own process group; no SIGHUP there
        for s in ((signal.CTRL_BREAK_EVENT,) if win else (signal.SIGTERM, signal.SIGHUP)):
            p = subprocess.Popen([sys.executable, os.path.join(ROOT, "tests", "fuzz_toolkit.py"), "--seed", "1", "--iterations",
                                  "500000"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env, cwd=ROOT,
                                 creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if win else 0)
            for _ in range(2400):                                       # up to 120 s: a macOS runner took over 30 s to start it
                if os.listdir(probe):
                    break
                time.sleep(0.05)
            self.assertEqual(len(os.listdir(probe)), 1)                # control: the corpus is there while it runs
            time.sleep(0.5)
            p.send_signal(s)
            _, err = p.communicate(timeout=60)
            self.assertEqual(os.listdir(probe), [], (s, p.returncode, err.decode("utf-8", "replace")[-600:]))

    def test_the_fuzzer_signal_handler_only_sets_a_flag(self):
        """fails on 0c56003: the handler raised SystemExit wherever the signal fell, also between os.open and its try
        in read_input, and that descriptor stayed open: on Windows the corpus folder could not be removed (CI, Ctrl-Break)"""
        import argparse
        import signal
        from unittest import mock
        sys.path.insert(0, os.path.join(ROOT, "tests"))
        import fuzz_toolkit as fz
        probe = self._fresh_tmp()
        for s in (signal.SIGTERM, signal.SIGINT):   # Ctrl-C too; the second run also sees a flag left by the first
            before = signal.getsignal(s)
            seen = []

            def fake_run(args, root, keep):
                signal.raise_signal(s)
                seen.append(os.path.isdir(root))   # reached only if the handler did not raise
                return 0
            with mock.patch.object(fz, "_run", fake_run), mock.patch.object(tempfile, "tempdir", probe):
                with self.assertRaises(SystemExit) as cm:
                    fz.run(argparse.Namespace())
            self.assertEqual(seen, [True], s)
            self.assertEqual(cm.exception.code, 128 + s)
            self.assertEqual(os.listdir(probe), [], s)
            self.assertIs(signal.getsignal(s), before)

if __name__ == "__main__":
    unittest.main(verbosity=1)
