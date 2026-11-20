# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""The six decisions of 20 November 2026 on behaviours that 0.13.0 documented and that two review benches flagged
(each measured on 404b60b before it was changed; the tests marked "fails on 404b60b" fail there).

(D1) `authenticated` was true for a signature by any key under any `signer_id` with no trust registry, and a trust
     registry given did not require a signature (no sidecar, or an unknown algorithm: exit 0).
(D2) The timestamp sidecar: any `tsr_b64` (text, or none) was a SKIP "token recorded", and `validation_material` was
     read as found (`cert_count: "lots"` printed as a count). Now the token's form and a closed material, FAIL.
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


if __name__ == "__main__":
    unittest.main(verbosity=1)
