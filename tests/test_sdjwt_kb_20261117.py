#!/usr/bin/env python3
# Copyright 2026 Roberto Locatelli — Apache-2.0
"""interop.sdjwt.verify (0.12.0): Key Binding JWT (RFC 9901 §4.3, §7.3; OpenID4VC HAIP 1.0 §6.1.1.1).

Until 0.11.4 an SD-JWT+KB was rejected as a whole and a credential carrying `cnf` verified without any KB-JWT.
Positive control: the ES256 SD-JWT VC + KB-JWT below is refused by 0.11.4 (measured on the tag v0.11.4 with this file:
`verified: False`, "an SD-JWT+KB is not supported here") and accepted now with `key_binding: verified`. Negatives: each
step of §7.3 step 5 broken alone (holder key, alg, typ, signature, iat window, aud, nonce, sd_hash, exp), a credential
with `cnf` presented without a KB-JWT, a KB-JWT where none is required."""
import base64
import hashlib
import json
import os
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from omega_evidence.interop import sdjwt  # noqa: E402
import test_sdjwt_es256_typ_20261117 as E  # noqa: E402

NOW = 1_800_000_000
AUD, NONCE = "https://verifier.example", "n-0S6_WzA2Mj"


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def sign(key, header, payload):
    """a compact JWS of `payload` under `header`, signed by `key` (EC: R || S; Ed25519)"""
    si = b64u(json.dumps(header, separators=(",", ":")).encode()) + "." + b64u(json.dumps(payload, separators=(",", ":")).encode())
    if isinstance(key, E.ec.EllipticCurvePrivateKey):
        r, s = E.decode_dss_signature(key.sign(si.encode(), E.ec.ECDSA(E.hashes.SHA256())))
        n = (key.curve.key_size + 7) // 8
        sig = r.to_bytes(n, "big") + s.to_bytes(n, "big")
    else:
        sig = key.sign(si.encode())
    return si + "." + b64u(sig)


def holder_jwk(key):
    if isinstance(key, E.ec.EllipticCurvePrivateKey):
        return E.jwk(key.public_key())
    raw = key.public_key().public_bytes(E.serialization.Encoding.Raw, E.serialization.PublicFormat.Raw)
    return {"kty": "OKP", "crv": "Ed25519", "x": b64u(raw)}


@unittest.skipUnless(E.HAVE, "cryptography absent: ES256 cannot be produced here")
class TestKeyBinding(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.issuer = E.ec.generate_private_key(E.ec.SECP256R1())
        cls.holder = E.ec.generate_private_key(E.ec.SECP256R1())
        cls.other = E.ec.generate_private_key(E.ec.SECP256R1())
        cls.ipub = E.jwk(cls.issuer.public_key())

    def sd(self, cnf=True, holder=None):
        plain = {"iss": "https://issuer.example", "vct": "urn:eudi:pid:1"}
        if cnf:
            plain["cnf"] = cnf if isinstance(cnf, dict) else {"jwk": holder_jwk(holder or self.holder)}
        return E.token(self.issuer, E.H, plain=plain)

    def kb(self, sd, key=None, header=None, **over):
        payload = {"iat": NOW - 10, "aud": AUD, "nonce": NONCE,
                   "sd_hash": b64u(hashlib.sha256(sd.encode("ascii")).digest())}
        payload.update(over)
        payload = {k: v for k, v in payload.items() if v is not DROP}
        return sd + sign(key or self.holder, header or {"alg": "ES256", "typ": "kb+jwt"}, payload)

    def v(self, tok, **kw):
        kw.setdefault("expected_aud", AUD); kw.setdefault("expected_nonce", NONCE)
        return sdjwt.verify(tok, self.ipub, now=NOW, **kw)

    def test_kb_verified(self):   # positive control: False on v0.11.4
        r = self.v(self.kb(self.sd()))
        self.assertEqual((r["verified"], r["key_binding"]), (True, "verified"), r)
        ed = E.ed25519.Ed25519PrivateKey.generate()                  # an Ed25519 holder key, KB-JWT in EdDSA
        r = self.v(self.kb(self.sd(holder=ed), key=ed, header={"alg": "EdDSA", "typ": "kb+jwt"}))
        self.assertIs(r["verified"], True, r)
        self.assertIs(self.v(self.kb(self.sd(), header={"alg": "ES256", "typ": "KB+JWT"}))["verified"], True)   # RFC 7515 §4.1.9

    def test_policy(self):
        r = self.v(self.sd())                                          # cnf, no KB-JWT: HAIP 1.0 §6.1.1.1
        self.assertIs(r["verified"], False); self.assertIn("no KB-JWT", r["error"])
        r = self.v(self.sd(), require_key_binding=False)               # the verifier's declared policy
        self.assertEqual((r["verified"], r["key_binding"]), (True, "not_required"))
        r = self.v(self.kb(self.sd(cnf=False)))                       # a KB-JWT nobody asked for
        self.assertIs(r["verified"], False); self.assertIn("not accepted unchecked", r["error"])
        r = self.v(self.kb(self.sd(cnf=False)), require_key_binding=True)   # required, no cnf.jwk: no holder key
        self.assertIs(r["verified"], False); self.assertIn("cnf.jwk", r["error"])
        r = sdjwt.verify(self.kb(self.sd()), self.ipub, now=NOW)     # cnf, nothing to check aud/nonce against
        self.assertIs(r["verified"], False); self.assertIn("expected_aud", r["error"])
        with self.assertRaises(ValueError):
            sdjwt.verify(self.kb(self.sd()), self.ipub, now=NOW, require_key_binding=True)
        with self.assertRaises(ValueError):
            sdjwt.verify(self.sd(), self.ipub, require_key_binding="yes")
        self.assertIs(sdjwt.verify(self.sd(cnf=False), self.ipub, now=NOW)["verified"], True)   # no cnf: as before

    def test_each_step_broken(self):
        sd = self.sd()
        cases = {
            "typ jwt": self.kb(sd, header={"alg": "ES256", "typ": "jwt"}),
            "typ missing": self.kb(sd, header={"alg": "ES256"}),
            "alg none": sd + b64u(b'{"alg":"none","typ":"kb+jwt"}') + "." + b64u(json.dumps({"iat": NOW, "aud": AUD,
                         "nonce": NONCE, "sd_hash": b64u(hashlib.sha256(sd.encode()).digest())}).encode()) + ".",
            "alg HS256": self.kb(sd, header={"alg": "HS256", "typ": "kb+jwt"}),
            "crit": self.kb(sd, header={"alg": "ES256", "typ": "kb+jwt", "crit": ["x"], "x": 1}),
            "another key": self.kb(sd, key=self.other),
            "aud": self.kb(sd, aud="https://other.example"),
            "aud list": self.kb(sd, aud=[AUD]),
            "nonce": self.kb(sd, nonce="other"),
            "iat too old": self.kb(sd, iat=NOW - 301),
            "iat in the future": self.kb(sd, iat=NOW + 61),
            "iat string": self.kb(sd, iat=str(NOW)),
            "iat missing": self.kb(sd, iat=DROP), "aud missing": self.kb(sd, aud=DROP),
            "nonce missing": self.kb(sd, nonce=DROP), "sd_hash missing": self.kb(sd, sd_hash=DROP),
            "sd_hash of another presentation": self.kb(sd, sd_hash=b64u(hashlib.sha256(sd[:-1].encode()).digest())),
            "exp past": self.kb(sd, exp=NOW - 1),
            "nbf future": self.kb(sd, nbf=NOW + 1000),
            "four parts": self.kb(sd) + ".x",
        }
        for name, tok in cases.items():
            r = self.v(tok)
            self.assertIs(r["verified"], False, name)
        for name in ("iat missing", "aud missing", "nonce missing", "sd_hash missing"):  # refused for the right reason
            self.assertIn(name.split()[0] + " missing", self.v(cases[name])["error"], name)
        self.assertIn("iat is not a finite number", self.v(cases["iat string"])["error"])
        self.assertIs(self.v(self.kb(sd, iat=NOW - 300))["verified"], True)            # window edges included
        self.assertIs(self.v(self.kb(sd, iat=NOW + 60))["verified"], True)

    def test_disclosure_dropped_after_kb(self):   # the holder signs one presentation, another is sent
        sd = self.sd(); tok = self.kb(sd)
        parts = sd.split("~")
        fewer = "~".join(parts[:1] + parts[2:])                         # one Disclosure removed, same KB-JWT
        r = self.v(fewer + tok[len(sd):])
        self.assertIs(r["verified"], False); self.assertIn("sd_hash", r["error"])

    def test_holder_key_bound_to_alg(self):
        k384 = E.ec.generate_private_key(E.ec.SECP384R1())
        r = self.v(self.kb(self.sd(holder=k384), key=k384))            # P-384 holder key under ES256
        self.assertIs(r["verified"], False)
        r = self.v(self.kb(self.sd(), header={"alg": "EdDSA", "typ": "kb+jwt"}))   # a valid ECDSA P-256 signature, alg EdDSA
        self.assertIs(r["verified"], False, r); self.assertIn("Ed25519 key", r["error"])
        r = self.v(self.kb(self.sd(cnf={"kid": "h1"})))                 # cnf without jwk
        self.assertIs(r["verified"], False); self.assertIn("cnf.jwk", r["error"])
        r = self.v(self.kb(self.sd(cnf={"jwk": dict(holder_jwk(self.holder), alg="EdDSA")})))
        self.assertIs(r["verified"], False)


DROP = object()

if __name__ == "__main__":
    unittest.main()
