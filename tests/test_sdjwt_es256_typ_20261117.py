#!/usr/bin/env python3
# Copyright 2026 Roberto Locatelli — Apache-2.0
"""interop.sdjwt.verify (0.12.0): the issuer JWS of an SD-JWT VC in ES256 and its `typ`.

An SD-JWT VC carries `typ` "dc+sd-jwt" (draft-ietf-oauth-sd-jwt-vc-27 §2.2.1), and OpenID4VC HAIP 1.0 (Final) §7 requires
issuers, verifiers and wallets to support ES256. Until
0.11.4 verify() accepted only EdDSA and did not read `typ`. Positive control: the ES256 SD-JWT VC below is refused by
0.11.4 (measured on the tag v0.11.4 with this file: `verified: False`, "alg must be EdDSA") and accepted now.
Negatives: a wrong, missing or non-string `typ`; a P-384 key, an Ed25519 key or a JWK of another `alg` under ES256; a
P-256 key under EdDSA; `crit`; alg none / ES384; a signature in DER or of 65 bytes; a changed payload."""
import base64
import json
import os
import sys
import unittest
import unittest.mock

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from omega_evidence.interop import sdjwt  # noqa: E402
from omega_evidence.signing import Identity  # noqa: E402

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    HAVE = True
except ImportError:
    HAVE = False


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def token(key, header, claims=None, plain=None, der_sig=False, extra_byte=False, pad_s=False):
    """an SD-JWT signed with `key` (an EC or Ed25519 private key) under `header`, its claims selectively disclosable"""
    claims = {"given_name": "Ada", "age_over_18": True} if claims is None else claims
    discl = [sdjwt._disclosure(f"salt{i}", k, v) for i, (k, v) in enumerate(claims.items())]
    body = dict(plain or {"iss": "https://issuer.example", "vct": "urn:eudi:pid:1"})
    body["_sd"] = sorted(sdjwt._digest(d) for d in discl)
    body["_sd_alg"] = "sha-256"
    si = b64u(json.dumps(header, separators=(",", ":")).encode()) + "." + b64u(json.dumps(body, separators=(",", ":")).encode())
    if isinstance(key, ec.EllipticCurvePrivateKey):
        der = key.sign(si.encode(), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        size = (key.curve.key_size + 7) // 8
        sig = der if der_sig else r.to_bytes(size, "big") + (b"\x00" if pad_s else b"") + s.to_bytes(size, "big")
    else:
        sig = key.sign(si.encode())
    if extra_byte:
        sig += b"\x00"
    return si + "." + b64u(sig) + "~" + "".join(d + "~" for d in discl)


def jwk(pub):
    n = pub.public_numbers()
    size = (pub.curve.key_size + 7) // 8
    crv = {"secp256r1": "P-256", "secp384r1": "P-384"}[pub.curve.name]
    return {"kty": "EC", "crv": crv, "x": b64u(n.x.to_bytes(size, "big")), "y": b64u(n.y.to_bytes(size, "big"))}


def pem(pub):
    return pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


H = {"alg": "ES256", "typ": "dc+sd-jwt"}


@unittest.skipUnless(HAVE, "cryptography absent: ES256 cannot be produced here")
class TestES256AndTyp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.k = ec.generate_private_key(ec.SECP256R1())
        cls.k384 = ec.generate_private_key(ec.SECP384R1())
        cls.ed = ed25519.Ed25519PrivateKey.generate()

    def ok(self, tok, key, **kw):
        return sdjwt.verify(tok, key, **kw)

    def test_es256_sd_jwt_vc_verified(self):   # positive control: False on v0.11.4
        tok = token(self.k, H)
        for key in (jwk(self.k.public_key()), pem(self.k.public_key())):
            r = self.ok(tok, key)
            self.assertIs(r["verified"], True, r)
            self.assertEqual(r["disclosed_claims"], {"given_name": "Ada", "age_over_18": True})

    def test_typ(self):
        pub = jwk(self.k.public_key())
        for typ in ("DC+SD-JWT", "application/dc+sd-jwt", "Application/DC+sd-jwt"):   # RFC 7515 §4.1.9
            self.assertIs(self.ok(token(self.k, {"alg": "ES256", "typ": typ}), pub)["verified"], True, typ)
        for typ in ("vc+sd-jwt", "jwt", "example+sd-jwt", "dc+sd-jwt ", "", "application/dc+sd-jwt;x=1",
                    "dc+sd-jwK", "DC+SD-JWK"):   # vc+sd-jwt: -27 removed the transition; U+212A KELVIN SIGN
            r = self.ok(token(self.k, {"alg": "ES256", "typ": typ}), pub)
            self.assertIs(r["verified"], False, typ)
            self.assertIn("typ_mismatch", r["error"])
        r = self.ok(token(self.k, {"alg": "ES256"}), pub)
        self.assertIn("typ_missing", r["error"])
        r = self.ok(token(self.k, {"alg": "ES256", "typ": ["dc+sd-jwt"]}), pub)
        self.assertIn("typ_not_string", r["error"])
        self.assertIs(self.ok(token(self.k, {"alg": "ES256", "typ": "example+sd-jwt"}), pub,
                              expected_typ="example+sd-jwt")["verified"], True)       # RFC 9901 explicit typing
        kb = {"alg": "ES256", "typ": "\u212ab+jwt"}                  # KELVIN SIGN: str.lower() would make it "kb+jwt"
        self.assertIn("typ_mismatch", self.ok(token(self.k, kb), pub, expected_typ="kb+jwt")["error"])
        self.assertIs(self.ok(token(self.k, {"alg": "ES256", "typ": "KB+JWT"}), pub, expected_typ="kb+jwt")["verified"], True)
        with self.assertRaises(ValueError):
            sdjwt.verify(token(self.k, H), pub, expected_typ="")

    def test_curve_bound_to_alg(self):
        tok384 = token(self.k384, H)                       # a P-384 key signs, header says ES256
        for key in (jwk(self.k384.public_key()), pem(self.k384.public_key())):
            r = self.ok(tok384, key)
            self.assertIs(r["verified"], False, r)
            self.assertIn("P-256", r["error"])
        r = self.ok(token(self.k, H), pem(self.ed.public_key()))     # Ed25519 key under ES256
        self.assertIs(r["verified"], False, r)
        edtok = token(self.ed, {"alg": "EdDSA", "typ": "dc+sd-jwt"})
        r = self.ok(edtok, jwk(self.k.public_key()))                # P-256 key under EdDSA
        self.assertIs(r["verified"], False, r)
        confused = token(self.k, {"alg": "EdDSA", "typ": "dc+sd-jwt"})   # a valid ECDSA P-256 signature, header EdDSA
        r = self.ok(confused, jwk(self.k.public_key()))
        self.assertIs(r["verified"], False, r)
        self.assertIn("Ed25519 key", r["error"])
        self.assertIs(self.ok(edtok, pem(self.ed.public_key()))["verified"], True)   # control: the right key
        raw = self.ed.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.assertIs(self.ok(token(self.ed, {"alg": "Ed25519", "typ": "dc+sd-jwt"}), {"kty": "OKP", "crv": "Ed25519",
                      "x": b64u(raw)})["verified"], True)              # RFC 9864 fully specified name

    def test_jwk_alg_use(self):
        tok = token(self.k, H)
        k = jwk(self.k.public_key())
        self.assertIs(self.ok(tok, dict(k, alg="ES256", use="sig", kid="x"))["verified"], True)
        self.assertIs(self.ok(tok, dict(k, alg="ES384"))["verified"], False)
        self.assertIs(self.ok(tok, dict(k, use="enc"))["verified"], False)
        self.assertIs(self.ok(tok, dict(k, key_ops=["sign"]))["verified"], False)
        self.assertIs(self.ok(tok, dict(k, y=k["x"]))["verified"], False)                # not a point of P-256

    def test_header_refusals(self):
        pub = jwk(self.k.public_key())
        for h, why in (({"alg": "ES256", "typ": "dc+sd-jwt", "crit": ["x"], "x": 1}, "crit_not_understood"),
                       ({"alg": "none", "typ": "dc+sd-jwt"}, "alg_not_allowed"),
                       ({"alg": "ES384", "typ": "dc+sd-jwt"}, "alg_not_allowed"),
                       ({"typ": "dc+sd-jwt"}, "alg_missing"), ({"alg": 1, "typ": "dc+sd-jwt"}, "alg_not_string")):
            r = self.ok(token(self.k, h), pub)
            self.assertIs(r["verified"], False, h)
            self.assertIn(why, r["error"])

    def test_signature_form(self):
        pub = jwk(self.k.public_key())
        self.assertIs(self.ok(token(self.k, H, der_sig=True), pub)["verified"], False)   # DER, not R || S
        self.assertIs(self.ok(token(self.k, H, extra_byte=True), pub)["verified"], False)
        self.assertIs(self.ok(token(self.k, H, pad_s=True), pub)["verified"], False)      # R || 00 || S: 65 bytes, same S
        tok = token(self.k, H)
        h, p, s = tok.split("~")[0].split(".")
        body = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
        body["iss"] = "https://other.example"
        p2 = b64u(json.dumps(body, separators=(",", ":")).encode())
        self.assertIs(self.ok(tok.replace(p, p2), pub)["verified"], False)

    def test_es256_without_cryptography_is_not_checked(self):
        tok, k = token(self.k, H), jwk(self.k.public_key())
        with unittest.mock.patch.dict(sys.modules, {"cryptography.hazmat.primitives.asymmetric": None,
                                                    "cryptography.hazmat.primitives.asymmetric.ec": None}):
            r = sdjwt.verify(tok, k)
        self.assertIsNone(r["verified"], r)


class TestEdDSAIssuedHere(unittest.TestCase):
    def test_issue_verify_unchanged(self):   # control: what issue() writes still verifies with the base64 key
        iss = Identity("issuer")
        tok = sdjwt.issue({"country": "IT"}, iss, plain_claims={"iss": "x", "vct": "urn:x"})
        self.assertIs(sdjwt.verify(tok, iss.public_key_b64)["verified"], True)
        h = json.loads(base64.urlsafe_b64decode(tok.split(".")[0] + "=="))
        self.assertEqual(h, {"alg": "EdDSA", "typ": "dc+sd-jwt"})


if __name__ == "__main__":
    unittest.main()
