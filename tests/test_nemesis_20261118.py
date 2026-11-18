# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""0.12.0 review of 18/11/2026: cases the 30 tests of test_uso_reale_20261118 did not hold.

  * a bundle's DSSE signature and payload in base64 without padding (proto3 JSON allows it) are read;
  * the publicKey hint and the DSSE keyid must be the same (sigstore_bundle.proto, MUST);
  * a caller key that is not the key of the bundle's certificate is refused (the certificate, and the signing time
    checked against it, would describe another key);
  * `not_verified` names the valid_for window of the trusted root (sigstore_trustroot.proto, MUST);
  * media types 0.1 and ";version=0.3" are read; a log entry whose logIndex is 0 (omitted in proto3 JSON) is read;
  * malformed inputs that were accepted or raised: 65-byte r||00||s, an X25519 SPKI, two PEM blocks, a base64 string
    in two alphabets, a signing time BEFORE the certificate, an artifact that is not bytes, bad TSA parameters.
"""
import base64
import copy
import hashlib
import os
import sys
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, HERE)

import test_uso_reale_20261118 as U  # noqa: E402
from omega_evidence import timestamp as T  # noqa: E402
from omega_evidence.interop import dsse, sigstore  # noqa: E402

if U.HAVE_CRYPTO:
    import datetime as dt
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, x25519
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature


@unittest.skipUnless(U.HAVE_CRYPTO, "cryptography absent")
class TestDsseKeysAndSignatures(unittest.TestCase):
    def test_raw_signature_of_65_bytes_is_refused(self):
        k = ec.generate_private_key(ec.SECP256R1())
        der = k.sign(b"m", ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        self.assertTrue(dsse._ecdsa_verify(k.public_key(), raw, b"m"))
        self.assertFalse(dsse._ecdsa_verify(k.public_key(), raw[:32] + b"\x00" + raw[32:], b"m"))
        self.assertFalse(dsse._ecdsa_verify(k.public_key(), b"\x00" + raw, b"m"))

    def test_x25519_spki_is_not_an_ed25519_key(self):
        spki = x25519.X25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.assertEqual(len(spki), 44)
        with self.assertRaisesRegex(ValueError, "unsupported key"):
            dsse.load_public_key(spki)

    def test_pem_with_a_second_unreadable_block_is_refused(self):
        pem = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        with self.assertRaisesRegex(ValueError, "exactly one block"):
            dsse.load_public_key(pem + b"-----BEGIN CERTIFICATE-----\n!!\n-----END CERTIFICATE-----\n")


class TestBundle(U.TestSigstoreBundle):
    """the bundles of TestSigstoreBundle (a local TSA, tokens without certificate), not its tests (set to None below)"""

    def _ok(self, b, **kw):
        r = sigstore.verify_bundle(b, artifact=b"artifact", **dict(self.kw, **kw))
        self.assertIs(r["verified"], True, r["error"])
        return r

    def _no(self, b, want, **kw):
        r = sigstore.verify_bundle(b, artifact=b"artifact", **dict(self.kw, **kw))
        self.assertIs(r["verified"], False)
        self.assertIn(want, r["error"])
        return r

    def test_unpadded_and_url_safe_base64_are_read(self):
        """proto3 JSON bytes: either alphabet, padding optional — on a signature and a payload whose base64 needs
        padding (a 72-byte DER signature or a payload of 3n bytes would need none, and prove nothing)"""
        st = {"_type": dsse.STATEMENT_TYPE, "predicateType": "x", "predicate": {}, "subject": [
            {"name": "a.bin", "digest": {"sha256": hashlib.sha256(b"artifact").hexdigest()}}]}
        while True:
            payload, signed = U._envelope(st)
            if len(payload) % 3:
                break
            st["predicate"]["pad"] = st["predicate"].get("pad", "") + "x"
        while True:
            env = U._sign_env(self.k, payload, signed)
            if len(base64.b64decode(env["signatures"][0]["sig"])) % 3:
                break
        b = {"mediaType": self.bundle["mediaType"],
             "verificationMaterial": {"certificate": self.bundle["verificationMaterial"]["certificate"]},
             "dsseEnvelope": env}
        self.assertIs(sigstore.verify_bundle(b, artifact=b"artifact")["verified"], True)
        for enc in (base64.b64encode, base64.urlsafe_b64encode):
            b2 = copy.deepcopy(b)
            e = b2["dsseEnvelope"]
            e["signatures"][0]["sig"] = enc(base64.b64decode(e["signatures"][0]["sig"])).decode().rstrip("=")
            e["payload"] = enc(payload).decode().rstrip("=")
            self.assertTrue(e["payload"] != env["payload"] and e["signatures"][0]["sig"] != env["signatures"][0]["sig"])
            r = sigstore.verify_bundle(b2, artifact=b"artifact")
            self.assertIs(r["verified"], True, r["error"])
            e["payload"] = enc(payload.replace(b'"predicateType": "x"', b'"predicateType": "y"')).decode().rstrip("=")
            r = sigstore.verify_bundle(b2, artifact=b"artifact")
            self.assertIs(r["verified"], False)
            self.assertIn("does not verify", r["error"])

    def test_two_alphabets_in_one_string_are_refused(self):
        """one character of the URL-safe alphabet in a standard base64 string: refused (the reader keeps one alphabet
        per string), while the same bytes in either alphabet alone verify"""
        payload, signed = U._envelope()
        while True:
            env = U._sign_env(self.k, payload, signed)
            sig = env["signatures"][0]["sig"]
            std = [n for n, ch in enumerate(sig) if ch in "+/"]
            if len(std) >= 2:
                break
        b = {"mediaType": self.bundle["mediaType"],
             "verificationMaterial": {"certificate": self.bundle["verificationMaterial"]["certificate"]},
             "dsseEnvelope": env}
        self.assertIs(sigstore.verify_bundle(b, artifact=b"artifact")["verified"], True)
        n = std[0]
        b["dsseEnvelope"]["signatures"][0]["sig"] = sig[:n] + {"+": "-", "/": "_"}[sig[n]] + sig[n + 1:]
        r = sigstore.verify_bundle(b, artifact=b"artifact")
        self.assertIs(r["verified"], False)
        self.assertIn("not base64", r["error"])

    def test_key_hint_and_keyid_must_match(self):
        pem = self.k.public_key().public_bytes(serialization.Encoding.PEM,
                                               serialization.PublicFormat.SubjectPublicKeyInfo)
        b = copy.deepcopy(self.bundle)
        b["verificationMaterial"] = {"publicKey": {"hint": "k1"}}
        b["dsseEnvelope"]["signatures"][0]["keyid"] = "k1"
        r = sigstore.verify_bundle(b, artifact=b"artifact", public_key=pem)
        self.assertIs(r["verified"], True, r["error"])
        for other in ("k2", None):
            b2 = copy.deepcopy(b)
            if other is None:
                del b2["dsseEnvelope"]["signatures"][0]["keyid"]
            else:
                b2["dsseEnvelope"]["signatures"][0]["keyid"] = other
            r = sigstore.verify_bundle(b2, artifact=b"artifact", public_key=pem)
            self.assertIs(r["verified"], False)
            self.assertIn("MUST be exactly the same", r["error"])
        b2 = copy.deepcopy(b)
        b2["dsseEnvelope"]["signatures"][0]["keyid"] = 5
        self.assertIn("keyid is not a string", sigstore.verify_bundle(b2, public_key=pem)["error"])

    def test_caller_key_must_be_the_certificate_key(self):
        pem = self.k.public_key().public_bytes(serialization.Encoding.PEM,
                                               serialization.PublicFormat.SubjectPublicKeyInfo)
        self._ok(self.bundle, public_key=pem)
        k2 = ec.generate_private_key(ec.SECP256R1())
        b = copy.deepcopy(self.bundle)
        b["dsseEnvelope"] = U._sign_env(k2, self.payload, self.signed)
        pem2 = k2.public_key().public_bytes(serialization.Encoding.PEM,
                                            serialization.PublicFormat.SubjectPublicKeyInfo)
        r = sigstore.verify_bundle(b, artifact=b"artifact", public_key=pem2)
        self.assertIs(r["verified"], False)
        self.assertIn("not the key of the bundle's certificate", r["error"])

    def test_caller_ed25519_key_must_be_the_certificate_key(self):
        """the same rule with Ed25519 keys (a certificate the reader accepts as well)"""
        from cryptography.hazmat.primitives.asymmetric import ed25519
        k1, k2 = ed25519.Ed25519PrivateKey.generate(), ed25519.Ed25519PrivateKey.generate()
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        cert = (x509.CertificateBuilder().subject_name(U._name("ed")).issuer_name(U._name("ed"))
                .public_key(k1.public_key()).serial_number(5).not_valid_before(now - dt.timedelta(hours=1))
                .not_valid_after(now + dt.timedelta(hours=1)).sign(k1, None))
        env = {"payload": base64.b64encode(self.payload).decode(), "payloadType": dsse.PAYLOAD_TYPE,
               "signatures": [{"sig": base64.b64encode(k1.sign(self.signed)).decode()}]}
        b = {"mediaType": self.bundle["mediaType"], "dsseEnvelope": env, "verificationMaterial": {
            "certificate": {"rawBytes": base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()}}}
        pem = {k: k.public_key().public_bytes(serialization.Encoding.PEM,
                                              serialization.PublicFormat.SubjectPublicKeyInfo) for k in (k1, k2)}
        r = sigstore.verify_bundle(b, artifact=b"artifact", public_key=pem[k1])
        self.assertIs(r["verified"], True, r["error"])
        r = sigstore.verify_bundle(b, artifact=b"artifact", public_key=pem[k2])
        self.assertIs(r["verified"], False)
        self.assertIn("not the key of the bundle's certificate", r["error"])

    def test_valid_for_is_listed_as_not_verified(self):
        r = self._ok(self.bundle)
        self.assertTrue(any("valid_for" in x for x in r["not_verified"]))

    def test_media_types_and_log_index_zero(self):
        self.assertEqual(sorted(sigstore.MEDIA_TYPES), sorted([   # the four the proto says clients must accept
            "application/vnd.dev.sigstore.bundle.v0.3+json", "application/vnd.dev.sigstore.bundle+json;version=0.1",
            "application/vnd.dev.sigstore.bundle+json;version=0.2", "application/vnd.dev.sigstore.bundle+json;version=0.3"]))
        for mt in sigstore.MEDIA_TYPES:
            b = copy.deepcopy(self.msg)
            b["mediaType"] = mt
            r = self._ok(b)
            self.assertEqual(r["bundle_version"], mt[-8:].split("=")[-1].replace("+json", "")[-3:])
        b = copy.deepcopy(self.msg)
        del b["verificationMaterial"]["tlogEntries"][0]["logIndex"]
        self.assertEqual(self._ok(b)["tlog_entries"][0]["log_index"], 0)

    def test_signing_time_before_the_certificate(self):
        """a token made BEFORE the leaf certificate's notBefore (the mirror of the notAfter case)"""
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        leaf = (x509.CertificateBuilder().subject_name(U._name("late")).issuer_name(U._name("late"))
                .public_key(self.k.public_key()).serial_number(77)
                .not_valid_before(now + dt.timedelta(hours=1)).not_valid_after(now + dt.timedelta(hours=2))
                .sign(self.k, hashes.SHA256()))
        b = copy.deepcopy(self.bundle)
        b["verificationMaterial"]["certificate"]["rawBytes"] = base64.b64encode(
            leaf.public_bytes(serialization.Encoding.DER)).decode()
        r = self._no(b, "outside the leaf certificate's validity")
        self.assertIs(r["checks"]["signing_time_in_certificate"], False)

    def test_certificate_not_read_without_cryptography(self):
        with mock.patch.object(sigstore, "_cert_facts", return_value={"sha256": "x", "read": False}):
            r = sigstore.verify_bundle(self.bundle, artifact=b"artifact", **self.kw)
        self.assertIs(r["verified"], False)
        self.assertIsNone(r["checks"]["signing_time_in_certificate"])

    def test_bad_arguments_are_an_error_not_an_exception(self):
        for kw, want in (({"artifact": "artifact"}, "artifact must be bytes"),
                         ({"tsa_at_gen_time": "yes"}, "tsa_at_gen_time"),
                         ({"tsa_untrusted": ""}, "tsa_untrusted"),
                         ({"tsa_ca_file": 5}, "tsa_ca_file")):
            args = dict(self.kw, **kw)
            r = sigstore.verify_bundle(self.bundle, **args)
            self.assertIs(r["verified"], False)
            self.assertIn(want, r["error"])


for _n in dir(U.TestSigstoreBundle):   # its own tests run in test_uso_reale_20261118, not twice
    if _n.startswith("test_"):
        setattr(TestBundle, _n, None)


class TestGenTimeRange(U.LocalTsa):
    def test_gen_time_before_1970_is_refused_with_its_reason(self):
        self._tsa("tsa_r")
        dg = hashlib.sha256(b"x").hexdigest()
        tok = self._token("tsa_r", dg)
        with mock.patch.object(T, "gen_time_of", return_value=-1):
            r = T.verify(tok, dg, ca_file=self._p("root.pem"), untrusted=self._p("tsa_r.untrusted.pem"),
                         at_gen_time=True)
        self.assertIs(r["verified"], False)
        self.assertIn("genTime could not be read", r["reason"])


if __name__ == "__main__":
    unittest.main()
