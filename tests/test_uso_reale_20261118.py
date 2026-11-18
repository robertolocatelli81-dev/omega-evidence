# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""0.12.0 — what real third-party material from GitHub needs (measured 18/11/2026 on 0.11.4: DSSE 0/24, RFC 3161 0/17).

  * interop.dsse.from_dsse: ECDSA P-256 / SHA-256 (DER and raw r||s), keys as SPKI or X.509 certificate (PEM/DER);
    every answer that is not verified carries `error` (until 0.11.4: `verified False, error None` for a valid ECDSA
    envelope and for a tampered one alike);
  * timestamp.verify: `untrusted=` (openssl -untrusted), `at_gen_time=` (openssl -attime at the token's genTime),
    `reason` for a refused token, the token without signer certificate named as such;
  * interop.sigstore.verify_bundle: closed reader of sigstore bundles, offline checks, `not_verified` always listed;
  * interop.sdjwt.verify: a `...` key that conveys no digest and an `_sd_alg` below the top level are named in the
    result (RFC 9901 §4.1 item 7 binds the issuer; §7.1 names no rejection);
  * README quick start runs as written.
Each class fails on 381f881 (the 0.12.0 branch before these changes): see the delivery note of 18/11/2026.
"""
import base64
import calendar
import copy
import datetime as dt
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from omega_evidence import timestamp as T  # noqa: E402
from omega_evidence.interop import dsse, sdjwt, sigstore  # noqa: E402
from omega_evidence.signing import Identity  # noqa: E402

EXE = shutil.which("openssl")
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover
    HAVE_CRYPTO = False

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(key, cn="leaf", issuer_key=None, issuer_name=None, seconds=3600, eku=None):
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    b = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(issuer_name or _name(cn))
         .public_key(key.public_key()).serial_number(random.getrandbits(60) + 1)
         .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(seconds=seconds)))
    if eku:
        b = b.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        b = b.add_extension(x509.ExtendedKeyUsage(eku), critical=True)
    elif issuer_key is None:
        b = b.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    return b.sign(issuer_key or key, hashes.SHA256())


def _envelope(statement=None):
    payload = json.dumps(statement or {"_type": dsse.STATEMENT_TYPE, "subject": [
        {"name": "a.bin", "digest": {"sha256": hashlib.sha256(b"artifact").hexdigest()}}],
        "predicateType": "https://slsa.dev/provenance/v1", "predicate": {}}).encode()
    return payload, dsse.pae(dsse.PAYLOAD_TYPE, payload)


def _sign_env(key, payload, signed, raw=False):
    sig = key.sign(signed, ec.ECDSA(hashes.SHA256()))
    if raw:
        r, s = decode_dss_signature(sig)
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return {"payload": base64.b64encode(payload).decode(), "payloadType": dsse.PAYLOAD_TYPE,
            "signatures": [{"sig": base64.b64encode(sig).decode()}]}


def _tamper(env):
    e = copy.deepcopy(env)
    raw = bytearray(base64.b64decode(e["payload"]))
    raw[len(raw) // 2] ^= 1
    e["payload"] = base64.b64encode(bytes(raw)).decode()
    return e


@unittest.skipUnless(HAVE_CRYPTO, "cryptography absent: ECDSA is not checked here (see TestWithoutCryptography)")
class TestDsseEcdsa(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.k = ec.generate_private_key(ec.SECP256R1())
        cls.pub = cls.k.public_key()
        cls.spki_der = cls.pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        cls.spki_pem = cls.pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        cls.cert = _cert(cls.k)
        cls.payload, cls.signed = _envelope()
        cls.env = _sign_env(cls.k, cls.payload, cls.signed)

    def test_every_key_form_verifies(self):
        for kw in ({"public_key": self.spki_pem}, {"public_key": self.spki_pem.decode()},
                   {"public_key": self.spki_der}, {"public_key": self.cert.public_bytes(serialization.Encoding.PEM)},
                   {"public_key": self.cert.public_bytes(serialization.Encoding.DER)},
                   {"public_key_b64": base64.b64encode(self.spki_der).decode()},
                   {"public_key_b64": base64.b64encode(self.cert.public_bytes(serialization.Encoding.DER)).decode()}):
            r = dsse.from_dsse(self.env, **kw)
            self.assertIs(r["verified"], True, (list(kw), r.get("error")))
            self.assertNotIn("error", r)
            self.assertTrue(r["key_source"].startswith("caller"), r["key_source"])

    def test_raw_r_s_signature(self):
        env = _sign_env(self.k, self.payload, self.signed, raw=True)
        self.assertEqual(len(base64.b64decode(env["signatures"][0]["sig"])), 64)
        self.assertIs(dsse.from_dsse(env, public_key=self.spki_pem)["verified"], True)

    def test_dsse_spec_ecdsa_vector(self):
        """protocol.md of DSSE v1.0.2, "Test Vectors": ECDSA P-256 / SHA-256, raw r||s, payloadType
        http://example.com/HelloWorld — read with the in-toto payloadType check out of the way (only PAE + signature)."""
        x = 46950820868899156662930047687818585632848591499744589407958293238635476079160
        y = 5640078356564379163099075877009565129882514886557779369047442380624545832820
        pub = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
        sig = base64.b64decode("A3JqsQGtVsJ2O2xqrI5IcnXip5GToJ3F+FnZ+O88SjtR6rDAajabZKciJTfUiHqJPcIAriEGAHTVeCUjW2JIZA==")
        signed = dsse.pae("http://example.com/HelloWorld", b"hello world")
        self.assertEqual(signed, b"DSSEv1 29 http://example.com/HelloWorld 11 hello world")
        self.assertTrue(dsse._ecdsa_verify(pub, sig, signed))
        self.assertFalse(dsse._ecdsa_verify(pub, sig, signed + b"!"))

    def test_tampered_and_wrong_key_are_refused_with_a_reason(self):
        other = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        for env, key in ((_tamper(self.env), self.spki_pem), (self.env, other)):
            r = dsse.from_dsse(env, public_key=key)
            self.assertIs(r["verified"], False)
            self.assertIn("does not verify", r["error"])

    def test_no_key_is_an_error_not_a_bare_false(self):
        r = dsse.from_dsse(self.env)
        self.assertIs(r["verified"], False)
        self.assertIn("no verification key", r["error"])

    def test_unsupported_and_malformed_keys(self):
        p384 = ec.generate_private_key(ec.SECP384R1()).public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        rsak = rsa.generate_private_key(65537, 2048).public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        cases = {"ECDSA on secp384r1": {"public_key": p384}, "RSAPublicKey": {"public_key": rsak},
                 "exactly one block": {"public_key": self.spki_pem + self.spki_pem},
                 "is not PUBLIC KEY or CERTIFICATE": {"public_key": self.spki_pem.replace(b"PUBLIC KEY", b"EC PARAMS")},
                 "must be PEM": {"public_key": "not a key"}, "PEM text or PEM/DER bytes": {"public_key": 5},
                 "neither a DER": {"public_key": b"\x30\x03\x02\x01\x01"},
                 "not both": {"public_key": self.spki_pem, "public_key_b64": "AAAA"},
                 "is not base64": {"public_key_b64": "a b"},
                 "non-empty base64": {"public_key_b64": ""}}
        for want, kw in cases.items():
            r = dsse.from_dsse(self.env, **kw)
            self.assertIs(r["verified"], False, want)
            self.assertIn(want, r["error"], (want, r["error"]))

    def test_non_strict_der_is_not_accepted(self):
        sig = base64.b64decode(self.env["signatures"][0]["sig"])
        # BER long-form length for the SEQUENCE: same r and s, not DER
        ber = b"\x30\x81" + bytes([sig[1]]) + sig[2:]
        env = copy.deepcopy(self.env)
        env["signatures"][0]["sig"] = base64.b64encode(ber).decode()
        self.assertIs(dsse.from_dsse(env, public_key=self.spki_pem)["verified"], False)
        env["signatures"][0]["sig"] = base64.b64encode(sig + b"\x00").decode()
        self.assertIs(dsse.from_dsse(env, public_key=self.spki_pem)["verified"], False)

    def test_generative_every_false_has_an_error(self):
        """mutations of the envelope at each level (keys, types, values): verified is True only for the original;
        every other answer has an error string."""
        rnd = random.Random(20261118)
        values = [None, 0, 1.5, True, "", "x", [], {}, [{}], {"sig": ""}, "A" * 8, "é"]
        n = 0
        for _ in range(400):
            env = copy.deepcopy(self.env)
            where = rnd.choice(["top", "sig", "new_top", "new_sig", "del"])
            if where == "top":
                env[rnd.choice(["payload", "payloadType", "signatures"])] = rnd.choice(values)
            elif where == "sig":
                env["signatures"][0][rnd.choice(["sig", "keyid", "publicKeyB64"])] = rnd.choice(values)
            elif where == "new_top":
                env["x%d" % rnd.randrange(9)] = rnd.choice(values)
            elif where == "new_sig":
                env["signatures"][0]["y%d" % rnd.randrange(9)] = rnd.choice(values)
            else:
                env.pop(rnd.choice(["payload", "payloadType", "signatures"]))
            r = dsse.from_dsse(env, public_key=self.spki_pem)
            if r["verified"] is not True:
                self.assertTrue(isinstance(r.get("error"), str) and r["error"], (env, r))
                n += 1
        self.assertGreater(n, 150)

    def test_unrecognized_fields_are_ignored_and_named(self):
        """DSSE envelope.md v1.0.2: "Consumers MUST ignore unrecognized fields" — the rule of the format wins; the
        result names them"""
        env = copy.deepcopy(self.env)
        env["cert"] = "x"
        env["signatures"][0]["extra"] = 1
        r = dsse.from_dsse(env, public_key=self.spki_pem)
        self.assertIs(r["verified"], True)
        self.assertEqual(r["unrecognized_fields"], ["cert", "signatures[0].extra"])

    def test_ed25519_unchanged(self):
        ident = Identity("t", seed=bytes(range(32)))
        env = dsse.to_dsse({"pack_sha3": "00" * 32}, ident)
        r = dsse.from_dsse(env)
        self.assertIs(r["verified"], True)
        self.assertIn("envelope publicKeyB64", r["key_source"])
        self.assertIs(dsse.from_dsse(_tamper(env))["verified"], False)
        spki = ed25519.Ed25519PublicKey.from_public_bytes(base64.b64decode(ident.public_key_b64)).public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.assertIs(dsse.from_dsse(env, public_key=spki)["verified"], True)


class TestWithoutCryptography(unittest.TestCase):
    def test_ecdsa_key_without_cryptography_is_named(self):
        """an ECDSA key where cryptography is missing: an error that says so, never a bare False"""
        der = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004") + b"\x04" * 64
        with mock.patch.object(dsse, "_crypto", lambda: None):
            with self.assertRaises(ValueError) as cm:
                dsse.load_public_key(der)
        self.assertIn("cryptography package", str(cm.exception))

    def test_ed25519_spki_without_cryptography(self):
        ident = Identity("t", seed=bytes(range(32)))
        env = dsse.to_dsse({"pack_sha3": "00" * 32}, ident)
        spki = dsse._ED25519_SPKI_PREFIX + base64.b64decode(ident.public_key_b64)
        with mock.patch.object(dsse, "_crypto", lambda: None):
            self.assertIs(dsse.from_dsse(env, public_key=spki)["verified"], True)


CNF = """[ t ]
serial = {d}/serial
crypto_device = builtin
signer_cert = {d}/{n}.crt
signer_key = {d}/{n}.key
signer_digest = sha256
default_policy = 1.2.3.4.1
digests = sha256
accuracy = secs:1
ordering = yes
tsa_name = no
ess_cert_id_chain = no
ess_cert_id_alg = sha256
"""


@unittest.skipUnless(EXE and HAVE_CRYPTO, "openssl or cryptography absent: the local TSA cannot be built")
class LocalTsa(unittest.TestCase):
    """a CA, an intermediate and TSA leaves; tokens WITHOUT certificates, as sigstore's and GitHub's TSAs make them"""
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="uso_reale_")
        cls.ca_key = ec.generate_private_key(ec.SECP256R1())
        cls.ca = _cert(cls.ca_key, "t-root", seconds=86400 * 2)
        cls.int_key = ec.generate_private_key(ec.SECP256R1())
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        cls.inter = (x509.CertificateBuilder().subject_name(_name("t-int")).issuer_name(cls.ca.subject)
                     .public_key(cls.int_key.public_key()).serial_number(2)
                     .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=2))
                     .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                     .sign(cls.ca_key, hashes.SHA256()))
        cls._w("root.pem", cls.ca.public_bytes(serialization.Encoding.PEM))
        cls._w("serial", b"01\n")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    @classmethod
    def _p(cls, n):
        return os.path.join(cls.d, n)

    @classmethod
    def _w(cls, n, data):
        with open(cls._p(n), "wb") as f:
            f.write(data)
        return cls._p(n)

    @classmethod
    def _tsa(cls, name, seconds=3600):
        k = ec.generate_private_key(ec.SECP256R1())
        c = _cert(k, name, cls.int_key, cls.inter.subject, seconds, eku=[ExtendedKeyUsageOID.TIME_STAMPING])
        cls._w(name + ".crt", c.public_bytes(serialization.Encoding.PEM))
        cls._w(name + ".key", k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                              serialization.NoEncryption()))
        with open(cls._p(name + ".cnf"), "w") as f:
            f.write(CNF.format(d=cls.d, n=name))
        cls._w(name + ".untrusted.pem", c.public_bytes(serialization.Encoding.PEM)
               + cls.inter.public_bytes(serialization.Encoding.PEM))
        return calendar.timegm(c.not_valid_after_utc.utctimetuple())

    @classmethod
    def _token(cls, name, digest_hex, with_cert=False):
        q, r = cls._p("q.tsq"), cls._p("r.tsr")
        subprocess.run([EXE, "ts", "-query", "-digest", digest_hex, "-sha256"] + (["-cert"] if with_cert else [])
                       + ["-out", q], check=True, capture_output=True)
        subprocess.run([EXE, "ts", "-reply", "-queryfile", q, "-config", cls._p(name + ".cnf"), "-section", "t",
                        "-out", r], check=True, capture_output=True)
        with open(r, "rb") as f:
            return base64.b64encode(f.read()).decode()


class TestTimestampUntrustedAndGenTime(LocalTsa):
    def test_token_without_certificate_needs_untrusted(self):
        self._tsa("tsa_a")
        dg = hashlib.sha256(b"sig").hexdigest()
        tok = self._token("tsa_a", dg)
        r = T.verify(tok, dg, ca_file=self._p("root.pem"))
        self.assertIs(r["verified"], False)
        self.assertIn("no TSA signer certificate", r["reason"])
        r = T.verify(tok, dg, ca_file=self._p("root.pem"), untrusted=self._p("tsa_a.untrusted.pem"))
        self.assertIs(r["verified"], True, r)
        self.assertEqual(r["validation_time"], "now")
        r = T.verify(tok, "11" * 32, ca_file=self._p("root.pem"), untrusted=self._p("tsa_a.untrusted.pem"))
        self.assertIs(r["verified"], False)
        self.assertTrue(r["reason"])
        # only the leaf as untrusted: the intermediate is missing, the chain does not build
        with open(self._p("tsa_a.crt"), "rb") as f:
            leaf = self._w("leaf_only.pem", f.read())
        r = T.verify(tok, dg, ca_file=self._p("root.pem"), untrusted=leaf)
        self.assertIs(r["verified"], False)
        self.assertTrue(r["reason"])

    def test_expired_tsa_certificate_at_gen_time(self):
        exp = self._tsa("tsa_short", 3)
        dg = hashlib.sha256(b"sig2").hexdigest()
        tok = self._token("tsa_short", dg)
        while time.time() < exp + 1.5:
            time.sleep(0.2)
        kw = dict(ca_file=self._p("root.pem"), untrusted=self._p("tsa_short.untrusted.pem"))
        now = T.verify(tok, dg, **kw)
        self.assertIs(now["verified"], False)
        self.assertIn("expired", now["reason"])
        at = T.verify(tok, dg, at_gen_time=True, **kw)
        self.assertIs(at["verified"], True, at)
        self.assertEqual(at["validation_time"], "gen_time")
        self.assertIn("revocation is not checked", at["validation_time_rule"])
        self.assertEqual(at["validated_at"], dt.datetime.fromtimestamp(T.gen_time_of(tok), dt.timezone.utc)
                         .strftime("%Y-%m-%dT%H:%M:%SZ"))

    def test_parameters_are_closed(self):
        self._tsa("tsa_p")
        dg = hashlib.sha256(b"p").hexdigest()
        tok = self._token("tsa_p", dg)
        for kw in ({"at_gen_time": 1}, {"at_gen_time": "yes"}, {"at_gen_time": True, "at_time": 5},
                   {"untrusted": ""}, {"untrusted": 5}, {"untrusted": b"/x"}):
            with self.assertRaises(ValueError, msg=kw):
                T.verify(tok, dg, ca_file=self._p("root.pem"), **kw)
        r = T.verify(tok, dg, ca_file=self._p("root.pem"), untrusted=self._p("nope.pem"))
        self.assertIs(r["verified"], False)
        self.assertIn("not readable", r["reason"])
        r = T.verify(tok, dg, ca_file=self._p("root.pem"), untrusted=self._p("tsa_p.cnf"))
        self.assertIn("no PEM certificate", r["reason"])

    def test_ski_path_takes_untrusted_and_at_gen_time(self):
        """the subjectKeyIdentifier path (_tsa_keyid) reads the caller's untrusted certificates and the instant too:
        without them a token with no certificate is refused with that reason"""
        from omega_evidence import _tsa_keyid
        facts = {"certificates": [], "token_der": b"", "granted": True, "imprint_hex": "", "tst_info": None}
        r = _tsa_keyid.check("openssl", facts, "ca", self.d, 5, None, None)
        self.assertIn("no TSA signer certificate", r["why"])
        seen = []

        def run(cmd, **kw):
            seen.append(cmd)
            return subprocess.CompletedProcess(cmd, 1, b"", b"")
        _tsa_keyid.check("openssl", dict(facts, certificates=[]), "ca", self.d, 5, run, lambda p, d: None,
                         untrusted_pem=b"PEM", at_time=123)
        self.assertIn("-certfile", seen[0])


class TestSigstoreBundle(LocalTsa):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._tsa("tsa_b")
        cls.k = ec.generate_private_key(ec.SECP256R1())
        cls.leaf = _cert(cls.k, "signer", seconds=600)
        cls.payload, cls.signed = _envelope()
        env = _sign_env(cls.k, cls.payload, cls.signed)
        sig = base64.b64decode(env["signatures"][0]["sig"])
        tok = cls._token("tsa_b", hashlib.sha256(sig).hexdigest())
        cls.bundle = {"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                      "verificationMaterial": {
                          "certificate": {"rawBytes": base64.b64encode(cls.leaf.public_bytes(
                              serialization.Encoding.DER)).decode()},
                          "timestampVerificationData": {"rfc3161Timestamps": [{"signedTimestamp": tok}]}},
                      "dsseEnvelope": env}
        art = b"artifact"
        msig = cls.k.sign(art, ec.ECDSA(hashes.SHA256()))
        mtok = cls._token("tsa_b", hashlib.sha256(msig).hexdigest())
        cls.msg = {"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.2",
                   "verificationMaterial": {
                       "x509CertificateChain": {"certificates": [{"rawBytes": base64.b64encode(
                           cls.leaf.public_bytes(serialization.Encoding.DER)).decode()}]},
                       "tlogEntries": [{"logIndex": "7", "logId": {"keyId": "AAEC"},
                                        "kindVersion": {"kind": "hashedrekord", "version": "0.0.1"},
                                        "integratedTime": "1700000000",
                                        "inclusionPromise": {"signedEntryTimestamp": "AAEC"}}],
                       "timestampVerificationData": {"rfc3161Timestamps": [{"signedTimestamp": mtok}]}},
                   "messageSignature": {"messageDigest": {"algorithm": "SHA2_256", "digest": base64.b64encode(
                       hashlib.sha256(art).digest()).decode()}, "signature": base64.b64encode(msig).decode()}}
        cls.kw = dict(tsa_ca_file=cls._p("root.pem"), tsa_untrusted=cls._p("tsa_b.untrusted.pem"))

    def test_dsse_bundle(self):
        r = sigstore.verify_bundle(self.bundle, artifact=b"artifact", **self.kw)
        self.assertIs(r["verified"], True, r["error"])
        self.assertEqual(r["checks"], {"signature": True, "artifact": True, "rfc3161[0]": True,
                                       "signing_time_in_certificate": True})
        self.assertEqual(r["not_verified"], list(sigstore.NOT_VERIFIED))
        self.assertIn("Fulcio", r["not_verified"][0])
        self.assertEqual(r["statement"]["predicateType"], "https://slsa.dev/provenance/v1")

    def test_message_signature_bundle(self):
        r = sigstore.verify_bundle(self.msg, artifact=b"artifact", **self.kw)
        self.assertIs(r["verified"], True, r["error"])
        self.assertEqual(r["tlog_entries"][0]["log_index"], 7)
        self.assertIsNone(r["tlog_entries"][0]["verified"])
        r = sigstore.verify_bundle(self.msg, **self.kw)   # over the bundle's own messageDigest
        self.assertIs(r["verified"], True, r["error"])
        for art in (b"artifacT", b""):
            r = sigstore.verify_bundle(self.msg, artifact=art, **self.kw)
            self.assertIs(r["verified"], False)
            self.assertTrue(r["error"])

    def test_tampered_and_partial(self):
        b = copy.deepcopy(self.bundle)
        b["dsseEnvelope"] = _tamper(b["dsseEnvelope"])
        r = sigstore.verify_bundle(b, **self.kw)
        self.assertIs(r["verified"], False)
        self.assertIn("signature", r["error"])
        r = sigstore.verify_bundle(self.bundle, artifact=b"other", **self.kw)
        self.assertIs(r["verified"], False)
        self.assertIn("not a subject", r["error"])
        r = sigstore.verify_bundle(self.bundle)   # no TSA anchor: the token is not verified, so neither is the bundle
        self.assertIs(r["verified"], False)
        self.assertIsNone(r["checks"]["rfc3161[0]"])
        self.assertIn("no TSA trust anchor", r["error"])

    def test_proto_field_names_and_closed_reader(self):
        b = copy.deepcopy(self.bundle)
        b["verification_material"] = b.pop("verificationMaterial")
        b["verification_material"]["timestamp_verification_data"] = b["verification_material"].pop(
            "timestampVerificationData")
        self.assertIs(sigstore.verify_bundle(b, **self.kw)["verified"], True)
        bad = []
        # an unknown key at every level read
        for path in ([], ["verificationMaterial"], ["verificationMaterial", "certificate"],
                     ["verificationMaterial", "timestampVerificationData"],
                     ["verificationMaterial", "timestampVerificationData", "rfc3161Timestamps", 0],
                     ["dsseEnvelope"], ["dsseEnvelope", "signatures", 0]):
            b = copy.deepcopy(self.bundle)
            node = b
            for p in path:
                node = node[p]
            node["zz"] = 1
            bad.append((b, "unknown field 'zz'"))
        b = copy.deepcopy(self.bundle)
        b["media_type"] = b["mediaType"]
        bad.append((b, "given twice"))
        b = copy.deepcopy(self.bundle)
        b["messageSignature"] = self.msg["messageSignature"]
        bad.append((b, "exactly one of messageSignature"))
        b = copy.deepcopy(self.bundle)
        b["verificationMaterial"]["publicKey"] = {"hint": "x"}
        bad.append((b, "exactly one of publicKey"))
        for mt in ("application/vnd.dev.sigstore.bundle.v0.4+json", "", None, 3):
            b = copy.deepcopy(self.bundle)
            b["mediaType"] = mt
            bad.append((b, "mediaType"))
        b = copy.deepcopy(self.bundle)
        b["dsseEnvelope"]["signatures"].append(b["dsseEnvelope"]["signatures"][0])
        bad.append((b, "exactly one signature"))
        b = copy.deepcopy(self.msg)
        b["messageSignature"]["messageDigest"]["algorithm"] = "MD5"
        bad.append((b, "messageDigest.algorithm"))
        b = copy.deepcopy(self.msg)
        b["verificationMaterial"]["tlogEntries"][0]["logIndex"] = "07"
        bad.append((b, "logIndex is not an integer"))
        b = copy.deepcopy(self.bundle)
        b["verificationMaterial"]["certificate"]["rawBytes"] = "!!"
        bad.append((b, "not base64"))
        bad.append(({"base64Signature": "x", "cert": "y"}, "cosign legacy bundle"))
        bad.append(("[", "not JSON"))
        bad.append(([], "Bundle is not a JSON object"))
        for b, want in bad:
            r = sigstore.verify_bundle(b, **self.kw)
            self.assertIs(r["verified"], False, want)
            self.assertIn(want, r["error"], (want, r["error"]))

    def test_generative_mutations_never_verify_silently(self):
        rnd = random.Random(1118)
        values = [None, 0, -1, 1.5, True, "", "x", "AAEC", [], {}, [{}], {"a": 1}]
        for _ in range(300):
            b = copy.deepcopy(rnd.choice([self.bundle, self.msg]))
            # pick a random dict node and change, add or remove a member
            nodes, stack = [], [b]
            while stack:
                n = stack.pop()
                if isinstance(n, dict):
                    nodes.append(n)
                    stack.extend(n.values())
                elif isinstance(n, list):
                    stack.extend(n)
            n = rnd.choice(nodes)
            op = rnd.choice(["set", "add", "del"])
            if op == "set" and n:
                n[rnd.choice(list(n))] = rnd.choice(values)
            elif op == "del" and n:
                n.pop(rnd.choice(list(n)))
            else:
                n["k%d" % rnd.randrange(5)] = rnd.choice(values)
            r = sigstore.verify_bundle(b, artifact=b"artifact", **self.kw)
            if r["verified"] is not True:
                self.assertTrue(isinstance(r["error"], str) and r["error"], r)
            self.assertEqual(r["not_verified"][:4], list(sigstore.NOT_VERIFIED))

    def test_bundle_as_text_is_closed(self):
        """a bundle given as JSON text: a member named twice (json.loads would keep the last, another parser the first),
        NaN, nesting beyond 512 and bytes that are not UTF-8 are refused with the reason"""
        txt = json.dumps(self.bundle)
        self.assertIs(sigstore.verify_bundle(txt, **self.kw)["verified"], True)
        self.assertIs(sigstore.verify_bundle(txt.encode(), **self.kw)["verified"], True)
        self.assertIs(sigstore.verify_bundle(bytearray(txt.encode()), **self.kw)["verified"], True)
        other = base64.b64encode(b'{"_type":"x"}').decode()
        cases = [(txt[:-1] + ', "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json"}', "given twice"),
                 (txt.replace('"dsseEnvelope": {', '"dsseEnvelope": {"payload": "%s", ' % other, 1), "given twice"),
                 (txt.replace('"signatures": [{', '"signatures": [{"sig": "AAEC", ', 1), "given twice"),
                 (txt[:-1] + ', "zz": NaN}', "non-standard JSON constant"),
                 ("[" * 600 + "]" * 600, "nesting exceeds 512"),
                 ("[" * 100000, "nesting exceeds 512"),
                 (b"\xff\xfe{}", "not UTF-8"), ("", "not JSON"), ("{", "not JSON")]
        for b, want in cases:
            r = sigstore.verify_bundle(b, **self.kw)
            self.assertIs(r["verified"], False, want)
            self.assertIn(want, r["error"], (want, r["error"]))

    def test_bundle_without_token_says_the_signing_time_is_not_verified(self):
        """8 of the 25 real bundles of 18/11/2026 carry a log entry and no RFC 3161 token: the signature is checked,
        the time of signing is not, and the result says so"""
        b = copy.deepcopy(self.bundle)
        del b["verificationMaterial"]["timestampVerificationData"]
        r = sigstore.verify_bundle(b, artifact=b"artifact")
        self.assertIs(r["verified"], True, r["error"])
        self.assertEqual(r["checks"], {"signature": True, "artifact": True})
        self.assertEqual(len(r["not_verified"]), 5)
        self.assertIn("time of signing", r["not_verified"][4])
        r = sigstore.verify_bundle(self.bundle, artifact=b"artifact", **self.kw)
        self.assertEqual(r["not_verified"], list(sigstore.NOT_VERIFIED))


@unittest.skipUnless(HAVE_CRYPTO, "cryptography absent")
class TestSdJwtReservedNamesInClear(unittest.TestCase):
    def test_reserved_names_in_clear(self):
        ident = Identity("iss", seed=bytes(range(32)))
        good = sdjwt.issue({"given_name": "A"}, ident, plain_claims={"iss": "x"})
        self.assertIs(sdjwt.verify(good, ident.public_key_b64, require_key_binding=False)["verified"], True)

        def forged(payload):
            h = {"alg": "EdDSA", "typ": "dc+sd-jwt"}
            enc = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()  # noqa: E731
            si = enc(h) + "." + enc(payload)
            sig = base64.urlsafe_b64encode(base64.b64decode(ident.sign(si.encode()))).rstrip(b"=").decode()
            return si + "." + sig + "~"
        # RFC 9901 §7.1 names no rejection for these (§4.1 item 7 and §4.1.1 bind the issuer): verified as the steps
        # leave them, and NAMED in the result — until 0.11.4 nothing said they were there
        for payload, want in (({"iss": "x", "...": "hidden"}, {"...": 1}),
                              ({"iss": "x", "a": {"...": "hidden"}}, {"...": 1}),
                              ({"iss": "x", "a": {"_sd_alg": "sha-256"}}, {"_sd_alg": 1}),
                              ({"iss": "x", "a": [{"...": 5}]}, {"...": 1}),
                              ({"iss": "x", "a": [{"...": "d", "b": 1}], "c": {"...": 1, "_sd_alg": "x"}},
                               {"...": 2, "_sd_alg": 1})):
            r = sdjwt.verify(forged(dict(payload, _sd_alg="sha-256")), ident.public_key_b64,
                             require_key_binding=False)
            self.assertIs(r["verified"], True, r)
            self.assertEqual(r["reserved_names_in_clear"], want, payload)
        for payload in ({"iss": "x"}, {"iss": "x", "a": [{"...": "no-such-digest"}]}):   # a digest, or nothing: no note
            r = sdjwt.verify(forged(dict(payload, _sd_alg="sha-256")), ident.public_key_b64,
                             require_key_binding=False)
            self.assertIs(r["verified"], True, r)
            self.assertNotIn("reserved_names_in_clear", r)


class TestReadmeQuickStart(unittest.TestCase):
    def test_quick_start_runs_as_written(self):
        """the Python block under "## Quick start", executed as written in an empty folder. Its TSA call goes to the
        network only with OMEGA_EVIDENCE_NET=1; otherwise stamp_pack is replaced by a no-op (the block's text is not
        changed). Until this fix it ended in AssertionError ("this pack is not anchored")."""
        with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as f:
            text = f.read()
        block = text.split("## Quick start", 1)[1].split("```python\n", 1)[1].split("```", 1)[0]
        from omega_evidence import pack
        d = tempfile.mkdtemp(prefix="qs_")
        cwd = os.getcwd()
        try:
            os.chdir(d)
            if os.environ.get("OMEGA_EVIDENCE_NET") == "1":
                exec(compile(block, "README quick start", "exec"), {})
            else:
                with mock.patch.object(pack, "stamp_pack", lambda *a, **k: {"anchored": False}):
                    exec(compile(block, "README quick start", "exec"), {})
        finally:
            os.chdir(cwd)
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
