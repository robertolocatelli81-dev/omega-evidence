#!/usr/bin/env python3
# Copyright 2026 Roberto Locatelli — Apache-2.0
"""timestamp.verify on an RFC 3161 token whose SignerInfo names its signer by subjectKeyIdentifier (0.12.0).

RFC 5652 §5.3 allows `sid` to be issuerAndSerialNumber or subjectKeyIdentifier. `openssl ts -verify` reads the token as
PKCS #7 and refuses the second form with an ASN.1 error, so until 0.12.0 a valid token of that kind was
`verified: False` here (the same defect cryptovalid-opencore measured in its 0.25.1; ported from its SPEC §11 step 7).

Everything is made with openssl on this machine: a CA and TSA certificates carrying a subjectKeyIdentifier, a reply of
`openssl ts -reply`, and the same TSTInfo re-signed by `openssl cms -sign -keyid -cades` (sid = subjectKeyIdentifier,
an ESS signingCertificateV2 attribute), wrapped in a granted TimeStampResp. Positive control: `openssl ts -verify`
refuses the re-signed token (test_openssl_ts_refuses_it) and 0.11.4 answered `verified: False` (measured on the tag
v0.11.4 with this file); now it is `verified: True`. Negatives: another digest, a certificate without timeStamping,
no ESS attribute, another CA, a `tsa` field naming another TSA, a reply not granted, a changed signature byte."""
import base64
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from omega_evidence import timestamp as T  # noqa: E402

EXE = shutil.which("openssl")
DIGEST = hashlib.sha256(b"an evidence pack manifest").hexdigest()
OID_TSTINFO = "1.2.840.113549.1.9.16.1.4"
EXT = ("[ v3_ca ]\nbasicConstraints = critical,CA:TRUE\nkeyUsage = critical,keyCertSign,cRLSign\n"
       "subjectKeyIdentifier = hash\n"
       "[ v3_tsa ]\nextendedKeyUsage = critical,timeStamping\nbasicConstraints = CA:FALSE\n"
       "subjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid\n"
       "[ v3_plain ]\nbasicConstraints = CA:FALSE\nkeyUsage = critical,digitalSignature\nsubjectKeyIdentifier = hash\n")


def _run(*cmd):
    return subprocess.run(cmd, check=True, capture_output=True)


def _tlv(tag, v):
    n = len(v)
    ln = bytes([n]) if n < 0x80 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag]) + ln + v


def reply(token_der, status=0):
    """a TimeStampResp {PKIStatusInfo {status}, token}"""
    return _tlv(0x30, _tlv(0x30, _tlv(0x02, bytes([status]))) + token_der)


class Lab:
    """a CA with a subjectKeyIdentifier and the certificates it issued; replies by openssl ts, re-signed by openssl cms"""

    def __init__(self, td, name):
        self.d = os.path.join(td, name)
        os.makedirs(self.d)
        j = self.j
        with open(j("ext.cnf"), "w") as f:
            f.write(EXT)
        with open(j("req.cnf"), "w") as f:
            f.write("[ req ]\ndistinguished_name = dn\n[ dn ]\n" + EXT)
        _run(EXE, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout",
             j("ca.key"), "-out", j("ca.crt"), "-subj", f"/CN={name}-ca", "-days", "2", "-config", j("req.cnf"),
             "-extensions", "v3_ca")
        for cert, ext in (("tsa", "v3_tsa"), ("tsa2", "v3_tsa"), ("plain", "v3_plain"), ("tsab", "v3_tsa")):
            if cert == "tsab":   # a second certificate for the key of "tsa": same subjectKeyIdentifier, another hash
                _run(EXE, "req", "-new", "-key", j("tsa.key"), "-out", j("tsab.csr"), "-subj", f"/CN={name}-tsab",
                     "-config", j("req.cnf"))
            else:
                _run(EXE, "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout",
                     j(f"{cert}.key"), "-out", j(f"{cert}.csr"), "-subj", f"/CN={name}-{cert}", "-config", j("req.cnf"))
            _run(EXE, "x509", "-req", "-in", j(f"{cert}.csr"), "-CA", j("ca.crt"), "-CAkey", j("ca.key"),
                 "-CAcreateserial", "-out", j(f"{cert}.crt"), "-days", "2", "-extfile", j("ext.cnf"), "-extensions", ext)
        with open(j("serial"), "w") as f:
            f.write("01\n")

    def j(self, n):
        return os.path.join(self.d, n)

    def tsr(self, tsa_name=False):
        """a granted reply of `openssl ts -reply` (sid = issuerAndSerialNumber)"""
        j = self.j
        with open(j("tsa.cnf"), "w") as f:
            f.write(f"[ tsa ]\ndefault_tsa = t1\n[ t1 ]\nserial = {j('serial')}\ncrypto_device = builtin\n"
                    f"signer_cert = {j('tsa.crt')}\ncerts = {j('ca.crt')}\nsigner_key = {j('tsa.key')}\n"
                    "signer_digest = sha256\ndefault_policy = 1.2.3.4.1\ndigests = sha256\naccuracy = secs:1\n"
                    f"ordering = yes\ntsa_name = {'yes' if tsa_name else 'no'}\ness_cert_id_chain = no\n"
                    "ess_cert_id_alg = sha256\n")
        _run(EXE, "ts", "-query", "-digest", DIGEST, "-sha256", "-cert", "-out", j("q.tsq"))
        _run(EXE, "ts", "-reply", "-queryfile", j("q.tsq"), "-config", j("tsa.cnf"), "-section", "t1", "-out", j("r.tsr"))
        with open(j("r.tsr"), "rb") as f:
            return f.read()

    def tstinfo(self, tsr):
        j = self.j
        with open(j("in.tsr"), "wb") as f:
            f.write(tsr)
        _run(EXE, "ts", "-reply", "-in", j("in.tsr"), "-token_out", "-out", j("in.der"))
        _run(EXE, "cms", "-verify", "-noverify", "-inform", "DER", "-in", j("in.der"), "-out", j("tst.der"))
        with open(j("tst.der"), "rb") as f:
            return f.read()

    def resign_other_cert(self, tst):
        """signed by the key of "tsa" through its second certificate "tsab" (the ESS certHash is tsab's), the token
        carrying "tsa" instead of "tsab": openssl cms finds "tsa" by the key identifier and the signature verifies"""
        j = self.j
        with open(j("tst_in.der"), "wb") as f:
            f.write(tst)
        with open(j("ca_tsa.pem"), "wb") as f:
            f.write(open(j("ca.crt"), "rb").read() + open(j("tsa.crt"), "rb").read())
        _run(EXE, "cms", "-sign", "-binary", "-nodetach", "-econtent_type", OID_TSTINFO, "-keyid", "-cades", "-md",
             "sha256", "-nosmimecap", "-nocerts", "-signer", j("tsab.crt"), "-inkey", j("tsa.key"),
             "-certfile", j("ca_tsa.pem"), "-in", j("tst_in.der"), "-outform", "DER", "-out", j("ski.der"))
        with open(j("ski.der"), "rb") as f:
            return f.read()

    def resign(self, tst, signer="tsa", ess=True):
        """`tst` (a TSTInfo) signed by openssl cms with `signer`'s key, the signer named by its key identifier"""
        j = self.j
        with open(j("tst_in.der"), "wb") as f:
            f.write(tst)
        _run(EXE, "cms", "-sign", "-binary", "-nodetach", "-econtent_type", OID_TSTINFO, "-keyid",
             *(["-cades"] if ess else []), "-md", "sha256", "-nosmimecap", "-signer", j(f"{signer}.crt"),
             "-inkey", j(f"{signer}.key"), "-certfile", j("ca.crt"), "-in", j("tst_in.der"), "-outform", "DER",
             "-out", j("ski.der"))
        with open(j("ski.der"), "rb") as f:
            return f.read()


def b64(b):
    return base64.b64encode(b).decode()


@unittest.skipUnless(EXE, "openssl absent: the local TSA cannot be built")
class TestSignerNamedByKeyId(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.td = tempfile.mkdtemp(prefix="tsa_keyid_")
        cls.a, cls.b = Lab(cls.td, "laba"), Lab(cls.td, "labb")
        cls.tsr_ias = cls.a.tsr()
        cls.tst = cls.a.tstinfo(cls.tsr_ias)
        cls.tsr_ski = reply(cls.a.resign(cls.tst))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.td, ignore_errors=True)

    def v(self, tsr, ca="a", digest=DIGEST):
        return T.verify(b64(tsr), digest, ca_file=getattr(self, ca).j("ca.crt"))

    def test_control_issuer_and_serial_form_verified(self):
        r = self.v(self.tsr_ias)
        self.assertIs(r["verified"], True, r)
        self.assertNotIn("signer_named_by", r)

    def test_openssl_ts_refuses_it(self):   # the cause: openssl ts cannot read the key-identified form
        p = os.path.join(self.td, "ski.tsr")
        with open(p, "wb") as f:
            f.write(self.tsr_ski)
        r = subprocess.run([EXE, "ts", "-verify", "-in", p, "-digest", DIGEST, "-CAfile", self.a.j("ca.crt")],
                           capture_output=True, text=True)
        self.assertFalse(r.returncode == 0 and "Verification: OK" in r.stdout, r.stdout + r.stderr)

    def test_key_identified_signer_verified(self):   # positive control: verified False on v0.11.4
        r = self.v(self.tsr_ski)
        self.assertEqual((r["verified"], r["crypto_verified"], r["granted"], r["imprint_ok"], r["signer_named_by"]),
                         (True, True, True, True, "subjectKeyIdentifier"), r)

    def test_other_digest(self):
        r = self.v(self.tsr_ski, digest=hashlib.sha256(b"another").hexdigest())
        self.assertEqual((r["verified"], r["imprint_ok"], r["crypto_verified"]), (False, False, True), r)

    def test_other_ca(self):
        r = self.v(self.tsr_ski, ca="b")
        self.assertEqual((r["verified"], r["crypto_verified"]), (False, False), r)

    def test_signer_without_timestamping(self):
        r = self.v(reply(self.a.resign(self.tst, signer="plain")))
        self.assertIs(r["verified"], False, r)

    def test_no_ess_attribute(self):
        r = self.v(reply(self.a.resign(self.tst, ess=False)))
        self.assertIs(r["verified"], False, r)
        self.assertIn("ESS", r["note"])

    def test_tsa_field(self):
        tst = self.a.tstinfo(self.a.tsr(tsa_name=True))
        self.assertIs(self.v(reply(self.a.resign(tst)))["verified"], True)              # names the signer: verified
        r = self.v(reply(self.a.resign(tst, signer="tsa2")))                             # names another TSA of the CA
        self.assertIs(r["verified"], False, r)
        self.assertIn("tsa field", r["note"])
        up = tst.replace(b"laba-tsa", b"LABA-tsa")                                       # same name in other letter case
        self.assertNotEqual(up, tst)
        self.assertIs(self.v(reply(self.a.resign(up)))["verified"], True)              # X509_NAME_cmp: equal
        other = tst.replace(b"laba-tsa", b"labx-tsa")
        self.assertIs(self.v(reply(self.a.resign(other)))["verified"], False)

    def test_ess_cert_hash_of_another_certificate(self):
        r = self.v(reply(self.a.resign_other_cert(self.tst)))
        self.assertEqual((r["verified"], r["crypto_verified"]), (False, False), r)
        self.assertIn("certHash", r["note"])

    def test_not_granted(self):
        r = self.v(reply(self.a.resign(self.tst), status=2))
        self.assertIs(r["verified"], False, r)

    def test_changed_signature_byte(self):
        tok = bytearray(self.a.resign(self.tst))
        tok[-5] ^= 0x01                                                                  # inside the signature value
        r = self.v(reply(bytes(tok)))
        self.assertEqual((r["verified"], r["crypto_verified"]), (False, False), r)

    def test_without_ca_file_never_green(self):
        self.assertIsNone(T.verify(b64(self.tsr_ski), DIGEST)["verified"])


if __name__ == "__main__":
    unittest.main()
