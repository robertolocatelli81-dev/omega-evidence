#!/usr/bin/env python3
# Copyright 2026 Roberto Locatelli — Apache-2.0
"""RFC 4998 section 5.3 step 2: "Each Archive Timestamp MUST be valid relative to the time of the following Archive
Timestamp"; only the last one "has to be valid at the time the verification is performed".

Until this change verify_evidence_record checked every RFC 3161 token of a renewal chain at the current time, so the
expiry of a TSA certificate turned a correctly renewed record into a FAIL: the case renewal exists to cover. Measured
on 2026-11-14 with a real token (rfc3161-client test/fixtures/identrust/issue-104.tsr, TSA certificate valid until
2026-01-17, genTime 2025-03-11): `openssl ts -verify` FAILED ("certificate has expired") without -attime, OK at genTime.

The TSAs here are local (cryptography builds the certificates, with expiries in seconds; openssl ts -reply signs the
tokens); nothing leaves the machine."""
import base64
import calendar
import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from omega_evidence import preservation as PR  # noqa: E402
from omega_evidence import timestamp as T  # noqa: E402

EXE = shutil.which("openssl")
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    HAVE_CRYPTO = True
except ImportError:  # pragma: no cover
    HAVE_CRYPTO = False

CNF = """[ tsa ]
default_tsa = t
[ t ]
serial = {d}/serial
crypto_device = builtin
signer_cert = {d}/{n}.crt
certs = {d}/ca.crt
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


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _key_pem(k):
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


@unittest.skipUnless(EXE and HAVE_CRYPTO, "openssl or cryptography absent: the local TSAs cannot be built")
class TestValidityTimeOfRenewedTokens(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="rfc4998_")
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        cls.ca_key = ec.generate_private_key(ec.SECP256R1())
        ca = (x509.CertificateBuilder().subject_name(_name("t-ca")).issuer_name(_name("t-ca"))
              .public_key(cls.ca_key.public_key()).serial_number(1)
              .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=2))
              .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
              .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
              .sign(cls.ca_key, hashes.SHA256()))
        cls.ca = ca
        with open(cls._p("ca.crt"), "wb") as f:
            f.write(ca.public_bytes(serialization.Encoding.PEM))
        with open(cls._p("serial"), "w") as f:
            f.write("01\n")
        cls.serial = 10

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    @classmethod
    def _p(cls, n):
        return os.path.join(cls.d, n)

    @classmethod
    def _tsa(cls, name, seconds):
        """A TSA certificate valid from one day ago until `seconds` from now."""
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        k = ec.generate_private_key(ec.SECP256R1())
        cls.serial += 1
        c = (x509.CertificateBuilder().subject_name(_name(name)).issuer_name(cls.ca.subject)
             .public_key(k.public_key()).serial_number(cls.serial)
             .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(seconds=seconds))
             .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
             .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
             .sign(cls.ca_key, hashes.SHA256()))
        with open(cls._p(name + ".crt"), "wb") as f:
            f.write(c.public_bytes(serialization.Encoding.PEM))
        with open(cls._p(name + ".key"), "wb") as f:
            f.write(_key_pem(k))
        with open(cls._p(name + ".cnf"), "w") as f:
            f.write(CNF.format(d=cls.d, n=name))
        return calendar.timegm(c.not_valid_after_utc.utctimetuple())

    @classmethod
    def _token(cls, name, digest_hex):
        q, r = cls._p("q.tsq"), cls._p("r.tsr")
        subprocess.run([EXE, "ts", "-query", "-digest", digest_hex, "-sha256", "-cert", "-out", q],
                       check=True, capture_output=True)
        subprocess.run([EXE, "ts", "-reply", "-queryfile", q, "-config", cls._p(name + ".cnf"), "-section", "t",
                        "-out", r], check=True, capture_output=True)
        with open(r, "rb") as f:
            return base64.b64encode(f.read()).decode()

    def _stamper(self, names):
        """stamp() replaced by the local TSAs, in order: one name per call."""
        queue = list(names)

        def fake(digest_hex, tsa_url, timeout=20):
            n = queue.pop(0)
            if n is None:
                return {"anchored": False, "note": "no TSA"}
            if n == "":                                   # a TSA reply recorded without its token
                return {"anchored": True, "tsa": "local:none", "tsr_b64": ""}
            return {"anchored": True, "tsa": "local:" + n, "tsr_b64": self._token(n, digest_hex)}
        return fake

    def _pack(self):
        p = self._p("pack_%d.json" % self.serial)
        self.serial += 1
        with open(p, "w") as f:
            json.dump({"pack_sha3": hashlib.sha3_256(p.encode()).hexdigest()}, f)
        return p

    def _record(self, names, gaps):
        """Record stamped by names[0], then one renewal per further name; gaps[i] seconds slept before renewal i."""
        with mock.patch.object(T, "stamp", self._stamper(names)):
            with mock.patch.object(PR, "_pack_sha3_of", lambda p: hashlib.sha3_256(p.encode()).hexdigest()):
                rec = PR.build_evidence_record([self._pack()], tsa_url="http://local.invalid/")
                for g in gaps:
                    time.sleep(g)
                    rec = PR.renew_timestamp(rec, tsa_url="http://local.invalid/")
        return rec

    @staticmethod
    def _wait_until(t):
        while time.time() < t + 1.2:
            time.sleep(0.2)

    @staticmethod
    def _time_layers(res):
        return [(x["layer"], x["status"]) for x in res["layers"] if x["layer"].startswith("time[")]

    def test_renewed_before_expiry_passes_after_expiry(self):
        exp = self._tsa("short_a", 4)
        self._tsa("long_a", 3600)
        rec = self._record(["short_a", "long_a"], [1])
        self._wait_until(exp)
        res = PR.verify_evidence_record(rec, tsa_ca_file=self._p("ca.crt"))
        self.assertEqual(self._time_layers(res), [("time[0]-rfc3161", "PASS"), ("time[1]-rfc3161", "PASS")], res)
        self.assertTrue(res["valid"], res)

    def test_renewed_after_expiry_fails(self):
        exp = self._tsa("short_b", 2)
        self._tsa("long_b", 3600)
        rec = self._record(["short_b"], [])
        self._wait_until(exp)
        with mock.patch.object(T, "stamp", self._stamper(["long_b"])):
            rec = PR.renew_timestamp(rec, tsa_url="http://local.invalid/")
        res = PR.verify_evidence_record(rec, tsa_ca_file=self._p("ca.crt"))
        self.assertEqual(self._time_layers(res), [("time[0]-rfc3161", "FAIL"), ("time[1]-rfc3161", "PASS")], res)
        self.assertFalse(res["valid"])

    def test_last_token_must_be_valid_now(self):
        exp = self._tsa("short_c", 2)
        rec = self._record(["short_c"], [])
        self._wait_until(exp)
        res = PR.verify_evidence_record(rec, tsa_ca_file=self._p("ca.crt"))
        self.assertEqual(self._time_layers(res), [("time[0]-rfc3161", "FAIL")], res)
        detail = [x["detail"] for x in res["layers"] if x["layer"] == "time[0]-rfc3161"][0]
        self.assertIn("expired", detail)

    def test_asserted_renewal_gives_no_trusted_time(self):
        exp = self._tsa("short_d", 3)
        rec = self._record(["short_d", None], [1])
        self._wait_until(exp)
        res = PR.verify_evidence_record(rec, tsa_ca_file=self._p("ca.crt"))
        self.assertEqual(self._time_layers(res), [("time[0]-rfc3161", "FAIL"), ("time[1]-asserted", "SKIP")], res)

    def test_asserted_between_two_tokens_keeps_the_later_trusted_time(self):
        exp = self._tsa("short_e", 4)
        self._tsa("long_e", 3600)
        rec = self._record(["short_e", None, "long_e"], [0.5, 0.5])
        self._wait_until(exp)
        res = PR.verify_evidence_record(rec, tsa_ca_file=self._p("ca.crt"))
        self.assertEqual(self._time_layers(res), [("time[0]-rfc3161", "PASS"), ("time[1]-asserted", "SKIP"),
                                                  ("time[2]-rfc3161", "PASS")], res)

    def test_untrusted_renewal_gives_no_trusted_time(self):
        exp = self._tsa("short_f", 4)
        self._tsa("long_f", 3600)
        rec = self._record(["short_f", "long_f"], [1])
        self._wait_until(exp)
        # the renewal token is tampered after the fact: it no longer verifies, so it proves no time for entry 0
        tok = base64.b64decode(rec["archive_timestamps"][1]["timestamp"]["tsr_b64"])
        i = len(tok) - 10
        rec["archive_timestamps"][1]["timestamp"]["tsr_b64"] = base64.b64encode(
            tok[:i] + bytes([tok[i] ^ 1]) + tok[i + 1:]).decode()
        res = PR.verify_evidence_record(rec, tsa_ca_file=self._p("ca.crt"))
        self.assertEqual(self._time_layers(res), [("time[0]-rfc3161", "FAIL"), ("time[1]-rfc3161", "FAIL")], res)

    def test_following_dated_before_this_one_fails(self):
        self._tsa("long_h", 3600)
        rec = self._record(["long_h", "long_h"], [1])
        real = T.gen_time_of
        toks = [a["timestamp"]["tsr_b64"] for a in rec["archive_timestamps"]]
        # the genTime read for the LATER token is set one hour before the earlier one
        fake = lambda tok, timeout=15: real(tok) - 3600 if tok == toks[1] else real(tok)  # noqa: E731
        with mock.patch.object(T, "gen_time_of", fake):
            res = PR.verify_evidence_record(rec, tsa_ca_file=self._p("ca.crt"))
        lay = {x["layer"]: x for x in res["layers"]}
        self.assertEqual(lay["time[0]-rfc3161"]["status"], "FAIL", res)
        self.assertIn("dated before", lay["time[0]-rfc3161"]["detail"])
        with mock.patch.object(T, "gen_time_of", lambda tok, timeout=15: None):
            res = PR.verify_evidence_record(rec, tsa_ca_file=self._p("ca.crt"))
        self.assertEqual(self._time_layers(res), [("time[0]-rfc3161", "PASS"), ("time[1]-rfc3161", "PASS")], res)
        unread = lambda tok, timeout=15: None if tok == toks[0] else real(tok)  # noqa: E731
        with mock.patch.object(T, "gen_time_of", unread):
            res = PR.verify_evidence_record(rec, tsa_ca_file=self._p("ca.crt"))
        lay = {x["layer"]: x for x in res["layers"]}
        self.assertEqual(lay["time[0]-rfc3161"]["status"], "FAIL", res)
        self.assertIn("not readable", lay["time[0]-rfc3161"]["detail"])

    def _three(self, tag):
        exp = self._tsa("short_" + tag, 5)
        self._tsa("long_" + tag, 3600)
        rec = self._record(["short_" + tag, "long_" + tag, "long_" + tag], [0.5, 1.2])
        self._wait_until(exp)
        return rec, [a["timestamp"]["tsr_b64"] for a in rec["archive_timestamps"]]

    def test_no_time_passes_through_a_broken_middle_entry(self):
        rec, toks = self._three("i")
        base = self._time_layers(PR.verify_evidence_record(rec, tsa_ca_file=self._p("ca.crt")))
        self.assertEqual(base, [("time[0]-rfc3161", "PASS"), ("time[1]-rfc3161", "PASS"), ("time[2]-rfc3161", "PASS")])
        real_gen, real_verify = T.gen_time_of, T.verify
        # (a) the last entry is dated before the middle one, so the middle one fails its ordering; its own genTime
        # (inside the short TSA's validity) then proves nothing for entry 0
        with mock.patch.object(T, "gen_time_of", lambda tok, timeout=15: real_gen(tok) - 5 if tok == toks[2]
                               else real_gen(tok)):
            got = self._time_layers(PR.verify_evidence_record(rec, tsa_ca_file=self._p("ca.crt")))
        self.assertEqual(got, [("time[0]-rfc3161", "FAIL"), ("time[1]-rfc3161", "FAIL"), ("time[2]-rfc3161", "PASS")])
        # (b) the middle entry has no token
        bad = json.loads(json.dumps(rec))
        del bad["archive_timestamps"][1]["timestamp"]["tsr_b64"]
        got = self._time_layers(PR.verify_evidence_record(bad, tsa_ca_file=self._p("ca.crt")))
        self.assertEqual(got, [("time[0]-rfc3161", "FAIL"), ("time[1]-rfc3161", "FAIL"), ("time[2]-rfc3161", "PASS")])

        # (c) the middle entry is recorded but not verified (SKIP)
        def skip_middle(tok, digest, timeout=15, ca_file=None, at_time=None):
            if tok == toks[1]:
                return {"verified": None, "note": "not verified"}
            return real_verify(tok, digest, timeout=timeout, ca_file=ca_file, at_time=at_time)
        with mock.patch.object(T, "verify", skip_middle):
            got = self._time_layers(PR.verify_evidence_record(rec, tsa_ca_file=self._p("ca.crt")))
        self.assertEqual(got, [("time[0]-rfc3161", "FAIL"), ("time[1]-rfc3161", "SKIP"), ("time[2]-rfc3161", "PASS")])

    def test_token_over_other_data_lends_no_time(self):
        """A timestamp renewal is checked over its prev_binding: an extra merkle_root naming the data of a foreign token
        (genuine, from a trusted TSA, made before the first TSA expired) does not make the expired entry PASS."""
        exp = self._tsa("short_j", 4)
        self._tsa("long_j", 3600)
        rec = self._record(["short_j"], [])
        other = hashlib.sha256(b"other data").hexdigest()
        alien = self._token("long_j", other)
        self._wait_until(exp)
        prev = rec["archive_timestamps"][-1]
        alg = prev["hash_alg"]
        rec = json.loads(json.dumps(rec))
        rec["archive_timestamps"].append({"seq": prev["seq"] + 1, "type": "timestamp-renewal", "hash_alg": alg,
                                          "covers": "previous-archive-timestamp",
                                          "prev_binding": PR._prev_binding(prev, alg), "merkle_root": other,
                                          "timestamp": {"time_source": "rfc3161", "tsa": "local:long_j",
                                                        "tsr_b64": alien},
                                          "created_utc": prev.get("created_utc", "")})
        rec = PR._finalize(rec)
        res = PR.verify_evidence_record(rec, tsa_ca_file=self._p("ca.crt"))
        self.assertEqual(self._time_layers(res), [("time[0]-rfc3161", "FAIL"), ("time[1]-rfc3161", "FAIL")], res)
        self.assertFalse(res["valid"])

    def test_broken_link_lends_no_time(self):
        """No time crosses an entry that does not bind the one before it."""
        exp = self._tsa("short_k", 4)
        self._tsa("long_k", 3600)
        rec = self._record(["short_k", "long_k"], [1])
        self._wait_until(exp)
        with mock.patch.object(PR, "_prev_binding", lambda prev, alg: "0" * 64):
            res = PR.verify_evidence_record(rec, tsa_ca_file=self._p("ca.crt"))
        self.assertEqual(self._time_layers(res), [("time[0]-rfc3161", "FAIL"), ("time[1]-rfc3161", "PASS")], res)

    def test_hash_tree_renewal_lends_its_time(self):
        exp = self._tsa("short_o", 4)
        self._tsa("long_o", 3600)
        rec = self._record(["short_o"], [])
        time.sleep(1)
        with mock.patch.object(T, "stamp", self._stamper(["long_o"])):
            rec = PR.renew_hash_tree(rec, None, "sha3_256", tsa_url="http://local.invalid/")
        self._wait_until(exp)
        res = PR.verify_evidence_record(rec, tsa_ca_file=self._p("ca.crt"))
        self.assertEqual(self._time_layers(res), [("time[0]-rfc3161", "PASS"), ("time[1]-rfc3161", "PASS")], res)
        self.assertTrue(res["valid"], res)

    def test_gen_time_before_its_own_certificate_lends_no_time(self):
        """A renewal token whose genTime precedes its own TSA certificate (openssl ts -verify does not compare them)
        is FAIL and lends no time to the expired entry before it."""
        exp = self._tsa("short_l", 4)
        now = calendar.timegm(time.gmtime())
        k = ec.generate_private_key(ec.SECP256R1())
        type(self).serial += 1
        c = (x509.CertificateBuilder().subject_name(_name("late_l")).issuer_name(self.ca.subject)
             .public_key(k.public_key()).serial_number(self.serial)
             .not_valid_before(dt.datetime.fromtimestamp(now + 2, dt.timezone.utc))
             .not_valid_after(dt.datetime.fromtimestamp(now + 3600, dt.timezone.utc))
             .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
             .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
             .sign(self.ca_key, hashes.SHA256()))
        with open(self._p("late_l.crt"), "wb") as f:
            f.write(c.public_bytes(serialization.Encoding.PEM))
        with open(self._p("late_l.key"), "wb") as f:
            f.write(_key_pem(k))
        with open(self._p("late_l.cnf"), "w") as f:
            f.write(CNF.format(d=self.d, n="late_l"))
        rec = self._record(["short_l", "late_l"], [0])        # late_l signs before its notBefore
        self._wait_until(max(exp, now + 2))
        res = PR.verify_evidence_record(rec, tsa_ca_file=self._p("ca.crt"))
        self.assertEqual(self._time_layers(res), [("time[0]-rfc3161", "FAIL"), ("time[1]-rfc3161", "FAIL")], res)
        self.assertIn("own genTime", [x["detail"] for x in res["layers"] if x["layer"] == "time[1]-rfc3161"][0])

    def test_gen_time_out_of_range_is_a_fail_not_a_malformed_record(self):
        self._tsa("long_m", 3600)
        rec = self._record(["long_m", "long_m"], [1])
        toks = [a["timestamp"]["tsr_b64"] for a in rec["archive_timestamps"]]
        real = T.gen_time_of
        for bad in (-144720000, 253402300800):
            with mock.patch.object(T, "gen_time_of", lambda tok, timeout=15, b=bad: b if tok == toks[1] else real(tok)):
                res = PR.verify_evidence_record(rec, tsa_ca_file=self._p("ca.crt"))
            self.assertNotIn("record-malformed", [x["layer"] for x in res["layers"]], res)
            self.assertEqual(self._time_layers(res), [("time[0]-rfc3161", "PASS"), ("time[1]-rfc3161", "FAIL")], res)

    def test_verify_at_time_bounds_and_reason(self):
        self._tsa("long_n", 3600)
        dig = hashlib.sha256(b"n").hexdigest()
        tok = self._token("long_n", dig)
        ca = self._p("ca.crt")
        for edge in (0, 253402300799):
            r = T.verify(tok, dig, ca_file=ca, at_time=edge)
            self.assertIs(r["verified"], False, r)
            self.assertTrue(r["reason"], r)
        self.assertNotIn("reason", T.verify(tok, dig, ca_file=ca))
        der = self._p("ca.der")
        with open(der, "wb") as f:
            f.write(self.ca.public_bytes(serialization.Encoding.DER))
        r = T.verify(tok, dig, ca_file=der)
        self.assertIs(r["verified"], False, r)
        self.assertTrue(r["reason"] and not r["reason"].endswith(".c") and not r["reason"].isdigit(), r)
        self.assertNotIn("loading file", r["reason"], r)      # the last error line, not the first

    def test_tokenless_middle_entry_lends_no_time(self):
        """A middle entry that declares rfc3161 without a token, correctly bound by the next one, lends no time."""
        exp = self._tsa("short_p", 4)
        self._tsa("long_p", 3600)
        rec = self._record(["short_p", "", "long_p"], [0.5, 0.5])
        self._wait_until(exp)
        res = PR.verify_evidence_record(rec, tsa_ca_file=self._p("ca.crt"))
        self.assertEqual([x["status"] for x in res["layers"] if x["layer"].startswith("renewal[")], ["PASS", "PASS"])
        self.assertEqual(self._time_layers(res), [("time[0]-rfc3161", "FAIL"), ("time[1]-rfc3161", "FAIL"),
                                                  ("time[2]-rfc3161", "PASS")], res)

    def test_middle_entry_with_an_unknown_time_source_lends_no_time(self):
        """20/11/2026: a middle entry whose time_source is neither rfc3161 nor asserted, correctly bound by the next one,
        is a FAIL and no later genTime crosses it (an asserted middle entry keeps the later time: the test above)."""
        exp = self._tsa("short_q", 4)
        self._tsa("long_q", 3600)
        with mock.patch.object(T, "stamp", self._stamper(["short_q", None, "long_q"])):
            with mock.patch.object(PR, "_pack_sha3_of", lambda p: hashlib.sha3_256(p.encode()).hexdigest()):
                rec = PR.build_evidence_record([self._pack()], tsa_url="http://local.invalid/")
                time.sleep(0.5)
                rec = PR.renew_timestamp(rec, tsa_url="http://local.invalid/")
                rec["archive_timestamps"][1]["timestamp"] = {"time_source": "bogus"}
                rec = PR._finalize(rec)
                time.sleep(0.5)
                rec = PR.renew_timestamp(rec, tsa_url="http://local.invalid/")
        self._wait_until(exp)
        res = PR.verify_evidence_record(rec, tsa_ca_file=self._p("ca.crt"))
        self.assertEqual([x["status"] for x in res["layers"] if x["layer"].startswith("renewal[")], ["PASS", "PASS"])
        self.assertEqual(self._time_layers(res), [("time[0]-rfc3161", "FAIL"), ("time[1]-source", "FAIL"),
                                                  ("time[2]-rfc3161", "PASS")], res)

    def test_gen_time_of_needs_a_clean_openssl_exit(self):
        fake = mock.Mock(return_value=mock.Mock(returncode=1, stdout="Time stamp: Mar 11 08:52:08 2025 GMT\n"))
        with mock.patch.object(T, "_run_openssl", fake):
            self.assertIsNone(T.gen_time_of(base64.b64encode(b"x").decode()))
        fake.return_value = mock.Mock(returncode=0, stdout="Time stamp: Mar 11 08:52:08 2025 GMT\n")
        with mock.patch.object(T, "_run_openssl", fake):
            self.assertEqual(T.gen_time_of(base64.b64encode(b"x").decode()), 1741683128)

    def test_verify_at_time(self):
        exp = self._tsa("short_g", 2)
        dig = hashlib.sha256(b"x").hexdigest()
        tok = self._token("short_g", dig)
        gen = T.gen_time_of(tok)
        self.assertIsInstance(gen, int)
        self.assertLessEqual(abs(gen - time.time()), 5)
        self._wait_until(exp)
        ca = self._p("ca.crt")
        self.assertFalse(T.verify(tok, dig, ca_file=ca)["verified"])
        self.assertTrue(T.verify(tok, dig, ca_file=ca, at_time=gen)["verified"])
        self.assertFalse(T.verify(tok, dig, ca_file=ca, at_time=exp + 2)["verified"])
        self.assertFalse(T.verify(tok, dig, ca_file=ca, at_time=gen - 3 * 86400)["verified"])
        for bad in (True, 1.5, "1", -1, float("nan")):
            with self.assertRaises(ValueError):
                T.verify(tok, dig, ca_file=ca, at_time=bad)


class TestGenTimeText(unittest.TestCase):
    def test_forms(self):
        f = T._gen_time_from_text
        self.assertEqual(f("x\nTime stamp: Mar 11 08:52:08 2025 GMT\ny"), 1741683128)
        self.assertEqual(f("Time stamp: Mar 11 08:52:08.250 2025 GMT"), 1741683128)
        self.assertEqual(f("Time stamp: May  9 11:58:55 2025 GMT"), calendar.timegm((2025, 5, 9, 11, 58, 55)))
        for bad in ("", "Time stamp: Mar 11 08:52:08 2025 UTC", "Time stamp: Foo 11 08:52:08 2025 GMT",
                    "Time stamp: Feb 30 08:52:08 2025 GMT", "Time stamp: Mar 11 25:00:00 2025 GMT",
                    "Time stamp: Mar 11 08:52:08 2025 GMT\nTime stamp: Mar 11 08:52:08 2025 GMT",
                    " Time stamp: Mar 11 08:52:08 2025 GMT", "Time stamp: Mar 11 08:52:08 2025 GMT ",
                    "Time stamp: Mar 11 08:52:08 \u0662\u0660\u0662\u0665 GMT", "Time stamp: Mar \uff11\uff11 08:52:08 2025 GMT"):
            self.assertIsNone(f(bad), bad)

    def test_generated_never_raises(self):
        import random
        rnd = random.Random(20261114)
        alphabet = "Time stamp:JanFebMayDec GMTUTC0123456789 .:\n\t\r-+Z\u00e9\u0660"
        for _ in range(20000):
            s = "".join(rnd.choice(alphabet) for _ in range(rnd.randint(0, 50)))
            v = T._gen_time_from_text(s)
            self.assertTrue(v is None or isinstance(v, int), s)

    def test_gen_time_of_refuses_non_tokens(self):
        for bad in (None, "", 5, "AAAA", "!!!", "A", base64.b64encode(b"\x30\x03\x02\x01\x00").decode()):
            self.assertIsNone(T.gen_time_of(bad), bad)


class TestSinglePackReason(unittest.TestCase):
    """The rfc3161 layer of a pack says why a token failed (openssl's reason), and never on a PASS."""

    def test_reason_on_fail_only(self):
        from omega_evidence import verifier as V
        d = tempfile.mkdtemp()
        try:
            p = os.path.join(d, "p.json")
            with open(p, "wb") as f:
                f.write(b"{}")
            with open(os.path.join(d, "p.tsr.json"), "w") as f:
                json.dump({"digest_sha256": hashlib.sha256(b"{}").hexdigest(), "tsa": "t", "tsr_b64": "AAAA"}, f)
            for ret, status, has in (({"verified": False, "reason": "certificate has expired"}, "FAIL", True),
                                     ({"verified": True, "reason": "certificate has expired"}, "PASS", False)):
                layers = []
                with mock.patch.object(T, "verify", return_value=ret):
                    self.assertEqual(V._check_timestamp(p, layers), status)
                self.assertEqual("certificate has expired" in layers[-1]["detail"], has, layers)
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
