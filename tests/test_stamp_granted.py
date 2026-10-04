#!/usr/bin/env python3
# Copyright 2026 Roberto Locatelli — Apache-2.0
"""timestamp.stamp() records anchored: True ONLY for a granted RFC 3161 token whose imprint is the requested digest
(2026-10-03: any HTTP body — an error page, a rejection, a token for another digest — was recorded as anchored: True).
A local TSA built with openssl answers over a local HTTP server; nothing leaves the machine."""
import base64
import hashlib
import http.server
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from omega_evidence import timestamp as T  # noqa: E402

EXE = shutil.which("openssl")
CNF = """[ tsa ]
default_tsa = t1
[ t1 ]
serial = {d}/serial
crypto_device = builtin
signer_cert = {d}/tsa.crt
certs = {d}/ca.crt
signer_key = {d}/tsa.key
signer_digest = sha256
default_policy = 1.2.3.4.1
digests = sha256
accuracy = secs:1
ordering = yes
tsa_name = no
ess_cert_id_chain = no
ess_cert_id_alg = sha256
[ v3_tsa ]
extendedKeyUsage = critical,timeStamping
basicConstraints = CA:FALSE
"""


def _read(path):
    with open(path, "rb") as f:
        return f.read()


def _run(*a):
    subprocess.run(list(a), check=True, capture_output=True)


@unittest.skipUnless(EXE, "openssl absent: stamp() returns anchored False by contract (tested elsewhere)")
class TestStampOnlyGrantedTokenForThisDigest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = d = tempfile.mkdtemp(prefix="tsa_")
        with open(os.path.join(d, "tsa.cnf"), "w") as f:
            f.write(CNF.format(d=d))
        with open(os.path.join(d, "serial"), "w") as f:
            f.write("01\n")
        j = lambda n: os.path.join(d, n)  # noqa: E731
        _run(EXE, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", j("ca.key"),
             "-out", j("ca.crt"), "-subj", "/CN=test-ca", "-days", "2")
        _run(EXE, "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", j("tsa.key"),
             "-out", j("tsa.csr"), "-subj", "/CN=test-tsa")
        _run(EXE, "x509", "-req", "-in", j("tsa.csr"), "-CA", j("ca.crt"), "-CAkey", j("ca.key"), "-CAcreateserial",
             "-out", j("tsa.crt"), "-days", "2", "-extfile", j("tsa.cnf"), "-extensions", "v3_tsa")
        with open(j("chain.pem"), "w") as f:
            f.write((_read(j("ca.crt")) + _read(j("tsa.crt"))).decode("ascii"))
        cls.mode = "honest"

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                q = self.rfile.read(int(self.headers["Content-Length"]))
                body = cls._answer(q)
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        cls.srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.srv.server_address[1]}/"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        shutil.rmtree(cls.d, ignore_errors=True)

    @classmethod
    def _reply(cls, query_bytes):
        q, r = os.path.join(cls.d, "q.tsq"), os.path.join(cls.d, "r.tsr")
        with open(q, "wb") as f:
            f.write(query_bytes)
        _run(EXE, "ts", "-reply", "-queryfile", q, "-config", os.path.join(cls.d, "tsa.cnf"), "-section", "t1", "-out", r)
        return _read(r)

    @classmethod
    def _query(cls, digest_hex, *extra):
        q = os.path.join(cls.d, "other.tsq")
        _run(EXE, "ts", "-query", "-digest", digest_hex, "-sha256", "-cert", *extra, "-out", q)
        return _read(q)

    @classmethod
    def _answer(cls, q):
        if cls.mode == "honest":
            return cls._reply(q)
        if cls.mode == "other-digest":                       # a genuine granted token, for ANOTHER digest
            return cls._reply(cls._query(hashlib.sha256(b"other").hexdigest()))
        if cls.mode == "rejection":                          # policy the TSA does not serve -> status rejection
            return cls._reply(cls._query(hashlib.sha256(b"x").hexdigest(), "-tspolicy", "1.9.9.9"))
        if cls.mode == "rejection-carrying-a-token":        # hostile: status rejection, a valid token for THIS digest inside
            r = cls._reply(q)
            i = r.find(b"\x02\x01\x00")                      # the first INTEGER 0 is the PKIStatus (granted)
            return r[:i] + b"\x02\x01\x02" + r[i + 3:]
        if cls.mode == "granted-with-mods":                 # status 1: a token is legitimately present (RFC 3161 §2.4.2)
            r = cls._reply(q)
            i = r.find(b"\x02\x01\x00")
            return r[:i] + b"\x02\x01\x01" + r[i + 3:]
        if cls.mode == "tampered-signature":                # the genuine token for this digest, last signature byte flipped
            r = cls._reply(q)
            return r[:-1] + bytes([r[-1] ^ 0x01])
        return b"<html><body>503 Service Unavailable</body></html>"

    def _stamp(self, mode, digest_hex=None):
        type(self).mode = mode
        return T.stamp(digest_hex or hashlib.sha256(b"x").hexdigest(), self.url, timeout=10)

    def test_granted_with_modifications_is_anchored_and_verifies(self):      # status 1 carries a token too
        r = self._stamp("granted-with-mods")
        self.assertIs(r["anchored"], True, r)
        v = T.verify(r["tsr_b64"], hashlib.sha256(b"x").hexdigest(), ca_file=os.path.join(self.d, "chain.pem"))
        self.assertIs(v["verified"], True, v)

    def test_digest_spelling_and_hexdump_ascii_column(self):
        # an uppercase digest is the same digest; a digest whose bytes print as ' ab ' in the ASCII column of
        # `openssl ts -reply -text` must not have that column read as hex (the imprint is read from the hex column only)
        for dig in (hashlib.sha256(b"x").hexdigest().upper(), "20616220" * 8):
            with self.subTest(digest=dig):
                r = self._stamp("honest", dig)
                self.assertIs(r["anchored"], True, r)
                v = T.verify(r["tsr_b64"], dig, ca_file=os.path.join(self.d, "chain.pem"))
                self.assertIs(v["verified"], True, v)

    def test_granted_token_for_this_digest_is_anchored_and_verifies(self):   # positive control
        r = self._stamp("honest")
        self.assertIs(r["anchored"], True)
        v = T.verify(r["tsr_b64"], hashlib.sha256(b"x").hexdigest(), ca_file=os.path.join(self.d, "chain.pem"))
        self.assertIs(v["verified"], True, v)
        other = T.verify(r["tsr_b64"], hashlib.sha256(b"other").hexdigest(), ca_file=os.path.join(self.d, "chain.pem"))
        self.assertIs(other["verified"], False, other)     # the same genuine token, presented for another digest

    def test_broken_signature_is_anchored_at_stamp_and_refused_by_verify(self):   # the stated limit, measured
        # a token with a broken CMS signature is NOT refused here: proving the signature needs the TSA's trust anchor,
        # which is the verifier's job (stated limit, 2026-10-03)
        r = self._stamp("tampered-signature")
        self.assertIs(r["anchored"], True, r)
        v = T.verify(r["tsr_b64"], hashlib.sha256(b"x").hexdigest(), ca_file=os.path.join(self.d, "chain.pem"))
        self.assertIs(v["verified"], False, v)
        self.assertIs(v["crypto_verified"], False, v)

    def test_verify_reports_the_reply_facts(self):
        # the fields beside the verdict say WHY: a rejection is not granted, a token for another digest has imprint_ok False
        ca = os.path.join(self.d, "chain.pem")
        rej = base64.b64encode(self._reply(self._query(hashlib.sha256(b"x").hexdigest(), "-tspolicy", "1.9.9.9"))).decode()
        v = T.verify(rej, hashlib.sha256(b"x").hexdigest(), ca_file=ca)
        self.assertEqual((v["verified"], v["granted"], v["imprint_ok"]), (False, False, False), v)
        other = base64.b64encode(self._reply(self._query(hashlib.sha256(b"other").hexdigest()))).decode()
        v = T.verify(other, hashlib.sha256(b"x").hexdigest(), ca_file=ca)
        self.assertEqual((v["verified"], v["granted"], v["imprint_ok"]), (False, True, False), v)

    def test_anything_else_is_not_anchored(self):
        for mode in ("other-digest", "rejection", "html", "rejection-carrying-a-token"):
            with self.subTest(mode=mode):
                r = self._stamp(mode)
                self.assertIs(r["anchored"], False, r)
                self.assertNotIn("tsr_b64", r)


if __name__ == "__main__":
    unittest.main()
