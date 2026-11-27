# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""0.14.1: a secret given to omega-evidence does not come out of it. A canary goes into every input that takes a key, a
URL or a token, and is searched in everything that comes out: the return value, the files written (pack, sidecars,
ledger, evidence record, AAT records and anchors, DSSE envelope, SD-JWT), standard output and error of the two CLIs,
the exception, the argv of openssl. The inputs (counted with grep on 0.14.0, 27/11/2026):

  keys     signing.Identity seed (sign_pack, dsse.to_dsse, sdjwt.issue); pqbackends.mldsa.MlDsaFileSigner key file
           (pq_cosign); AwsKmsMlDsaSigner key_id and the errors of its client (credentials are boto3's); the ES256
           private PEM of interop.aat (from_omega, sign_record, sign_record_hybrid, tombstone)
  URLs     tsa_url of timestamp.stamp, pack.stamp_pack, preservation.build_evidence_record / renew_timestamp /
           renew_hash_tree, interop.aat.anchor_epoch; the calendars of ots.submit / ots.stamp_pack; the feed of
           chip_registry.discover_online and the update of fetch_signed_update_online
  values   attestation.attest attribute values; agent device_attestation service token
  misuse   a key file where a pack, a ledger, a trust store, an AAT chain or public key goes (verifier CLI, aat CLI,
           sign_pack, anchor_pack); a private JWK where sdjwt.verify takes the issuer's public key, and as the holder key in
           the cnf of sdjwt.issue

Searched raw, as any 12-character piece (a message cut at a length), in hex, HEX, decimal, base64 and base64url at each
of the three offsets. Positive control: the search finds each form, and a producer that leaks is found. On 0.14.0
(c26f4e6; the package files of the PyPI wheel are the same) the tests marked "fails on 0.14.0" fail."""
import base64
import contextlib
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)

from omega_evidence import agent, attestation, ots, pack as P, preservation as PR, timestamp as TS  # noqa: E402
from omega_evidence.chip_registry import ChipRegistry  # noqa: E402
from omega_evidence.interop import aat, dsse, sdjwt  # noqa: E402
from omega_evidence.pqbackends import mldsa  # noqa: E402
from omega_evidence.signing import Identity  # noqa: E402

SEED = hashlib.sha256(b"omega-evidence test_secrets canary seed").digest()      # a test key, not anyone's
PASSWORD = "Pw" + base64.urlsafe_b64encode(hashlib.sha256(b"pw" + SEED).digest()).decode()[:30]
KEYNAME = base64.urlsafe_b64encode(SEED).decode().rstrip("=")                    # 43 characters: a key where a name goes
MLSEED = hashlib.sha256(b"mldsa" + SEED).digest()
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
P256_D = (int.from_bytes(hashlib.sha256(b"p256" + SEED).digest(), "big") % (P256_N - 1) + 1).to_bytes(32, "big")
CANARIES = (SEED, PASSWORD.encode(), KEYNAME.encode(), MLSEED, P256_D)
SCOPE = "test only, NOT a conformity assessment"
PY = [sys.executable, "-B"]

try:
    from cryptography.hazmat.primitives import serialization as SER
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519
    HAVE_CRYPTO = True
except ImportError:   # the CI runs without cryptography too
    HAVE_CRYPTO = False


def forms(secret):
    out = {"raw": secret, "hex": secret.hex().encode(), "HEX": secret.hex().upper().encode(),
           "decimal": str(int.from_bytes(secret, "big")).encode()}
    for k in range(3):          # base64 of the secret inside a longer text: what depends on the secret alone, at each offset
        whole = base64.b64encode(b"\0" * k + secret + b"\0" * ((3 - (k + len(secret)) % 3) % 3))
        part = whole[(k * 8 + 5) // 6:(k + len(secret)) * 8 // 6]
        out["base64+%d" % k], out["base64url+%d" % k] = part, part.replace(b"+", b"-").replace(b"/", b"_")
    for name, text in (("raw", secret), ("hex", secret.hex().encode())):   # a message cut at a length keeps a piece
        for i in range(0, len(text) - 12 + 1):
            out["%s[%d:]" % (name, i)] = text[i:i + 12]
    return out


def found(secret, *outputs):
    blob = b"\n".join(o if isinstance(o, bytes) else str(o).encode("utf-8", "surrogatepass") for o in outputs)
    blob += b"\n" + blob.replace(b"\\/", b"/")      # JSON may escape the slash of base64
    return sorted(n for n, f in forms(secret).items() if f in blob)


def p256_pem():
    sk = ec.derive_private_key(int.from_bytes(P256_D, "big"), ec.SECP256R1())
    return (sk.private_bytes(SER.Encoding.PEM, SER.PrivateFormat.PKCS8, SER.NoEncryption()),
            sk.public_key().public_bytes(SER.Encoding.PEM, SER.PublicFormat.SubjectPublicKeyInfo))


class Base(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="oesec-")
        self.addCleanup(shutil.rmtree, self.d, True)

    def file(self, name, data):
        p = os.path.join(self.d, name)
        with open(p, "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode())
        return p

    def left(self, inputs=()):
        out = []
        for base, _, files in os.walk(self.d):
            for n in files:
                p = os.path.join(base, n)
                if os.path.abspath(p) in {os.path.abspath(i) for i in inputs}:
                    continue
                with open(p, "rb") as f:
                    out.append(f.read())
        return out

    def none(self, what, *outputs, inputs=()):
        """No canary in the outputs nor in any file of the folder but the inputs (which hold it by construction)."""
        for c in CANARIES:
            self.assertEqual(found(c, *outputs, *self.left(inputs)), [], what)

    def clean(self, *keep):
        """remove what the last call wrote, so the next one is judged on its own output"""
        keep = {os.path.abspath(k) for k in keep}
        for base, _, files in os.walk(self.d):
            for n in files:
                if os.path.abspath(os.path.join(base, n)) not in keep:
                    os.remove(os.path.join(base, n))

    def a_pack(self, name="p.json"):
        return P.write_pack(os.path.join(self.d, name), P.build_pack("test", {"n": 1}, SCOPE))

    def run_and_catch(self, fn, *a, **k):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                r = fn(*a, **k)
            except Exception as e:  # noqa: BLE001 - the exception is an output too
                r = "%s: %s %r" % (type(e).__name__, e, e.args)
        return r, out.getvalue(), err.getvalue()

    def cli(self, module, *argv):
        env = dict(os.environ, PYTHONPATH=ROOT)
        return subprocess.run(PY + ["-m", module] + list(argv), capture_output=True, timeout=120, cwd=self.d, env=env,
                              stdin=subprocess.DEVNULL)


class TheSearchFinds(Base):
    """Positive control of the search, and of a producer that leaks."""

    def test_every_form(self):
        s = SEED
        for name, text in (("raw", b"x" + s + b"y"), ("hex", b'"' + s.hex().encode()), ("HEX", s.hex().upper().encode()),
                           ("decimal", str(int.from_bytes(s, "big")).encode()), ("base64+0", base64.b64encode(s)),
                           ("base64+1", base64.b64encode(b"{" + s + b"}")), ("base64+2", base64.b64encode(b'{"' + s)),
                           ("base64url+0", base64.urlsafe_b64encode(s)), ("base64url+1", base64.urlsafe_b64encode(b"a" + s)),
                           ("base64url+2", base64.urlsafe_b64encode(b"ab" + s + b"c")),
                           ("hex[20:]", s.hex()[20:40].encode())):
            self.assertIn(name, found(s, text), name)
        self.assertIn("raw[3:]", found(PASSWORD.encode(), "as '" + PASSWORD[3:17]))
        self.assertEqual(found(s, b"nothing", hashlib.sha256(s).hexdigest(), Identity("x", s).public_key_b64), [])

    def test_a_producer_that_leaks_is_found(self):
        p = self.a_pack()
        P.sign_pack(p, Identity(SEED.hex(), SEED))      # the seed where the name goes: written as signer_id
        with self.assertRaises(AssertionError):
            self.none("a leak in a sidecar")
        self.file("leak.txt", base64.b64encode(b"ab" + SEED))
        with self.assertRaises(AssertionError):
            self.none("a leak in a file", inputs=[p + ".sig.json"])


class Keys(Base):
    def test_the_seed_does_not_come_out_of_what_it_signs(self):
        ident = Identity("producer", SEED)
        p = self.a_pack()
        led = os.path.join(self.d, "l.jsonl")
        outs = [P.anchor_pack(p, led), P.sign_pack(p, ident), dsse.to_dsse(json.load(open(p, encoding="utf-8")), ident),
                sdjwt.issue({"name": "x"}, ident, {"iss": "https://issuer.example"}), repr(ident), str(vars(ident).keys())]
        self.none("sign", *outs)

    def test_a_seed_of_the_wrong_form_is_not_repeated(self):
        for bad in (SEED + b"\0", SEED[:31] + b"", SEED.hex(), SEED.hex().encode(), bytearray(SEED * 2), PASSWORD):
            r = self.run_and_catch(Identity, "p", bad)
            self.none(repr(type(bad)), *r)

    @unittest.skipUnless(HAVE_CRYPTO and mldsa.available(), "ML-DSA-65 needs cryptography >= 48")
    def test_the_mldsa_key_file_does_not_come_out(self):
        sk = mldsa._mldsa().MLDSA65PrivateKey.from_seed_bytes(MLSEED)
        der = sk.private_bytes(SER.Encoding.DER, SER.PrivateFormat.PKCS8, SER.NoEncryption())
        key = self.file("k.mldsa", base64.b64encode(der).decode() + "\n")
        p = self.a_pack()
        P.sign_pack(p, Identity("producer", SEED))
        signer = mldsa.MlDsaFileSigner(key)
        outs = [P.pq_cosign(p, signer), signer.describe(), repr(signer)]
        self.none("pq_cosign", *outs, inputs=[key])
        ed = ed25519.Ed25519PrivateKey.from_private_bytes(SEED).private_bytes(
            SER.Encoding.DER, SER.PrivateFormat.PKCS8, SER.NoEncryption())
        for i, body in enumerate((base64.b64encode(der[:-3]) + b"\n", base64.b64encode(ed) + b"\n", der, base64.b64encode(der) + b"!",
                                  sk.private_bytes(SER.Encoding.PEM, SER.PrivateFormat.PKCS8, SER.NoEncryption()))):
            bad = self.file("bad%d" % i, body)
            self.none("bad key file %d" % i, *self.run_and_catch(mldsa.MlDsaFileSigner, bad), inputs=[key, bad])
            os.remove(bad)

    def test_the_kms_signer_does_not_repeat_its_key_id_nor_its_client_errors(self):
        """fails on 0.14.0: the KeyId given and str() of the client's exception were in the RuntimeError"""
        class Client:
            def __init__(self, fail):
                self.fail = fail

            def get_public_key(self, KeyId):
                if self.fail == "get":
                    raise RuntimeError("denied for %s with token %s" % (KeyId, PASSWORD))
                return {"KeyId": KeyId, "PublicKey": mldsa.MLDSA65_SPKI_OID + b"\0" * 10}

        for fail in ("get", "spki"):
            r = self.run_and_catch(mldsa.AwsKmsMlDsaSigner, KEYNAME, client=Client(fail))
            self.assertIn("Error", r[0])
            self.none("kms " + fail, *r)

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography absent")
    def test_the_es256_private_key_does_not_come_out_of_the_aat_records(self):
        priv, pub = p256_pem()
        log = agent.AgentEvidenceLog(os.path.join(self.d, "agent.jsonl"), runtime_id="rt-1")
        log.record("bot-7", "sess-a", "tool_call", "https://api.example/x", "rule-1", agent.Decision.ALLOW, agent.Outcome.EXECUTED)
        recs = next(iter(aat.from_omega(list(log._ledger.entries()), "1.0", private_key_pem=priv, close=True).values()))
        tomb = aat.tombstone(dict(recs[1]), "GDPR art. 17", recs[1]["timestamp"], key=priv)
        self.none("aat", json.dumps(recs), json.dumps(tomb), aat.verify_chain(recs, pubkey_pem=pub))
        for bad in (priv[:-40], priv.replace(b"PRIVATE", b"PUBLIC"), b"x" + priv):
            self.none("bad pem", *self.run_and_catch(aat.sign_record, dict(recs[0]), bad))


class Urls(Base):
    BAD = ("http://u:%s@127.0.0.1:1/" % PASSWORD, "http://%s@127.0.0.1:1/" % PASSWORD, "HTTPS://u:%s@127.0.0.1:1/" % PASSWORD,
           "http://%s:@127.0.0.1:1/" % PASSWORD, "http://u:%s@[::1]:1/" % PASSWORD, "http://u:%s@127.0.0.1:99999/" % PASSWORD,
           "http://127.0.0.1:%s/" % PASSWORD, "http://[%s]/" % PASSWORD, "http://127.0.0.1:1/\\@" + PASSWORD,
           "http://127.0.0.1:1/ " + PASSWORD, "http://127.0.0.1:1/\x00" + PASSWORD, "ftp://u:%s@127.0.0.1/" % PASSWORD,
           "x%s://127.0.0.1/" % PASSWORD.replace("_", "").replace("-", ""), PASSWORD)
    WITH_QUERY = ("http://127.0.0.1:1/tsa?apikey=%s" % PASSWORD, "http://127.0.0.1:1/tsa#%s" % PASSWORD,
                  "http://127.0.0.1:1/tsa?a=1&k=%s#f" % PASSWORD)

    def stampers(self, p):
        rec = PR.build_evidence_record([p])
        log = agent.AgentEvidenceLog(os.path.join(tempfile.mkdtemp(dir=self.d), "agent.jsonl"))
        log.record("bot", "s", "tool_call", "r", "rule", agent.Decision.ALLOW, agent.Outcome.EXECUTED)
        chain = next(iter(aat.from_omega(list(log._ledger.entries()), "1.0", close=True).values()))
        return (("stamp", lambda u: TS.stamp("ab" * 32, u)),
                ("stamp_pack", lambda u: P.stamp_pack(p, u, capture_ltv=True)),
                ("build_evidence_record", lambda u: PR.build_evidence_record([p], tsa_url=u)),
                ("renew_timestamp", lambda u: PR.renew_timestamp(json.loads(json.dumps(rec)), tsa_url=u)),
                ("renew_hash_tree", lambda u: PR.renew_hash_tree(json.loads(json.dumps(rec)), [p], "sha3_256", tsa_url=u)),
                ("anchor_epoch", lambda u: aat.anchor_epoch(json.loads(json.dumps(chain)), tsa_url=u)),
                ("ots.stamp_pack", lambda u: ots.stamp_pack(p, calendars=[u])),
                ("discover_online", lambda u: self.discover(u)),
                ("fetch_signed_update_online", lambda u: ChipRegistry().fetch_signed_update_online(u, p)))

    @staticmethod
    def discover(u):
        reg = ChipRegistry()
        return reg.discover_online(u), reg.candidates()

    def test_a_url_with_credentials_is_refused_before_the_network(self):
        """fails on 0.14.0: ots wrote the calendar URL as given into calendar_errors of the sidecar, and a port that is
        not a number came back in the note"""
        p = self.a_pack()
        for url in self.BAD:
            for name, fn in self.stampers(p):
                with mock.patch("urllib.request.build_opener") as net:
                    r = self.run_and_catch(fn, url)
                with self.subTest(url=url[:30], via=name):
                    self.assertFalse(net.called)
                    self.none(name, *r, inputs=[p])
                self.clean(p)

    def test_the_network_error_says_its_type_not_its_text(self):
        """fails on 0.14.0: str() of the exception, which a library may fill with the URL, went into the note"""
        p = self.a_pack()
        for exc in (OSError("cannot reach http://127.0.0.1:1/?k=%s" % PASSWORD), ValueError(PASSWORD)):
            for name, fn in self.stampers(p):
                opener = mock.Mock()
                opener.open.side_effect = exc
                with mock.patch("urllib.request.build_opener", return_value=opener):
                    r = self.run_and_catch(fn, "http://127.0.0.1:1/tsa")
                with self.subTest(exc=type(exc).__name__, via=name):
                    self.none(name, *r, inputs=[p])
                self.clean(p)

    @unittest.skipUnless(shutil.which("openssl"), "openssl absent: stamp() stops before the network")
    def test_the_url_written_into_a_record_has_no_query_and_no_fragment(self):
        """fails on 0.14.0: the TSA URL was written as given (`tsa`, `tsa_url`)"""
        p = self.a_pack()
        seen = []
        real_run = subprocess.run

        def run(argv, *a, **k):     # timestamp's own subprocess.run, not the global one: every program runs, its argv is kept
            seen.append((list(argv), k.get("env")))
            return real_run(argv, *a, **k)

        class Resp:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *e):
                return False

            def __init__(self):
                self.left = [b'{"candidates": [{"attestation_class": "new-chip-x", "vendor": "v"}]}']

            def read1(self, n):
                return self.left.pop() if self.left else b""

        for url in self.WITH_QUERY:
            for name, fn in self.stampers(p)[:-1]:     # fetch_signed_update_online writes no URL when it succeeds
                opener = mock.Mock()
                opener.open.side_effect = lambda *a, **k: Resp()
                with mock.patch("urllib.request.build_opener", return_value=opener), \
                        mock.patch.object(TS, "_reply_facts", lambda exe, tsr, t, run=None: (True, self._imprint)), \
                        mock.patch.object(TS, "extract_validation_material", lambda *a, **k: {"available": False}), \
                        mock.patch.object(TS, "subprocess", types.SimpleNamespace(**dict(vars(subprocess), run=run))):
                    self._imprint = None
                    real_stamp = TS.stamp

                    def stamp(digest_hex, tsa_url, timeout=20):
                        self._imprint = digest_hex.lower()
                        return real_stamp(digest_hex, tsa_url, timeout)
                    with mock.patch.object(TS, "stamp", stamp):
                        r = self.run_and_catch(fn, url)
                with self.subTest(url=url[-12:], via=name):
                    self.assertIn("127.0.0.1", json.dumps(r[0]) if not isinstance(r[0], str) else r[0])
                    self.assertNotIn("Error", r[0] if isinstance(r[0], str) else "")
                    self.none(name, *r, inputs=[p])
                self.clean(p)
        self.assertTrue(seen)
        self.none("openssl argv", json.dumps(seen))


class Values(Base):
    def test_an_attribute_value_and_a_service_token_are_not_recorded(self):
        att = attestation.attest("subject-1", {"iban": PASSWORD, "seed": SEED.hex()})
        log = agent.AgentEvidenceLog(os.path.join(self.d, "agent.jsonl"))
        a = log.record("bot", "s", "tool_call", "r", "rule", agent.Decision.ALLOW, agent.Outcome.EXECUTED,
                       device_attestation={"attestation_class": "nvidia-h100", "service_attestation_token": PASSWORD,
                                           "service_quote": SEED.hex(), "verified_by_service": True})
        self.none("attest", json.dumps(att.__dict__), att.digest(), repr(a), log.evidence_pack())


@unittest.skipUnless(HAVE_CRYPTO, "cryptography absent")
class KeyWhereSomethingElseGoes(Base):
    def keys(self):
        priv, _ = p256_pem()
        ed = ed25519.Ed25519PrivateKey.from_private_bytes(SEED).private_bytes(
            SER.Encoding.PEM, SER.PrivateFormat.PKCS8, SER.NoEncryption())
        return [self.file("seed.hex", SEED.hex() + "\n"), self.file("seed.bin", SEED), self.file("ed.pem", ed),
                self.file("p256.pem", priv), self.file("jwk.json", json.dumps({"kty": "OKP", "crv": "Ed25519", "d": KEYNAME,
                                                                               "x": KEYNAME}))]

    def test_the_verifier_cli_does_not_print_a_key_given_as_an_input(self):
        keys = self.keys()
        p = self.a_pack()
        for k in keys:
            for argv in ([k], [p, "--ledger", k], [p, "--trust-store", k], [k, "--ledger", k, "--trust-store", k]):
                r = self.cli("omega_evidence", *argv)
                with self.subTest(argv=[os.path.basename(a) for a in argv]):
                    self.none("verifier", r.stdout, r.stderr, inputs=keys)

    def test_the_aat_cli_does_not_print_a_key_given_as_an_input(self):
        keys = self.keys()
        log = agent.AgentEvidenceLog(os.path.join(self.d, "agent.jsonl"))
        log.record("bot", "s", "tool_call", "r", "rule", agent.Decision.ALLOW, agent.Outcome.EXECUTED)
        chain = self.file("c.jsonl", "\n".join(json.dumps(r) for r in next(iter(aat.from_omega(
            list(log._ledger.entries()), "1.0", close=True).values()))) + "\n")
        for k in keys:
            for argv in (["verify", k], ["csv", k], ["verify", chain, "--key", "kid=" + k], ["verify", chain, "--pubkey", k],
                         ["verify", chain, "--epochs", k], ["verify", chain, "--tsa-ca", k, "--epochs", k]):
                r = self.cli("omega_evidence.interop.aat", *argv)
                with self.subTest(argv=[os.path.basename(a) for a in argv]):
                    self.none("aat cli", r.stdout, r.stderr, inputs=keys + [chain])

    def test_the_library_does_not_repeat_a_key_given_as_a_pack(self):
        keys = self.keys()
        led = os.path.join(self.d, "l.jsonl")
        for k in keys:
            for name, fn in (("sign_pack", lambda: P.sign_pack(k, Identity("p", SEED))), ("anchor_pack", lambda: P.anchor_pack(k, led)),
                             ("build_evidence_record", lambda: PR.build_evidence_record([k])),
                             ("load_public_key", lambda: dsse.load_public_key(open(k, "rb").read()))):
                with self.subTest(key=os.path.basename(k), via=name):
                    self.none(name, *self.run_and_catch(fn), inputs=keys)

    def test_a_private_jwk_is_not_an_issuer_key(self):
        """fails on 0.14.0: a JWK with its private member `d` was taken as the issuer's public key"""
        ident = Identity("issuer", SEED)
        tok = sdjwt.issue({"name": "x"}, ident, {"iss": "https://issuer.example"})
        x = base64.urlsafe_b64encode(base64.b64decode(ident.public_key_b64)).decode().rstrip("=")
        pub = {"kty": "OKP", "crv": "Ed25519", "x": x}
        self.assertIs(sdjwt.verify(tok, pub)["verified"], True)                     # control
        for member in ("d", "p", "q", "dp", "dq", "qi", "k", "oth"):
            r = sdjwt.verify(tok, dict(pub, **{member: KEYNAME}))
            with self.subTest(member=member):
                self.assertIs(r["verified"], False)
                self.assertIn("private", r.get("error", ""))
                self.none("sdjwt", json.dumps(r))

    def test_a_private_jwk_is_not_the_holder_key_either(self):
        """fails on 0.14.0: a credential whose cnf carried the holder's private key verified, Key Binding included"""
        import test_sdjwt_kb_20261117 as K   # the KB-JWT helpers of that test
        K.TestKeyBinding.setUpClass()
        t = K.TestKeyBinding("test_kb_verified")
        holder = ec.derive_private_key(int.from_bytes(P256_D, "big"), ec.SECP256R1())
        good = t.v(t.kb(t.sd(holder=holder), key=holder))
        self.assertIs(good["verified"], True, good)                                # control
        leaky = t.sd(cnf={"jwk": dict(K.holder_jwk(holder), d=K.b64u(P256_D))})
        r = t.v(t.kb(leaky, key=holder))
        self.assertIs(r["verified"], False, r)
        self.assertIn("private", r["error"])
        self.none("cnf", json.dumps(r))

    def test_issue_does_not_write_a_private_holder_key(self):
        """fails on 0.14.0 and on 4d7869f: issue() signed a cnf.jwk with its private member into the SD-JWT, in clear"""
        holder = {"kty": "OKP", "crv": "Ed25519", "x": KEYNAME}
        ok = sdjwt.issue({"a": 1}, Identity("i", SEED), plain_claims={"iss": "x", "cnf": {"jwk": holder}})   # control
        self.assertIn(KEYNAME[:12], base64.urlsafe_b64decode(ok.split(".")[1] + "==").decode())
        for m in ("d", "p", "q", "dp", "dq", "qi", "oth", "k"):
            with self.subTest(member=m):
                r = self.run_and_catch(sdjwt.issue, {"a": 1}, Identity("i", SEED),
                                       plain_claims={"iss": "x", "cnf": {"jwk": dict(holder, **{m: PASSWORD})}})
                self.assertTrue(str(r[0]).startswith("ValueError"), r)
                self.none("issue", *r)


class Kept(Base):
    def test_a_refusal_keeps_its_reason_and_stamp_refuses_before_openssl(self):
        """kills two mutants of 4d7869f that leak nothing: reason() dropping the text of a Refused, and stamp() sending a
        URL to openssl and the network before check_url"""
        url = "http://u:%s@127.0.0.1:1/" % PASSWORD
        with mock.patch.object(TS.subprocess, "run") as run, mock.patch("urllib.request.build_opener") as net:
            r = TS.stamp("ab" * 32, url)
            o = ots.submit("ab" * 32, [url])
        self.assertFalse(run.called or net.called)
        self.assertEqual(r, {"anchored": False, "note": "TSA URL refused: userinfo in the URL"})
        self.assertEqual(o["errors"], [{"calendar": "", "error": "Refused: userinfo in the URL"}])

    def test_the_kms_error_code_is_named_only_when_it_is_a_name_and_the_cause_is_not_chained(self):
        """kills two mutants of 4d7869f: the AWS error code taken whatever it holds, and the client's error chained as
        the cause (the traceback printed it)"""
        import traceback

        class Err(Exception):
            def __init__(self, code):
                super().__init__("denied: " + PASSWORD)
                self.response = {"Error": {"Code": code}}

        class Client:
            def __init__(self, code):
                self.code = code

            def get_public_key(self, KeyId):
                raise Err(self.code)

        for code, named in (("AccessDeniedException", "Err (AccessDeniedException)"), ("x " + PASSWORD, "Err"),
                            ("x" * 65, "Err"), ("", "Err"), (7, "Err")):
            with self.subTest(code=str(code)[:20]):
                with self.assertRaises(RuntimeError) as cm:
                    mldsa.AwsKmsMlDsaSigner(KEYNAME, client=Client(code))
                self.assertEqual(str(cm.exception), "AWS KMS GetPublicKey failed: " + named)
                self.assertIsNone(cm.exception.__cause__)
                tb = "".join(traceback.format_exception(type(cm.exception), cm.exception, cm.exception.__traceback__))
                self.assertEqual(found(PASSWORD.encode(), tb), [])

        class Signs:
            def sign(self, **k):
                raise Err("AccessDeniedException")
        s = object.__new__(mldsa.AwsKmsMlDsaSigner)   # sign() alone, without a real ML-DSA public key
        s._key_id, s._client, s.key_arn = KEYNAME, Signs(), KEYNAME
        with self.assertRaises(RuntimeError) as cm:
            s.sign(b"m")
        self.assertEqual(str(cm.exception), "AWS KMS Sign failed: Err (AccessDeniedException)")
        self.assertIsNone(cm.exception.__cause__)


class NetworkReasons(unittest.TestCase):
    def test_an_ip_literal_is_checked_on_every_python(self):
        """fails on 310194c: Python 3.9.13 (macOS and Windows runners) splits "http://[text" without a closing bracket
        and the text became the host; the check no longer depends on urlsplit refusing it"""
        from unittest import mock
        from urllib.parse import SplitResult
        from omega_evidence import _crl_fetch as F
        for netloc in ("[" + PASSWORD, "[::1", "[zz]", "a]b", "[::1]" + PASSWORD, "[1.2.3.4]"):
            with mock.patch.object(F, "urlsplit", lambda u, n=netloc: SplitResult("http", n, "/", "", "")):
                with self.assertRaises(F.Refused) as c:
                    F.check_url("x")
                self.assertNotIn(PASSWORD, str(c.exception))
                self.assertNotIn(PASSWORD.lower(), str(c.exception))
        with mock.patch.object(F, "urlsplit", lambda u: SplitResult("http", "[::1]:8080", "/", "", "")):
            self.assertEqual(F.check_url("x")[:3], ("http", "::1", 8080))   # control: a real IPv6 literal passes

    def test_a_tls_failure_is_not_named_by_a_posix_errno(self):
        """fails on 4d7869f: ssl errno 1 (an OpenSSL code) was printed as EPERM"""
        import errno
        import ssl
        import urllib.error
        from omega_evidence import _crl_fetch as F
        tls = urllib.error.URLError(ssl.SSLCertVerificationError(1, "[SSL: CERTIFICATE_VERIFY_FAILED] " + PASSWORD))
        self.assertEqual(F.reason(tls), "URLError (SSLCertVerificationError)")
        self.assertEqual(F.reason(ssl.SSLError(1, PASSWORD)), "SSLError")
        refused = urllib.error.URLError(ConnectionRefusedError(errno.ECONNREFUSED, PASSWORD))   # control: a POSIX errno keeps its name
        self.assertEqual(F.reason(refused), "URLError (%s)" % errno.errorcode[errno.ECONNREFUSED])   # WSAECONNREFUSED on Windows


if __name__ == "__main__":
    unittest.main()
