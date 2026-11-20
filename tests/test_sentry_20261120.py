"""Three defects found on 0.12.0 by a security review tool on 20 November 2026, each reproduced before it was fixed.

(1) `interop.aat.verify_chain` chose the session's recorder with a min() over all recorders for EVERY record: quadratic
    in a chain whose records each name their own recording_component (4000 records: 4.13 s, 0.29 s with one recorder).
    The `aat` CLI read its input files with open().read(): a FIFO in place of the chain blocked it, a file of any size
    was read whole.
(2) `chip_registry.apply_signed_update` verified the update pack from its path and then read it again from the same
    path (and the signature sidecar a third time): a pack replaced between the two reads was applied unverified.
(3) `timestamp.extract_validation_material(fetch_crl=True)` (reached by `pack.stamp_pack(capture_ltv=True,
    fetch_crl=True)`) asked the CRL distribution points of every certificate of a token nobody had verified: a GET
    to a loopback address named by a self-made certificate, its answer stored in the sidecar.

Positive control: on 9c55515 (the commit before these fixes) the tests marked "fails on 9c55515" in their docstring fail.
"""
import base64
import hashlib
import http.server
import ipaddress
import json
import os
import random
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
from unittest import mock

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)

from omega_evidence import chip_registry, ledger, ots, pack, signing, trust  # noqa: E402
from omega_evidence import timestamp as T  # noqa: E402
from omega_evidence.verifier import verify_pack  # noqa: E402

try:
    from omega_evidence import _crl_fetch as F  # noqa: E402
except ImportError:   # 9c55515: the module is not there; the tests that need it fail on their first use of it
    F = None
EXE = shutil.which("openssl")
from omega_evidence.interop import aat  # noqa: E402

SECOND = "a second recording component in one session"


def _record(i, sid, recorder=None, detail=None):
    r = {"record_id": str(uuid.UUID(int=random.Random(f"{sid}/{i}").getrandbits(128), version=4)),
         "timestamp": "2026-11-20T00:%02d:%02dZ" % (i // 60 % 60, i % 60), "agent_id": "urn:a:b", "agent_version": "1",
         "session_id": sid, "action_type": "lifecycle" if i == 0 else "decision", "outcome": "success",
         "trust_level": "L2", "record_phase": "concurrent" if i == 0 else "post_execution",
         "action_detail": detail if detail is not None else ({"event": "session_start"} if i == 0 else {})}
    if recorder is not None:
        r["recording_component"] = recorder
    return r


class TestAatSessionRecorderChosenOnce(unittest.TestCase):
    POOL = ["urn:rec:a", "urn:rec:b", "urn:rec:c", "urn:a:b", "", "é", "urn:rec:\U0001F600", "URN:REC:A"]

    def test_min_is_not_called_once_per_record(self):
        """fails on 9c55515: there min() ran once per record, twice per record naming another recorder"""
        n = 300
        sid = str(uuid.UUID(int=7, version=4))
        chain = [_record(i, sid, f"urn:rec:{i}") for i in range(n)]
        calls = []

        def counting_min(*a, **k):
            calls.append(1)
            return min(*a, **k)
        with mock.patch.object(aat, "min", counting_min, create=True):
            res = aat.verify_chain(chain)
        self.assertEqual(len([p for p in res["problems"] if SECOND in p["why"]]), n - 1)   # all but the session's own
        self.assertLessEqual(len(calls), 1)

    def test_generated_chains_name_the_same_recorder_as_the_rule(self):
        """The rule, computed here record by record the way 9c55515 did: the session's recorder is the genesis'
        recording_component_id when it is among the recorders, else the first in code point order; every other string
        recorder is a problem that names it. 3 000 generated chains (recorders from a pool with an empty string, a
        non-ASCII one, the agent's own id; non-string recorders; records that are not objects; every genesis mode)."""
        rng = random.Random(20261120)
        seen_second = seen_multi = 0
        for case in range(3000):
            sid = str(uuid.UUID(int=rng.getrandbits(128), version=4))
            gmode = rng.choice([None, "self", "independent", "x", 3])
            gid = rng.choice([None] + self.POOL + [5])
            chain = []
            for i in range(rng.randint(0, 8)):
                detail = None
                if i == 0:
                    detail = {"event": "session_start"}
                    if gmode is not None:
                        detail["recording_mode"] = gmode
                    if gid is not None:
                        detail["recording_component_id"] = gid
                k = rng.random()
                rec = rng.choice(self.POOL) if k < 0.7 else (rng.choice([1, ["urn:rec:a"], {"a": 1}, True]) if k < 0.8 else None)
                r = _record(i, sid, rec, detail)
                chain.append(rng.choice([None, 1, "x", []]) if rng.random() < 0.05 else r)
            # the oracle
            g0 = chain[0] if chain and isinstance(chain[0], dict) else {}
            gd0 = g0.get("action_detail") if isinstance(g0.get("action_detail"), dict) else {}
            recorders = {r["recording_component"] for r in chain if isinstance(r, dict)
                         and isinstance(r.get("recording_component"), str) and r["recording_component"] != r.get("agent_id")}
            if isinstance(gd0.get("recording_component_id"), str) and gd0.get("recording_mode") == "independent":
                recorders.add(gd0["recording_component_id"])
            independent = gd0.get("recording_mode") == "independent" or bool(recorders)
            want = []
            for i, r in enumerate(chain):
                if isinstance(r, dict) and independent and len(recorders) > 1 and isinstance(r.get("recording_component"), str):
                    chosen = min(recorders, key=lambda x: (x != gd0.get("recording_component_id"), x))
                    if r["recording_component"] != chosen:
                        want.append({"i": i, "why": f"{SECOND} ({r['recording_component']!r}; the session's is {chosen!r}) "
                                                    "(§5.2: one independent recorder)"})
            got = [p for p in aat.verify_chain(chain)["problems"] if SECOND in p["why"]]
            self.assertEqual(got, want, f"case {case}: {chain!r}")
            seen_second += len(want)
            seen_multi += len(recorders) > 1
        self.assertGreater(seen_second, 1000)    # the generator does reach the rule
        self.assertGreater(seen_multi, 1000)


class TestAatCliReadsBoundedRegularFiles(unittest.TestCase):
    """Every input file of the aat CLI goes through ledger.read_input: a regular file, at most 64 MiB, never blocking."""

    @staticmethod
    def _limit_memory():   # the old code read a device without end: the control must not exhaust this host
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (2 << 30, 2 << 30))

    def _cli(self, *args):
        env = dict(os.environ, PYTHONPATH=ROOT)
        try:
            p = subprocess.run([sys.executable, "-m", "omega_evidence.interop.aat", *args], capture_output=True, text=True,
                               timeout=20, env=env, cwd=ROOT, preexec_fn=self._limit_memory if os.name == "posix" else None)
        except subprocess.TimeoutExpired:
            self.fail(f"aat {' '.join(args)}: no answer within 20 s (blocked on an input file)")
        return p.returncode, p.stdout, p.stderr

    def _chain_file(self, tmp, newline="\n"):
        sid = str(uuid.UUID(int=11, version=4))
        recs = [_record(i, sid) for i in range(3)]
        for k in range(1, len(recs)):
            recs[k]["prev_hash"] = aat.record_hash(recs[k - 1], strict=False)
        p = os.path.join(tmp, "chain.jsonl")
        with open(p, "wb") as f:
            f.write(newline.join(json.dumps(r) for r in recs).encode() + newline.encode())
        return p

    @unittest.skipUnless(hasattr(os, "mkfifo"), "no FIFO on this system")
    def test_a_fifo_in_place_of_any_input_is_refused_at_once(self):
        """fails on 9c55515: the CLI blocked on the FIFO (chain, --pubkey, --key, --epochs)"""
        with tempfile.TemporaryDirectory() as tmp:
            fifo = os.path.join(tmp, "fifo")
            os.mkfifo(fifo)
            chain = self._chain_file(tmp)
            for args in (["verify", fifo], ["csv", fifo], ["verify", chain, "--pubkey", fifo],
                         ["verify", chain, "--key", "kid=" + fifo], ["verify", chain, "--epochs", fifo]):
                rc, out, err = self._cli(*args)
                self.assertEqual(rc, 2, (args, out, err))
                self.assertIn("not a regular file", json.loads(out)["error"], args)

    @unittest.skipUnless(os.path.exists("/dev/zero"), "no /dev/zero")
    def test_a_device_or_a_directory_is_refused(self):
        """fails on 9c55515: a symlink to /dev/zero was read until memory ran out"""
        with tempfile.TemporaryDirectory() as tmp:
            link = os.path.join(tmp, "chain.jsonl")
            os.symlink("/dev/zero", link)
            for path in (link, tmp):
                rc, out, err = self._cli("verify", path)
                self.assertEqual(rc, 2, (path, out[:200], err[-300:]))
                self.assertIn("not a regular file", json.loads(out)["error"])

    def test_beyond_the_bound_is_refused_and_the_bound_itself_is_read(self):
        """fails on 9c55515 (the module had no read_input): the bound, here lowered to the size of the chain file"""
        with tempfile.TemporaryDirectory() as tmp:
            chain = self._chain_file(tmp)
            size = os.path.getsize(chain)
            real = ledger.read_input
            for limit, want in ((size, 0), (size - 1, 2)):
                with mock.patch.object(aat, "read_input", lambda p, limit=limit: real(p, limit)), \
                        mock.patch("omega_evidence.verifier.write_receipt", lambda text: True):
                    self.assertEqual(aat.main(["csv", chain]), want, limit)
            self.assertEqual(ledger.MAX_INPUT_BYTES, 64 * 1024 * 1024)

    def test_line_ends_are_read_as_before(self):
        """CR LF, lone CR and LF chains give the same verdict and the same CSV (open() in text mode did the same)"""
        with tempfile.TemporaryDirectory() as tmp:
            outs = []
            for nl in ("\n", "\r\n", "\r"):
                chain = self._chain_file(tmp, nl)
                rc_v, out_v, _ = self._cli("verify", chain)
                rc_c, out_c, _ = self._cli("csv", chain)
                outs.append((rc_v, out_v, rc_c, out_c))
            self.assertEqual(outs[0][2], 0)
            self.assertIn("record_id", outs[0][3])
            self.assertEqual(outs[0], outs[1])
            self.assertEqual(outs[0], outs[2])
            self.assertEqual(aat._text_of(b"a\r\n\r\nb\rc\n"), "a\n\nb\nc\n")


class TestChipRegistryAppliesTheBytesItVerified(unittest.TestCase):
    FUTURE = "nvidia-rubin-cc"

    def _update(self, tmp, classes, name="update.json"):
        ident = signing.Identity("curator")
        up = os.path.join(tmp, name)
        chip_registry.publish_signed_update(up, classes, ident, update_seq=1)
        store = os.path.join(tmp, "trust.jsonl")
        trust.TrustRegistry(store).trust(ident.name, ident.public_key_b64)
        return up, store, ident

    @staticmethod
    def _evil(path):
        """an update nobody signed, self-consistent, with a sidecar naming another signer"""
        pk = chip_registry.build_pack(chip_registry.UPDATE_KIND, {"chip_classes": {"evil-chip": "attacker-service"}},
                                      "a mapping, NOT a statement about any chip")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(pk, f)
        side = path[:-5] + ".sig.json" if path.endswith(".json") else path + ".sig.json"
        with open(side, "w", encoding="utf-8") as f:
            json.dump({"signer_id": "forged"}, f)

    def test_a_pack_replaced_after_verification_is_not_what_gets_applied(self):
        """fails on 9c55515: the pack put in place after verify_pack returned was applied (evil-chip known, signer
        "forged" recorded). The replacement is made at the instant the old code was open to it: when verify_pack
        returns."""
        with tempfile.TemporaryDirectory() as tmp:
            up, store, ident = self._update(tmp, {self.FUTURE: "nvidia-nras"})
            real = chip_registry.verify_pack

            def verify_then_replace(path, **kw):
                v = real(path, **kw)
                self._evil(up)
                return v
            reg = chip_registry.ChipRegistry()
            with mock.patch.object(chip_registry, "verify_pack", verify_then_replace):
                r = reg.apply_signed_update(up, store)
            self.assertFalse(reg.is_known("evil-chip"), r)
            self.assertTrue(r["applied"])
            self.assertEqual((r["added"], r["signer_id"]), ([self.FUTURE], ident.name))
            self.assertEqual(reg.service_for(self.FUTURE), "nvidia-nras")
            self.assertEqual(reg.sources()[0]["signer_id"], ident.name)
            # and the replaced file itself, verified on its own, is refused
            r2 = chip_registry.ChipRegistry().apply_signed_update(up, store)
            self.assertEqual((r2["applied"], r2["reason"]), (False, "update is not trusted-signed"))

    def test_generated_replacements_at_every_read_never_apply_an_unverified_class(self):
        """fails on 9c55515. 200 rounds: the pack, the sidecar or both are replaced before, during (after the n-th
        read_input of the verification) or after it; whatever is applied was signed by the trusted curator."""
        rng = random.Random(20261120)
        applied = refused = 0
        for case in range(200):
            with tempfile.TemporaryDirectory() as tmp:
                up, store, ident = self._update(tmp, {self.FUTURE: "nvidia-nras"})
                when, n_read, what = rng.choice(["before", "read", "after"]), rng.randint(1, 4), rng.choice(["pack", "side", "both"])
                side = up[:-5] + ".sig.json"
                good = {}
                for p in (up, side):
                    with open(p, "rb") as f:
                        good[p] = f.read()

                def replace():
                    self._evil(up)
                    for p, keep in ((up, what == "side"), (side, what == "pack")):
                        if keep:
                            with open(p, "wb") as f:
                                f.write(good[p])
                reads = []
                real_read, real_verify = ledger.read_input, chip_registry.verify_pack

                def counting_read(path, *a, **k):
                    data = real_read(path, *a, **k)
                    reads.append(path)
                    if when == "read" and len(reads) == n_read:
                        replace()
                    return data

                def verify(path, **kw):
                    v = real_verify(path, **kw)
                    if when == "after":
                        replace()
                    return v
                if when == "before":
                    replace()
                reg = chip_registry.ChipRegistry()
                with mock.patch.object(chip_registry, "verify_pack", verify), \
                        mock.patch.object(ledger, "read_input", counting_read), \
                        mock.patch("omega_evidence.verifier.read_input", counting_read), \
                        mock.patch.object(chip_registry, "read_input", counting_read, create=True):
                    r = reg.apply_signed_update(up, store)
                ctx = (case, when, n_read, what, r)
                self.assertFalse(reg.is_known("evil-chip"), ctx)
                if r["applied"]:
                    applied += 1
                    self.assertEqual((r["added"], r["signer_id"]), ([self.FUTURE], ident.name), ctx)
                    self.assertEqual(reg.sources()[0]["signer_id"], ident.name, ctx)
                else:
                    refused += 1
                    self.assertFalse(reg.is_known(self.FUTURE), ctx)
                    self.assertEqual(reg.sources(), [], ctx)
        self.assertGreater(applied, 30)
        self.assertGreater(refused, 30)

    def test_the_pack_and_each_sidecar_are_read_once(self):
        """fails on 9c55515: the pack was read twice and the signature sidecar twice"""
        with tempfile.TemporaryDirectory() as tmp:
            up, store, _ = self._update(tmp, {self.FUTURE: "nvidia-nras"})
            opened = []
            real_open = os.open

            def counting_open(path, *a, **k):
                opened.append(os.fspath(path))
                return real_open(path, *a, **k)
            import builtins
            real_bopen = builtins.open

            def counting_bopen(path, *a, **k):
                if isinstance(path, (str, bytes, os.PathLike)):
                    opened.append(os.fspath(path))
                return real_bopen(path, *a, **k)
            with mock.patch.object(os, "open", counting_open), mock.patch.object(builtins, "open", counting_bopen):
                r = chip_registry.ChipRegistry().apply_signed_update(up, store)
            self.assertTrue(r["applied"])
            self.assertEqual(opened.count(up), 1)
            self.assertEqual(opened.count(up[:-5] + ".sig.json"), 1)

    def test_chip_classes_that_is_not_an_object_is_refused(self):
        """fails on 9c55515: AttributeError (a list, a string, a number, null, true)"""
        for bad in ([], ["x"], "x", 1, None, True):
            with tempfile.TemporaryDirectory() as tmp:
                ident = signing.Identity("curator")
                up = os.path.join(tmp, "update.json")
                pk = chip_registry.build_pack(chip_registry.UPDATE_KIND, {"chip_classes": bad}, "a mapping, NOT more")
                chip_registry.write_pack(up, pk)
                chip_registry.sign_pack(up, ident)
                store = os.path.join(tmp, "trust.jsonl")
                trust.TrustRegistry(store).trust(ident.name, ident.public_key_b64)
                reg = chip_registry.ChipRegistry()
                r = reg.apply_signed_update(up, store)
                self.assertEqual((r["applied"], r["reason"]), (False, "chip_classes is not a JSON object"), bad)
                self.assertEqual(reg.sources(), [])

    def test_a_failing_file_beside_the_pack_still_refuses_the_update(self):
        """The copy that is verified holds every file the verifier reads beside the pack: a timestamp sidecar for
        another digest, a ledger that does not record the pack, a sidecar that is there but is not a regular file."""
        def tsr(stem):
            with open(stem + ".tsr.json", "w") as f:
                json.dump({"digest_sha256": "0" * 64, "tsa": "x", "tsr_b64": "AA=="}, f)

        def led(stem):
            ledger.Ledger(stem + ".ledger.jsonl").append({"anchored_pack_sha3": "0" * 64, "anchored_utc": "2026-11-20T00:00:00+00:00"})

        def directory(suffix):
            return lambda stem: os.mkdir(stem + suffix)
        for name in ("update.json", "update.pack"):
            for what, put, reason in (("tsr", tsr, "update is not trusted-signed"), ("ledger", led, "update is not trusted-signed"),
                                      ("tsr-dir", directory(".tsr.json"), "update not read"),
                                      ("ledger-dir", directory(".ledger.jsonl"), "update not read"),
                                      ("sig-dir", None, "update not read")):
                with tempfile.TemporaryDirectory() as tmp:
                    up, store, _ = self._update(tmp, {self.FUTURE: "nvidia-nras"}, name)
                    stem = up[:-5] if up.endswith(".json") else up
                    if put is None:
                        os.remove(stem + ".sig.json")
                        os.mkdir(stem + ".sig.json")
                    else:
                        put(stem)
                    reg = chip_registry.ChipRegistry()
                    r = reg.apply_signed_update(up, store)
                    self.assertFalse(r["applied"], (name, what, r))
                    self.assertTrue(r["reason"].startswith(reason), (name, what, r))
                    self.assertFalse(reg.is_known(self.FUTURE))

    def test_a_pack_not_named_json_and_a_missing_pack(self):
        with tempfile.TemporaryDirectory() as tmp:
            up, store, ident = self._update(tmp, {self.FUTURE: "nvidia-nras"}, "update.pack")
            reg = chip_registry.ChipRegistry()
            r = reg.apply_signed_update(up, store)
            self.assertEqual((r["applied"], r["added"], r["signer_id"]), (True, [self.FUTURE], ident.name))
            r = reg.apply_signed_update(os.path.join(tmp, "absent.json"), store)
            self.assertEqual((r["applied"], r["reason"]), (False, "update is not trusted-signed"))

    def test_valid_but_unsigned_and_signed_but_of_another_kind_are_refused(self):
        """The two gates before anything is applied (unchanged lines, held here): a pack that is intact but carries no
        signature, and a pack signed by the trusted curator whose kind is not the registry update's."""
        with tempfile.TemporaryDirectory() as tmp:
            up, store, ident = self._update(tmp, {self.FUTURE: "nvidia-nras"})
            os.remove(up[:-5] + ".sig.json")
            reg = chip_registry.ChipRegistry()
            r = reg.apply_signed_update(up, store)
            self.assertEqual((r["applied"], r["reason"]), (False, "update is not trusted-signed"))
            self.assertFalse(reg.is_known(self.FUTURE))
            # valid for the verifier, yet not trusted-signed: anchored in a ledger without a signature, and signed by
            # anybody when no trust registry is named (measured 20/11/2026: both are valid=True, authenticity PASS)
            pack.anchor_pack(up, up[:-5] + ".ledger.jsonl")
            r = reg.apply_signed_update(up, store)
            self.assertEqual((r["applied"], r["reason"]), (False, "update is not trusted-signed"), r)
            # Unreleased (Decision 1): the trust store requires a signature, so the unsigned anchored update is a FAIL
            self.assertIn("required but absent", r["authenticity"])
            anybody = os.path.join(tmp, "anybody.json")
            chip_registry.publish_signed_update(anybody, {self.FUTURE: "x"}, signing.Identity("anybody"), update_seq=1)
            for no_store in ("", None):
                r = reg.apply_signed_update(anybody, no_store)
                self.assertEqual((r["applied"], r["reason"]), (False, "update is not trusted-signed"), r)
                self.assertIn("NOT checked against a registry", r["authenticity"])   # wording of Unreleased (Decision 1)
            self.assertFalse(reg.is_known(self.FUTURE))
            other = os.path.join(tmp, "other.json")
            chip_registry.write_pack(other, chip_registry.build_pack("something_else", {"chip_classes": {self.FUTURE: "x"}},
                                                                     "a mapping, NOT more"))
            chip_registry.sign_pack(other, ident)
            r = reg.apply_signed_update(other, store)
            self.assertEqual((r["applied"], r["reason"]), (False, "wrong kind: something_else"))
            self.assertFalse(reg.is_known(self.FUTURE))
            self.assertEqual(reg.sources(), [])

    def test_signer_id_is_a_string_of_an_object_or_empty(self):
        f = chip_registry.ChipRegistry._signer_in
        self.assertEqual(f(b' {"signer_id": "curator"}\n'), "curator")
        for bad in (b"", b"[1]", b'"x"', b'{"signer_id": 5}', b'{"signer_id": ["a"]}', b'{"signer_id": null}', b"{}",
                    b'{"signer_id": "a", "signer_id": "b"}', b"\xff\xfe", b'{"signer_id": 1.5}'):
            self.assertEqual(f(bad), "", bad)


def _ossl(*args, cwd):
    p = subprocess.run([EXE, *args], cwd=cwd, capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"openssl {' '.join(args[:3])}: {p.stderr[-400:]}")
    return p


class _Server:
    """A local HTTP server: `routes[path]` is (status, headers, body) or a callable(handler); every request is logged."""

    def __init__(self, tls_context=None):
        outer = self
        self.routes, self.hits = {}, []

        class H(http.server.BaseHTTPRequestHandler):
            def _serve(self):
                outer.hits.append((self.command, self.path, self.headers.get("Host")))
                route = outer.routes.get(self.path.split("?")[0], (404, {}, b"no"))
                if callable(route):
                    return route(self)
                status, headers, body = route
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            do_GET = do_POST = _serve

            def log_message(self, *a):
                pass
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.httpd.daemon_threads = True
        if tls_context is not None:
            self.httpd.socket = tls_context.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@unittest.skipUnless(EXE, "openssl absent: the local TSAs cannot be built")
class TestCrlCaptureClosedRule(unittest.TestCase):
    """The lab, made with openssl here: root -> int -> tsa (the signer's chain), and beside them certificates that
    must never name a URL that is asked: `evil` (self-made), `sib` (issued by root, not an issuer of the signer),
    `int2` (issued by root with the NAME of int and another key), `fakeint` (the name and the key of int, issued by another "root": its signature does not verify under root).
    A second lab, `evilroot` -> `eviltsa`, is the TSA nobody trusts. Names under example.test never resolve: the tests
    give their addresses (`_resolve`) and carry the connections to the local servers (`_connect`)."""
    PUBLIC = "93.184.216.34"

    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp()
        cls.internal = _Server()     # stands for a service only this host can reach
        cls.internal.routes["/latest/meta-data"] = (200, {}, b"INTERNAL-SECRET-token")
        cls.crl_server = _Server()   # stands for the public host of the CRLs
        ip = cls.internal.port
        ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes"]

        def ext(name, text):
            with open(os.path.join(cls.d, name + ".ext"), "w") as f:
                f.write(text)

        def selfsigned(name, cn, cdp=None):
            _ossl("req", "-x509", *ec, "-keyout", name + ".key", "-out", name + ".pem", "-subj", "/CN=" + cn, "-days", "2",
                  *(["-addext", "crlDistributionPoints=" + cdp] if cdp else []), cwd=cls.d)

        def issued(name, cn, ca, text, key_of=None):
            if key_of is None:
                _ossl("req", *ec, "-keyout", name + ".key", "-out", name + ".csr", "-subj", "/CN=" + cn, cwd=cls.d)
            ext(name, text)
            _ossl("x509", "-req", "-in", (key_of or name) + ".csr", "-CA", ca + ".pem", "-CAkey", ca + ".key",
                  "-CAcreateserial", "-out", name + ".pem", "-days", "2", "-extfile", name + ".ext", cwd=cls.d)
        ca_ext = "basicConstraints=critical,CA:TRUE\nkeyUsage=keyCertSign,cRLSign\n"
        tsa_ext = "extendedKeyUsage=critical,timeStamping\nbasicConstraints=CA:FALSE\n"
        selfsigned("root", "root")
        issued("int", "int", "root", ca_ext + "crlDistributionPoints=URI:http://crl.example.test/root.crl\n")
        issued("tsa", "tsa", "int", tsa_ext + "crlDistributionPoints=URI:http://crl.example.test/int.crl\n")
        issued("sib", "sib", "root", ca_ext + "crlDistributionPoints=URI:http://crl.example.test/sibling.crl\n")
        # the name of int, another key, issued by root: verifies under root, has the issuer's name, did not issue tsa
        issued("int2", "int", "root", ca_ext + "crlDistributionPoints=URI:http://crl.example.test/int2.crl\n")
        selfsigned("evil", "evil", f"URI:http://127.0.0.1:{ip}/latest/meta-data")
        selfsigned("fakeroot", "root")
        issued("fakeint", "int", "fakeroot", ca_ext + f"crlDistributionPoints=URI:http://127.0.0.1:{ip}/latest/meta-data,"
               "URI:http://crl.example.test/forged.crl\n", key_of="int")
        # a TSA of the trusted chain whose own certificate names addresses that are not public, in several forms
        cls.inner_urls = [f"http://127.0.0.1:{ip}/latest/meta-data", f"http://127.1:{ip}/latest/meta-data",
                          f"http://0x7f000001:{ip}/latest/meta-data", f"http://[::ffff:127.0.0.1]:{ip}/latest/meta-data",
                          f"http://localhost:{ip}/latest/meta-data", "http://169.254.169.254/latest/meta-data",
                          "http://10.0.0.1/x", f"http://0.0.0.0:{ip}/latest/meta-data", "ftp://crl.example.test/x.crl",
                          f"http://%31%32%37.0.0.1:{ip}/latest/meta-data"]
        issued("tsain", "tsain", "int", tsa_ext + "crlDistributionPoints=" + ",".join("URI:" + u for u in cls.inner_urls) + "\n")
        selfsigned("evilroot", "evil-ca")
        issued("eviltsa", "evil-tsa", "evilroot", tsa_ext + f"crlDistributionPoints=URI:http://127.0.0.1:{ip}/latest/meta-data\n")
        # the CRLs of root and int, DER (RFC 5280 section 4.2.1.13) and PEM
        for ca in ("root", "int"):
            with open(os.path.join(cls.d, ca + ".cnf"), "w") as f:
                f.write(f"[ ca ]\ndefault_ca = c\n[ c ]\ndatabase = ./{ca}.index\ncrlnumber = ./{ca}.crlnumber\n"
                        "default_md = sha256\ndefault_crl_days = 1\n")
            open(os.path.join(cls.d, ca + ".index"), "w").close()
            with open(os.path.join(cls.d, ca + ".crlnumber"), "w") as f:
                f.write("01\n")
            _ossl("ca", "-gencrl", "-config", ca + ".cnf", "-keyfile", ca + ".key", "-cert", ca + ".pem", "-out", ca + ".crl.pem", cwd=cls.d)
            _ossl("crl", "-in", ca + ".crl.pem", "-outform", "DER", "-out", ca + ".crl", cwd=cls.d)
        cls.root_crl, cls.int_crl = cls._read("root.crl"), cls._read("int.crl")
        cls.crl_server.routes["/root.crl"] = (200, {"Content-Type": "application/pkix-crl"}, cls.root_crl)
        cls.crl_server.routes["/int.crl"] = (200, {"Content-Type": "application/pkix-crl"}, cls.int_crl)
        with open(os.path.join(cls.d, "serial"), "w") as f:
            f.write("01\n")
        cls.digest = hashlib.sha256(b"the pack").hexdigest()
        cls.root = os.path.join(cls.d, "root.pem")

    @classmethod
    def tearDownClass(cls):
        cls.internal.close()
        cls.crl_server.close()
        shutil.rmtree(cls.d, ignore_errors=True)

    @classmethod
    def _read(cls, name):
        with open(os.path.join(cls.d, name), "rb") as f:
            return f.read()

    @classmethod
    def _reply(cls, signer, carried, digest=None, query=None):
        """a granted reply of `openssl ts -reply` signed by `signer`, carrying the certificates `carried`"""
        with open(os.path.join(cls.d, "carried.pem"), "wb") as f:
            f.write(b"".join(cls._read(c + ".pem") for c in carried))
        with open(os.path.join(cls.d, "ts.cnf"), "w") as f:
            f.write(f"[ tsa ]\ndefault_tsa = t\n[ t ]\ndir = .\nserial = ./serial\nsigner_cert = ./{signer}.pem\n"
                    f"certs = ./carried.pem\nsigner_key = ./{signer}.key\nsigner_digest = sha256\ndefault_policy = 1.2.3.4.1\n"
                    "digests = sha256\ness_cert_id_chain = no\ness_cert_id_alg = sha256\n")
        if query is None:
            _ossl("ts", "-query", "-digest", digest or cls.digest, "-sha256", "-cert", "-out", "q.tsq", cwd=cls.d)
        else:
            with open(os.path.join(cls.d, "q.tsq"), "wb") as f:
                f.write(query)
        _ossl("ts", "-reply", "-config", "ts.cnf", "-queryfile", "q.tsq", "-out", "r.tsr", cwd=cls.d)
        return cls._read("r.tsr")

    def setUp(self):
        del self.internal.hits[:]
        del self.crl_server.hits[:]
        self.resolved, self.connected = [], []
        self.answers = {"crl.example.test": [self.PUBLIC]}
        self.carry_to = self.crl_server.port

        def resolve(host, port):
            self.resolved.append(host)
            if host not in self.answers:
                raise socket.gaierror("no such name (test)")
            got = self.answers[host]
            return got.pop(0) if got and isinstance(got[0], list) else got

        def connect(address, port, timeout):
            self.connected.append((address, port))
            return socket.create_connection(("127.0.0.1", self.carry_to), timeout=timeout)
        for name, fn in (("_resolve", resolve), ("_connect", connect)):
            if F is not None:
                pt = mock.patch.object(F, name, fn)
                pt.start()
                self.addCleanup(pt.stop)

    def _material(self, signer, carried, **kw):
        tsr = base64.b64encode(self._reply(signer, carried)).decode()
        return T.extract_validation_material(tsr, timeout=10, **kw)

    # ---- (a) no verified token, no request ----------------------------------------------------------------------
    def test_stamp_pack_with_a_tsa_nobody_trusts_asks_nothing(self):
        """fails on 9c55515: one GET reached the loopback service and its answer was in the sidecar. The real path:
        pack.stamp_pack against a local TSA whose self-made certificate names a loopback URL."""
        outer = self

        def tsa(handler):
            body = outer._reply("eviltsa", ["evilroot"], query=handler.rfile.read(int(handler.headers["Content-Length"])))
            handler.send_response(200)
            handler.send_header("Content-Length", str(len(body)))
            handler.end_headers()
            handler.wfile.write(body)
        fake_tsa = _Server()
        self.addCleanup(fake_tsa.close)
        fake_tsa.routes["/"] = tsa
        with tempfile.TemporaryDirectory() as tmp:
            pp = os.path.join(tmp, "p.json")
            pack.write_pack(pp, pack.build_pack("demo", {"x": 1}, "a demo, NOT a real pack"))
            wrong = os.path.join(self.d, "root.pem")     # a real anchor, not this TSA's
            for kw in ({}, {"ca_file": wrong}, {"ca_file": os.path.join(tmp, "absent.pem")}):
                try:
                    r = pack.stamp_pack(pp, f"http://127.0.0.1:{fake_tsa.port}/", capture_ltv=True, fetch_crl=True, **kw)
                except TypeError:
                    if not kw:
                        raise
                    continue      # 9c55515 has no ca_file: its failure is the first round
                self.assertTrue(r["anchored"])
                self.assertEqual(self.internal.hits, [], kw)
                self.assertEqual((self.resolved, self.connected), ([], []))
                with open(pp[:-5] + ".tsr.json", encoding="utf-8") as f:
                    vm = json.load(f)["validation_material"]
                self.assertEqual(vm["crls_b64"], [])
                self.assertIs(vm["crl_fetch"]["fetched"], False)
                self.assertIn("not verified against the caller's trust anchor", vm["crl_fetch"]["reason"])
                self.assertEqual(vm["token_verified"], False if kw else None)
                self.assertEqual(vm["tsa_transport"], "http")
                self.assertIn("not verified against a trust anchor", vm["note"])
                self.assertEqual(vm["crl_distribution_points"], [f"http://127.0.0.1:{self.internal.port}/latest/meta-data"])
                self.assertNotIn(base64.b64encode(b"INTERNAL-SECRET-token").decode()[:24], json.dumps(vm))
                v = verify_pack(pp)     # the sidecar with the new fields is still read by the verifier
                self.assertEqual([ly for ly in v["layers"] if ly["status"] == "FAIL" and ly["layer"] != "authenticity"], [], v)

    def test_stamp_pack_with_the_tsa_of_the_callers_anchor_captures_its_crls(self):
        """The same path when the caller names the anchor and the token verifies against it: the two CRLs of the
        signer's chain are in the sidecar, and verify_pack (Python) still reads it."""
        outer = self

        def tsa(handler):
            body = outer._reply("tsa", ["int", "evil"], query=handler.rfile.read(int(handler.headers["Content-Length"])))
            handler.send_response(200)
            handler.send_header("Content-Length", str(len(body)))
            handler.end_headers()
            handler.wfile.write(body)
        fake_tsa = _Server()
        self.addCleanup(fake_tsa.close)
        fake_tsa.routes["/"] = tsa
        with tempfile.TemporaryDirectory() as tmp:
            pp = os.path.join(tmp, "p.json")
            pack.write_pack(pp, pack.build_pack("demo", {"x": 1}, "a demo, NOT a real pack"))
            r = pack.stamp_pack(pp, f"http://127.0.0.1:{fake_tsa.port}/", capture_ltv=True, fetch_crl=True, ca_file=self.root)
            self.assertTrue(r["anchored"])
            with open(pp[:-5] + ".tsr.json", encoding="utf-8") as f:
                vm = json.load(f)["validation_material"]
            self.assertEqual((vm["token_verified"], vm["tsa_transport"], vm["crl_fetch"]),
                             (True, "http", {"fetched": True, "chain_certificates": 2}))
            self.assertNotIn("note", vm)
            self.assertEqual([(c["url"], base64.b64decode(c["crl_b64"])) for c in vm["crls_b64"]],
                             [("http://crl.example.test/int.crl", self.int_crl), ("http://crl.example.test/root.crl", self.root_crl)])
            self.assertEqual(self.internal.hits, [])
            ltv = [ly for ly in verify_pack(pp)["layers"] if ly["layer"] == "ltv-material"]
            self.assertEqual(len(ltv), 1)
            self.assertIn("3 cert(s), 2 CRL(s)", ltv[0]["detail"])
            # capture_ltv without fetch_crl: verified and said so, nothing asked
            del self.connected[:]
            pack.stamp_pack(pp, f"http://127.0.0.1:{fake_tsa.port}/", capture_ltv=True, ca_file=self.root)
            with open(pp[:-5] + ".tsr.json", encoding="utf-8") as f:
                vm = json.load(f)["validation_material"]
            self.assertEqual((vm["token_verified"], "crls_b64" in vm, "crl_fetch" in vm, self.connected), (True, False, False, []))

    def test_no_anchor_wrong_anchor_wrong_digest_or_check_not_run_ask_nothing(self):
        """fails on 9c55515. The token of the trusted chain itself, when the caller does not give what verifies it."""
        tsr = base64.b64encode(self._reply("tsa", ["int"])).decode()
        evilroot = os.path.join(self.d, "evilroot.pem")
        cases = [({}, None), ({"ca_file": self.root}, None), ({"expected_digest_hex": self.digest}, None),
                 ({"ca_file": self.root, "expected_digest_hex": ""}, None),
                 ({"ca_file": evilroot, "expected_digest_hex": self.digest}, False),
                 ({"ca_file": self.root, "expected_digest_hex": "0" * 64}, False),
                 ({"ca_file": os.path.join(self.d, "absent.pem"), "expected_digest_hex": self.digest}, False)]
        real = T.verify
        for kw, verified in cases:
            calls = []

            def counting(*a, **k):
                calls.append(k.get("ca_file"))
                return real(*a, **k)
            with mock.patch.object(T, "verify", counting):
                m = T.extract_validation_material(tsr, fetch_crl=True, timeout=10, **kw)
            # verified against the anchor the CALLER gave, or not at all: never against one found elsewhere
            self.assertEqual(calls, [] if verified is None else [kw["ca_file"]], kw)
            self.assertEqual((self.resolved, self.connected, self.crl_server.hits), ([], [], []), kw)
            self.assertEqual((m["available"], m["crls_b64"], m["crl_fetch"]["fetched"], m["token_verified"]),
                             (True, [], False, verified), kw)
            self.assertTrue(m["crl_fetch"]["reason"].endswith("no URL named by its certificates is asked"), m)

        def not_run(*a, **k):
            raise T.CheckNotRun("cannot run openssl here: test")
        with mock.patch.object(T, "verify", not_run):
            m = T.extract_validation_material(tsr, fetch_crl=True, timeout=10, ca_file=self.root, expected_digest_hex=self.digest)
        self.assertEqual((self.connected, m["crls_b64"], m["crl_fetch"]["fetched"], m["token_verified"]), ([], [], False, None))
        self.assertIn("could not be run", m["crl_fetch"]["reason"])
        for answer in ({"verified": None}, {"verified": 1}, {"verified": "True"}, {}):   # only True is verified
            with mock.patch.object(T, "verify", lambda *a, answer=answer, **k: answer):
                m = T.extract_validation_material(tsr, fetch_crl=True, timeout=10, ca_file=self.root, expected_digest_hex=self.digest)
            self.assertEqual((self.connected, m["crls_b64"], m["crl_fetch"]["fetched"]), ([], [], False), answer)
            self.assertIsNone(m["token_verified"], answer)
        self.assertIs(real, T.verify)
        # without fetch_crl nothing about CRLs is said and nothing is asked, as before
        m = T.extract_validation_material(tsr, timeout=10)
        self.assertNotIn("crls_b64", m)
        self.assertNotIn("crl_fetch", m)
        self.assertEqual(m["cert_count"], 2)

    # ---- (b) only the signer's chain ------------------------------------------------------------------------------
    def test_verified_token_only_the_signers_chain_names_a_url(self):
        """fails on 9c55515 (the loopback URL of `evil` was asked). The token carries int beside evil, sib and fakeint:
        the two distribution points of tsa and int are asked, at the public address, and their CRLs kept."""
        kw = dict(fetch_crl=True, ca_file=self.root, expected_digest_hex=self.digest)
        # with the forged copy of the issuer met first, openssl does not build the chain: not verified, nothing asked
        m = self._material("tsa", ["fakeint", "evil", "sib", "int"], **kw)
        self.assertEqual((m["token_verified"], m["crls_b64"], m["crl_fetch"]["fetched"], self.connected), (False, [], False, []))
        m = self._material("tsa", ["int", "fakeint", "evil", "sib", "int2"], **kw)
        self.assertIs(m["token_verified"], True)
        self.assertNotIn("note", m)
        self.assertEqual(m["crl_fetch"], {"fetched": True, "chain_certificates": 2})
        self.assertEqual(self.internal.hits, [])
        self.assertEqual(sorted(self.connected), [(self.PUBLIC, 80), (self.PUBLIC, 80)])
        self.assertEqual(sorted(h[1] for h in self.crl_server.hits), ["/int.crl", "/root.crl"])
        self.assertEqual({h[2] for h in self.crl_server.hits}, {"crl.example.test"})
        self.assertEqual(m["crls_b64"], [
            {"url": "http://crl.example.test/int.crl", "crl_b64": base64.b64encode(self.int_crl).decode(), "bytes": len(self.int_crl)},
            {"url": "http://crl.example.test/root.crl", "crl_b64": base64.b64encode(self.root_crl).decode(), "bytes": len(self.root_crl)}])
        # every distribution point the token carries is still listed, asked or not
        self.assertEqual(len(m["crl_distribution_points"]), 6)
        self.assertEqual(m["cert_count"], 6)

    def test_chain_through_untrusted_and_a_signer_that_is_not_anchored(self):
        """The issuer given by the caller (`untrusted`) joins the chain; when it is not given the token does not verify."""
        tsr = base64.b64encode(self._reply("tsa", ["evil"])).decode()
        kw = dict(fetch_crl=True, timeout=10, ca_file=self.root, expected_digest_hex=self.digest)
        m = T.extract_validation_material(tsr, **kw)
        self.assertEqual((m["token_verified"], m["crls_b64"], self.connected), (False, [], []))
        m = T.extract_validation_material(tsr, untrusted=os.path.join(self.d, "int.pem"), **kw)
        self.assertEqual((m["token_verified"], m["crl_fetch"]), (True, {"fetched": True, "chain_certificates": 2}))
        self.assertEqual([c["url"] for c in m["crls_b64"]], ["http://crl.example.test/int.crl", "http://crl.example.test/root.crl"])
        # the chain is not taken on verify's word alone: a signer that does not verify under ca_file names nothing
        del self.connected[:]
        # ... and "under ca_file" is that file alone, not the store openssl finds by itself (here made to hold evilroot)
        with mock.patch.object(T, "verify", lambda *a, **k: {"verified": True}), \
                mock.patch.dict(os.environ, {"SSL_CERT_FILE": os.path.join(self.d, "evilroot.pem")}):
            m = T.extract_validation_material(base64.b64encode(self._reply("eviltsa", ["evilroot"])).decode(), **kw)
        self.assertEqual((m["crls_b64"], m["crl_fetch"]["fetched"], self.connected, self.internal.hits), ([], False, [], []))
        self.assertIn("does not verify under ca_file", m["crl_fetch"]["reason"])
        with mock.patch.object(T, "_CHAIN_POOL_MAX", 1):
            m = self._material("tsa", ["int"], **{k: v for k, v in kw.items() if k != "timeout"})
        self.assertEqual((m["crls_b64"], m["crl_fetch"]["fetched"]), ([], False))
        self.assertIn("more than 1 certificates", m["crl_fetch"]["reason"])

    def test_verified_chain_naming_addresses_that_are_not_public_is_refused_per_url(self):
        """A TSA of the trusted chain whose certificate names loopback, link-local and private addresses in several
        forms: none is asked, each refusal is recorded; the issuer's public one is still asked."""
        m = self._material("tsain", ["int"], fetch_crl=True, ca_file=self.root, expected_digest_hex=self.digest)
        self.assertIs(m["token_verified"], True)
        self.assertEqual(self.internal.hits, [])
        self.assertEqual(self.connected, [(self.PUBLIC, 80)])
        got = {c["url"]: c for c in m["crls_b64"]}
        self.assertEqual(sorted(got), sorted(self.inner_urls + ["http://crl.example.test/root.crl"]))
        for u in self.inner_urls:
            self.assertTrue(got[u]["error"].startswith("refused: "), got[u])
            self.assertNotIn("crl_b64", got[u])
        self.assertEqual(got["http://crl.example.test/root.crl"]["bytes"], len(self.root_crl))

    # ---- (c) the URL rule, generated --------------------------------------------------------------------------------
    @staticmethod
    def _forms(rng, a):
        """the texts a resolver reads as the IPv4 address `a` (inet_aton), and IPv6 texts that carry it"""
        o = list(a.packed)
        n = int(a)
        fmt = lambda v: rng.choice(["%d", "0x%x", "0X%X", "0%o"]) % v   # noqa: E731
        forms = [str(a), str(n), hex(n), "0%o" % n, ".".join(fmt(x) for x in o), "%s.%s" % (fmt(o[0]), fmt(n & 0xFFFFFF)),
                 "%s.%s.%s" % (fmt(o[0]), fmt(o[1]), fmt(n & 0xFFFF)), str(a) + ".",
                 "".join(chr(ord(c) + 0xFEE0) if c.isdigit() else c for c in str(a)),
                 "[::ffff:%s]" % a, "[::ffff:%x:%x]" % (n >> 16, n & 0xFFFF), "[::FFFF:%s]" % a,
                 "[0:0:0:0:0:ffff:%x:%x]" % (n >> 16, n & 0xFFFF)]
        return forms

    def _refused(self, url, also_resolved=False):
        with self.assertRaises(ValueError, msg=url) as cm:
            F.fetch(url, timeout=5)
        self.assertIsInstance(cm.exception, F.Refused, url)
        self.assertEqual(self.connected, [], url)
        if not also_resolved:
            self.assertEqual(self.resolved, [], url)
        return str(cm.exception)

    def test_generated_addresses_that_are_not_public_are_never_connected_to(self):
        """fails on 9c55515. 400 addresses drawn from the ranges the rule names, each in 13 texts for IPv4 (decimal,
        hexadecimal, octal, one to four parts, a final dot, fullwidth digits, IPv4-mapped IPv6) and with a random
        scheme case, port and path; then the same texts for 60 public addresses, which ARE connected to (the control
        of the generator: it does not refuse everything)."""
        rng = random.Random(20261120)
        v4 = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10", "0.0.0.0/32",
              "0.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32", "192.0.2.0/24", "198.18.0.0/15"]
        v6 = ["::1/128", "::/128", "fe80::/10", "fc00::/7", "fec0::/10", "ff00::/8", "2001:db8::/32", "64:ff9b::/96",
              "2002:7f00::/24", "2002:a00::/24", "2002:c0a8::/32", "2001:0:7f00::/40", "::/96", "100::/64"]
        n_urls = 0
        kinds = set()
        for _ in range(400):
            if rng.random() < 0.7:
                net = ipaddress.ip_network(rng.choice(v4))
                a = net[rng.randrange(net.num_addresses)]
                hosts = self._forms(rng, a)
            else:
                net = ipaddress.ip_network(rng.choice(v6))
                a = net[rng.randrange(net.num_addresses)]
                hosts = ["[%s]" % a, "[%s]" % a.exploded, "[%s]" % str(a).upper()]
            for h in hosts:
                url = "%s://%s%s%s" % (rng.choice(["http", "https", "HTTP", "hTtPs"]), h,
                                       rng.choice(["", ":80", ":8080", ":%d" % self.internal.port]), rng.choice(["", "/", "/a.crl", "/latest/meta-data?x=1"]))
                why = self._refused(url)
                self.assertIn("address", why, url)
                kinds.add(why.split(" a ", 1)[1].split(" ")[0])
                n_urls += 1
        self.assertGreater(n_urls, 3500)
        self.assertGreaterEqual(len(kinds), 8, kinds)
        self.assertEqual(self.internal.hits, [])
        self.crl_server.routes["/ok.crl"] = (200, {}, self.int_crl)
        asked = 0
        for _ in range(60):
            a = ipaddress.IPv4Address(rng.choice(["8.8.8.8", "1.1.1.1", "93.184.216.34", "151.101.1.69", "9.9.9.9"]))
            for h in self._forms(rng, a):
                del self.connected[:]
                self.assertEqual(F.fetch("http://%s/ok.crl" % h, timeout=5), self.int_crl, h)
                self.assertEqual(self.connected, [(str(a), 80)], h)
                asked += 1
        self.assertEqual(asked, 60 * 13)
        self.assertEqual(self.resolved, [])
        # the two functions on their own: the text read as an address, and the kind that refuses it
        for text, want in (("127.0.0.1.", "127.0.0.1"), ("\uff11\uff12\uff17.\uff10.\uff10.\uff11", "127.0.0.1"), ("[::1]", "::1"),
                           ("::ffff:10.0.0.1", "10.0.0.1"), ("fe80::1%eth0", "fe80::1"), ("0x7f.1", "127.0.0.1")):
            self.assertEqual(str(F.address_of(text)), want, text)
        for text in ("crl.example.test", "", "127.0.0.1 x", "1.2.3.4.5", "\u2603", None, 5):
            self.assertIsNone(F.address_of(text), text)
        for text, kind in (("127.0.0.1", "loopback"), ("0.0.0.0", "unspecified"), ("169.254.169.254", "link-local"),
                           ("100.64.0.1", "shared (100.64.0.0/10)"), ("fec0::1", "site-local"), ("10.0.0.1", "private"),
                           ("192.168.1.1", "private"), ("fc00::1", "private"), ("224.0.0.1", "multicast"), ("8.8.8.8", None)):
            self.assertEqual(F.why_not_public(ipaddress.ip_address(text)), kind, text)

    def test_generated_urls_outside_the_grammar_are_refused_before_any_io(self):
        """fails on 9c55515. Schemes, userinfo, percent signs, white space, control characters, backslashes, ports,
        empty hosts and values that are not strings; `localhost` in every spelling without asking the resolver."""
        rng = random.Random(20261121)
        bad = [None, 1, b"http://crl.example.test/x", ["http://crl.example.test/x"], "", "crl.example.test/x.crl", "//crl.example.test/x",
               "http://", "http:///x.crl", "https://:443/x", "http://crl.example.test:0/x", "http://crl.example.test:65536/x",
               "http://crl.example.test:port/x", "http://crl.example.test:-1/x", "http://[::1/x", "http://[zz]/x",
               "http://user@crl.example.test/x", "http://user:pw@crl.example.test/x", "http://crl.example.test@127.0.0.1/x",
               "http://@crl.example.test/x", "http://127.0.0.1\\@crl.example.test/x", "http://crl.example.test\\x",
               "http://%31%32%37.0.0.1/x", "http://crl%2eexample.test/x", "http://[fe80::1%25eth0]/x", "http://[fe80::1%eth0]/x",
               "http://crl.example.test /x", " http://crl.example.test/x", "http://crl.example.test/x\n", "http://crl.exa\tmple.test/x",
               "http://crl.example.test/x\r\nHost: 127.0.0.1", "http://crl.example.test/\x00", "http://crl.example.test/\x7f",
               "http://\u00a0crl.example.test/x", "http://xn--\u00e9.example.test/x"]
        for scheme in ("file", "ftp", "gopher", "data", "ldap", "ldaps", "jar", "dict", "sftp", "tftp", "ws", "wss", "httpx", "shttp", "h", ""):
            for rest in ("://crl.example.test/x.crl", ":///etc/passwd", "://127.0.0.1/x"):
                bad.append(scheme + rest)
                bad.append(scheme.upper() + rest)
        for _ in range(300):   # a valid URL with one character of the forbidden set put in at a random place
            u = list("http://crl.example.test:8080/pki/a.crl?x=1")
            u.insert(rng.randrange(len(u) + 1), rng.choice([" ", "\t", "\n", "\r", "\x00", "\x1f", "\x7f", "\\", "\u2028", "\u00a0", "\x0b", "\x0c"]))
            bad.append("".join(u))
        for url in bad:
            self._refused(url)
        for name in ("localhost", "LOCALHOST", "localhost.", "LocalHost.", "a.localhost", "a.b.LOCALHOST.", "localhost:8080"):
            self.assertIn("localhost", self._refused("http://%s/x" % name))
        self.assertGreater(len(bad), 400)
        self.assertEqual(self.internal.hits + self.crl_server.hits, [])

    def test_names_are_judged_by_every_address_and_connected_to_the_one_judged(self):
        """A name is refused when ANY of its addresses is not public, when it gives none, when it does not resolve; the
        connection goes to the address that was judged, and the name is asked once (an answer that changes afterwards
        moves nothing)."""
        rng = random.Random(20261122)
        inner = ["127.0.0.1", "10.1.2.3", "169.254.169.254", "::1", "fe80::1%eth0", "0.0.0.0", "::ffff:10.0.0.1", "192.168.0.9", "100.64.0.1", "fd00::1"]
        outer = ["93.184.216.34", "8.8.8.8", "2606:4700:4700::1111", "1.1.1.1"]
        for _ in range(300):
            answer = [rng.choice(outer) for _ in range(rng.randint(0, 3))]
            answer.insert(rng.randint(0, len(answer)), rng.choice(inner))
            self.answers["mixed.example.test"] = answer
            del self.resolved[:]
            why = self._refused("http://mixed.example.test/x.crl", also_resolved=True)
            self.assertIn("resolves to a", why)
            self.assertEqual(self.resolved, ["mixed.example.test"])
        for answer in ([], ["not-an-address"], ["93.184.216.34", "x"]):
            self.answers["odd.example.test"] = answer
            self.assertIn("does not resolve to IP addresses", self._refused("http://odd.example.test/x", also_resolved=True))
        self.assertIn("does not resolve here", self._refused("http://absent.example.test/x", also_resolved=True))
        # rebinding: public when judged, loopback when asked again -> never asked again
        self.answers["rebind.example.test"] = [["8.8.4.4"], ["127.0.0.1"], ["127.0.0.1"]]
        self.crl_server.routes["/r.crl"] = (200, {}, self.root_crl)
        del self.resolved[:]
        self.assertEqual(F.fetch("http://rebind.example.test:8081/r.crl?ca=1&x=y#frag", timeout=5), self.root_crl)
        self.assertEqual((self.resolved, self.connected), (["rebind.example.test"], [("8.8.4.4", 8081)]))
        self.assertEqual(self.crl_server.hits[-1], ("GET", "/r.crl?ca=1&x=y", "rebind.example.test:8081"))
        # a name outside ASCII is asked in its IDNA form
        self.answers["xn--caf-dma.example.test"] = [self.PUBLIC]
        del self.resolved[:]
        self.assertEqual(F.fetch("http://caf\u00e9.example.test/r.crl", timeout=5), self.root_crl)
        self.assertEqual(self.resolved, ["xn--caf-dma.example.test"])

    def test_no_redirect_no_proxy_and_only_status_200(self):
        """A redirect to the loopback service, to another public name, a 404 and a 206 are errors that name the
        status; the proxies of the environment are not asked."""
        loc = f"http://127.0.0.1:{self.internal.port}/latest/meta-data"
        for status, headers in ((301, {"Location": loc}), (302, {"Location": loc}), (303, {"Location": loc}), (307, {"Location": loc}),
                                (308, {"Location": loc}), (302, {"Location": "http://crl.example.test/int.crl"}),
                                (404, {}), (206, {}), (204, {}), (500, {}), (401, {"WWW-Authenticate": "Basic"})):
            self.crl_server.routes["/s"] = (status, headers, self.int_crl)
            with self.assertRaises(F.Refused) as cm:
                F.fetch("http://crl.example.test/s", timeout=5)
            self.assertIn(f"HTTP status {status}", str(cm.exception))
            self.assertEqual("redirects are not followed" in str(cm.exception), 300 <= status < 400)
        self.assertEqual(self.internal.hits, [])
        self.assertEqual([h[1] for h in self.crl_server.hits], ["/s"] * 11)
        proxy = _Server()
        self.addCleanup(proxy.close)
        env = {k: f"http://127.0.0.1:{proxy.port}" for k in ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY")}
        with mock.patch.dict(os.environ, env):
            self.assertEqual(F.fetch("http://crl.example.test/int.crl", timeout=5), self.int_crl)
        self.assertEqual(proxy.hits, [])

    def test_bounds_on_bytes_and_time(self):
        """One byte more than the bound, an answer without end and an answer of one byte at a time are dropped whole;
        the bound itself is read."""
        size = len(self.int_crl)
        self.assertEqual(F.fetch("http://crl.example.test/int.crl", timeout=5, max_bytes=size), self.int_crl)
        for limit in (size - 1, 1, 0):
            with self.assertRaises(F.Refused) as cm:
                F.fetch("http://crl.example.test/int.crl", timeout=5, max_bytes=limit)
            self.assertIn(f"exceeds {limit} bytes", str(cm.exception))
        sent = []

        def endless(handler):
            handler.send_response(200)
            handler.end_headers()
            try:
                while len(sent) < 4096:
                    handler.wfile.write(b"\x30" * 65536)
                    sent.append(1)
            except OSError:
                pass
        self.crl_server.routes["/endless"] = endless
        with self.assertRaises(F.Refused) as cm:
            F.fetch("http://crl.example.test/endless", timeout=10, max_bytes=300000)
        self.assertIn("exceeds 300000 bytes", str(cm.exception))
        self.assertLess(len(sent), 200)     # 4096 x 64 KiB were on offer

        def dribble(handler, body=self.int_crl, head=True):
            if head:
                handler.send_response(200)
                handler.send_header("Content-Length", str(len(body)))
                handler.end_headers()
            try:
                for i in range(len(body)):
                    handler.wfile.write(body[i:i + 1] if head else b"X")
                    handler.wfile.flush()
                    time.sleep(0.05)
            except OSError:
                pass
        self.crl_server.routes["/dribble"] = dribble
        self.crl_server.routes["/slowhead"] = lambda h: dribble(h, head=False)
        for path in ("/dribble", "/slowhead"):
            t0 = time.monotonic()
            with self.assertRaises(F.Refused) as cm:
                F.fetch("http://crl.example.test" + path, timeout=1)
            self.assertIn("no whole answer within 1 s", str(cm.exception), path)
            self.assertLess(time.monotonic() - t0, 4, path)
        self.assertGreater(size * 0.05, 5)   # the whole dribble would have taken longer than the bound

    def test_only_a_der_crl_is_kept(self):
        """RFC 5280 section 4.2.1.13: the URI MUST point to a single DER encoded CRL. Anything else is not kept: a text,
        the CRL in PEM, a certificate (same outer structure), a CRL cut short or followed by a byte, two CRLs."""
        cert = base64.b64decode(b"".join(self._read("int.pem").split(b"-----")[2].split()))

        def tlv(tag, *parts):
            v = b"".join(parts)
            return bytes([tag, len(v)]) + v
        empty, bits = tlv(0x30), tlv(0x03, b"\x00")
        # the outer shape of a CertificateList around a tbs without thisUpdate where RFC 5280 section 5.1 puts it: a
        # version 1 certificate (INTEGER, then four SEQUENCEs), and a tbs that ends after the issuer
        v1_cert = tlv(0x30, tlv(0x30, tlv(0x02, b"\x01"), empty, empty, empty, empty), empty, bits)
        no_time = tlv(0x30, tlv(0x30, empty, empty), empty, bits)
        least = tlv(0x30, tlv(0x30, empty, empty, tlv(0x17)), empty, bits)       # the least that has the structure
        self.assertEqual([F.is_der_crl(b) for b in (v1_cert, no_time, least, tlv(0x30, tlv(0x30, tlv(0x02, b"\x01"), empty, empty, tlv(0x18)), empty, bits))],
                         [False, False, True, True])
        self.assertTrue(F.is_der_crl(self.int_crl) and F.is_der_crl(self.root_crl))
        rng = random.Random(20261123)
        bodies = [b"", b"INTERNAL-SECRET-token", self._read("int.crl.pem"), cert, self.int_crl[:-1], self.int_crl + b"\x00",
                  self.int_crl + self.int_crl, b"\x30\x00", b"\x30\x80" + self.int_crl[2:], b"<html>404</html>", b"{}",
                  base64.b64encode(self.int_crl), v1_cert, no_time]
        for _ in range(300):    # the CRL with one byte of its structure changed, or cut at a random place
            b = bytearray(self.int_crl)
            if rng.random() < 0.5:
                b = b[:rng.randrange(len(b))]
            else:
                b[rng.randrange(8)] ^= 1 << rng.randrange(8)     # among the outer tags and lengths
            if bytes(b) != self.int_crl:
                bodies.append(bytes(b))
        kept = 0
        for body in bodies:
            ok = F.is_der_crl(body)
            kept += ok
            self.crl_server.routes["/b"] = (200, {"Content-Type": "application/pkix-crl"}, body)
            if ok:      # a changed byte that is still a CertificateList by structure (a tag of the same shape)
                self.assertEqual(F.fetch("http://crl.example.test/b", timeout=5), body)
            else:
                with self.assertRaises(F.Refused) as cm:
                    F.fetch("http://crl.example.test/b", timeout=5)
                self.assertIn("not a DER CRL", str(cm.exception))
        self.assertLess(kept, 20)
        self.assertFalse(any(F.is_der_crl(b) for b in bodies[:14]))
        # in the capture: the refusal is recorded, the bytes are not
        self.crl_server.routes["/int.crl"] = (200, {}, b"INTERNAL-SECRET-token")
        try:
            m = self._material("tsa", ["int"], fetch_crl=True, ca_file=self.root, expected_digest_hex=self.digest)
        finally:
            self.crl_server.routes["/int.crl"] = (200, {}, self.int_crl)
        self.assertEqual(m["crls_b64"][0], {"url": "http://crl.example.test/int.crl",
                                            "error": "refused: the answer is not a DER CRL (RFC 5280 section 4.2.1.13)"})
        self.assertEqual(m["crls_b64"][1]["bytes"], len(self.root_crl))

    def test_caps_on_the_number_of_urls_and_on_the_bytes_in_all(self):
        asked = []

        def fake(url, timeout, max_bytes):
            asked.append((url, max_bytes))
            return b"x" * 1000
        urls = ["http://crl.example.test/%02d.crl" % i for i in range(20)]
        with mock.patch.object(F, "fetch", fake):
            out = T._fetch_crls(urls, 5)
            self.assertEqual((len(asked), F.CRL_MAX_URLS), (16, 16))
            self.assertEqual([("crl_b64" in c, c.get("bytes")) for c in out[:16]], [(True, 1000)] * 16)
            self.assertEqual([c["error"] for c in out[16:]], ["not asked: more than 16 distribution points"] * 4)
            self.assertEqual({m for _, m in asked}, {F.CRL_MAX_BYTES})
            del asked[:]
            with mock.patch.object(F, "CRL_TOTAL_MAX_BYTES", 2500):
                out = T._fetch_crls(urls[:5], 5)
            self.assertEqual([m for _, m in asked], [2500, 1500, 500])
            self.assertEqual([c.get("bytes") for c in out[:3]], [1000] * 3)
            self.assertEqual([c["error"] for c in out[3:]], ["not asked: 2500 bytes of CRLs already captured"] * 2)
            del asked[:]
            with mock.patch.object(F, "CRL_TOTAL_MAX_BYTES", 3000):     # the bound reached exactly: nothing more is asked
                out = T._fetch_crls(urls[:5], 5)
            self.assertEqual([m for _, m in asked], [3000, 2000, 1000])
            self.assertEqual([c["error"] for c in out[3:]], ["not asked: 3000 bytes of CRLs already captured"] * 2)

            def boom(url, timeout, max_bytes):
                raise ConnectionResetError("reset by peer")
        with mock.patch.object(F, "fetch", boom):
            self.assertEqual(T._fetch_crls(urls[:1], 5), [{"url": urls[0], "error": "ConnectionResetError: reset by peer"}])
        self.assertEqual((F.CRL_MAX_BYTES, F.CRL_TOTAL_MAX_BYTES), (8 * 1024 * 1024, 32 * 1024 * 1024))
        self.assertLess(F.CRL_TOTAL_MAX_BYTES * 4 // 3 + 4, ledger.MAX_INPUT_BYTES)   # the sidecar stays readable by a verifier

    def test_https_is_checked_against_the_name_of_the_url(self):
        """Over TLS the connection is carried to the judged address and the server's certificate must be for the
        URL's host: a certificate for another name is a failed connection, not a CRL."""
        for cn, ok in (("crl.example.test", True), ("other.example.test", False)):
            name = "srv-" + cn.split(".")[0]
            _ossl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", name + ".key",
                  "-out", name + ".pem", "-subj", "/CN=" + cn, "-days", "2", "-addext", "subjectAltName=DNS:" + cn, cwd=self.d)
            sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            sctx.load_cert_chain(os.path.join(self.d, name + ".pem"), os.path.join(self.d, name + ".key"))
            srv = _Server(sctx)
            self.addCleanup(srv.close)
            srv.routes["/int.crl"] = (200, {}, self.int_crl)
            self.carry_to = srv.port
            real = ssl.create_default_context

            def trusting(*a, name=name, **k):
                c = real(*a, **k)
                c.load_verify_locations(os.path.join(self.d, name + ".pem"))
                return c
            del self.connected[:]
            with mock.patch.object(ssl, "create_default_context", trusting):
                if ok:
                    self.assertEqual(F.fetch("https://crl.example.test/int.crl", timeout=5), self.int_crl)
                    self.assertEqual(srv.hits, [("GET", "/int.crl", "crl.example.test")])
                else:
                    with self.assertRaises(ssl.SSLCertVerificationError):
                        F.fetch("https://crl.example.test/int.crl", timeout=5)
                    self.assertEqual(srv.hits, [])
            self.assertEqual(self.connected, [(self.PUBLIC, 443)])
            with self.assertRaises(ssl.SSLError):      # the same server without its certificate trusted
                F.fetch("https://crl.example.test/int.crl", timeout=5)


class TestCallerUrlsNoRedirectBounded(unittest.TestCase):
    """The four fetchers of a URL the CALLER gives (timestamp.stamp, ots.submit, chip_registry.discover_online and
    fetch_signed_update_online) go through _crl_fetch.ask: a redirect is never followed and the answer is bounded.
    Fails on 61d755d: each followed a 302 to another host (ots.submit stored that host's answer in its result) and read
    an answer of any size."""

    def setUp(self):
        self.hits, self.servers = [], []
        test = self

        class Inner(http.server.BaseHTTPRequestHandler):
            def _do(self):
                test.hits.append(self.path)
                self.send_response(200)
                self.send_header("Content-Length", "6")
                self.end_headers()
                self.wfile.write(b"SECRET")
            do_GET = do_POST = _do

            def log_message(self, *a):
                pass
        self.inner = self._serve(Inner)

    def tearDown(self):
        for srv in self.servers:
            srv.shutdown()
            srv.server_close()

    def _serve(self, handler):
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.servers.append(srv)
        return srv.server_address[1]

    def _outer(self, status=302, body=None):
        inner = self.inner

        class Outer(http.server.BaseHTTPRequestHandler):
            def _do(self):
                n = int(self.headers.get("Content-Length") or 0)
                if n:
                    self.rfile.read(n)
                if body is None:
                    self.send_response(status)
                    self.send_header("Location", f"http://localhost:{inner}/latest/meta-data/")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                else:
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
            do_GET = do_POST = _do

            def log_message(self, *a):
                pass
        return self._serve(Outer)

    def _four(self, port, tmp):
        d = "ab" * 32
        return {"stamp": T.stamp(d, f"http://127.0.0.1:{port}/tsa", timeout=5),
                "ots": ots.submit(d, [f"http://127.0.0.1:{port}/cal"], timeout=5),
                "discover": chip_registry.ChipRegistry().discover_online(f"http://127.0.0.1:{port}/feed.json", timeout=5),
                "update": chip_registry.ChipRegistry().fetch_signed_update_online(
                    f"http://127.0.0.1:{port}/u.json", os.path.join(tmp, "t.jsonl"), timeout=5)}

    def test_a_redirect_is_never_followed(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {"no_proxy": "*", "NO_PROXY": "*"}):
            for status in (301, 302, 303, 307, 308):
                got = self._four(self._outer(status), tmp)
                self.assertEqual(self.hits, [], (status, got))
                self.assertIn(f"HTTP status {status}", got["stamp"]["note"])
                self.assertEqual(got["ots"]["submitted"], [])
                self.assertIn(f"HTTP status {status}", got["ots"]["errors"][0]["error"])
                self.assertIn(f"HTTP status {status}", got["discover"]["reason"])
                self.assertIn(f"HTTP status {status}", got["update"]["reason"])
            ok = self._four(self.inner, tmp)                         # control: the same servers, no redirect
            self.assertEqual(len(self.hits), 5, ok)
            self.assertEqual(base64.b64decode(ok["ots"]["submitted"][0]["timestamp_b64"]), b"SECRET")

    def test_the_url_rule_and_only_status_200(self):
        """rule 1 of _crl_fetch before any connection, and a 2xx that is not 200 is an error"""
        with mock.patch.dict(os.environ, {"no_proxy": "*", "NO_PROXY": "*"}):
            for url in (f"http://u@127.0.0.1:{self.inner}/cal", f"http://127.0.0.1:{self.inner}\\@x/cal",
                        f"http://127.0.0.1:{self.inner}/c al", f"ftp://127.0.0.1:{self.inner}/cal"):
                got = ots.submit("ab" * 32, [url], timeout=5)
                self.assertEqual(got["submitted"], [], url)
                self.assertTrue(got["errors"][0]["error"].startswith("Refused: "), got)
            self.assertEqual(self.hits, [])

            class Created(http.server.BaseHTTPRequestHandler):
                def do_POST(self):
                    self.rfile.read(int(self.headers.get("Content-Length") or 0))
                    self.send_response(201)
                    self.send_header("Content-Length", "6")
                    self.end_headers()
                    self.wfile.write(b"SECRET")

                def log_message(self, *a):
                    pass
            got = ots.submit("ab" * 32, [f"http://127.0.0.1:{self._serve(Created)}/cal"], timeout=5)
            self.assertEqual((got["submitted"], got["errors"][0]["error"]), ([], "Refused: HTTP status 201"))

    def test_the_answer_is_bounded(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(os.environ, {"no_proxy": "*", "NO_PROXY": "*"}), \
                mock.patch.object(T, "TSA_REPLY_MAX_BYTES", 1000), mock.patch.object(ots, "OTS_REPLY_MAX_BYTES", 1000), \
                mock.patch.object(chip_registry, "MAX_INPUT_BYTES", 1000):
            got = self._four(self._outer(body=b"{" + b" " * 999 + b"}"), tmp)     # 1001 bytes
            for k, v in (("stamp", got["stamp"]["note"]), ("ots", got["ots"]["errors"][0]["error"]),
                         ("discover", got["discover"]["reason"]), ("update", got["update"]["reason"])):
                self.assertIn("exceeds 1000 bytes", v, k)
            got = self._four(self._outer(body=b"{" + b" " * 998 + b"}"), tmp)     # 1000 bytes: read whole
            self.assertEqual(len(base64.b64decode(got["ots"]["submitted"][0]["timestamp_b64"])), 1000)
            self.assertNotIn("exceeds", got["discover"].get("reason", ""))
            self.assertNotIn("exceeds", got["stamp"]["note"])


if __name__ == "__main__":
    unittest.main()
