"""Three defects found on 0.12.0 by a security review tool on 20 November 2026, each reproduced before it was fixed.

(1) `interop.aat.verify_chain` chose the session's recorder with a min() over all recorders for EVERY record: quadratic
    in a chain whose records each name their own recording_component (4000 records: 4.13 s, 0.29 s with one recorder).
    The `aat` CLI read its input files with open().read(): a FIFO in place of the chain blocked it, a file of any size
    was read whole.
(2) `chip_registry.apply_signed_update` verified the update pack from its path and then read it again from the same
    path (and the signature sidecar a third time): a pack replaced between the two reads was applied unverified.

Positive control: on c4953ac (the commit before these fixes) the tests marked "fails on c4953ac" in their docstring fail.
"""
import json
import os
import random
import subprocess
import sys
import tempfile
import unittest
import uuid
from unittest import mock

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)

from omega_evidence import chip_registry, ledger, pack, signing, trust  # noqa: E402
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
        """fails on c4953ac: there min() ran once per record, twice per record naming another recorder"""
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
        """The rule, computed here record by record the way c4953ac did: the session's recorder is the genesis'
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
        """fails on c4953ac: the CLI blocked on the FIFO (chain, --pubkey, --key, --epochs)"""
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
        """fails on c4953ac: a symlink to /dev/zero was read until memory ran out"""
        with tempfile.TemporaryDirectory() as tmp:
            link = os.path.join(tmp, "chain.jsonl")
            os.symlink("/dev/zero", link)
            for path in (link, tmp):
                rc, out, err = self._cli("verify", path)
                self.assertEqual(rc, 2, (path, out[:200], err[-300:]))
                self.assertIn("not a regular file", json.loads(out)["error"])

    def test_beyond_the_bound_is_refused_and_the_bound_itself_is_read(self):
        """fails on c4953ac (the module had no read_input): the bound, here lowered to the size of the chain file"""
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
        chip_registry.publish_signed_update(up, classes, ident)
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
        """fails on c4953ac: the pack put in place after verify_pack returned was applied (evil-chip known, signer
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
        """fails on c4953ac. 200 rounds: the pack, the sidecar or both are replaced before, during (after the n-th
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
        """fails on c4953ac: the pack was read twice and the signature sidecar twice"""
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
        """fails on c4953ac: AttributeError (a list, a string, a number, null, true)"""
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
            self.assertIn("anchored", r["authenticity"])
            anybody = os.path.join(tmp, "anybody.json")
            chip_registry.publish_signed_update(anybody, {self.FUTURE: "x"}, signing.Identity("anybody"))
            for no_store in ("", None):
                r = reg.apply_signed_update(anybody, no_store)
                self.assertEqual((r["applied"], r["reason"]), (False, "update is not trusted-signed"), r)
                self.assertIn("identity not checked", r["authenticity"])
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


if __name__ == "__main__":
    unittest.main()
