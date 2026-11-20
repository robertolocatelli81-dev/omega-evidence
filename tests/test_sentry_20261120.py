"""Three defects found on 0.12.0 by a security review tool on 20 November 2026, each reproduced before it was fixed.

(1) `interop.aat.verify_chain` chose the session's recorder with a min() over all recorders for EVERY record: quadratic
    in a chain whose records each name their own recording_component (4000 records: 4.13 s, 0.29 s with one recorder).
    The `aat` CLI read its input files with open().read(): a FIFO in place of the chain blocked it, a file of any size
    was read whole.

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

from omega_evidence import ledger  # noqa: E402
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


if __name__ == "__main__":
    unittest.main()
