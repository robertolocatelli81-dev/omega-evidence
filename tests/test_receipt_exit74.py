# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""2026-10-12 — a receipt that was not written whole is exit 74 (sysexits EX_IOERR), never the verdict's code.

Measured on 0.11.2 (864bef4) on 12 October 2026: with stdout on /dev/full or on a pipe whose reader had gone, Node and
Java exited 0 on a valid pack and 1 on a tampered one with an empty stderr; Go did the same on /dev/full and died of
SIGPIPE (141) on the pipe; Python exited 120 with an "Exception ignored" message from the interpreter's last flush (1 with
a traceback for a receipt over 64 KiB), and with stdout closed (`>&-`) exited 0 / 1 in silence. Where the exit code was the
verdict's, the receipt was lost and the code still said "verified" (or "not valid").

Every CLI that prints an outcome is run here as a real process (no mocked write), on a valid and an invalid input, in
these modes:
  file       stdout to a regular file: the verdict's code and the whole receipt (the control)
  devfull    stdout on /dev/full (ENOSPC); devfull-both: stderr on /dev/full too (exit 74 all the same)
  gone       stdout on a pipe whose read end was closed before the process started (EPIPE, deterministic)
  head       `cmd | head -c 0` through bash, the producer started 0.2 s after head, exit code of the producer (PIPESTATUS)
  closed     stdout closed (`>&-`): Python and Java see it; Node and Go get fd 1 reopened on /dev/null by their runtime,
             so for them `>&-` is `>/dev/null` and the verdict's code is the right answer (declared in the README)
  slow       a pipe read 0.5 s late: a receipt over 64 KiB still arrives whole, byte for byte the file's
  fsize      stdout to a regular file under `ulimit -f 4` (4 096 bytes): a receipt over that size gets a SHORT write and
             then EFBIG — Node's stdout on a file used to drop the rest of a short write and exit 0 (12/10/2026)
In every losing mode: exit 74, one `receipt not written: <reason>` line on stderr, no traceback, no "Exception ignored".

Runtimes: Python always; Node from PATH; Go from OEVERIFY_GO or built with the `go` on PATH; Java from OEVERIFY_JAVA or
compiled with the `javac` on PATH. A runtime that is not found is SKIPPED and said; with OE_EXIT74_REQUIRE_ALL=1 (the CI
job that installs all four) a missing runtime is a failure, so a skip can never read as green there."""
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
from omega_evidence import pack as P, signing as S   # noqa: E402

EX_IOERR = 74
SCOPE = "Proves the recorded facts' integrity and order; does NOT prove their truth and is NOT an accredited certification."
REQUIRE_ALL = os.environ.get("OE_EXIT74_REQUIRE_ALL") == "1"
_UTC = re.compile(rb'"verified_utc": ?"[0-9T:Z-]+"')


def same_receipt(a, b):
    """Byte for byte, except the second at which each run verified (`verified_utc`)."""
    return _UTC.sub(b'"verified_utc":"-"', a) == _UTC.sub(b'"verified_utc":"-"', b)
FX = {}          # fixtures, built once
RUNTIMES = {}    # name -> argv prefix, or a reason string when not available


def _build_fixtures(d):
    idt = S.Identity("exit74-signer", seed=bytes(range(32)))

    def mk(name, body, alg=None):
        p = os.path.join(d, name + ".json")
        P.write_pack(p, P.build_pack("probe-kind", body, SCOPE))
        P.anchor_pack(p, p[:-5] + ".ledger.jsonl")
        P.sign_pack(p, idt)
        if alg is not None:
            sp = p[:-5] + ".sig.json"
            with open(sp, encoding="utf-8") as f:
                sd = json.load(f)
            sd["sig_alg"] = alg
            with open(sp, "w", encoding="utf-8") as f:
                json.dump(sd, f)
        return p

    FX["valid"] = mk("valid", {"subject": "probe", "records": [{"a": 1}]})
    bad = mk("tampered", {"subject": "probe", "records": [{"a": 1}]})
    with open(bad, encoding="utf-8") as f:
        t = f.read()
    with open(bad, "w", encoding="utf-8") as f:
        f.write(t.replace('"a": 1', '"a": 2').replace('"a":1', '"a":2'))
    FX["invalid"] = bad
    # anchored, unknown sig_alg of 70 000 bytes: PASS, and the layer detail quotes it whole (receipt > 64 KiB)
    FX["big"] = mk("big", {"subject": "probe", "records": [{"a": 1}]}, alg="rsa-pss-" + "x" * 70000)
    from omega_evidence import agent
    from omega_evidence.interop import aat
    log = agent.AgentEvidenceLog(os.path.join(d, "agent.jsonl"), runtime_id="rt-1")
    log.record("bot-7", "sess-a", "tool_call", "https://api.example/x", "rule-1", agent.Decision.ALLOW, agent.Outcome.EXECUTED)
    log.record("bot-7", "sess-a", "file_write", "/tmp/out", "rule-2", agent.Decision.DENY, agent.Outcome.BLOCKED)
    chain = next(iter(aat.from_omega(list(log._ledger.entries()), "1.0", close=True).values()))
    FX["chain"] = os.path.join(d, "chain.jsonl")
    with open(FX["chain"], "w", encoding="utf-8") as f:
        f.write(aat.to_jsonl(chain))
    broken = json.loads(json.dumps(chain))
    broken[1]["action_detail"]["tool_name"] = "tampered"
    FX["chain_bad"] = os.path.join(d, "chain_bad.jsonl")
    with open(FX["chain_bad"], "w", encoding="utf-8") as f:
        f.write(aat.to_jsonl(broken))
    FX["missing"] = os.path.join(d, "no-such-chain.jsonl")


def _find_runtimes(d):
    RUNTIMES["python"] = [sys.executable, "-m", "omega_evidence"]
    RUNTIMES["node"] = ["node", os.path.join(ROOT, "verifiers", "js", "oeverify.mjs")] if shutil.which("node") else "no node on PATH"
    go = os.environ.get("OEVERIFY_GO")
    if not go and shutil.which("go"):
        b = os.path.join(d, "oeverify")
        r = subprocess.run(["go", "build", "-o", b, "./cmd/oeverify"], cwd=os.path.join(ROOT, "verifiers", "go"), capture_output=True, text=True)
        go = b if r.returncode == 0 else None
        if go is None:
            RUNTIMES["go"] = "go build failed: " + r.stderr[-300:]
    if go:
        RUNTIMES["go"] = shlex.split(go)
    elif "go" not in RUNTIMES:
        RUNTIMES["go"] = "no OEVERIFY_GO and no go on PATH"
    java = os.environ.get("OEVERIFY_JAVA")
    if not java and shutil.which("javac"):
        out = os.path.join(d, "oej")
        r = subprocess.run(["javac", "-d", out, os.path.join(ROOT, "verifiers", "java", "OeVerify.java")], capture_output=True, text=True)
        if r.returncode == 0:
            java = f"{os.path.join(os.path.dirname(os.path.realpath(shutil.which('javac'))), 'java')} -cp {out} OeVerify"
        else:
            RUNTIMES["java"] = "javac failed: " + r.stderr[-300:]
    if java:
        RUNTIMES["java"] = shlex.split(java)
    elif "java" not in RUNTIMES:
        RUNTIMES["java"] = "no OEVERIFY_JAVA and no javac on PATH"


def setUpModule():
    d = tempfile.mkdtemp(prefix="oe-exit74-")
    FX["dir"] = d
    _build_fixtures(d)
    _find_runtimes(d)


def tearDownModule():
    shutil.rmtree(FX.get("dir", ""), ignore_errors=True)


def _argv(runtime, pack):
    """The four pack CLIs take the ledger the same way; Go wants its flags before the positional argument."""
    base = RUNTIMES[runtime]
    led = pack[:-5] + ".ledger.jsonl"
    if runtime == "go":
        return base + ["-ledger", led, pack]
    return base + [pack, "--ledger", led] if runtime in ("python", "node") else base + [pack, "-ledger", led]


def run_mode(argv, mode):
    """Run argv as a real process with stdout in `mode`; return (rc, stdout bytes or None, stderr text)."""
    if mode == "file":
        with tempfile.TemporaryFile() as f:
            p = subprocess.run(argv, stdout=f, stderr=subprocess.PIPE, cwd=ROOT, timeout=120)
            f.seek(0)
            return p.returncode, f.read(), p.stderr.decode("utf-8", "replace")
    if mode == "devfull":
        with open("/dev/full", "wb") as f:
            p = subprocess.run(argv, stdout=f, stderr=subprocess.PIPE, cwd=ROOT, timeout=120)
        return p.returncode, None, p.stderr.decode("utf-8", "replace")
    if mode == "devfull-both":   # stderr full too: no line can be written, the exit is still 74 and nothing is raised
        with open("/dev/full", "wb") as f:
            p = subprocess.run(argv, stdout=f, stderr=f, cwd=ROOT, timeout=120)
        return p.returncode, None, ""
    if mode == "gone":
        r, w = os.pipe()
        os.close(r)           # the reader is gone before the process starts: every write is EPIPE
        try:
            p = subprocess.run(argv, stdout=w, stderr=subprocess.PIPE, cwd=ROOT, timeout=120)
        finally:
            os.close(w)
        return p.returncode, None, p.stderr.decode("utf-8", "replace")
    if mode in ("head", "closed"):
        cmd = " ".join(shlex.quote(a) for a in argv)
        # head: the producer starts 0.2 s after head, so the reader is gone when it writes. Started together, a fast
        # producer can write into the pipe buffer before head exits: the kernel accepted the bytes, the write succeeded,
        # and no program can know they were never read (measured 12/10/2026: Go, 1 run of 50, exit = the verdict's)
        script = f"(sleep 0.2; exec {cmd}) | head -c 0; exit ${{PIPESTATUS[0]}}" if mode == "head" else f"{cmd} >&-"
        p = subprocess.run(["bash", "-c", script], stderr=subprocess.PIPE, stdout=subprocess.DEVNULL, cwd=ROOT, timeout=120)
        return p.returncode, None, p.stderr.decode("utf-8", "replace")
    if mode == "fsize":   # a regular file that takes 4 096 bytes and no more: a short write, then EFBIG
        with tempfile.TemporaryDirectory() as td:
            o = os.path.join(td, "out")
            cmd = " ".join(shlex.quote(a) for a in argv)
            p = subprocess.run(["bash", "-c", f"ulimit -f 4; exec {cmd} > {shlex.quote(o)}"], stderr=subprocess.PIPE, cwd=ROOT, timeout=120)
            with open(o, "rb") as f:
                return p.returncode, f.read(), p.stderr.decode("utf-8", "replace")
    if mode == "slow":
        p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=ROOT)
        got = {}

        def drain_err():
            got["err"] = p.stderr.read()
        t = threading.Thread(target=drain_err)
        t.start()
        time.sleep(0.5)       # the writer fills the pipe buffer and waits
        out = p.stdout.read()
        rc = p.wait(timeout=120)
        t.join()
        p.stdout.close()
        p.stderr.close()
        return rc, out, got["err"].decode("utf-8", "replace")
    raise ValueError(mode)


class _Base(unittest.TestCase):
    runtime = None

    def setUp(self):
        v = RUNTIMES.get(self.runtime)
        if isinstance(v, str):
            if REQUIRE_ALL:
                self.fail(f"{self.runtime} verifier not available and OE_EXIT74_REQUIRE_ALL=1: {v}")
            self.skipTest(f"{self.runtime} verifier NOT measured: {v}")

    def assert_lost(self, argv, mode, label):
        rc, _, err = run_mode(argv, mode)
        self.assertEqual(rc, EX_IOERR, f"{label} {mode}: exit {rc}, stderr {err[-400:]!r}")
        self.assertIn("receipt not written:", err, f"{label} {mode}")
        self.assertNotIn("Traceback", err, f"{label} {mode}")
        self.assertNotIn("Exception ignored", err, f"{label} {mode}")
        self.assertNotIn("panic", err, f"{label} {mode}")

    def check_cli(self, argv, expected_rc, label, closed_seen=True):
        rc, out, err = run_mode(argv, "file")
        self.assertEqual(rc, expected_rc, f"{label} file: exit {rc}, stderr {err[-400:]!r}")
        self.assertTrue(out and out.endswith(b"\n"), f"{label} file: no receipt")
        self.assertNotIn("receipt not written", err)
        for mode in ("devfull", "gone", "head"):
            self.assert_lost(argv, mode, label)
        rc3, _, _ = run_mode(argv, "devfull-both")
        self.assertEqual(rc3, EX_IOERR, f"{label} devfull-both: exit {rc3}")
        if closed_seen:
            self.assert_lost(argv, "closed", label)
        else:   # runtime reopens fd 1 on /dev/null: `>&-` is `>/dev/null`, the verdict's code is the right answer
            rc2, _, err2 = run_mode(argv, "closed")
            self.assertEqual(rc2, expected_rc, f"{label} closed: exit {rc2}, stderr {err2[-400:]!r}")
        return out


class _PackCLI(_Base):
    closed_seen = True

    def test_valid_pack(self):
        out = self.check_cli(_argv(self.runtime, FX["valid"]), 0, f"{self.runtime} valid", self.closed_seen)
        self.assertEqual(json.loads(out)["verdict"], "PASS")

    def test_invalid_pack(self):
        out = self.check_cli(_argv(self.runtime, FX["invalid"]), 1, f"{self.runtime} invalid", self.closed_seen)
        self.assertEqual(json.loads(out)["verdict"], "FAIL")

    def test_big_receipt_on_a_slow_pipe_is_whole(self):
        argv = _argv(self.runtime, FX["big"])
        rc_f, whole, _ = run_mode(argv, "file")
        self.assertGreater(len(whole), 65536)
        rc_s, piped, err = run_mode(argv, "slow")
        self.assertEqual((rc_s, rc_f), (0, 0), err[-400:])
        self.assertTrue(same_receipt(piped, whole), f"{len(piped)} piped bytes against {len(whole)} in a file")
        self.assertEqual(json.loads(piped)["verdict"], "PASS")
        self.assert_lost(argv, "devfull", f"{self.runtime} big")
        self.assert_lost(argv, "gone", f"{self.runtime} big")
        self.assert_lost(argv, "fsize", f"{self.runtime} big")


class TestPython(_PackCLI):
    runtime = "python"


class TestNode(_PackCLI):
    runtime = "node"
    closed_seen = False


class TestGo(_PackCLI):
    runtime = "go"
    closed_seen = False


class TestJava(_PackCLI):
    runtime = "java"


class TestPythonAAT(_Base):
    runtime = "python"
    AAT = [sys.executable, "-m", "omega_evidence.interop.aat"]

    def test_verify_ok(self):
        out = self.check_cli(self.AAT + ["verify", FX["chain"]], 0, "aat verify ok")
        self.assertTrue(json.loads(out)["ok"])

    def test_verify_broken(self):
        out = self.check_cli(self.AAT + ["verify", FX["chain_bad"]], 1, "aat verify broken")
        self.assertFalse(json.loads(out)["ok"])

    def test_verify_unreadable_input(self):   # the error object is the outcome (exit 2): lost, it is 74 too
        out = self.check_cli(self.AAT + ["verify", FX["missing"]], 2, "aat verify missing")
        self.assertFalse(json.loads(out)["ok"])

    def test_verify_bad_key_argument(self):   # the --key / --pubkey error object (exit 2) goes through the same writer
        self.check_cli(self.AAT + ["verify", FX["chain"], "--key", "no-equals-sign"], 2, "aat verify --key")
        self.check_cli(self.AAT + ["verify", FX["chain"], "--pubkey", FX["missing"]], 2, "aat verify --pubkey")

    def test_verify_unreadable_epochs(self):
        self.check_cli(self.AAT + ["verify", FX["chain"], "--epochs", FX["missing"]], 2, "aat verify --epochs")

    def test_csv_stdout_cannot_encode(self):   # ValueError branch: stdout in ASCII, a non-ASCII agent id in the CSV
        from omega_evidence import agent
        from omega_evidence.interop import aat
        d = tempfile.mkdtemp(dir=FX["dir"])
        log = agent.AgentEvidenceLog(os.path.join(d, "a.jsonl"), runtime_id="rt-1")
        log.record("b\u00f6t", "sess-a", "tool_call", "x", "rule-1", agent.Decision.ALLOW, agent.Outcome.EXECUTED)
        ch = os.path.join(d, "c.jsonl")
        with open(ch, "w", encoding="utf-8") as f:
            f.write(aat.to_jsonl(next(iter(aat.from_omega(list(log._ledger.entries()), "1.0", close=True).values()))))
        p = subprocess.run(self.AAT + ["csv", ch], capture_output=True, cwd=ROOT, timeout=120, env=dict(os.environ, PYTHONIOENCODING="ascii"))
        err = p.stderr.decode("utf-8", "replace")
        self.assertEqual(p.returncode, EX_IOERR, err[-400:])
        self.assertIn("receipt not written:", err)
        self.assertNotIn("Traceback", err)

    def test_csv(self):
        out = self.check_cli(self.AAT + ["csv", FX["chain"]], 0, "aat csv")
        self.assertTrue(out.splitlines()[0])

    def test_csv_unreadable_input(self):
        self.check_cli(self.AAT + ["csv", FX["missing"]], 2, "aat csv missing")


del _PackCLI   # the four subclasses run its tests; the base class alone has no runtime


if __name__ == "__main__":
    unittest.main(verbosity=2)
