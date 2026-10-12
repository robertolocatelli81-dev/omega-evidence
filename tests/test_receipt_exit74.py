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
  fsize_cut  stdout appended to a file of 1 000 bytes under `ulimit -f 1` (1 024 bytes): 24 bytes taken, then EFBIG — with
             PYTHONUNBUFFERED (or -u) Python's text layer dropped the rest of that short write and 0.11.3 at 5520cd8 exited
             with the verdict's code (13/10/2026)
In every losing mode: exit 74, one `receipt not written: <reason>` line on stderr, no traceback, no "Exception ignored".

Added on 13/10/2026 (all as real processes unless said): the Python CLIs again with PYTHONUNBUFFERED=1; a stdout that is
non-blocking and already FULL when the process starts (a reader that reads late): the process waits — alive, and in a
1-second window under 0.2 s of CPU, so it sleeps instead of spinning — and once the pipe is read the receipt arrives
whole with the verdict's code, small and over 64 KiB, buffered and unbuffered (5520cd8: Python and Java exited 74 with
65 536 bytes of a 71 KB receipt, Python unbuffered exited 0 with it cut); the usage error with stderr full or closed
(exit 2, nothing on stdout: Python exited 120 with stderr full or its reader gone, and with stderr closed wrote the usage
on STDOUT); the
AAT `-h` whose help is lost (74); the bytes in five stdout encodings and one error handler, to a file, appended and to a
pipe, against Python's own text layer; `main()` in process with sys.stdout set to a StringIO and to a TextIOWrapper over
io.BytesIO, and after text the caller wrote first.

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


def run_mode(argv, mode, env=None):
    """Run argv as a real process with stdout in `mode`; return (rc, stdout bytes or None, stderr text)."""
    if env is not None:
        return _with_env(env, run_mode, argv, mode)
    if mode == "fsize_cut":   # 1 000 bytes already in the file, limit 1 024: a short write of 24 bytes, then EFBIG
        with tempfile.TemporaryDirectory() as td:
            o = os.path.join(td, "out")
            with open(o, "wb") as f:
                f.write(b"x" * 1000)
            cmd = " ".join(shlex.quote(a) for a in argv)
            p = subprocess.run(["bash", "-c", f"ulimit -f 1; exec {cmd} >> {shlex.quote(o)}"], stderr=subprocess.PIPE, cwd=ROOT, timeout=120)
            with open(o, "rb") as f:
                return p.returncode, f.read()[1000:], p.stderr.decode("utf-8", "replace")
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


def _with_env(env, fn, *a):
    """Run fn with os.environ updated by env (the child processes inherit it), then restore it."""
    saved = {k: os.environ.get(k) for k in env}
    os.environ.update(env)
    try:
        return fn(*a)
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _cpu_seconds(pid):
    """utime + stime of a live process, all its threads, from /proc (Linux)."""
    with open(f"/proc/{pid}/stat", "rb") as f:
        fields = f.read().rsplit(b")", 1)[1].split()
    return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")


def run_prefilled(argv, env=None):
    """stdout is a NON-BLOCKING pipe that is already full when the process starts, and nobody reads it for a while: the
    process must wait asleep, as on a blocking pipe — still alive, and in some 1-second window (looked at from the 1st to
    the 10th second, so a slow start is not taken for a spin) using under 0.2 s of CPU, which a loop retrying EAGAIN never
    does — and once the pipe is drained the receipt must arrive whole. Returns (idle, min_cpu_window, rc, receipt bytes or
    None, stderr text)."""
    import fcntl
    r, w = os.pipe()
    fcntl.fcntl(w, fcntl.F_SETFL, fcntl.fcntl(w, fcntl.F_GETFL) | os.O_NONBLOCK)
    filled = 0
    while True:
        try:
            filled += os.write(w, b"P" * 4096)
        except BlockingIOError:
            break
    try:
        p = subprocess.Popen(argv, stdout=w, stderr=subprocess.PIPE, cwd=ROOT, env=dict(os.environ, **(env or {})))
    finally:
        os.close(w)
    errs = {}
    t = threading.Thread(target=lambda: errs.setdefault("err", p.stderr.read()))
    t.start()
    idle, windows, t0 = False, [], time.time()
    time.sleep(1.0)
    while p.poll() is None and time.time() - t0 < 10:
        try:
            c0 = _cpu_seconds(p.pid)
            time.sleep(1.0)
            c1 = _cpu_seconds(p.pid)
        except OSError:   # exited during the window
            break
        if p.poll() is not None:
            break
        windows.append(c1 - c0)
        if c1 - c0 < 0.2:
            idle = True
            break
    chunks = []
    while True:
        b = os.read(r, 1 << 16)
        if not b:
            break
        chunks.append(b)
    os.close(r)
    rc = p.wait(timeout=120)
    t.join()
    p.stderr.close()
    data = b"".join(chunks)
    return idle, min(windows, default=None), rc, data[filled:] if data[:filled] == b"P" * filled else None, errs["err"].decode("utf-8", "replace")


def usage_with_stderr_lost(argv):
    """argv is a usage error. With stderr full, closed, or a pipe whose reader has gone, the exit stays 2 and nothing is
    written to stdout (a file here). Returns the cases that did otherwise."""
    bad = []
    for redir in ("2>/dev/full", "2>&-", "gone"):
        with tempfile.TemporaryDirectory() as td:
            o = os.path.join(td, "out")
            if redir == "gone":
                r, w = os.pipe()
                os.close(r)
                try:
                    with open(o, "wb") as f:
                        rc = subprocess.run(argv, stdout=f, stderr=w, cwd=ROOT, timeout=120).returncode
                finally:
                    os.close(w)
            else:
                cmd = " ".join(shlex.quote(a) for a in argv)
                rc = subprocess.run(["bash", "-c", f"exec {cmd} > {shlex.quote(o)} {redir}"], cwd=ROOT, timeout=120).returncode
            with open(o, "rb") as f:
                got = f.read()
            if (rc, got) != (2, b""):
                bad.append((redir, rc, got[:80]))
    return bad


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


    def test_short_write_to_a_file(self):   # 24 bytes taken, then EFBIG: 74, never the verdict's code
        for k in ("valid", "invalid"):
            self.assert_lost(_argv(self.runtime, FX[k]), "fsize_cut", f"{self.runtime} {k}")

    def test_non_blocking_stdout_full_at_start_is_waited_for(self):
        for k, expected in (("valid", 0), ("big", 0), ("invalid", 1)):
            argv = _argv(self.runtime, FX[k])
            _, whole, _ = run_mode(argv, "file")
            for env in self.BUFFERINGS:
                label = f"{self.runtime} {k} {env}"
                idle, cpu, rc, got, err = run_prefilled(argv, env)
                self.assertTrue(idle, f"{label}: not waiting asleep (least CPU in a 1 s window {cpu}, exit {rc}, stderr {err[-300:]!r})")
                self.assertEqual(rc, expected, f"{label}: stderr {err[-300:]!r}")
                self.assertTrue(got is not None and same_receipt(got, whole), f"{label}: {len(got or b'')} bytes against {len(whole)}")

    def test_usage_with_stderr_lost(self):   # the usage error keeps exit 2 and never goes to stdout
        self.assertEqual(usage_with_stderr_lost(RUNTIMES[self.runtime][:]), [])

    BUFFERINGS = ({},)


class TestPython(_PackCLI):
    runtime = "python"
    BUFFERINGS = ({}, {"PYTHONUNBUFFERED": "1"})

    def test_unbuffered(self):   # -u / PYTHONUNBUFFERED: the bytes go to a raw FileIO that can take part of them in silence
        u = {"PYTHONUNBUFFERED": "1"}
        for k, code in (("valid", 0), ("invalid", 1)):
            argv = _argv("python", FX[k])
            rc, out, err = run_mode(argv, "file", u)
            self.assertEqual(rc, code, err[-300:])
            for mode in ("devfull", "gone", "head", "closed", "fsize_cut"):
                rc2, _, err2 = run_mode(argv, mode, u)
                self.assertEqual(rc2, EX_IOERR, f"unbuffered {k} {mode}: exit {rc2}, stderr {err2[-300:]!r}")
                self.assertEqual(err2.count("receipt not written:"), 1, err2[-300:])
        argv = _argv("python", FX["big"])
        rc, whole, _ = run_mode(argv, "file")
        rc_s, piped, err = run_mode(argv, "slow", u)
        self.assertEqual(rc_s, 0, err[-300:])
        self.assertTrue(same_receipt(piped, whole))
        for mode in ("fsize", "fsize_cut", "head"):
            self.assertEqual(run_mode(argv, mode, u)[0], EX_IOERR, f"unbuffered big {mode}")

    def test_encodings_are_the_text_layers(self):
        """The receipt's bytes are the ones Python's own stdout text layer writes for the same text, in five encodings (a
        byte order mark included or not as that layer decides) and one error handler, to a new file, appended to a file
        and to a pipe, buffered and unbuffered. The reference is a second process writing the same text with
        sys.stdout.write."""
        from omega_evidence import agent
        from omega_evidence.interop import aat
        d = tempfile.mkdtemp(dir=FX["dir"])
        log = agent.AgentEvidenceLog(os.path.join(d, "a.jsonl"), runtime_id="rt-1")
        log.record("b\u00f6t", "sess-a", "tool_call", "x", "rule-1", agent.Decision.ALLOW, agent.Outcome.EXECUTED)
        ch = os.path.join(d, "c.jsonl")
        with open(ch, "w", encoding="utf-8") as f:
            f.write(aat.to_jsonl(next(iter(aat.from_omega(list(log._ledger.entries()), "1.0", close=True).values()))))
        text_path = os.path.join(d, "text")
        with open(text_path, "w", encoding="utf-8", newline="") as f:
            f.write(aat.to_csv(aat.from_jsonl(open(ch, encoding="utf-8").read())))
        cli = [sys.executable, "-m", "omega_evidence.interop.aat", "csv", ch]
        ref = [sys.executable, "-c", "import sys; sys.stdout.write(open(sys.argv[1], encoding='utf-8', newline='').read())", text_path]

        def out_of(argv, enc, dest, env):
            e = dict(os.environ, PYTHONIOENCODING=enc, **env)
            if dest == "pipe":
                return subprocess.run(argv, env=e, capture_output=True, cwd=ROOT, timeout=120).stdout
            o = os.path.join(d, "o")
            with open(o, "wb") as f:
                f.write(b"PRE" if dest == "append" else b"")
            with open(o, "ab" if dest == "append" else "wb") as f:
                subprocess.run(argv, env=e, stdout=f, cwd=ROOT, timeout=120)
            with open(o, "rb") as f:
                return f.read()
        for enc in ("utf-8", "utf-16", "utf-32", "utf-8-sig", "latin-1", "ascii:backslashreplace"):
            for dest in ("file", "append", "pipe"):
                for env in self.BUFFERINGS:
                    a, b = out_of(cli, enc, dest, env), out_of(ref, enc, dest, env)
                    self.assertGreater(len(b), 10)
                    self.assertEqual(a, b, f"{enc} {dest} {env}")

    def test_in_process_streams(self):
        """main() in process with sys.stdout replaced: a StringIO (no bytes below it), a TextIOWrapper over io.BytesIO
        (pytest's capsys: bytes below, no descriptor) with and without write_through — the receipt and the verdict's code."""
        import io
        from omega_evidence import verifier
        for make in (io.StringIO, lambda: io.TextIOWrapper(io.BytesIO(), encoding="utf-8", write_through=True),
                     lambda: io.TextIOWrapper(io.BytesIO(), encoding="utf-8")):
            s = make()
            saved = sys.stdout
            sys.stdout = s
            try:
                rc = verifier.main([FX["valid"], "--ledger", FX["valid"][:-5] + ".ledger.jsonl"])
            finally:
                sys.stdout = saved
            text = s.getvalue() if isinstance(s, io.StringIO) else s.buffer.getvalue().decode("utf-8")
            self.assertEqual((rc, json.loads(text)["verdict"]), (0, "PASS"), type(s).__name__)
        # what the caller wrote before stays before the receipt: the text layer is flushed first
        s = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
        s.write("before\n")
        saved = sys.stdout
        sys.stdout = s
        try:
            rc = verifier.main([FX["valid"], "--ledger", FX["valid"][:-5] + ".ledger.jsonl"])
        finally:
            sys.stdout = saved
        head, _, rest = s.buffer.getvalue().decode("utf-8").partition("\n")
        self.assertEqual((rc, head, json.loads(rest)["verdict"]), (0, "before", "PASS"))


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

    def test_unbuffered_short_write(self):
        for args, code in ((["verify", FX["chain"]], 0), (["verify", FX["chain_bad"]], 1), (["verify", FX["missing"]], 2),
                           (["csv", FX["chain"]], 0)):
            rc, _, err = run_mode(self.AAT + args, "fsize_cut", {"PYTHONUNBUFFERED": "1"})
            self.assertEqual(rc, EX_IOERR, f"{args} unbuffered fsize_cut: exit {rc} (verdict {code}), stderr {err[-300:]!r}")
            self.assertEqual(err.count("receipt not written:"), 1)

    def test_full_non_blocking_stdout_is_waited_for(self):
        _, whole, _ = run_mode(self.AAT + ["verify", FX["chain"]], "file")
        for env in ({}, {"PYTHONUNBUFFERED": "1"}):
            idle, cpu, rc, got, err = run_prefilled(self.AAT + ["verify", FX["chain"]], env)
            self.assertTrue(idle, f"{env}: least CPU in a 1 s window {cpu}, exit {rc}, {err[-300:]!r}")
            self.assertEqual((rc, got), (0, whole), env)

    def test_usage_with_stderr_lost(self):
        for args in (["verify"], ["nosuchcommand"], []):
            self.assertEqual(usage_with_stderr_lost(self.AAT + args), [], args)
        p = subprocess.run(self.AAT + ["verify"], capture_output=True, cwd=ROOT, timeout=120)
        self.assertEqual((p.returncode, p.stdout), (2, b""))
        self.assertIn(b"error: the following arguments are required: chain", p.stderr)

    def test_help_is_output(self):   # -h prints the help as the command's output: lost, it is 74
        rc, out, err = run_mode(self.AAT + ["-h"], "file")
        self.assertEqual(rc, 0, err)
        self.assertTrue(out.startswith(b"usage: omega-evidence-aat"))
        for mode in ("devfull", "gone", "closed"):
            self.assert_lost(self.AAT + ["-h"], mode, "aat -h")
            self.assert_lost(self.AAT + ["verify", "-h"], mode, "aat verify -h")

    def test_csv(self):
        out = self.check_cli(self.AAT + ["csv", FX["chain"]], 0, "aat csv")
        self.assertTrue(out.splitlines()[0])

    def test_csv_unreadable_input(self):
        self.check_cli(self.AAT + ["csv", FX["missing"]], 2, "aat csv missing")


del _PackCLI   # the four subclasses run its tests; the base class alone has no runtime


if __name__ == "__main__":
    unittest.main(verbosity=2)
