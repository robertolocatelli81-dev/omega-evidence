# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""0.11.4 — an RFC 3161 check that cannot run here is not a verdict (13/10/2026).

timestamp.verify(tsr_b64, digest, ca_file=...) runs openssl. Measured on 0.11.3 (6d712c8) with a valid token from a
local TSA: under RLIMIT_NPROC 1 (fork refused), with openssl answering after the timeout, with the binary gone since
`which`, and with the token's temporary file refused (EFBIG) it returned `verified: False` — a verdict on the token — and
preservation.verify_evidence_record made the record carrying it `valid: false`; with no usable temporary directory it
raised a bare FileNotFoundError; `python -m omega_evidence.interop.aat verify ... --tsa-ca CA` under RLIMIT_NPROC 1
exited 1, for a token in an epoch anchor ("RFC 3161 token over the root does not verify") and in a record's
external_timestamp ("external_timestamp token not verified"). Now each of these raises timestamp.CheckNotRun ("cannot
run openssl here: ..." / "cannot write a temporary file for openssl: ..."), never a PASS or a FAIL, and the AAT CLI exits 74 with one line
"receipt not written: " + that message, and nothing on stdout. Not covered (declared in the README): an openssl that
starts and ends without an answer (a signal, exit 127) is still `verified: False`. openssl ABSENT is still `verified: None`, and
a token that is not base64 is still `verified: False` (the input's fault). Each case runs in a child process, so the
limits are real."""
import base64
import errno
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
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

# the child: sets its case up, calls verify and verify_evidence_record, prints what each returned or raised
CHILD = r"""
import json, os, resource, shutil, sys, tempfile
sys.path.insert(0, sys.argv[1])
case, root, tsr, ca, recp = sys.argv[2:7]
from omega_evidence import timestamp as T, preservation as P
rec = json.load(open(recp))
kw = {}
if case == "nproc":
    resource.setrlimit(resource.RLIMIT_NPROC, (1, 1))
elif case == "notmp":
    tempfile.tempdir = os.path.join(recp + ".missing", "x")
elif case == "efbig":
    tempfile.gettempdir()
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
elif case == "slow":
    kw = {"timeout": 1}
elif case == "enoent":
    shutil.which = lambda *a, **k: recp + ".missing/openssl"
elif case == "badb64":
    tsr = "!!not base64!!"
out = {}
for name, fn in (("verify", lambda: T.verify(tsr, root, ca_file=ca, **kw)),
                 ("record", lambda: P.verify_evidence_record(rec, tsa_ca_file=ca) if not kw else None)):
    try:
        r = fn()
        out[name] = {"returned": r if name == "verify" else (r and r["valid"])}
    except Exception as e:
        out[name] = {"raised": type(e).__name__, "msg": str(e), "oserror": isinstance(e, OSError)}
print(json.dumps(out))
"""


def _run(*a):
    subprocess.run(list(a), check=True, capture_output=True)


@unittest.skipUnless(EXE and hasattr(os, "fork"), "openssl absent (or no fork): the local TSA cannot be built")
class TestCheckNotRun(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, ROOT)
        from omega_evidence import preservation as P
        cls.d = d = tempfile.mkdtemp(prefix="c16_")
        j = lambda n: os.path.join(d, n)  # noqa: E731
        cls.j = staticmethod(j)
        with open(j("tsa.cnf"), "w") as f:
            f.write(CNF.format(d=d))
        with open(j("serial"), "w") as f:
            f.write("01\n")
        _run(EXE, "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout",
             j("ca.key"), "-out", j("ca.crt"), "-subj", "/CN=c16-ca", "-days", "2")
        _run(EXE, "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", j("tsa.key"),
             "-out", j("tsa.csr"), "-subj", "/CN=c16-tsa")
        _run(EXE, "x509", "-req", "-in", j("tsa.csr"), "-CA", j("ca.crt"), "-CAkey", j("ca.key"), "-CAcreateserial",
             "-out", j("tsa.crt"), "-days", "2", "-extfile", j("tsa.cnf"), "-extensions", "v3_tsa")
        with open(j("p.json"), "w") as f:
            json.dump({"pack_sha3": "ab" * 32}, f)
        rec = P.build_evidence_record([j("p.json")])
        cls.root = rec["archive_timestamps"][0]["merkle_root"]
        _run(EXE, "ts", "-query", "-digest", cls.root, "-sha256", "-cert", "-out", j("q.tsq"))
        _run(EXE, "ts", "-reply", "-config", j("tsa.cnf"), "-queryfile", j("q.tsq"), "-out", j("r.tsr"))
        with open(j("r.tsr"), "rb") as f:
            cls.tsr = base64.b64encode(f.read()).decode()
        rec["archive_timestamps"][0]["timestamp"] = {"time_source": "rfc3161", "tsa": "local", "tsr_b64": cls.tsr,
                                                     "stamped_utc": "2026-10-13T00:00:00Z"}
        P._finalize(rec)
        with open(j("rec.json"), "w") as f:
            json.dump(rec, f)
        # an AAT chain with one epoch anchor whose RFC 3161 token (over SHA-256 of the raw root) comes from the local TSA
        import hashlib
        from omega_evidence import agent
        from omega_evidence.interop import aat
        log = agent.AgentEvidenceLog(j("agent.jsonl"), runtime_id="rt-1")
        log.record("bot-7", "sess-a", "tool_call", "https://api.example/x", "rule-1", agent.Decision.ALLOW,
                   agent.Outcome.EXECUTED)
        chain = next(iter(aat.from_omega(list(log._ledger.entries()), "1.0", close=True).values()))
        last = json.loads(json.dumps(chain[-1]))   # a second chain: an external_timestamp on its close record
        imprint_r = hashlib.sha256(aat.jcs({k: v for k, v in last.items() if k not in ("signature", "signature_classical",
                                                                                     "batch", "external_timestamp")},
                                           strict=False)).hexdigest()
        _run(EXE, "ts", "-query", "-digest", imprint_r, "-sha256", "-cert", "-out", j("qr.tsq"))
        _run(EXE, "ts", "-reply", "-config", j("tsa.cnf"), "-queryfile", j("qr.tsq"), "-out", j("rr.tsr"))
        with open(j("rr.tsr"), "rb") as f:
            last["external_timestamp"] = {"tsa_url": "http://127.0.0.1/tsr", "token": base64.b64encode(f.read()).decode(),
                                          "anchored_at": "2026-10-13T00:00:00Z"}
        with open(j("chain_et.jsonl"), "w", encoding="utf-8") as f:
            f.write(aat.to_jsonl(chain[:-1] + [last]))
        anchor = aat.anchor_epoch(chain)
        imprint = hashlib.sha256(bytes.fromhex(anchor["merkle_root"])).hexdigest()
        _run(EXE, "ts", "-query", "-digest", imprint, "-sha256", "-cert", "-out", j("qa.tsq"))
        _run(EXE, "ts", "-reply", "-config", j("tsa.cnf"), "-queryfile", j("qa.tsq"), "-out", j("ra.tsr"))
        with open(j("ra.tsr"), "rb") as f:
            anchor["tsa"] = {"message_imprint_sha256": imprint, "token": base64.b64encode(f.read()).decode(),
                             "anchored": True}
        with open(j("chain.jsonl"), "w", encoding="utf-8") as f:
            f.write(aat.to_jsonl(chain))
        with open(j("epochs.json"), "w") as f:
            json.dump([anchor], f)
        os.mkdir(j("slow"))   # an openssl that answers `ts -verify` at once and `ts -reply` after 3 s
        with open(j("slow/openssl"), "w") as f:
            f.write('#!/bin/sh\ncase "$*" in *-reply*) sleep 3;; esac\nexec %s "$@"\n' % EXE)
        os.chmod(j("slow/openssl"), 0o755)
        os.mkdir(j("slowverify"))   # an openssl that answers `ts -verify` after 3 s
        with open(j("slowverify/openssl"), "w") as f:
            f.write('#!/bin/sh\ncase "$*" in *-verify*) sleep 3;; esac\nexec %s "$@"\n' % EXE)
        os.chmod(j("slowverify/openssl"), 0o755)
        os.mkdir(j("empty"))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def child(self, case, path=None):
        env = dict(os.environ)
        if path is not None:
            env["PATH"] = path
        p = subprocess.run([sys.executable, "-I", "-B", "-c", CHILD, ROOT, case, self.root, self.tsr, self.j("ca.crt"),
                            self.j("rec.json")], env=env, capture_output=True, text=True, timeout=120)
        self.assertEqual(p.returncode, 0, p.stderr[-500:])
        return json.loads(p.stdout)

    def assertNotRun(self, out, prefix, record=True):
        for name in ("verify", "record") if record else ("verify",):
            self.assertEqual(out[name].get("raised"), "CheckNotRun", (name, out))
            self.assertTrue(out[name]["oserror"], out)
            self.assertTrue(out[name]["msg"].startswith(prefix), (name, out))

    def test_control_a_valid_token_verifies(self):
        out = self.child("normal")
        self.assertIs(out["verify"]["returned"]["verified"], True, out)
        self.assertIs(out["record"]["returned"], True, out)

    def test_fork_refused(self):   # 0.11.3: verified False, record valid false
        out = self.child("nproc")
        self.assertNotRun(out, "cannot run openssl here: BlockingIOError")
        self.assertEqual(out["verify"]["msg"], "cannot run openssl here: BlockingIOError: " + os.strerror(errno.EAGAIN))

    def test_no_temporary_directory(self):   # 0.11.3: a bare FileNotFoundError
        self.assertNotRun(self.child("notmp"), "cannot write a temporary file for openssl: OSError: no usable "
                                               "temporary directory")

    def test_token_file_refused(self):   # 0.11.3: verified False (EFBIG on the token's temporary file)
        self.assertNotRun(self.child("efbig"), "cannot write a temporary file for openssl: OSError: File too large")

    def test_binary_gone_since_which(self):   # 0.11.3: verified False
        self.assertNotRun(self.child("enoent"), "cannot run openssl here: FileNotFoundError")

    def test_no_answer_to_reply_within_the_timeout(self):   # 0.11.3: verified False
        out = self.child("slow", self.j("slow") + os.pathsep + os.environ.get("PATH", ""))
        self.assertNotRun(out, "cannot run openssl here: OSError: no answer within 1 s", record=False)

    def test_no_answer_to_verify_within_the_timeout(self):
        out = self.child("slow", self.j("slowverify") + os.pathsep + os.environ.get("PATH", ""))
        self.assertNotRun(out, "cannot run openssl here: OSError: no answer within 1 s", record=False)

    def aat_cli(self, nproc, epochs=True):
        pre = "import resource; resource.setrlimit(resource.RLIMIT_NPROC, (1, 1)); " if nproc else ""
        args = (["verify", self.j("chain.jsonl"), "--epochs", self.j("epochs.json")] if epochs else
                ["verify", self.j("chain_et.jsonl")])
        return subprocess.run([sys.executable, "-c", pre + "import os, sys; os.execv(sys.argv[1], sys.argv[1:])",
                               sys.executable, "-B", "-m", "omega_evidence.interop.aat"] + args +
                              ["--tsa-ca", self.j("ca.crt")], cwd=ROOT, capture_output=True, timeout=120)

    def test_aat_cli_control_the_record_token_verifies(self):
        p = self.aat_cli(False, epochs=False)
        self.assertEqual(p.returncode, 0, p.stdout[-600:])
        self.assertTrue(json.loads(p.stdout)["ok"])

    def test_aat_cli_record_token_fork_refused_is_74(self):   # 0.11.3: exit 1, "external_timestamp token not verified"
        p = self.aat_cli(True, epochs=False)
        self.assertEqual((p.returncode, p.stdout), (74, b""), p.stderr[-300:])
        self.assertEqual(p.stderr, ("receipt not written: cannot run openssl here: BlockingIOError: %s\n"
                                    % os.strerror(errno.EAGAIN)).encode())

    def test_aat_cli_control_the_epoch_token_verifies(self):
        p = self.aat_cli(False)
        self.assertEqual(p.returncode, 0, p.stderr[-300:])
        out = json.loads(p.stdout)
        self.assertTrue(out["ok"] and out["epochs"]["time_verified"], out)

    def test_aat_cli_fork_refused_is_74(self):   # 0.11.3: exit 1, "RFC 3161 token over the root does not verify"
        p = self.aat_cli(True)
        self.assertEqual((p.returncode, p.stdout), (74, b""), p.stderr[-300:])
        self.assertEqual(p.stderr, ("receipt not written: cannot run openssl here: BlockingIOError: %s\n"
                                    % os.strerror(errno.EAGAIN)).encode())

    def test_aat_cli_no_temporary_file_is_74_with_its_own_line(self):   # 0.11.3: exit 2, "verifier error: FileNotFoundError"
        pre = "import resource; resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0)); "
        p = subprocess.run([sys.executable, "-c", pre + "import os, sys; os.execv(sys.argv[1], sys.argv[1:])",
                            sys.executable, "-B", "-m", "omega_evidence.interop.aat", "verify", self.j("chain_et.jsonl"),
                            "--tsa-ca", self.j("ca.crt")], cwd=ROOT, capture_output=True, timeout=120)
        self.assertEqual((p.returncode, p.stdout), (74, b""), p.stderr[-300:])
        self.assertEqual(p.stderr, b"receipt not written: cannot write a temporary file for openssl: OSError: no usable "
                                   b"temporary directory\n")

    def test_openssl_absent_is_still_none(self):
        out = self.child("absent", self.j("empty"))
        self.assertIsNone(out["verify"]["returned"]["verified"], out)
        self.assertIs(out["record"]["returned"], True, out)   # SKIP layer, as in 0.11.3

    def test_token_not_base64_is_still_false(self):
        out = self.child("badb64")
        self.assertIs(out["verify"]["returned"]["verified"], False, out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
