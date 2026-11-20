# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""The six decisions of 20 November 2026 on behaviours that 0.13.0 documented and that two review benches flagged
(each measured on 404b60b before it was changed; the tests marked "fails on 404b60b" fail there).

(D1) `authenticated` was true for a signature by any key under any `signer_id` with no trust registry, and a trust
     registry given did not require a signature (no sidecar, or an unknown algorithm: exit 0).
"""
import itertools
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)

from omega_evidence import pack as P, trust as TR  # noqa: E402
from omega_evidence.ledger import Ledger  # noqa: E402
from omega_evidence.signing import Identity  # noqa: E402
from omega_evidence.verifier import verify_pack  # noqa: E402

SCOPE = "test only, NOT a conformity assessment"
NODE = shutil.which("node")
JS = os.path.join(ROOT, "verifiers", "js", "oeverify.mjs")


def _tmp(test):
    d = tempfile.mkdtemp(prefix="oe-decisioni-")
    test.addCleanup(shutil.rmtree, d, ignore_errors=True)
    return d


def _pack(d, name, body=None):
    p = os.path.join(d, name + ".json")
    P.write_pack(p, P.build_pack("x", body if body is not None else {"amount": "10"}, SCOPE))
    return p


def _rj(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _wj(path, obj):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f)


def _layer(r, name):
    return next((ly for ly in r["layers"] if ly["layer"] == name), {})


def _cli_verdicts(pack, flags):
    """(verdict, authenticated) from the Python CLI and, when Node is installed, from the Node verifier"""
    out = {}
    cmds = [("python", [sys.executable, "-I", "-c", "import sys; sys.path.insert(0, sys.argv[1]); "
                        "from omega_evidence.verifier import main; raise SystemExit(main(sys.argv[2:]))", ROOT])]
    if NODE:
        cmds.append(("node", [NODE, JS]))
    for name, cmd in cmds:
        r = subprocess.run(cmd + [pack] + flags, capture_output=True, text=True, timeout=120)
        j = json.loads(r.stdout)
        out[name] = (j["verdict"], j["authenticated"], r.returncode)
    return out


class D1AuthenticatedIsTrustedSigned(unittest.TestCase):
    def test_signed_without_registry_is_not_authenticated(self):
        """fails on 404b60b: authenticated True for a fresh key under signer_id 'bank-official', no registry"""
        d = _tmp(self)
        p = _pack(d, "p")
        P.sign_pack(p, Identity("bank-official"))
        r = verify_pack(p)
        self.assertTrue(r["valid"])                                     # the signed tier stays a PASS
        self.assertIs(r["authenticated"], False)
        self.assertIn("NOT checked against a registry", _layer(r, "authenticity")["detail"])
        self.assertIn("not covered", _layer(r, "producer-signature")["detail"])

    def test_trusted_signed_is_authenticated(self):
        """control (passes on 404b60b too): the registry binds signer_id to the key"""
        d = _tmp(self)
        p = _pack(d, "p")
        ident = Identity("bank")
        P.sign_pack(p, ident)
        ts = os.path.join(d, "trust.jsonl")
        TR.TrustRegistry(ts).trust("bank", ident.public_key_b64)
        r = verify_pack(p, trust_store=ts)
        self.assertEqual((r["valid"], r["authenticated"], _layer(r, "authenticity")["detail"]), (True, True, "trusted-signed"))

    def test_trust_store_requires_a_signature(self):
        """fails on 404b60b: an anchored unsigned pack, and an anchored pack with an unknown sig_alg, were valid beside a
        trust store"""
        d = _tmp(self)
        ts = os.path.join(d, "trust.jsonl")
        TR.TrustRegistry(ts).trust("bank", Identity("bank").public_key_b64)
        p = _pack(d, "unsigned")
        P.anchor_pack(p, p[:-5] + ".ledger.jsonl")
        self.assertTrue(verify_pack(p)["valid"])                         # control: the anchored tier without a store
        r = verify_pack(p, trust_store=ts)
        self.assertEqual((r["valid"], _layer(r, "producer-signature")["status"]), (False, "FAIL"))
        q = _pack(d, "alg")
        P.anchor_pack(q, q[:-5] + ".ledger.jsonl")
        P.sign_pack(q, Identity("x"))
        sp = q[:-5] + ".sig.json"
        side = _rj(sp)
        side["sig_alg"] = "x-unknown"
        _wj(sp, side)
        self.assertTrue(verify_pack(q)["valid"])                         # control: SKIP and the anchored tier, no store
        r = verify_pack(q, trust_store=ts)
        self.assertEqual((r["valid"], _layer(r, "producer-signature")["status"]), (False, "FAIL"))

    def test_generated_space(self):
        """every combination of signature (none / valid / unknown algorithm), anchor, registry (none / trusts the signer /
        trusts another key / revoked) and --require-signed: authenticated iff trusted-signed with an intact body; with a
        registry, valid only for trusted-signed. Python and, where installed, Node give the same pair."""
        d = _tmp(self)
        rnd = random.Random(20261120)
        ident, other = Identity("acme"), Identity("acme")
        stores = {"none": None}
        for nm in ("trusts", "other", "revoked"):
            stores[nm] = os.path.join(d, nm + ".jsonl")
        TR.TrustRegistry(stores["trusts"]).trust("acme", ident.public_key_b64)
        TR.TrustRegistry(stores["other"]).trust("acme", other.public_key_b64)
        rv = TR.TrustRegistry(stores["revoked"])
        rv.trust("acme", ident.public_key_b64)
        rv.revoke("acme", "test")
        n = 0
        for sig, anchored, store, req in itertools.product(("none", "valid", "unknown", "tampered"), (False, True),
                                                          stores, (False, True)):
            n += 1
            p = _pack(d, f"c{n}", {"amount": str(rnd.randrange(10 ** 6))})
            if anchored:
                P.anchor_pack(p, p[:-5] + ".ledger.jsonl")
            if sig != "none":
                P.sign_pack(p, ident)
            if sig == "unknown":
                sp = p[:-5] + ".sig.json"
                side = _rj(sp)
                side["sig_alg"] = rnd.choice(["rsa-pss", "x-" + str(rnd.randrange(999)), "ml-dsa-65"])
                _wj(sp, side)
            if sig == "tampered":
                body = _rj(p)
                body["amount"] = "tampered"
                _wj(p, body)
            r = verify_pack(p, trust_store=stores[store], require_signed=req)
            trusted_signed = sig == "valid" and store == "trusts"
            self.assertIs(r["authenticated"], trusted_signed, (sig, anchored, store, req))
            if store != "none" or req:
                self.assertIs(r["valid"], trusted_signed or (sig == "valid" and store == "none"), (sig, anchored, store, req))
            if n % 7 == 0:   # a sample through the CLIs (the four agree on the full set in verifiers/differential_oracle.py)
                flags = (["--trust-store", stores[store]] if stores[store] else []) + (["--require-signed"] if req else [])
                got = _cli_verdicts(p, flags)
                self.assertEqual(len(set(got.values())), 1, got)
                self.assertIs(got["python"][1], trusted_signed)
        self.assertEqual(n, 64)


if __name__ == "__main__":
    unittest.main(verbosity=1)
