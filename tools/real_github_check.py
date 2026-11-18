#!/usr/bin/env python3
# Copyright 2026 Roberto Locatelli
# SPDX-License-Identifier: Apache-2.0
"""Measure omega-evidence on REAL third-party sigstore bundles from GitHub (opt-in, needs the network and `gh`).

    python tools/real_github_check.py fetch DIR      # download what tests/fixtures/real_github_20261118.json names
    python tools/real_github_check.py measure DIR    # run omega_evidence (the one on sys.path) on it; JSON on stdout

`fetch` downloads, into DIR, the first attestation the GitHub API returns for each subject digest
(`gh api repos/<repo>/attestations/<digest>`), the message-signature bundle and its artifact, the Sigstore Public Good
trusted root (sigstore/root-signing, main) and GitHub's (`gh attestation trusted-root`), and writes DIR/SHA256SUMS. Nothing
downloaded is committed: the repository keeps only the identifiers and URLs (tests/fixtures/real_github_20261118.json).

`measure` works with any omega_evidence version: where the 0.12.0 parameters do not exist it measures what the old API
offers (the call made on 18/11/2026 against 0.11.4), so the same script shows the before and the after. Counts:
  dsse_verified           DSSE envelope verified with the key of the bundle's certificate (24 expected)
  dsse_tampered_refused   one character of the payload changed: verified False WITH an error (24 expected)
  rfc3161_verified        tokens verified at their genTime with the TSA roots as ca_file and the rest as untrusted
  rfc3161_wrong_digest    the same tokens against a wrong digest: must be 0
  bundle_verified         interop.sigstore.verify_bundle on the 25 bundles (24 DSSE + 1 message signature)
  bundle_tampered_refused the same with the payload (DSSE) or one bit of the artifact (message signature) changed
  bundle_time_checked     bundles whose verified timestamp falls inside the leaf certificate's validity
  bundle_subject_checked  bundles whose statement names the fixture's subject digest (or whose artifact is the signed one)
  bundle_wrong_artifact_refused  the same bundles asked about another SHA-256: verified False with an error
"""
from __future__ import annotations

import base64
import copy
import hashlib
import inspect
import json
import os
import subprocess
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURE = os.path.join(HERE, "..", "tests", "fixtures", "real_github_20261118.json")
PG_ROOT = "https://raw.githubusercontent.com/sigstore/root-signing/main/targets/trusted_root.json"


def _read(path: str, mode: str = "rb"):
    with open(path, mode, **({} if "b" in mode else {"encoding": "utf-8"})) as f:
        return f.read()


def _write(path: str, data: bytes) -> None:
    with open(path, "wb") as f:
        f.write(data)


def _get(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as r:  # nosec B310 - fixed https URLs from the fixture
        return r.read()


def fetch(d: str) -> None:
    fx = json.loads(_read(FIXTURE, "r"))
    os.makedirs(d, exist_ok=True)
    files = {}
    for i, a in enumerate(fx["attestations"]):
        out = subprocess.run(["gh", "api", a["api"]], capture_output=True, check=True).stdout
        files[f"att{i:02d}.json"] = out
    for i, m in enumerate(fx["message_signature_bundles"]):
        files[f"msg{i:02d}_bundle.json"] = _get(m["bundle_url"])
        art = _get(m["artifact_url"])
        if "sha256:" + hashlib.sha256(art).hexdigest() != m["artifact_digest"]:
            raise SystemExit(f"artifact digest differs from the fixture: {m['artifact_url']}")
        files[f"msg{i:02d}_artifact"] = art
    files["pg_trusted_root.json"] = _get(PG_ROOT)
    files["gh_trusted_root.jsonl"] = subprocess.run(["gh", "attestation", "trusted-root"], capture_output=True,
                                                    check=True).stdout
    for name, data in files.items():
        with open(os.path.join(d, name), "wb") as f:
            f.write(data)
    with open(os.path.join(d, "SHA256SUMS"), "w", encoding="ascii") as f:
        for name in sorted(files):
            f.write(f"{hashlib.sha256(files[name]).hexdigest()}  {name}\n")


def _pem(der: bytes) -> bytes:
    return b"-----BEGIN CERTIFICATE-----\n" + base64.encodebytes(der) + b"-----END CERTIFICATE-----\n"


def tsa_material(d: str):
    """(roots.pem, untrusted.pem) from the timestampAuthorities of both trusted roots: the last certificate of each
    chain is the anchor, the others are given as untrusted."""
    docs = [json.loads(_read(os.path.join(d, "pg_trusted_root.json"), "r"))]
    docs += [json.loads(x) for x in _read(os.path.join(d, "gh_trusted_root.jsonl"), "r").splitlines() if x.strip()]
    roots, untrusted = b"", b""
    for doc in docs:
        for a in doc.get("timestampAuthorities", []):
            ders = [base64.b64decode(c["rawBytes"]) for c in a["certChain"]["certificates"]]
            roots += _pem(ders[-1])
            untrusted += b"".join(_pem(x) for x in ders[:-1])
    rp, up = os.path.join(d, "tsa_roots.pem"), os.path.join(d, "tsa_untrusted.pem")
    _write(rp, roots)
    _write(up, untrusted)
    return rp, up


def tamper(env: dict) -> dict:
    """the change of the 18/11 measure: one hex character of the first subject digest"""
    e = copy.deepcopy(env)
    raw = bytearray(base64.b64decode(e["payload"]))
    i = raw.find(b'"sha256"')
    j = raw.find(b'"', i + 9) + 1 if i >= 0 else len(raw) // 2
    raw[j] = ord("0") if raw[j] != ord("0") else ord("1")
    e["payload"] = base64.standard_b64encode(bytes(raw)).decode()
    return e


def bundles(d: str):
    """[(name, bundle, artifact_bytes_or_None)]"""
    out = []
    for name in sorted(os.listdir(d)):
        if name.startswith("att") and name.endswith(".json"):
            atts = json.loads(_read(os.path.join(d, name), "r")).get("attestations", [])
            if atts:
                out.append((name, atts[0]["bundle"], None))
        elif name.startswith("msg") and name.endswith("_bundle.json"):
            art = _read(os.path.join(d, name.replace("_bundle.json", "_artifact")))
            out.append((name, json.loads(_read(os.path.join(d, name), "r")), art))
    return out


def measure(d: str) -> dict:
    import omega_evidence
    from omega_evidence import timestamp
    from omega_evidence.interop import dsse
    try:
        from omega_evidence.interop import sigstore
    except ImportError:
        sigstore = None
    roots, untrusted = tsa_material(d)
    new_dsse = "public_key" in inspect.signature(dsse.from_dsse).parameters
    new_ts = "untrusted" in inspect.signature(timestamp.verify).parameters
    res = {"omega_evidence": getattr(omega_evidence, "__version__", "?"), "file": omega_evidence.__file__,
           "api_0_12_0": {"from_dsse(public_key=)": new_dsse, "timestamp.verify(untrusted=, at_gen_time=)": new_ts,
                          "interop.sigstore": sigstore is not None},
           "dsse": 0, "dsse_verified": 0, "dsse_tampered_refused": 0, "dsse_errors": [],
           "rfc3161": 0, "rfc3161_verified": 0, "rfc3161_verified_now": 0, "rfc3161_wrong_digest": 0,
           "rfc3161_reasons": [], "bundle": 0, "bundle_verified": 0, "bundle_tampered_refused": 0,
           "bundle_time_checked": 0, "bundle_subject_checked": 0, "bundle_wrong_artifact_refused": 0,
           "bundle_errors": []}
    fx = json.loads(_read(FIXTURE, "r"))
    for name, b, art in bundles(d):
        vm = b["verificationMaterial"]
        cert_der = base64.b64decode(vm["certificate"]["rawBytes"]) if "certificate" in vm else None
        if "dsseEnvelope" in b:
            env = b["dsseEnvelope"]
            res["dsse"] += 1
            if new_dsse:
                r = dsse.from_dsse(env, public_key=_pem(cert_der))
                rt = dsse.from_dsse(tamper(env), public_key=_pem(cert_der))
            else:
                r, rt = dsse.from_dsse(env), dsse.from_dsse(tamper(env))
            res["dsse_verified"] += r["verified"] is True
            res["dsse_tampered_refused"] += rt["verified"] is False and bool(rt.get("error"))
            if r["verified"] is not True:
                res["dsse_errors"].append([name, r.get("error")])
            sig = base64.b64decode(env["signatures"][0]["sig"])
        else:
            sig = base64.b64decode(b["messageSignature"]["signature"])
        dg = hashlib.sha256(sig).hexdigest()   # sigstore: the token's imprint is over the signature bytes
        for t in (vm.get("timestampVerificationData") or {}).get("rfc3161Timestamps", []):
            tok = t["signedTimestamp"]
            res["rfc3161"] += 1
            if new_ts:
                v = timestamp.verify(tok, dg, ca_file=roots, untrusted=untrusted, at_gen_time=True)
                vn = timestamp.verify(tok, dg, ca_file=roots, untrusted=untrusted)
                w = timestamp.verify(tok, "11" * 32, ca_file=roots, untrusted=untrusted, at_gen_time=True)
            else:
                chains = os.path.join(d, "tsa_chains.pem")
                _write(chains, _read(roots) + _read(untrusted))
                v = vn = timestamp.verify(tok, dg, ca_file=chains)
                w = timestamp.verify(tok, "11" * 32, ca_file=chains)
            res["rfc3161_verified"] += v.get("verified") is True
            res["rfc3161_verified_now"] += vn.get("verified") is True
            res["rfc3161_wrong_digest"] += w.get("verified") is True
            if v.get("verified") is not True or vn.get("verified") is not True:
                res["rfc3161_reasons"].append([name, v.get("reason") or v.get("note"),
                                               vn.get("reason") or vn.get("note")])
        if sigstore is not None:
            res["bundle"] += 1
            sha = None
            if art is None:   # an attestation: the subject digest the fixture names must be a subject of its statement
                sha = fx["attestations"][int(name[3:5])]["subject_digest"].split(":", 1)[1]
            r = sigstore.verify_bundle(b, artifact=art, artifact_sha256=sha, tsa_ca_file=roots, tsa_untrusted=untrusted)
            res["bundle_subject_checked"] += r["checks"].get("artifact") is True
            wrong = sigstore.verify_bundle(b, artifact_sha256="0" * 64, tsa_ca_file=roots, tsa_untrusted=untrusted)
            res["bundle_wrong_artifact_refused"] += wrong["verified"] is False and bool(wrong.get("error"))
            res["bundle_verified"] += r["verified"] is True
            res["bundle_time_checked"] += r["checks"].get("signing_time_in_certificate") is True
            bt, art_t = copy.deepcopy(b), art
            if "dsseEnvelope" in bt:
                bt["dsseEnvelope"] = tamper(bt["dsseEnvelope"])
            else:
                art_t = bytes([art[0] ^ 1]) + art[1:]
            rt = sigstore.verify_bundle(bt, artifact=art_t, tsa_ca_file=roots, tsa_untrusted=untrusted)
            res["bundle_tampered_refused"] += rt["verified"] is False and bool(rt.get("error"))
            if r["verified"] is not True:
                res["bundle_errors"].append([name, r.get("error"), r.get("checks")])
    return res


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2 or argv[0] not in ("fetch", "measure"):
        print(__doc__, file=sys.stderr)
        return 2
    if argv[0] == "fetch":
        fetch(argv[1])
        return 0
    json.dump(measure(argv[1]), sys.stdout, indent=1)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
