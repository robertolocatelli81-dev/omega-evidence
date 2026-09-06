# Copyright 2026 Roberto Locatelli
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
omega_evidence.timestamp — RFC 3161 trusted timestamping via openssl.

Graceful degradation: if openssl is absent, verification returns None
("recorded but not verified") — never a false positive. A qualified TSA (on the
EU Trusted List) additionally carries legal presumption of time; judging
qualification is left to the consumer of the evidence.
"""

from __future__ import annotations

import base64
import os
import shutil
import subprocess  # nosec B404 - fixed-arg openssl calls, no shell
import tempfile
import urllib.request
from urllib.parse import urlparse
from typing import Dict, Optional


def stamp(digest_hex: str, tsa_url: str, timeout: int = 20) -> Dict:
    """Request an RFC 3161 token for digest_hex from a TSA. Returns
    {anchored, tsa, tsr_b64} or {anchored: False, note}."""
    if urlparse(tsa_url).scheme not in ("http", "https"):
        return {"anchored": False, "note": "TSA URL scheme not allowed"}
    exe = shutil.which("openssl")
    if not exe:
        return {"anchored": False, "note": "openssl absent (RFC 3161 optional)"}
    d = tempfile.mkdtemp()
    try:
        tsq = os.path.join(d, "q.tsq")
        r = subprocess.run(  # nosec B603
            [exe, "ts", "-query", "-digest", digest_hex, "-sha256", "-cert", "-out", tsq],
            capture_output=True, timeout=timeout)
        if r.returncode != 0 or not os.path.exists(tsq):
            return {"anchored": False, "note": "openssl ts-query failed"}
        req = open(tsq, "rb").read()
        http = urllib.request.Request(tsa_url, data=req, method="POST",
                                      headers={"Content-Type": "application/timestamp-query"})
        resp = urllib.request.urlopen(http, timeout=timeout).read()  # nosec B310 - scheme checked
        return {"anchored": True, "tsa": tsa_url, "tsr_b64": base64.b64encode(resp).decode()}
    except Exception as e:  # noqa: BLE001
        return {"anchored": False, "note": f"{type(e).__name__}: {str(e)[:80]}"}
    finally:
        shutil.rmtree(d, ignore_errors=True)


def extract_validation_material(tsr_b64: str, fetch_crl: bool = False,
                                timeout: int = 20) -> Dict:
    """Capture the material needed to validate the TSA signature in the FUTURE
    (LTV / RFC 4998 spirit): the TSA certificate chain embedded in the token, and
    — optionally, best-effort — the CRLs its CDP points to at stamping time, so the
    non-revocation state at T is preserved. openssl absent → {available: False}.

    Honest: this captures the chain the TSA embedded and (if fetch_crl) the CRL
    bytes at capture time; it does NOT itself judge revocation nor build a legally
    complete LTV bundle — it preserves the inputs a validator would need later."""
    exe = shutil.which("openssl")
    if not exe:
        return {"available": False, "note": "openssl absent"}
    d = tempfile.mkdtemp()
    try:
        tsr = os.path.join(d, "t.tsr")
        open(tsr, "wb").write(base64.b64decode(tsr_b64))
        tok = os.path.join(d, "tok.der")
        r = subprocess.run(  # nosec B603 - extract token (NOT -token_in: input is a response)
            [exe, "ts", "-reply", "-in", tsr, "-token_out", "-out", tok],
            capture_output=True, timeout=timeout)
        if r.returncode != 0 or not os.path.exists(tok):
            return {"available": False, "note": "could not extract token from TSR"}
        pem = subprocess.run(  # nosec B603
            [exe, "pkcs7", "-inform", "DER", "-in", tok, "-print_certs"],
            capture_output=True, text=True, timeout=timeout).stdout
        certs = _split_pem_certs(pem)
        certs_der_b64, subjects, cdps = [], [], []
        for c in certs:
            der = _pem_cert_to_der_b64(exe, c, d)
            if der:
                certs_der_b64.append(der)
            subjects.append(_cert_field(exe, c, d, "-subject"))
            cdps.extend(_cert_crl_dps(exe, c, d))
        material = {"available": True, "certs_der_b64": certs_der_b64,
                    "cert_count": len(certs_der_b64), "subjects": subjects,
                    "crl_distribution_points": sorted(set(cdps))}
        if fetch_crl:
            material["crls_b64"] = _fetch_crls(sorted(set(cdps)), timeout)
        return material
    except Exception as e:  # noqa: BLE001
        return {"available": False, "note": f"{type(e).__name__}: {str(e)[:80]}"}
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _split_pem_certs(pem_text: str):
    out, cur = [], []
    for ln in pem_text.splitlines():
        if "BEGIN CERTIFICATE" in ln:
            cur = [ln]
        elif "END CERTIFICATE" in ln:
            cur.append(ln)
            out.append("\n".join(cur) + "\n")
            cur = []
        elif cur:
            cur.append(ln)
    return out


def _pem_cert_to_der_b64(exe: str, pem: str, d: str) -> Optional[str]:
    f = os.path.join(d, "c.pem")
    open(f, "w").write(pem)
    r = subprocess.run(  # nosec B603
        [exe, "x509", "-in", f, "-outform", "DER"], capture_output=True, timeout=15)
    return base64.b64encode(r.stdout).decode() if r.returncode == 0 and r.stdout else None


def _cert_field(exe: str, pem: str, d: str, flag: str) -> str:
    f = os.path.join(d, "c.pem")
    open(f, "w").write(pem)
    r = subprocess.run(  # nosec B603
        [exe, "x509", "-in", f, "-noout", flag], capture_output=True, text=True, timeout=15)
    return (r.stdout or "").strip()


def _cert_crl_dps(exe: str, pem: str, d: str):
    """URIs listed under 'CRL Distribution Points' only (not the AIA/OCSP URIs)."""
    f = os.path.join(d, "c.pem")
    open(f, "w").write(pem)
    txt = subprocess.run(  # nosec B603
        [exe, "x509", "-in", f, "-noout", "-text"], capture_output=True, text=True, timeout=15).stdout or ""
    dps, grab = [], False
    for ln in txt.splitlines():
        stripped = ln.strip()
        if "X509v3 CRL Distribution Points" in ln:
            grab = True
            continue
        if grab:
            # a new extension header (a line like 'X509v3 ...:' or 'Authority ...')
            # at the same indent ends the CRL DP section
            if stripped.startswith("X509v3 ") or stripped.startswith("Authority Information Access"):
                grab = False
                continue
            if stripped.startswith("URI:"):
                dps.append(stripped[4:])
    return dps


def _fetch_crls(urls, timeout: int):
    out = []
    for u in urls:
        if urlparse(u).scheme not in ("http", "https"):
            continue
        try:
            data = urllib.request.urlopen(u, timeout=timeout).read()  # nosec B310 - scheme checked
            out.append({"url": u, "crl_b64": base64.b64encode(data).decode(), "bytes": len(data)})
        except Exception as e:  # noqa: BLE001 - best-effort per CDP
            out.append({"url": u, "error": f"{type(e).__name__}: {str(e)[:60]}"})
    return out


def verify(tsr_b64: str, expected_digest_hex: str, timeout: int = 15,
           ca_file: Optional[str] = None) -> Dict:
    """CRYPTOGRAPHICALLY verify an RFC 3161 token against a TRUST ANCHOR.

    `ca_file` = PEM of the TSA's trusted root/chain. WITHOUT it, the token's signature
    and TSA certificate chain CANNOT be validated — decoding a token only reads its
    claimed contents, it does NOT prove a real TSA issued it — so we return
    {verified: None} ("recorded, not verified"), NEVER a green. With `ca_file` we run
    `openssl ts -verify -CAfile <ca> -digest <hex> -in <tsr>` and require 'Verification: OK'.
    openssl absent → {verified: None}."""
    exe = shutil.which("openssl")
    if not exe:
        return {"verified": None, "note": "openssl absent — token recorded but NOT verified"}
    if not ca_file:
        return {"verified": None, "note": "no TSA trust anchor (ca_file) — token decoded but its "
                                          "signature/chain is UNVERIFIED; supply the TSA roots to verify"}
    if not os.path.exists(ca_file):
        return {"verified": False, "note": f"ca_file not found: {ca_file}"}
    d = tempfile.mkdtemp()
    try:
        tsr = os.path.join(d, "t.tsr")
        with open(tsr, "wb") as f:
            f.write(base64.b64decode(tsr_b64))
        vr = subprocess.run(  # nosec B603 - fixed args, no shell
            [exe, "ts", "-verify", "-in", tsr, "-digest", expected_digest_hex.lower(),
             "-CAfile", ca_file], capture_output=True, text=True, timeout=timeout)
        vtext = (vr.stdout or "") + (vr.stderr or "")
        crypto_ok = vr.returncode == 0 and "Verification: OK" in vtext
        r = subprocess.run(  # nosec B603 - decode only, for reporting the imprint
            [exe, "ts", "-reply", "-in", tsr, "-text"], capture_output=True, text=True, timeout=timeout)
        text = r.stdout or ""
        granted = "Status: Granted" in text or "Granted." in text
        grab, hexbytes = False, []
        for ln in text.splitlines():
            if "Message data:" in ln:
                grab = True
                continue
            if grab:
                if ln.strip() and ln[0] not in " \t":
                    break
                if " - " not in ln:
                    continue
                hexpart = ln.split(" - ", 1)[1].split("   ")[0]
                for tok in hexpart.replace("-", " ").split():
                    if len(tok) == 2 and all(c in "0123456789abcdefABCDEF" for c in tok):
                        hexbytes.append(tok.lower())
        imprint_ok = "".join(hexbytes) == expected_digest_hex.lower()
        return {"verified": bool(crypto_ok and granted and imprint_ok),
                "crypto_verified": crypto_ok, "granted": granted, "imprint_ok": imprint_ok}
    except Exception as e:  # noqa: BLE001
        return {"verified": False, "note": f"{type(e).__name__}: {str(e)[:80]}"}
    finally:
        shutil.rmtree(d, ignore_errors=True)
