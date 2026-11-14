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
("not verified") — never a false positive. A qualified electronic time stamp
enjoys the presumption of the accuracy of its date and time (eIDAS Art. 41(2)); a
token the TSA declares qualified carries a non-critical qcStatements extension with
esi4-qtstStatement-1 (Implementing Regulation (EU) 2025/1929, Annex, EN 319 422
clause 9.1) and its TSA is on the EU Trusted List. This module checks neither and
never calls a token qualified: judging qualification is left to the consumer.
"""

from __future__ import annotations

import base64
import binascii
import calendar
import datetime
import os
import re
import shutil
import subprocess  # nosec B404 - fixed-arg openssl calls, no shell
import tempfile
import urllib.request
from urllib.parse import urlparse
from typing import Dict, Optional

from . import _tsa_keyid


class CheckNotRun(OSError):
    """An RFC 3161 check asked for (`verify` with `ca_file`) that cannot be RUN here: openssl present but not started
    (fork refused, no descriptor left, the binary gone since `which`), openssl giving no answer within the timeout, or
    no temporary file for the bytes openssl reads. Raised, never returned as `verified: False`, which is a verdict on
    the token (0.11.4; measured 13/10/2026 on 0.11.3 under RLIMIT_NPROC 1: a valid token was `verified: False` and the
    evidence record carrying it `valid: false`). openssl ABSENT is still `verified: None`."""


def _not_run(what: str, e: BaseException) -> CheckNotRun:
    why = os.strerror(e.errno) if isinstance(getattr(e, "errno", None), int) else str(e)
    return CheckNotRun(f"{what}: {type(e).__name__}: {why}")


def _run_openssl(cmd, **kw):
    """subprocess.run of openssl for a check: not started, or no answer within the timeout, is CheckNotRun."""
    try:
        return subprocess.run(cmd, **kw)  # nosec B603 - fixed args, no shell
    except subprocess.TimeoutExpired as e:
        raise _not_run("cannot run openssl here", OSError(f"no answer within {e.timeout:g} s")) from e
    except OSError as e:
        raise _not_run("cannot run openssl here", e) from e


_MONTHS = {m: i for i, m in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov",
                                       "Dec"), 1)}
_GEN_TIME = re.compile(r"\ATime stamp: ([A-Z][a-z]{2}) {1,2}(\d{1,2}) (\d\d):(\d\d):(\d\d)(?:\.\d+)? (\d{4}) GMT\Z", re.ASCII)


def _gen_time_from_text(text: str) -> Optional[int]:
    """genTime (whole seconds since the epoch, fraction dropped) from `openssl ts -reply -text`; None when the reply
    holds no single line of that exact form."""
    hits = [m for m in (_GEN_TIME.match(ln) for ln in text.splitlines()) if m]
    if len(hits) != 1 or hits[0].group(1) not in _MONTHS:
        return None
    mon, day, hh, mm, ss, year = hits[0].group(1), *(int(x) for x in hits[0].groups()[1:])
    try:
        return calendar.timegm(datetime.datetime(year, _MONTHS[mon], day, hh, mm, ss).timetuple())
    except ValueError:
        return None


def gen_time_of(tsr_b64: str, timeout: int = 15) -> Optional[int]:
    """The genTime a token CLAIMS (whole seconds since the epoch), read with openssl; None without openssl or for bytes
    that are not a granted reply. A claim, not a verified time: verify() proves it with a trust anchor."""
    exe = shutil.which("openssl")
    if not exe or not isinstance(tsr_b64, str) or not tsr_b64:
        return None
    d = tempfile.mkdtemp()
    try:
        p = os.path.join(d, "t.tsr")
        with open(p, "wb") as f:
            f.write(base64.b64decode(tsr_b64))
        r = _run_openssl([exe, "ts", "-reply", "-in", p, "-text"], capture_output=True, text=True, timeout=timeout)
        return _gen_time_from_text(r.stdout or "") if r.returncode == 0 else None
    except (ValueError, binascii.Error):
        return None
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _reply_facts(exe: str, tsr_path: str, timeout: int, run=subprocess.run):
    """(granted, imprint_hex) read from an RFC 3161 reply with `openssl ts -reply -text`: what the reply CLAIMS, not
    proof that a real TSA issued it (that needs `ts -verify` with a trust anchor)."""
    r = run(  # nosec B603 - decode only, fixed args, no shell
        [exe, "ts", "-reply", "-in", tsr_path, "-text"], capture_output=True, text=True, timeout=timeout)
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
    return granted, "".join(hexbytes)


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
        with open(tsq, "rb") as fq:
            req = fq.read()
        http = urllib.request.Request(tsa_url, data=req, method="POST",
                                      headers={"Content-Type": "application/timestamp-query"})
        with urllib.request.urlopen(http, timeout=timeout) as rh:  # nosec B310 - scheme checked
            resp = rh.read()
        tsr = os.path.join(d, "t.tsr")
        with open(tsr, "wb") as f:
            f.write(resp)
        # anchored only on a reply carrying a token whose imprint is THIS digest (2026-10-03: any HTTP body — an error
        # page, a rejection, a token for another digest — was recorded as anchored: True). A token is present only on a
        # granted status: openssl refuses to parse a non-granted reply that carries one ("token present").
        _, imprint_hex = _reply_facts(exe, tsr, timeout)
        if imprint_hex != digest_hex.lower():
            return {"anchored": False, "tsa": tsa_url, "note": "TSA reply carries no token for this digest"}
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
        with open(tsr, "wb") as fw:
            fw.write(base64.b64decode(tsr_b64))
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
    with open(f, "w") as fw:
        fw.write(pem)
    r = subprocess.run(  # nosec B603
        [exe, "x509", "-in", f, "-outform", "DER"], capture_output=True, timeout=15)
    return base64.b64encode(r.stdout).decode() if r.returncode == 0 and r.stdout else None


def _cert_field(exe: str, pem: str, d: str, flag: str) -> str:
    f = os.path.join(d, "c.pem")
    with open(f, "w") as fw:
        fw.write(pem)
    r = subprocess.run(  # nosec B603
        [exe, "x509", "-in", f, "-noout", flag], capture_output=True, text=True, timeout=15)
    return (r.stdout or "").strip()


def _cert_crl_dps(exe: str, pem: str, d: str):
    """URIs listed under 'CRL Distribution Points' only (not the AIA/OCSP URIs)."""
    f = os.path.join(d, "c.pem")
    with open(f, "w") as fw:
        fw.write(pem)
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
            with urllib.request.urlopen(u, timeout=timeout) as rh:  # nosec B310 - scheme checked
                data = rh.read()
            out.append({"url": u, "crl_b64": base64.b64encode(data).decode(), "bytes": len(data)})
        except Exception as e:  # noqa: BLE001 - best-effort per CDP
            out.append({"url": u, "error": f"{type(e).__name__}: {str(e)[:60]}"})
    return out


def verify(tsr_b64: str, expected_digest_hex: str, timeout: int = 15,
           ca_file: Optional[str] = None, at_time: Optional[int] = None) -> Dict:
    """CRYPTOGRAPHICALLY verify an RFC 3161 token against a TRUST ANCHOR.

    `ca_file` = PEM of the TSA's trusted root/chain. A token whose SignerInfo names its signer by subjectKeyIdentifier
    (RFC 5652 §5.3), which `openssl ts` cannot read, is checked step by step by `_tsa_keyid` (0.12.0; until 0.11.4 such a
    valid token was `verified: False`); its result carries `signer_named_by: "subjectKeyIdentifier"`. WITHOUT it, the token's signature
    and TSA certificate chain CANNOT be validated — decoding a token only reads its
    claimed contents, it does NOT prove a real TSA issued it — so we return
    {verified: None} ("recorded, not verified"), NEVER a green. With `ca_file` we run
    `openssl ts -verify -CAfile <ca> -digest <hex> -in <tsr>` and require 'Verification: OK'.
    openssl absent → {verified: None}. openssl present but not started here, no answer within `timeout`, or no
    temporary file → CheckNotRun is raised (0.11.4): neither verified nor a failed check.

    `at_time` (whole seconds since the epoch) checks the TSA certificate chain at that instant (`openssl ts -verify
    -attime`) instead of now: RFC 4998 section 5.3 step 2, "Each Archive Timestamp MUST be valid relative to the time
    of the following Archive Timestamp"; only the last one is checked at the time of verification. Anything but a
    int from 0 to 253402300799 (9999-12-31T23:59:59Z) is refused with ValueError. The result names the instant (`validated_at`) and, when openssl
    refuses the token, its reason (`reason`, the last informative field of its last error line). Revocation is not checked at either instant."""
    if at_time is not None and (isinstance(at_time, bool) or not isinstance(at_time, int) or not 0 <= at_time <= 253402300799):
        raise ValueError("at_time must be an int of seconds since the epoch, 0 to 9999-12-31T23:59:59Z, not %r" % (at_time,))
    exe = shutil.which("openssl")
    # what the caller holds: a token string, or none at all (absent, empty or not a string) — never claimed otherwise
    tok = "token recorded" if isinstance(tsr_b64, str) and tsr_b64 else "no token recorded (tsr_b64 missing, empty or not a string)"
    if not exe:
        return {"verified": None, "note": f"openssl absent — {tok}, NOT verified"}
    if not ca_file:
        return {"verified": None, "note": f"no TSA trust anchor (ca_file) — {tok}, not decoded or "
                                          "verified; supply the TSA roots to verify"}
    if not os.path.exists(ca_file):
        return {"verified": False, "note": f"ca_file not found: {ca_file}"}
    try:
        d = tempfile.mkdtemp()   # gettempdir() probes each candidate by writing a file there
    except OSError as e:
        raise _not_run("cannot write a temporary file for openssl", OSError("no usable temporary directory")) from e
    try:
        tsr = os.path.join(d, "t.tsr")
        raw = base64.b64decode(tsr_b64)   # a token that is not base64 is the input's fault: verified False, as before
        try:
            with open(tsr, "wb") as f:
                f.write(raw)
        except OSError as e:
            raise _not_run("cannot write a temporary file for openssl", e) from e
        facts = _tsa_keyid.read_reply(raw)
        if facts is not None:   # 0.12.0: a signer named by subjectKeyIdentifier, which openssl ts cannot read
            def _write(path, data):
                try:
                    with open(path, "wb") as fw:
                        fw.write(data)
                except OSError as e:
                    raise _not_run("cannot write a temporary file for openssl", e) from e
            k = _tsa_keyid.check(exe, facts, ca_file, d, timeout, _run_openssl, _write)
            imprint_ok = facts["imprint_hex"] == expected_digest_hex.lower()
            crypto_ok = k["signature_ok"] and k["anchor_ok"]
            out = {"verified": bool(crypto_ok and facts["granted"] and imprint_ok), "crypto_verified": crypto_ok,
                   "granted": facts["granted"], "imprint_ok": imprint_ok, "signer_named_by": "subjectKeyIdentifier"}
            if k["why"]:
                out["note"] = k["why"]
            return out
        cmd = [exe, "ts", "-verify", "-in", tsr, "-digest", expected_digest_hex.lower(), "-CAfile", ca_file]
        if at_time is not None:
            cmd += ["-attime", str(at_time)]
        vr = _run_openssl(cmd, capture_output=True, text=True, timeout=timeout)
        vtext = (vr.stdout or "") + (vr.stderr or "")
        crypto_ok = vr.returncode == 0 and "Verification: OK" in vtext
        granted, imprint_hex = _reply_facts(exe, tsr, timeout, run=_run_openssl)
        imprint_ok = imprint_hex == expected_digest_hex.lower()
        out = {"verified": bool(crypto_ok and granted and imprint_ok),
               "crypto_verified": crypto_ok, "granted": granted, "imprint_ok": imprint_ok,
               "validated_at": "now" if at_time is None else
               datetime.datetime.fromtimestamp(at_time, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
        if not crypto_ok:
            errs = [ln.strip() for ln in vtext.splitlines() if "error" in ln.lower()]
            # the last field of the last error line that is not empty, a source file or a line number: an OpenSSL 3
            # line ends "...:<reason>:<file>.c:<line>:<data>", and <data> is empty for a CA file it cannot load
            fields = [x.strip() for x in (errs[-1].split(":") if errs else [])]
            fields = [x for x in fields if x and not x.isdigit() and not x.endswith(".c")]
            out["reason"] = (fields[-1] if fields else "openssl ts -verify did not print OK")[:160]
        return out
    except CheckNotRun:
        raise
    except Exception as e:  # noqa: BLE001
        return {"verified": False, "note": f"{type(e).__name__}: {str(e)[:80]}"}
    finally:
        shutil.rmtree(d, ignore_errors=True)
