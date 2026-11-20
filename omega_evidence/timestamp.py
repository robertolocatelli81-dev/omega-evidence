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

Capturing CRLs (`extract_validation_material(fetch_crl=True)`, `pack.stamp_pack(capture_ltv=True, fetch_crl=True)`) is
the one place where this module asks a URL it did not get from its caller: a CRL distribution point is written by
whoever made the certificate. The rule, closed by construction (20/11/2026; until 0.12.0 the distribution points of
every certificate of a token nobody had verified were asked, see `_crl_fetch`):

  (a) no URL is asked unless the token verifies (`verify`: signature, chain, imprint) against the trust anchor the
      CALLER gives (`ca_file`) for the digest the caller gives; without them, or when it does not verify or the check
      cannot be run, nothing is asked and `crl_fetch.reason` says why;
  (b) only the certificates of the signer's chain name a URL: the signer certificate and, upwards, each certificate
      carried by the token (or given as `untrusted`) that issued one already in the chain, and each of them must itself
      verify under `ca_file`. Any other certificate the token carries is listed (`crl_distribution_points`) and never
      asked;
  (c) each URL is asked under the rule of `_crl_fetch` (public addresses only, judged as addresses; no redirect, no
      proxy; a bound on bytes and time; only a DER CRL is kept); at most `_crl_fetch.CRL_MAX_URLS` URLs and
      `_crl_fetch.CRL_TOTAL_MAX_BYTES` in all;
  (d) what is refused is recorded per URL (`error`), never dropped in silence.
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
from urllib.parse import urlparse
from typing import Dict, List, Optional, Tuple

from . import _crl_fetch, _tsa_keyid


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
    that are not a granted reply; for a token whose signer is named by subjectKeyIdentifier, which openssl ts does not
    print, read from the TSTInfo itself (0.12.0). A claim, not a verified time: verify() proves it with a trust anchor."""
    exe = shutil.which("openssl")
    if not exe or not isinstance(tsr_b64, str) or not tsr_b64:
        return None
    d = tempfile.mkdtemp()
    try:
        p = os.path.join(d, "t.tsr")
        raw = base64.b64decode(tsr_b64)
        with open(p, "wb") as f:
            f.write(raw)
        r = _run_openssl([exe, "ts", "-reply", "-in", p, "-text"], capture_output=True, text=True, timeout=timeout)
        g = _gen_time_from_text(r.stdout or "") if r.returncode == 0 else None
        if g is None:   # 0.12.0: a signer named by subjectKeyIdentifier, which openssl ts does not print
            facts = _tsa_keyid.read_reply(raw)
            if facts is not None and facts["granted"]:
                g = _gen_time_of_der(facts["tst_info"])
        return g
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


TSA_REPLY_MAX_BYTES = 1024 * 1024   # an RFC 3161 reply with its certificates is a few kB


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
        resp = _crl_fetch.ask(tsa_url, data=req, headers={"Content-Type": "application/timestamp-query"},
                              timeout=timeout, max_bytes=TSA_REPLY_MAX_BYTES)   # no redirect, bounded (_crl_fetch.ask)
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


_UNVERIFIED_NOTE = ("read from a token that was not verified against a trust anchor: these are the certificates the "
                    "reply carries, not proof of who issued it")


def extract_validation_material(tsr_b64: str, fetch_crl: bool = False, timeout: int = 20,
                                ca_file: Optional[str] = None, expected_digest_hex: Optional[str] = None,
                                untrusted: Optional[str] = None) -> Dict:
    """Capture the material needed to validate the TSA signature in the FUTURE
    (LTV / RFC 4998 spirit): the TSA certificate chain embedded in the token, and
    — optionally, best-effort — the CRLs its CDP points to at stamping time, so the
    non-revocation state at T is preserved. openssl absent → {available: False}.

    Honest: this captures the chain the TSA embedded and (if fetch_crl) the CRL
    bytes at capture time; it does NOT itself judge revocation nor build a legally
    complete LTV bundle — it preserves the inputs a validator would need later.

    `ca_file` (PEM trust anchor of the TSA) and `expected_digest_hex` (the digest the token must be over), with
    `untrusted` as in `verify`: when both are given the token is verified and the result says so (`token_verified`:
    True or False; None when they are not given, openssl cannot run the check or cannot say). `fetch_crl=True` asks a
    URL only under the rule in the module docstring: a verified token, the signer's chain, the closed URL rule of
    `_crl_fetch`. Otherwise `crls_b64` is empty and `crl_fetch` is `{"fetched": False, "reason": ...}`; when URLs are
    asked it is `{"fetched": True, "chain_certificates": n}` and each entry of `crls_b64` is `{url, crl_b64, bytes}`
    or `{url, error}`. Until 0.12.0 `fetch_crl=True` asked the distribution points of every certificate of the token,
    verified or not, with no bound (measured 20/11/2026: a GET to a loopback address, its answer in the sidecar)."""
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
        verified, why = None, "no trust anchor (ca_file) and digest (expected_digest_hex) given"
        if ca_file and isinstance(expected_digest_hex, str) and expected_digest_hex:
            try:
                v = verify(tsr_b64, expected_digest_hex, timeout=timeout, ca_file=ca_file, untrusted=untrusted)
                verified = v.get("verified")
                why = "" if verified is True else str(v.get("reason") or v.get("note") or "not verified")[:160]
            except (CheckNotRun, ValueError) as e:
                why = f"the check could not be run: {str(e)[:120]}"
        material["token_verified"] = verified if isinstance(verified, bool) else None
        if verified is not True:
            material["note"] = _UNVERIFIED_NOTE
        if fetch_crl:
            material["crls_b64"], material["crl_fetch"] = [], {"fetched": False}
            if verified is not True:
                material["crl_fetch"]["reason"] = ("the token is not verified against the caller's trust anchor (" + why
                                                   + "): no URL named by its certificates is asked")
            else:
                try:
                    chain, why = _signer_chain(exe, tok, certs, ca_file, untrusted, d, timeout)
                except CheckNotRun as e:
                    chain, why = None, f"the check could not be run: {str(e)[:120]}"
                if chain is None:
                    material["crl_fetch"]["reason"] = why + ": no URL is asked"
                else:
                    urls = sorted({u for c in chain for u in _cert_crl_dps(exe, _pem_text(c), d)})
                    material["crl_fetch"] = {"fetched": True, "chain_certificates": len(chain)}
                    material["crls_b64"] = _fetch_crls(urls, timeout)
        return material
    except Exception as e:  # noqa: BLE001
        return {"available": False, "note": f"{type(e).__name__}: {str(e)[:80]}"}
    finally:
        shutil.rmtree(d, ignore_errors=True)


_CHAIN_POOL_MAX = 16   # certificates looked at to build the signer's chain (the token's and the caller's untrusted)


def _pem_text(der: bytes) -> str:
    return _tsa_keyid._pem(der).decode("ascii")


def _names_of(der: bytes) -> Tuple[bytes, bytes]:
    """(issuer, subject) of a certificate, each as the DER of its Name; DerError when it is not read"""
    cert = _tsa_keyid._items(_tsa_keyid._one(der, "certificate", 0x30), "certificate")
    tbs = _tsa_keyid._items(cert[0][1], "tbsCertificate")
    k = 1 if tbs[0][0] == 0xA0 else 0
    if len(tbs) < k + 5:
        raise _tsa_keyid.DerError("tbsCertificate: too short")
    return _tsa_keyid._tlv(0x30, tbs[k + 2][1]), _tsa_keyid._tlv(0x30, tbs[k + 4][1])


def _signer_chain(exe: str, tok: str, certs_pem: List[str], ca_file: str, untrusted: Optional[str], d: str,
                  timeout: int) -> Tuple[Optional[List[bytes]], str]:
    """Rule (b) of the module docstring, for a token `verify` has accepted under `ca_file`: ([signer, issuers...], "")
    as DER, or (None, why). The signer is the certificate whose key `openssl cms -verify` checks the signature with;
    a certificate of the pool joins the chain when it issued one already in it (same Name as that one's issuer, and
    `openssl verify -partial_chain -trusted <it>` accepts that one) AND itself verifies under `ca_file` — a copy of an
    issuer with the same name and key and another distribution point has no valid signature and stays out."""
    def write(path: str, data: bytes) -> None:
        with open(path, "wb") as f:
            f.write(data)
    pool: List[bytes] = []
    extra_pem = b""
    if untrusted is not None:
        with open(untrusted, "rb") as f:
            extra_pem = f.read()
    for block in certs_pem + _split_pem_certs(extra_pem.decode("ascii", "replace")):
        der = _tsa_keyid._first_pem_der(block.encode("ascii", "replace"))
        if der is not None and der not in pool:
            pool.append(der)
    if len(pool) > _CHAIN_POOL_MAX:
        return None, f"more than {_CHAIN_POOL_MAX} certificates to build the signer's chain from"
    sp, pp = os.path.join(d, "chain_signer.pem"), os.path.join(d, "chain_pool.pem")
    write(pp, b"".join(_tsa_keyid._pem(c) for c in pool))
    r = _run_openssl([exe, "cms", "-verify", "-noverify", "-binary", "-inform", "DER", "-in", tok, "-signer", sp,
                      "-out", os.devnull, "-certfile", pp], capture_output=True, timeout=timeout)
    signer = None
    if r.returncode == 0 and os.path.exists(sp):
        with open(sp, "rb") as f:
            signer = _tsa_keyid._first_pem_der(f.read())
    if signer is None or signer not in pool:
        return None, "the signer certificate of the token was not found among its certificates"

    def anchored(der: bytes, purpose: List[str]) -> bool:
        cp = os.path.join(d, "chain_c.pem")
        write(cp, _tsa_keyid._pem(der))
        return _run_openssl([exe, "verify", "-CAfile", ca_file, "-no-CApath", "-no-CAstore", "-untrusted", pp] + purpose
                            + [cp], capture_output=True, timeout=timeout).returncode == 0

    def issued(issuer: bytes, subject: bytes) -> bool:
        try:
            if not _tsa_keyid.names_equal(_names_of(subject)[0], _names_of(issuer)[1]):
                return False
        except (ValueError, IndexError):
            return False
        ip, cp = os.path.join(d, "chain_i.pem"), os.path.join(d, "chain_s.pem")
        write(ip, _tsa_keyid._pem(issuer))
        write(cp, _tsa_keyid._pem(subject))
        return _run_openssl([exe, "verify", "-partial_chain", "-trusted", ip, "-no-CApath", "-no-CAstore", cp],
                            capture_output=True, timeout=timeout).returncode == 0
    if not anchored(signer, ["-purpose", "timestampsign"]):
        return None, "the signer certificate does not verify under ca_file"
    chain, todo = [signer], [signer]
    while todo:
        cur = todo.pop()
        for cand in pool:
            if cand not in chain and issued(cand, cur) and anchored(cand, []):
                chain.append(cand)
                todo.append(cand)
    return chain, ""


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
    """Rule (c) of the module docstring: each URL asked through `_crl_fetch.fetch`, its refusals recorded."""
    out, total = [], 0
    for n, u in enumerate(urls):
        if n >= _crl_fetch.CRL_MAX_URLS:
            out.append({"url": u, "error": f"not asked: more than {_crl_fetch.CRL_MAX_URLS} distribution points"})
            continue
        left = _crl_fetch.CRL_TOTAL_MAX_BYTES - total
        if left <= 0:
            out.append({"url": u, "error": f"not asked: {_crl_fetch.CRL_TOTAL_MAX_BYTES} bytes of CRLs already captured"})
            continue
        try:
            data = _crl_fetch.fetch(u, timeout, min(_crl_fetch.CRL_MAX_BYTES, left))
        except _crl_fetch.Refused as e:
            out.append({"url": u, "error": f"refused: {str(e)[:120]}"})
            continue
        except Exception as e:  # noqa: BLE001 - best-effort per CDP
            out.append({"url": u, "error": f"{type(e).__name__}: {str(e)[:60]}"})
            continue
        total += len(data)
        out.append({"url": u, "crl_b64": base64.b64encode(data).decode(), "bytes": len(data)})
    return out


_NO_SIGNER = ("the token carries no TSA signer certificate and no certificate given as untrusted is it: pass the TSA's "
              "certificates with untrusted= (as openssl ts -verify -untrusted)")
_POLICIES = {"now": "now", "at_time": "the caller's at_time",
             "gen_time": "the token's own genTime (Sigstore Client Spec 4.2.1: the TSA chain is verified with the signed "
                         "timestamp as the current time; revocation is not checked, so a TSA key compromised later "
                         "could date a token inside its certificate's validity)"}


def _iso(t: int) -> str:
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _gen_time_of_der(tst) -> Optional[int]:
    """genTime of a TSTInfo read by _tsa_keyid (a GeneralizedTime YYYYMMDDHHMMSS[.f]Z, RFC 3161 section 2.4.2)"""
    try:
        m = re.fullmatch(rb"(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(?:\.\d*[1-9])?Z", tst[4][1])
        if not m:
            return None
        return calendar.timegm(datetime.datetime(*(int(x) for x in m.groups())).timetuple())
    except (IndexError, TypeError, ValueError):
        return None


def verify(tsr_b64: str, expected_digest_hex: str, timeout: int = 15,
           ca_file: Optional[str] = None, at_time: Optional[int] = None, untrusted: Optional[str] = None,
           at_gen_time: bool = False) -> Dict:
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

    `untrusted` (0.12.0) = PEM file of certificates that are NOT trust anchors but may build the chain or be the signer
    (`openssl ts -verify -untrusted`): a token that does not carry its TSA certificate — the RFC 3161 tokens of sigstore
    bundles, GitHub's and Sigstore's TSA, measured 18/11/2026 — cannot be verified without it. Such a token checked
    without the certificate is `verified: False` with that `reason`, never a bare False.

    `at_time` (whole seconds since the epoch) checks the TSA certificate chain at that instant (`openssl ts -verify
    -attime`) instead of now: RFC 4998 section 5.3 step 2, "Each Archive Timestamp MUST be valid relative to the time
    of the following Archive Timestamp"; only the last one is checked at the time of verification. Anything but a
    int from 0 to 253402300799 (9999-12-31T23:59:59Z) is refused with ValueError. `at_gen_time=True` (0.12.0) checks it
    at the genTime the token itself claims (Sigstore Client Spec 4.2.1, for its TSA timestamps); a token whose genTime
    cannot be read is `verified: False` with its reason. Both together is ValueError. The result names the instant
    (`validated_at`) and the rule (`validation_time`: "now", "at_time" or "gen_time") and, when the token is refused,
    its reason (`reason`; for openssl, the last informative field of its last error line). Revocation is not checked at
    any instant."""
    if at_time is not None and (isinstance(at_time, bool) or not isinstance(at_time, int) or not 0 <= at_time <= 253402300799):
        raise ValueError("at_time must be an int of seconds since the epoch, 0 to 9999-12-31T23:59:59Z, not %r" % (at_time,))
    if not isinstance(at_gen_time, bool):
        raise ValueError("at_gen_time must be True or False, not %r" % (at_gen_time,))
    if at_gen_time and at_time is not None:
        raise ValueError("at_time and at_gen_time=True name two instants: give one")
    if untrusted is not None and (not isinstance(untrusted, str) or not untrusted):
        raise ValueError("untrusted must be the path of a PEM file, not %r" % (untrusted,))
    policy = "gen_time" if at_gen_time else ("now" if at_time is None else "at_time")
    exe = shutil.which("openssl")
    # what the caller holds: a token string, or none at all (absent, empty or not a string) — never claimed otherwise
    tok = "token recorded" if isinstance(tsr_b64, str) and tsr_b64 else "no token recorded (tsr_b64 missing, empty or not a string)"
    if not exe:
        return {"verified": None, "note": f"openssl absent — {tok}, NOT verified"}
    if not ca_file:
        return {"verified": None, "note": f"no TSA trust anchor (ca_file) — {tok}, not decoded or "
                                          "verified; supply the TSA roots to verify"}
    if not os.path.exists(ca_file):
        return {"verified": False, "note": f"ca_file not found: {ca_file}", "reason": "ca_file not found"}
    untrusted_pem = b""
    if untrusted is not None:
        try:
            with open(untrusted, "rb") as f:
                untrusted_pem = f.read()
        except OSError as e:
            return {"verified": False, "note": f"untrusted not readable: {untrusted}",
                    "reason": f"untrusted file not readable: {type(e).__name__}"}
        if b"-----BEGIN CERTIFICATE-----" not in untrusted_pem:
            return {"verified": False, "note": f"untrusted holds no PEM certificate: {untrusted}",
                    "reason": "untrusted file holds no PEM certificate"}
    try:
        d = tempfile.mkdtemp()   # gettempdir() probes each candidate by writing a file there
    except OSError as e:
        raise _not_run("cannot write a temporary file for openssl", OSError("no usable temporary directory")) from e
    try:
        tsr = os.path.join(d, "t.tsr")
        raw = base64.b64decode(tsr_b64)   # a token that is not base64 is the input's fault: verified False, as before

        def _write(path, data):
            try:
                with open(path, "wb") as fw:
                    fw.write(data)
            except OSError as e:
                raise _not_run("cannot write a temporary file for openssl", e) from e
        _write(tsr, raw)
        facts = _tsa_keyid.read_reply(raw)
        when = at_time
        if at_gen_time:
            when = _gen_time_of_der(facts["tst_info"]) if facts is not None else gen_time_of(tsr_b64, timeout)
            if when is None or not 0 <= when <= 253402300799:
                return {"verified": False, "crypto_verified": False, "validation_time": policy,
                        "reason": "at_gen_time: the token's genTime could not be read"}
        stamp_out = {"validation_time": policy, "validated_at": "now" if when is None else _iso(when)}
        if at_gen_time:
            stamp_out["validation_time_rule"] = _POLICIES["gen_time"]
        if facts is not None:   # 0.12.0: a signer named by subjectKeyIdentifier, which openssl ts cannot read
            k = _tsa_keyid.check(exe, facts, ca_file, d, timeout, _run_openssl, _write,
                                 untrusted_pem=untrusted_pem, at_time=when)
            imprint_ok = facts["imprint_hex"] == expected_digest_hex.lower()
            crypto_ok = k["signature_ok"] and k["anchor_ok"]
            out = {"verified": bool(crypto_ok and facts["granted"] and imprint_ok), "crypto_verified": crypto_ok,
                   "granted": facts["granted"], "imprint_ok": imprint_ok, "signer_named_by": "subjectKeyIdentifier"}
            out.update(stamp_out)
            if k["why"]:
                out["note"] = k["why"]
                out["reason"] = k["why"]
            elif not facts["granted"]:
                out["reason"] = "the TSA did not grant the request"
            elif not imprint_ok:
                out["reason"] = "message imprint differs from the expected digest"
            return out
        cmd = [exe, "ts", "-verify", "-in", tsr, "-digest", expected_digest_hex.lower(), "-CAfile", ca_file]
        if untrusted is not None:
            up = os.path.join(d, "untrusted.pem")
            _write(up, untrusted_pem)
            cmd += ["-untrusted", up]
        if when is not None:
            cmd += ["-attime", str(when)]
        vr = _run_openssl(cmd, capture_output=True, text=True, timeout=timeout)
        vtext = (vr.stdout or "") + (vr.stderr or "")
        crypto_ok = vr.returncode == 0 and "Verification: OK" in vtext
        granted, imprint_hex = _reply_facts(exe, tsr, timeout, run=_run_openssl)
        imprint_ok = imprint_hex == expected_digest_hex.lower()
        out = {"verified": bool(crypto_ok and granted and imprint_ok),
               "crypto_verified": crypto_ok, "granted": granted, "imprint_ok": imprint_ok}
        out.update(stamp_out)
        if not crypto_ok:
            errs = [ln.strip() for ln in vtext.splitlines() if "error" in ln.lower()]
            # the last field of the last error line that is not empty, a source file or a line number: an OpenSSL 3
            # line ends "...:<reason>:<file>.c:<line>:<data>", and <data> is empty for a CA file it cannot load
            fields = [x.strip() for x in (errs[-1].split(":") if errs else [])]
            fields = [x for x in fields if x and not x.isdigit() and not x.endswith(".c")]
            out["reason"] = (fields[-1] if fields else "openssl ts -verify did not print OK")[:160]
            if "signer certificate not found" in vtext:
                out["reason"] = _NO_SIGNER
        elif not granted:
            out["reason"] = "the TSA did not grant the request"
        elif not imprint_ok:
            out["reason"] = "message imprint differs from the expected digest"
        return out
    except CheckNotRun:
        raise
    except Exception as e:  # noqa: BLE001
        return {"verified": False, "note": f"{type(e).__name__}: {str(e)[:80]}",
                "reason": f"token not read: {type(e).__name__}"}
    finally:
        shutil.rmtree(d, ignore_errors=True)
