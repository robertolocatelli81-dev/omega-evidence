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
omega_evidence.interop.sdjwt — issue and verify SD-JWT (RFC 9901, Selective
Disclosure for JWTs), so OMEGA can produce PII-free, selectively-disclosable
credentials for the eIDAS 2.0 / EUDI wallet lane.

The holder can present only chosen claims; the verifier checks the issuer's
signature and that each presented claim's digest is in the signed `_sd` array —
without the issuer learning what was shown, and without undisclosed claims
leaking.

issue() writes top-level, selectively disclosable claims in the RFC 9901 wire format below (no decoy digests, no
nested or array-element Disclosures) and refuses names RFC 9901 §4.1 / §4.2.1 forbid; verify() applies §7.1 (see its
docstring for what is left to the caller or not implemented):
  * Disclosure = base64url_nopad(utf8(json([salt, name, value])))
  * digest     = base64url_nopad(sha256(ascii(Disclosure)))     ; _sd_alg="sha-256"
  * Combined   = <JWS>~<Disclosure>~...~     (trailing '~', no key-binding JWT here)
  * JWS header = {"alg":"EdDSA","typ":"dc+sd-jwt"}, Ed25519 over the JWS input.

Honest scope: this is the SD-JWT wire format + issuer signature. It is NOT an
eIDAS-qualified credential, NOT SD-JWT VC typing/status, and carries NO
key-binding (holder proof-of-possession) — those are separate layers. The digests
are recomputed per-spec (sha-256), NOT reused from attestation.py's sha3 digests.
Self-contained: Python stdlib + this toolkit's Ed25519 signing. Apache-2.0.
"""

from __future__ import annotations

import base64
import re
import hashlib
import json
import math
import secrets
import time
from typing import Any, Dict, List, Optional

from ..signing import Identity, verify_signature

JWS_TYP = "dc+sd-jwt"
SD_ALG = "sha-256"


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_dec(s: str) -> bytes:
    """Strict BASE64URL (RFC 7515 §2, used by RFC 9901): URL alphabet, no '=' padding, no whitespace, canonical.
    audit V2 #3 (30/09/2026): spaces, newlines and '==' in the signature segment were accepted."""
    if not isinstance(s, str) or not re.fullmatch(r"[A-Za-z0-9_-]*", s) or len(s) % 4 == 1:
        raise ValueError("not strict base64url (RFC 7515)")
    raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    if _b64u(raw) != s:
        raise ValueError("non-canonical base64url (RFC 7515)")
    return raw


def _disclosure(salt: str, name: str, value: Any) -> str:
    payload = json.dumps([salt, name, value], separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    return _b64u(payload)


def _digest(disclosure: str) -> str:
    return _b64u(hashlib.sha256(disclosure.encode("ascii")).digest())


def _raw_sig(identity: Identity, signing_input: bytes) -> bytes:
    # Identity.sign returns standard-base64 of the raw Ed25519 signature
    return base64.b64decode(identity.sign(signing_input))


def _names_ok(node: Any) -> None:
    """Every object key in what issue() signs is a string (JSON would turn 1 / True / None into "1" / "true" / "null",
    and a name check on Python objects would miss the clash; RFC 7519 §4: claim names unique) and never _sd, ... or
    _sd_alg, which RFC 9901 reserves (§4.1 item 7, §4.1.1, §4.2.1). Raises ValueError on a refused name; a circular
    structure is a RecursionError. Claim values are not checked here: an exp that is not a number is signed, and verify()
    rejects the token only when that exp is in the processed payload (in clear, or in a presented Disclosure)."""
    if isinstance(node, dict):
        for k, v in node.items():
            if not isinstance(k, str) or k in ("_sd", "...", "_sd_alg"):
                raise ValueError(f"name {k!r} is not allowed in an issued SD-JWT (RFC 9901 §4.1, RFC 7519 §4)")
            _names_ok(v)
    elif isinstance(node, (list, tuple)):
        for v in node:
            _names_ok(v)


def issue(claims: Dict[str, Any], identity: Identity,
          plain_claims: Optional[Dict[str, Any]] = None) -> str:
    """Issue an SD-JWT. Every entry in `claims` is selectively disclosable; entries
    in `plain_claims` (e.g. iss, iat) travel in clear in the signed payload."""
    plain = dict(plain_claims or {})
    _names_ok(plain); _names_ok(list(claims.values()) if isinstance(claims, dict) else claims)
    for name in claims:   # §4.2.1: a claim name is a string, never _sd / ... or a permanently disclosed claim (NEMESIS V2 N6)
        if not isinstance(name, str) or name in ("_sd", "...", "_sd_alg") or name in plain:
            rule = "§4.1.1: _sd_alg stays at the top level, in clear" if name == "_sd_alg" else "§4.2.1"
            raise ValueError(f"claim name {name!r} cannot be selectively disclosed (RFC 9901 {rule})")
    json.dumps([claims, plain], allow_nan=False)   # NaN / Infinity are not JSON (RFC 8259): ValueError
    disclosures: List[str] = []
    digests: List[str] = []
    for name, value in claims.items():
        d = _disclosure(secrets.token_urlsafe(16), name, value)
        disclosures.append(d)
        digests.append(_digest(d))
    body: Dict[str, Any] = dict(plain_claims or {})
    body["_sd"] = sorted(digests)          # sorted: no ordering leak
    body["_sd_alg"] = SD_ALG
    header = {"alg": "EdDSA", "typ": JWS_TYP}
    signing_input = (_b64u(json.dumps(header, separators=(",", ":")).encode())
                     + "." + _b64u(json.dumps(body, separators=(",", ":")).encode()))
    jws = signing_input + "." + _b64u(_raw_sig(identity, signing_input.encode("ascii")))
    return jws + "~" + "".join(d + "~" for d in disclosures)


def _split(sdjwt: str):
    parts = sdjwt.split("~")
    jws = parts[0]
    disclosures = [p for p in parts[1:] if p]   # trailing '~' -> empty tail dropped
    return jws, disclosures


def present(sdjwt: str, disclose: List[str]) -> str:
    """Holder-side selective disclosure: keep only the disclosures for the named
    claims, drop the rest. The JWS is unchanged (still issuer-signed)."""
    jws, disclosures = _split(sdjwt)
    keep = []
    for d in disclosures:
        name = json.loads(_b64u_dec(d).decode("utf-8"))[1]
        if name in disclose:
            keep.append(d)
    return jws + "~" + "".join(d + "~" for d in keep)


def verify(sdjwt: str, issuer_public_key_b64: str, now: Optional[float] = None) -> Dict[str, Any]:
    """Verify an SD-JWT per RFC 9901 §7.1 and return {verified, header, plain_claims, disclosed_claims,
    undisclosed_digests, processed_payload}. `verified` is True only if every step holds: alg EdDSA (never "none"),
    the issuer's Ed25519 signature, `_sd_alg` sha-256 (the default when absent, §4.1.1), every Disclosure of the right
    shape and referenced exactly once (recursively, in objects and array elements), no claim name `_sd` / `...` or one
    already present at that level, no digest seen twice, and `exp` / `nbf` when present (at `now`, default the clock).
    Format rules of §4.2.1 / §4.2.4.1 are enforced too: a salt is a string, an `_sd` key refers to an array of strings.
    Any failure rejects the whole SD-JWT, never just the Disclosure (§7.1: «If any step fails, the SD-JWT is not valid»).
    A malformed token is a verdict, never a traceback. Left to the caller or not implemented: Key Binding (§7.3) — an
    SD-JWT+KB (anything after the last '~') is rejected as a whole; that the key belongs to the Issuer (step 2.c), which
    is the caller's choice of `issuer_public_key_b64`; `aud` and which validity claims are required (step 6, §9.7);
    the JWS `crit` header (RFC 7515). Stricter than §7.1, and declared: the same Disclosure presented twice is a reject."""
    try:
        return _verify(sdjwt, issuer_public_key_b64, now)
    except _Reject as e:
        return {"verified": False, "error": str(e), "disclosed_claims": {}}
    except (ValueError, TypeError, AttributeError, KeyError, RecursionError) as e:
        # a malformed token is a verdict, never a traceback (audit V2 #4, 30/09/2026)
        return {"verified": False, "error": f"malformed SD-JWT: {type(e).__name__}", "disclosed_claims": {}}


class _Reject(Exception):
    pass


def _loads(raw: bytes) -> Any:
    def _no_constant(c):   # NaN / Infinity are not JSON (RFC 8259); a signed `exp: NaN` would never expire (NEMESIS V2 Q4)
        raise ValueError(f"non-standard JSON constant {c}")
    return json.loads(raw.decode("utf-8"), parse_constant=_no_constant)


def _verify(sdjwt: str, issuer_public_key_b64: str, now: Optional[float]) -> Dict[str, Any]:
    if not isinstance(sdjwt, str):
        raise TypeError("SD-JWT is not a string")
    if not sdjwt.endswith("~"):
        raise _Reject("not an SD-JWT ending in '~' (an SD-JWT+KB is not supported here)")
    parts = sdjwt.split("~")
    jws, disclosures = parts[0], parts[1:-1]
    if any(d == "" for d in disclosures):
        raise _Reject("empty Disclosure")
    try:
        h_b64, p_b64, sig_b64 = jws.split(".")
    except ValueError:
        return {"verified": False, "error": "malformed JWS", "disclosed_claims": {}}
    header = _loads(_b64u_dec(h_b64))
    if not isinstance(header, dict) or header.get("alg") != "EdDSA":
        raise _Reject("alg must be EdDSA (step 2.a: the only algorithm this verifier accepts; never 'none')")
    signing_input = (h_b64 + "." + p_b64).encode("ascii")
    raw_sig = _b64u_dec(sig_b64)
    if not verify_signature(issuer_public_key_b64, base64.b64encode(raw_sig).decode(), signing_input):
        return {"verified": False, "error": "issuer signature invalid", "header": header, "disclosed_claims": {}}
    body = _loads(_b64u_dec(p_b64))
    if not isinstance(body, dict):
        raise _Reject("payload is not a JSON object")
    if body.get("_sd_alg", SD_ALG) != SD_ALG:
        raise _Reject("_sd_alg not understood (step 2.d: only sha-256)")
    by_digest: Dict[str, str] = {}
    for d in disclosures:
        dg = _digest(d)
        if dg in by_digest:
            raise _Reject("the same Disclosure is presented twice")
        by_digest[dg] = d
    seen: set = set()
    used: set = set()

    def _take(dg: str, n: int) -> List[Any]:
        if dg in seen:
            raise _Reject("digest encountered more than once (step 4)")
        seen.add(dg)
        if dg not in by_digest:
            return []
        used.add(dg)
        content = _loads(_b64u_dec(by_digest[dg]))
        if not isinstance(content, list) or len(content) != n:
            raise _Reject(f"Disclosure is not a JSON array of {n} elements (step 3.c.{'ii' if n == 3 else 'iii'}.1)")
        if not isinstance(content[0], str):
            raise _Reject("Disclosure salt is not a string (§4.2.1)")
        return content

    def _process(node: Any) -> Any:
        if isinstance(node, dict):
            if "_sd" in node and not (isinstance(node["_sd"], list) and all(isinstance(x, str) for x in node["_sd"])):
                raise _Reject("_sd is not an array of strings")
            out = {k: _process(v) for k, v in node.items() if k != "_sd"}
            for dg in node.get("_sd", []):
                c = _take(dg, 3)
                if not c:
                    continue                                   # step 3.c.i: no Disclosure, digest ignored
                name, value = c[1], c[2]
                if not isinstance(name, str):
                    raise _Reject("claim name is not a string (§4.2.1)")
                if name in ("_sd", "..."):
                    raise _Reject("claim name is _sd or ... (step 3.c.ii.2)")
                if name in out:
                    raise _Reject("claim name already exists at that level (step 3.c.ii.3)")
                out[name] = _process(value)
            return out
        if isinstance(node, list):
            res = []
            for el in node:
                if isinstance(el, dict) and len(el) == 1 and "..." in el and isinstance(el["..."], str):
                    c = _take(el["..."], 2)
                    if c:
                        res.append(_process(c[1]))             # step 3.d: elements without a Disclosure are removed
                else:
                    res.append(_process(el))
            return res
        return node

    processed = _process(body)
    if set(by_digest) - used:
        raise _Reject("a Disclosure is not referenced by any digest (step 5)")
    processed.pop("_sd_alg", None)
    t = time.time() if now is None else now
    for claim, bad in (("exp", lambda v: t >= v), ("nbf", lambda v: t < v)):
        if claim in processed:
            v = processed[claim]
            if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v):
                raise _Reject(f"{claim} is not a finite number")   # 1e400 parses to inf: a token that would never expire
            if bad(v):
                raise _Reject(f"{claim} check failed (step 6)")
    top_sd = body.get("_sd", [])
    disclosed = {k: v for k, v in processed.items() if k not in body}
    plain = {k: v for k, v in body.items() if k not in ("_sd", "_sd_alg")}
    return {"verified": True, "header": header, "plain_claims": plain, "disclosed_claims": disclosed,
            "undisclosed_digests": sorted(set(top_sd) - used), "processed_payload": processed}
