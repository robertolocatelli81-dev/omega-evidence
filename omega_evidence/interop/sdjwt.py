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
credentials, and verify the issuer JWS of an SD-JWT VC (scope below).

The holder can present only chosen claims; the verifier checks the issuer's
signature and that each presented claim's digest is in the signed `_sd` array —
without the issuer learning what was shown, and without undisclosed claims
leaking.

issue() writes top-level, selectively disclosable claims in the RFC 9901 wire format below (no decoy digests, no
nested or array-element Disclosures) and refuses names RFC 9901 §4.1 / §4.2.1 forbid; verify() applies §7.1 (see its
docstring for what is left to the caller or not implemented) and, since 0.12.0, the JOSE header of an SD-JWT VC
(draft-ietf-oauth-sd-jwt-vc-27 §2.2.1: `typ` "dc+sd-jwt", compared as RFC 7515 §4.1.9 says) and the issuer signature
in ES256 (ECDSA on P-256 with SHA-256, RFC 7518 §3.4; OpenID4VC HAIP 1.0, Final, §7: issuers, verifiers and wallets
MUST at least support it) as well as EdDSA/Ed25519,
each algorithm bound to one curve (RFC 9864):
  * Disclosure = base64url_nopad(utf8(json([salt, name, value])))
  * digest     = base64url_nopad(sha256(ascii(Disclosure)))     ; _sd_alg="sha-256"
  * Combined   = <JWS>~<Disclosure>~...~     (trailing '~', no key-binding JWT here)
  * JWS header = {"alg":"EdDSA","typ":"dc+sd-jwt"}, Ed25519 over the JWS input.

Scope: the SD-JWT wire format, the SD-JWT VC header (`typ`) and the issuer signature. It is NOT an eIDAS-qualified
credential; the SD-JWT VC claims (`vct`, `status`, `cnf`) are not checked; issue() puts `vct` only if the caller passes
it in `plain_claims`; there is NO key binding (holder proof-of-possession): an SD-JWT+KB, which a wallet presents, is
refused as a whole (HAIP 1.0 §6.1.1.1: a KB-JWT MUST be present when an SD-JWT VC with holder binding is presented). Those
are separate layers. The digests
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

from ..ledger import loads_bounded
from ..signing import Identity, verify_signature

JWS_TYP = "dc+sd-jwt"
SD_ALG = "sha-256"
# 0.12.0: each JWS algorithm accepted here, bound to the one key type it verifies with. ES256 is ECDSA on P-256 with
# SHA-256 (RFC 7518 §3.4); "Ed25519" is the fully specified name and "EdDSA" the polymorphic one, deprecated by RFC 9864
# §2.2 and held here to Ed25519 only. Any other "alg" is refused (never "none", RFC 8725 §3.2).
ALG_KEY = {"ES256": "P-256", "Ed25519": "Ed25519", "EdDSA": "Ed25519"}
_ASCII_LOWER = {c: c + 32 for c in range(0x41, 0x5B)}


def _media_type(typ: str) -> str:
    """RFC 7515 §4.1.9: a media type compared without regard to ASCII case (only A-Z folded: str.lower would make
    U+212A KELVIN SIGN a 'k'), with "application/" implied when the value has no '/'"""
    t = typ.translate(_ASCII_LOWER)
    return t if "/" in t else "application/" + t


def check_jose_header(header: Any, expected_typ: str) -> Optional[str]:
    """The JOSE header of the issuer JWS: None when it holds, else the reason. `crit` is refused (RFC 7515 §4.1.11: no
    extension is understood here); `alg` a string of ALG_KEY; `typ` a string equal to `expected_typ` as RFC 7515 §4.1.9
    compares media types. The same checks, in the same order, as ap2-evidence-pack's check_jose_header (SPEC §13)."""
    if not isinstance(header, dict):
        return "header_not_object"
    if "crit" in header:
        return "crit_not_understood"
    if "alg" not in header:
        return "alg_missing"
    if not isinstance(header["alg"], str):
        return "alg_not_string"
    if header["alg"] not in ALG_KEY:
        return "alg_not_allowed"
    if "typ" not in header:
        return "typ_missing"
    if not isinstance(header["typ"], str):
        return "typ_not_string"
    if _media_type(header["typ"]) != _media_type(expected_typ):
        return "typ_mismatch"
    return None


class _NoBackend(Exception):
    pass


def _issuer_key(key: Any):
    """("Ed25519", standard-base64 raw key) or ("P-256", cryptography public key) or (other kind, None). `key` is the
    standard base64 of a raw Ed25519 key (as before 0.12.0), a PEM SubjectPublicKeyInfo, or a JWK (RFC 7517) of kty
    OKP/Ed25519 or EC/P-256. A JWK's `use` other than "sig", or `key_ops` without "verify", makes it unusable (RFC 7517
    §4.2, §4.3); its `alg`, when present, must be the header's (checked by the caller); other members are ignored, as
    RFC 7517 §4 says."""
    if isinstance(key, dict):
        kty, crv = key.get("kty"), key.get("crv")
        if ("use" in key and key["use"] != "sig") or ("key_ops" in key and (not isinstance(key["key_ops"], list)
                                                                            or "verify" not in key["key_ops"])):
            return "unusable", None
        if kty == "OKP" and crv == "Ed25519":
            x = _b64u_dec(key.get("x"))
            if len(x) != 32:
                raise ValueError("Ed25519 JWK: x is not 32 bytes")
            return "Ed25519", base64.b64encode(x).decode()
        if kty == "EC" and crv == "P-256":
            x, y = _b64u_dec(key.get("x")), _b64u_dec(key.get("y"))
            if len(x) != 32 or len(y) != 32:
                raise ValueError("P-256 JWK: x and y are 32 bytes each (RFC 7518 §6.2.1.2)")
            try:
                from cryptography.hazmat.primitives.asymmetric import ec
            except ImportError as e:
                raise _NoBackend from e
            pub = ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"),
                                                ec.SECP256R1()).public_key()   # ValueError when not on the curve
            return "P-256", pub
        return f"{kty}/{crv}", None
    if isinstance(key, str) and key.lstrip().startswith("-----BEGIN PUBLIC KEY-----"):
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import ec, ed25519
        except ImportError as e:
            raise _NoBackend from e
        pub = serialization.load_pem_public_key(key.encode("ascii"))
        if isinstance(pub, ed25519.Ed25519PublicKey):
            raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            return "Ed25519", base64.b64encode(raw).decode()
        if isinstance(pub, ec.EllipticCurvePublicKey):
            return ("P-256", pub) if pub.curve.name == "secp256r1" else (pub.curve.name, None)
        return type(pub).__name__, None
    if isinstance(key, str):
        return "Ed25519", key
    raise TypeError("issuer key: a base64 Ed25519 key, a PEM public key or a JWK")


def _es256_ok(pub, raw_sig: bytes, signing_input: bytes) -> bool:
    """RFC 7518 §3.4: the JWS signature is R || S, 32 bytes each"""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    if len(raw_sig) != 64:
        return False
    try:
        pub.verify(encode_dss_signature(int.from_bytes(raw_sig[:32], "big"), int.from_bytes(raw_sig[32:], "big")),
                   signing_input, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


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
        name = loads_bounded(_b64u_dec(d).decode("utf-8"))[1]
        if name in disclose:
            keep.append(d)
    return jws + "~" + "".join(d + "~" for d in keep)


def verify(sdjwt: str, issuer_public_key_b64: Any, now: Optional[float] = None,
           expected_typ: str = JWS_TYP) -> Dict[str, Any]:
    """Verify an SD-JWT per RFC 9901 §7.1 and return {verified, header, plain_claims, disclosed_claims,
    undisclosed_digests, processed_payload}. `verified` is True only if every step holds: the JOSE header
    (check_jose_header: no `crit`, `alg` ES256, Ed25519 or EdDSA, never "none"; `typ` equal to `expected_typ`, by default
    "dc+sd-jwt" of SD-JWT VC -27 §2.2.1, compared as RFC 7515 §4.1.9 says; since 0.12.0, before which only EdDSA was
    accepted and `typ` not read), the issuer key of the kind the algorithm names (ALG_KEY: a P-384 key under ES256 is
    refused; `issuer_public_key_b64` is the base64 of a raw Ed25519 key as before, a PEM public key or a JWK) and its
    signature, `_sd_alg` sha-256 (the default when absent, §4.1.1), every Disclosure of the right
    shape and referenced exactly once (recursively, in objects and array elements), no claim name `_sd` / `...` or one
    already present at that level, no digest seen twice, and `exp` / `nbf` when present (at `now`, default the clock).
    Format rules of §4.2.1 / §4.2.4.1 are enforced too: a salt is a string, an `_sd` key refers to an array of strings.
    Any failure rejects the whole SD-JWT, never just the Disclosure (§7.1: «If any step fails, the SD-JWT is not valid»).
    A malformed token is a verdict, never a traceback. Left to the caller or not implemented: Key Binding (§7.3) — an
    SD-JWT+KB (anything after the last '~') is rejected as a whole; that the key belongs to the Issuer (step 2.c), which
    is the caller's choice of `issuer_public_key_b64`; `aud` and which validity claims are required (step 6, §9.7);
    the SD-JWT VC claims (`vct`, `status`, `cnf`). Stricter than §7.1, and declared: the same Disclosure presented twice
    is a reject. ES256 needs the `cryptography` package: without it, an ES256 token is `verified: None` (not checked
    here), never False."""
    if not isinstance(expected_typ, str) or not expected_typ:
        raise ValueError("expected_typ: a non-empty string")
    try:
        return _verify(sdjwt, issuer_public_key_b64, now, expected_typ)
    except _Reject as e:
        return {"verified": False, "error": str(e), "disclosed_claims": {}}
    except _NoBackend:
        return {"verified": None, "error": "ES256 or a PEM key needs the cryptography package: not checked here",
                "disclosed_claims": {}}
    except (ValueError, TypeError, AttributeError, KeyError, RecursionError) as e:
        # a malformed token is a verdict, never a traceback (audit V2 #4, 30/09/2026)
        return {"verified": False, "error": f"malformed SD-JWT: {type(e).__name__}", "disclosed_claims": {}}


class _Reject(Exception):
    pass


def _loads(raw: bytes) -> Any:
    def _no_constant(c):   # NaN / Infinity are not JSON (RFC 8259); a signed `exp: NaN` would never expire (NEMESIS V2 Q4)
        raise ValueError(f"non-standard JSON constant {c}")
    return loads_bounded(raw.decode("utf-8"), parse_constant=_no_constant)


def _verify(sdjwt: str, issuer_public_key_b64: Any, now: Optional[float], expected_typ: str) -> Dict[str, Any]:
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
    why = check_jose_header(header, expected_typ)
    if why is not None:
        raise _Reject(f"JOSE header: {why} (step 2.a; SD-JWT VC -27 §2.2.1; RFC 7515 §4.1.9, §4.1.11)")
    alg = header["alg"]
    if isinstance(issuer_public_key_b64, dict) and "alg" in issuer_public_key_b64 and issuer_public_key_b64["alg"] != alg:
        raise _Reject(f"the issuer JWK is for alg {issuer_public_key_b64['alg']!r}, the header says {alg!r} (RFC 7517 §4.4)")
    kind, key = _issuer_key(issuer_public_key_b64)
    if kind != ALG_KEY[alg] or key is None:
        raise _Reject(f"alg {alg} verifies with a {ALG_KEY[alg]} key, not {kind} (RFC 7518 §3.4, RFC 9864)")
    signing_input = (h_b64 + "." + p_b64).encode("ascii")
    raw_sig = _b64u_dec(sig_b64)
    ok = _es256_ok(key, raw_sig, signing_input) if kind == "P-256" else \
        verify_signature(key, base64.b64encode(raw_sig).decode(), signing_input)
    if not ok:
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
            out = {}
            for k, v in node.items():      # a loop, not a comprehension: on Python < 3.12 a comprehension is a call of its
                if k != "_sd":             # own, two frames per level, and 498 object levels (inside the 512 bound) raised
                    out[k] = _process(v)   # RecursionError on 3.9/3.11 while 3.13/3.14 verified them (0.11.1 review)
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
