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

Implemented to RFC 9901 to the letter (so a real EUDI verifier reads it):
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
import hashlib
import json
import secrets
from typing import Any, Dict, List, Optional

from ..signing import Identity, verify_signature

JWS_TYP = "dc+sd-jwt"
SD_ALG = "sha-256"


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _disclosure(salt: str, name: str, value: Any) -> str:
    payload = json.dumps([salt, name, value], separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    return _b64u(payload)


def _digest(disclosure: str) -> str:
    return _b64u(hashlib.sha256(disclosure.encode("ascii")).digest())


def _raw_sig(identity: Identity, signing_input: bytes) -> bytes:
    # Identity.sign returns standard-base64 of the raw Ed25519 signature
    return base64.b64decode(identity.sign(signing_input))


def issue(claims: Dict[str, Any], identity: Identity,
          plain_claims: Optional[Dict[str, Any]] = None) -> str:
    """Issue an SD-JWT. Every entry in `claims` is selectively disclosable; entries
    in `plain_claims` (e.g. iss, iat) travel in clear in the signed payload."""
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


def verify(sdjwt: str, issuer_public_key_b64: str) -> Dict[str, Any]:
    """Verify the issuer signature and bind each presented disclosure to the signed
    `_sd` set. Returns {verified, disclosed_claims, undisclosed_digests, header}.
    A disclosure whose digest is not in `_sd` is rejected (not returned)."""
    jws, disclosures = _split(sdjwt)
    try:
        h_b64, p_b64, sig_b64 = jws.split(".")
    except ValueError:
        return {"verified": False, "error": "malformed JWS", "disclosed_claims": {}}
    signing_input = (h_b64 + "." + p_b64).encode("ascii")
    raw_sig = _b64u_dec(sig_b64)
    verified = verify_signature(issuer_public_key_b64,
                                base64.b64encode(raw_sig).decode(), signing_input)
    header = json.loads(_b64u_dec(h_b64).decode("utf-8"))
    body = json.loads(_b64u_dec(p_b64).decode("utf-8"))
    sd_set = set(body.get("_sd", []))
    disclosed: Dict[str, Any] = {}
    for d in disclosures:
        if _digest(d) not in sd_set:        # digest must be in the signed _sd array
            continue
        salt, name, value = json.loads(_b64u_dec(d).decode("utf-8"))
        disclosed[name] = value
    presented_digests = {_digest(d) for d in disclosures}
    plain = {k: v for k, v in body.items() if k not in ("_sd", "_sd_alg")}
    return {"verified": verified, "header": header,
            "plain_claims": plain, "disclosed_claims": disclosed,
            "undisclosed_digests": sorted(sd_set - presented_digests)}
