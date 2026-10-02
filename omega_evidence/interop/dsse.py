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
omega_evidence.interop.dsse — export/import an OMEGA evidence pack as a DSSE
envelope wrapping an in-toto Statement v1, so it is verifiable by the wider
supply-chain ecosystem (cosign, slsa-verifier, in-toto) — not only by OMEGA's
own verifier.

Standards, implemented to the letter:
  * DSSE Pre-Authentication Encoding (PAE), secure-systems-lab/dsse v1.0.0:
        PAE(type, body) = "DSSEv1" SP len(type) SP type SP len(body) SP body
    ('DSSEv1' has NO internal space; the signature is over PAE, not the raw body).
  * in-toto Statement v1 (in-toto/attestation spec v1): _type
    "https://in-toto.io/Statement/v1", subject[].digest, predicateType, predicate.

The subject digest carries BOTH `sha256` (of the canonical pack — what cosign /
slsa-verifier match on) AND `sha3_256` (the pack's native pack_sha3), so the
envelope is matchable by mainstream tools while staying bound to OMEGA's hash.

Honest scope: this is a standards-correct wrapper — it does NOT turn the pack into
a SLSA provenance attestation or make any claim beyond what the pack already says;
the predicateType is OMEGA's own. Signature is Ed25519 (EdDSA) via signing.py.
"""

from __future__ import annotations

import base64
import binascii
import re
import json
from typing import Any, Dict, Optional

from ..canonical import canonical_json, sha256_bytes, sha3
from ..signing import Identity, verify_signature

PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://omega-evidence.org/pack/v1"


def _b64(data: bytes) -> str:
    return base64.standard_b64encode(data).decode("ascii")


def _unb64(s: str) -> bytes:
    """DSSE v1.0.0: «Either standard or URL-safe base64 encodings are allowed. Signers may use either, and verifiers
    MUST accept either.» One alphabet per string, padding only at the end, length a multiple of 4; no whitespace or
    stray characters (audit V2 #1/#2). Checked here, not left to base64.b64decode(validate=True), which tolerates
    excess padding on Python 3.9/3.11 but not on 3.13 (NEMESIS V2 P2, 01/10/2026). Raises ValueError otherwise."""
    if not isinstance(s, str) or len(s) % 4 or not (_STD.fullmatch(s) or _URL.fullmatch(s)):
        raise ValueError("not base64 (one alphabet, padding only at the end, length a multiple of 4)")
    return base64.b64decode(s.encode("ascii"), altchars=b"-_" if ("-" in s or "_" in s) else None, validate=True)


def _no_constant(c):
    raise ValueError(f"non-standard JSON constant {c}")


_STD = re.compile(r"[A-Za-z0-9+/]*={0,2}")
_URL = re.compile(r"[A-Za-z0-9_-]*={0,2}")


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding (v1.0.0). The bytes that get signed."""
    pt = payload_type.encode("utf-8")
    return (b"DSSEv1 " + str(len(pt)).encode() + b" " + pt + b" "
            + str(len(payload)).encode() + b" " + payload)


def build_statement(pack: Dict[str, Any], subject_name: Optional[str] = None) -> Dict[str, Any]:
    """Wrap an evidence pack as an in-toto Statement v1. The subject binds the
    pack by BOTH sha256 (of the canonical pack) and its native sha3_256."""
    canon = canonical_json(pack)
    name = subject_name or pack.get("kind", "omega-evidence-pack")
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": name, "digest": {
            "sha256": sha256_bytes(canon),         # what cosign/slsa-verifier match on
            "sha3_256": pack.get("pack_sha3") or sha3(pack)}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": pack,
    }


def to_dsse(pack: Dict[str, Any], identity: Identity,
            subject_name: Optional[str] = None) -> Dict[str, Any]:
    """Produce a signed DSSE envelope for the pack. The signature is Ed25519 over
    PAE(payloadType, statement) — the standard DSSE signing input."""
    statement = build_statement(pack, subject_name)
    payload = canonical_json(statement)
    sig_b64 = identity.sign(pae(PAYLOAD_TYPE, payload))
    return {
        "payload": _b64(payload),
        "payloadType": PAYLOAD_TYPE,
        "signatures": [{"keyid": identity.fingerprint,
                        "publicKeyB64": identity.public_key_b64,
                        "sig": sig_b64}],
    }


def from_dsse(envelope: Dict[str, Any],
              public_key_b64: Optional[str] = None) -> Dict[str, Any]:
    """Verify a DSSE envelope and return {verified, statement, pack}. Verifies the
    Ed25519 signature over PAE. If public_key_b64 is given it is required to match;
    otherwise the envelope's embedded publicKeyB64 is used (verifies integrity, not
    identity — trust the key via the OMEGA trust registry separately)."""
    def _fail(why):   # a malformed envelope is a verdict, never a traceback (audit V2 #5, 30/09/2026)
        return {"verified": False, "error": why, "payload_type": None, "statement": None, "pack": None}
    if not isinstance(envelope, dict):
        return _fail("envelope is not a JSON object")
    if "payloadType" not in envelope:   # envelope.md: payload and payloadType «are REQUIRED and MUST be set, even if empty» (NEMESIS V2 Q5)
        return _fail("payloadType missing")
    payload_type = envelope["payloadType"]
    if "signatures" not in envelope:    # envelope.md: «signatures» is REQUIRED too
        return _fail("signatures missing")
    sigs = envelope["signatures"]
    if not isinstance(payload_type, str) or not isinstance(sigs, list):
        return _fail("payloadType must be a string and signatures a list")
    if payload_type != PAYLOAD_TYPE:    # protocol.md: «Reject if PAYLOAD_TYPE is not a supported type»; only in-toto is read here
        return _fail(f"payloadType not supported (only {PAYLOAD_TYPE})")
    try:
        payload = _unb64(envelope["payload"])
    except (KeyError, ValueError, binascii.Error) as e:
        return _fail(f"payload missing or not base64: {type(e).__name__}")
    signed = pae(payload_type, payload)
    verified = False
    for s in sigs:
        if not isinstance(s, dict):
            continue
        pk = public_key_b64 or s.get("publicKeyB64", "")
        if public_key_b64 and s.get("publicKeyB64") and s["publicKeyB64"] != public_key_b64:
            continue
        try:
            raw_sig = _unb64(s.get("sig", ""))
        except (ValueError, binascii.Error):
            continue
        if pk and isinstance(pk, str) and verify_signature(pk, _b64(raw_sig), signed):
            verified = True
            break
    try:
        statement = json.loads(payload.decode("utf-8"), parse_constant=_no_constant)   # NaN/Infinity are not JSON (NEMESIS V2 Q4)
    except (ValueError, RecursionError) as e:
        # DSSE protocol.md: «Parse SERIALIZED_BODY according to PAYLOAD_TYPE. Reject if the parsing fails.» — a right
        # signature over an unparsable body is still a reject (NEMESIS V2 P1, 01/10/2026)
        return dict(_fail(f"payload could not be parsed as UTF-8 JSON: {type(e).__name__}"), payload_type=payload_type)
    if not isinstance(statement, dict):
        return dict(_fail("statement is not a JSON object"), payload_type=payload_type)
    return {"verified": verified, "payload_type": payload_type,
            "statement": statement, "pack": statement.get("predicate")}
