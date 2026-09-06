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
    return base64.standard_b64decode(s.encode("ascii"))


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
    payload_type = envelope.get("payloadType", "")
    payload = _unb64(envelope["payload"])
    signed = pae(payload_type, payload)
    verified = False
    for s in envelope.get("signatures", []):
        pk = public_key_b64 or s.get("publicKeyB64", "")
        if public_key_b64 and s.get("publicKeyB64") and s["publicKeyB64"] != public_key_b64:
            continue
        if pk and verify_signature(pk, s.get("sig", ""), signed):
            verified = True
            break
    statement = json.loads(payload.decode("utf-8"))
    return {"verified": verified, "payload_type": payload_type,
            "statement": statement, "pack": statement.get("predicate")}
