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
envelope wrapping an in-toto Statement v1, a format DSSE implementations other
than OMEGA's own verifier read, and verify DSSE envelopes made by others.

Direction of each claim (measured 18/11/2026): OUT — an envelope written by `to_dsse` (Ed25519) is verified by
securesystemslib 1.6.0, the in-toto project's DSSE implementation, and refused when altered; it was NOT run through
cosign or slsa-verifier, which are named below only for the digest they match on. IN —
`from_dsse` verifies Ed25519 and, since 0.12.0, ECDSA P-256 with SHA-256 (the signatures of GitHub artifact attestations
and of sigstore keyless signing), with a key the CALLER gives (an SPKI public key or an X.509 certificate, PEM or DER).
It checks the signature only: whose key it is (the certificate chain to Fulcio, the workflow identity, Rekor) is not
checked here — see interop.sigstore for what a sigstore bundle adds and what it still does not.

Standards, implemented to the letter:
  * DSSE Pre-Authentication Encoding (PAE), secure-systems-lab/dsse v1.0.2 (protocol.md, unchanged since v1.0.0):
        PAE(type, body) = "DSSEv1" SP len(type) SP type SP len(body) SP body
    ('DSSEv1' has NO internal space; the signature is over PAE, not the raw body).
  * in-toto Statement v1 (in-toto/attestation spec v1): _type
    "https://in-toto.io/Statement/v1", subject[].digest, predicateType, predicate.

The subject digest carries BOTH `sha256` (of the canonical pack — what cosign /
slsa-verifier match on) AND `sha3_256` (the pack's native pack_sha3), so the
envelope is matchable by mainstream tools while staying bound to OMEGA's hash.

Scope: this is a standards-correct wrapper — it does NOT turn the pack into
a SLSA provenance attestation or make any claim beyond what the pack already says;
the predicateType is OMEGA's own. `to_dsse` signs with Ed25519 (EdDSA) via signing.py.

ECDSA signature encoding: DSSE leaves it to the algorithm. Its own ECDSA P-256 test vector (protocol.md, v1.0.2) is the
raw concatenation r||s (64 bytes); sigstore and GitHub write ASN.1 DER (24/24 real envelopes, 18/11/2026). Both are
read: DER strictly (re-encoded byte for byte), r||s when the signature is exactly 64 bytes. Any other key — RSA, another
curve, ECDSA with another hash — is refused with its reason (closed: never a bare `verified: False`).
"""

from __future__ import annotations

import base64
import binascii
import re
import json
from typing import Any, Dict, Optional

from ..canonical import canonical_json, sha256_bytes, sha3
from ..ledger import _reject_dup, loads_bounded
from ..signing import Identity, verify_signature

_ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")   # RFC 8410 §4: SubjectPublicKeyInfo of an Ed25519 key
SUPPORTED_KEYS = "Ed25519, ECDSA P-256 with SHA-256"

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


def _crypto():
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec, ed25519
        return x509, serialization, ec, ed25519
    except ImportError:
        return None


def _key_from_object(k, source: str):
    c = _crypto()
    x509, serialization, ec, ed25519 = c
    if isinstance(k, ed25519.Ed25519PublicKey):
        raw = k.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return ("ed25519", _b64(raw), source)
    if isinstance(k, ec.EllipticCurvePublicKey):
        if k.curve.name != "secp256r1":
            raise ValueError(f"unsupported key: ECDSA on {k.curve.name} (supported: {SUPPORTED_KEYS})")
        return ("ecdsa-p256", k, source)
    raise ValueError(f"unsupported key: {type(k).__name__} (supported: {SUPPORTED_KEYS})")


def _key_from_der(der: bytes, source: str):
    if len(der) == 44 and der.startswith(_ED25519_SPKI_PREFIX):   # read without cryptography
        return ("ed25519", _b64(der[12:]), source + " (SPKI)")
    c = _crypto()
    if c is None:
        raise ValueError("this key needs the cryptography package, which is not installed: not checked")
    x509, serialization = c[0], c[1]
    try:
        return _key_from_object(serialization.load_der_public_key(der), source + " (SPKI)")
    except ValueError as e:
        if str(e).startswith("unsupported key"):
            raise
    except Exception:  # noqa: BLE001 - not an SPKI: try a certificate below
        pass
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:  # noqa: BLE001
        raise ValueError("key is neither a DER SubjectPublicKeyInfo nor a DER X.509 certificate") from None
    return _key_from_object(cert.public_key(), source + " (X.509 certificate; its chain and identity are NOT checked)")


def load_public_key(public_key=None, public_key_b64: Optional[str] = None):
    """(kind, key, source) for from_dsse: kind "ed25519" (key = base64 of the 32 raw bytes) or "ecdsa-p256" (key = a
    cryptography public key). `public_key`: PEM text or bytes holding exactly one PUBLIC KEY (SPKI) or CERTIFICATE block,
    or DER bytes of either. `public_key_b64`: base64 of a raw 32-byte Ed25519 key (as before 0.12.0) or of a DER SPKI or
    certificate. Raises ValueError with the reason for anything else."""
    if public_key is not None and public_key_b64 is not None:
        raise ValueError("give public_key or public_key_b64, not both")
    if public_key_b64 is not None:
        if not isinstance(public_key_b64, str) or not public_key_b64:
            raise ValueError("public_key_b64 must be a non-empty base64 string")
        try:
            raw = _unb64(public_key_b64)
        except (ValueError, binascii.Error):
            raise ValueError("public_key_b64 is not base64") from None
        if len(raw) == 32:
            return ("ed25519", _b64(raw), "caller public_key_b64 (raw Ed25519)")
        return _key_from_der(raw, "caller public_key_b64")
    if isinstance(public_key, str):
        if "-----BEGIN" not in public_key:
            raise ValueError("public_key as text must be PEM (a PUBLIC KEY or CERTIFICATE block)")
        try:
            public_key = public_key.encode("ascii")
        except UnicodeEncodeError:
            raise ValueError("public_key PEM is not ASCII") from None
    if not isinstance(public_key, (bytes, bytearray)) or not public_key:
        raise ValueError("public_key must be PEM text or PEM/DER bytes")
    data = bytes(public_key)
    if b"-----BEGIN" not in data:
        return _key_from_der(data, "caller public_key")
    blocks = re.findall(rb"-----BEGIN ([A-Z0-9 ]+)-----\r?\n([A-Za-z0-9+/=\r\n]+?)-----END \1-----", data)
    if len(blocks) != 1 or data.count(b"-----BEGIN") != 1:
        raise ValueError("public_key PEM must hold exactly one block")
    label, body = blocks[0]
    if label not in (b"PUBLIC KEY", b"CERTIFICATE"):
        raise ValueError(f"public_key PEM block {label.decode()!r} is not PUBLIC KEY or CERTIFICATE")
    try:
        der = base64.b64decode(b"".join(body.split()), validate=True)
    except (ValueError, binascii.Error):
        raise ValueError("public_key PEM body is not base64") from None
    return _key_from_der(der, "caller public_key")


def _ecdsa_verify(key, sig: bytes, message: bytes) -> bool:
    """ECDSA P-256 / SHA-256 over `message`; the signature as strict DER or as raw r||s (64 bytes)."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
    candidates = []
    if sig[:1] == b"\x30":
        try:
            r, s_ = decode_dss_signature(sig)
            if encode_dss_signature(r, s_) == sig:   # strict DER: no BER lengths, no extra bytes
                candidates.append(sig)
        except ValueError:
            pass
    if len(sig) == 64:
        candidates.append(encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")))
    for c in candidates:
        try:
            key.verify(c, message, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            continue
    return False


def from_dsse(envelope: Dict[str, Any],
              public_key_b64: Optional[str] = None, public_key=None) -> Dict[str, Any]:
    """Verify a DSSE envelope and return {verified, error, key_source, payload_type, statement, pack}.

    The signature is checked over PAE with the CALLER's key — `public_key` (PEM/DER SPKI or X.509 certificate; 0.12.0)
    or `public_key_b64` (raw Ed25519 as before, or base64 DER) — Ed25519 or ECDSA P-256/SHA-256. Without a caller key,
    a signature carrying `publicKeyB64` (as `to_dsse` writes) is checked with that embedded key: integrity, not identity
    (trust the key through the OMEGA trust registry). `verified` is True only when one signature verifies; every other
    answer carries `error` with the reason: no key, an unsupported key, a key that needs `cryptography` where it is not
    installed, or no signature that verifies (0.12.0; until 0.11.4 an ECDSA envelope — valid or tampered — gave
    `verified: False` with no error). The payload is a Statement v1 or the envelope is refused: a `_type` other than
    `https://in-toto.io/Statement/v1` (in-toto docs/validation.md) or a member name twice in one object is `verified:
    False` with the reason; `pack` is the predicate only when `predicateType` is OMEGA's (PREDICATE_TYPE), else None —
    `statement` carries the rest (20/11/2026; until 0.13.0 none of the three was read)."""
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
    # envelope.md v1.0.2, Parsing rules: "Consumers MUST ignore unrecognized fields" — ignored as the rule says, and
    # named in the result (0.12.0) so that a caller sees them
    unrecognized = sorted(k for k in envelope if k not in ("payload", "payloadType", "signatures"))
    unrecognized += sorted(f"signatures[{n}].{k}" for n, s in enumerate(sigs) if isinstance(s, dict)
                           for k in s if k not in ("sig", "keyid", "publicKeyB64"))
    caller_key = None
    key_error = None
    if public_key is not None or public_key_b64 is not None:
        try:
            caller_key = load_public_key(public_key, public_key_b64)
        except ValueError as e:
            key_error = str(e)
    verified, key_source, reasons = False, None, []
    if not sigs:
        reasons.append("the envelope has no signature")
    for n, s in enumerate(sigs):
        if not isinstance(s, dict):
            reasons.append(f"signature {n}: not a JSON object")
            continue
        embedded = s.get("publicKeyB64")
        if caller_key is None and key_error is None:
            if not embedded:
                reasons.append(f"signature {n}: no verification key (no publicKeyB64 in the envelope and no public_key "
                           "given; a sigstore bundle's key is its certificate: interop.sigstore.verify_bundle)")
                continue
            try:
                key = load_public_key(public_key_b64=embedded)
                key = (key[0], key[1], "envelope publicKeyB64 (integrity, not identity)")
            except ValueError as e:
                reasons.append(f"signature {n}: publicKeyB64: {e}")
                continue
        elif key_error is not None:
            reasons.append(key_error)
            break
        else:
            key = caller_key
            if public_key_b64 and embedded and embedded != public_key_b64:
                reasons.append(f"signature {n}: its publicKeyB64 is not the key given")
                continue
        try:
            raw_sig = _unb64(s.get("sig", ""))
        except (ValueError, binascii.Error):
            reasons.append(f"signature {n}: sig missing or not base64")
            continue
        kind, k, src = key
        if kind == "ed25519":
            ok = verify_signature(k, _b64(raw_sig), signed)
        else:
            ok = _ecdsa_verify(k, raw_sig, signed)
        if ok:
            verified, key_source = True, src
            break
        reasons.append(f"signature {n}: does not verify with the key ({kind}, {src})")
    try:
        # NaN/Infinity are not JSON (NEMESIS V2 Q4); a member name twice in one object is refused (20/11/2026: the last
        # one won here, so a signed statement could read differently to another parser — RFC 8259 §4: with names that
        # are not unique "the behavior of software that receives such an object is unpredictable")
        statement = loads_bounded(payload.decode("utf-8"), parse_constant=_no_constant, object_pairs_hook=_reject_dup)
    except (ValueError, RecursionError) as e:
        # DSSE protocol.md: «Parse SERIALIZED_BODY according to PAYLOAD_TYPE. Reject if the parsing fails.» — a right
        # signature over an unparsable body is still a reject (NEMESIS V2 P1, 01/10/2026)
        why = ("nesting exceeds 512" if str(e).startswith("json_too_deep") else
               "a member name appears twice in one object" if str(e).startswith("duplicate") else type(e).__name__)
        return dict(_fail(f"payload could not be parsed as UTF-8 JSON: {why}"), payload_type=payload_type)
    if not isinstance(statement, dict):
        return dict(_fail("statement is not a JSON object"), payload_type=payload_type)
    if statement.get("_type") != STATEMENT_TYPE:
        # in-toto attestation docs/validation.md, Statement layer: «Reject if statement.type != https://in-toto.io/Statement/v1»
        # (20/11/2026: any _type, or none, was read as a Statement v1)
        return dict(_fail(f"statement _type is not {STATEMENT_TYPE}: {str(statement.get('_type'))[:80]!r}"),
                    payload_type=payload_type)
    # `pack` is the predicate only when the predicateType is OMEGA's (20/11/2026: the predicate of any attestation — an
    # SLSA provenance, a statement of another kind — was handed back as `pack`); the statement is returned as before
    pack = statement.get("predicate") if statement.get("predicateType") == PREDICATE_TYPE else None
    out = {"verified": verified, "payload_type": payload_type, "key_source": key_source,
           "statement": statement, "pack": pack}
    if unrecognized:
        out["unrecognized_fields"] = unrecognized[:50]
    if not verified:
        out["error"] = "; ".join(reasons)[:600] or "no signature verifies"
    return out
