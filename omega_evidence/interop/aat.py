# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""
omega_evidence.interop.aat — Agent Audit Trail (IETF draft-sharif-agent-audit-trail-00) interop.

Why (2026-09-14): the field is converging on the REQUIREMENT (tamper-evident logs of what an AI agent did,
EU AI Act Art. 12 from 2 August 2026) but not yet on the RECORD. The first Internet-Draft that proposes a
record is "Agent Audit Trail: A Standard Logging Format for Autonomous AI Systems" (R. Sharif, 29 March
2026, expires 29 September 2026; individual draft, NOT an IETF standard). This module lets an
`AgentEvidenceLog` ledger be EXPORTED as an AAT chain and lets any AAT chain be VERIFIED offline — so an
omega evidence pack can be read by tools that adopt that format, and AAT logs from elsewhere can be checked
with the same fail-closed discipline as ours.

What the draft fixes (transcribed): mandatory fields `record_id` (UUID v4), `timestamp` (RFC 3339 UTC),
`agent_id` (URI), `agent_version`, `session_id` (UUID v4), `action_type` in {tool_call, tool_response,
decision, delegation, escalation, error, lifecycle}, `action_detail` (object), `outcome` in {success,
failure, timeout, denied, escalated}, `trust_level` in {L0..L4}, `parent_record_id`, `prev_hash` =
hex(SHA-256(JCS(previous record, ALL fields))) with null at genesis; optional `signature` = ECDSA P-256 over
SHA-256(JCS(record without `signature`)), IEEE P1363 r||s, base64url.

Honest scope: JCS (RFC 8785) is implemented for the subset AAT needs — objects, arrays, strings, integers
within ±2^53 (the IEEE 754 exactness bound RFC 8785 relies on), booleans, null; keys sorted by UTF-16 code
units; non-integral numbers and integers beyond 2^53 are refused (their ES6 serialisation is out of scope).
The mapping from omega records is lossy by design (policy_rule, decision, attestation travel in
`action_detail`) but never FABRICATES: an unknown omega action/outcome, a missing agent id or an unparsable
timestamp raise instead of being guessed (review of 2026-09-14). Identifiers are UUID v4-FORMAT values derived
deterministically from the omega digests, so the same ledger exports to the same chain (reproducible evidence);
`trust_level` is what the caller declares, never inferred. Signing happens INSIDE the export (each record is
signed before the next `prev_hash` is computed, as the draft hashes ALL fields). The draft may change or
expire: its version is pinned in `AAT_DRAFT`.
"""
from __future__ import annotations
import base64
import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

AAT_DRAFT = "draft-sharif-agent-audit-trail-00 (2026-03-29, expires 2026-09-29; individual Internet-Draft)"
ACTION_TYPES = ("tool_call", "tool_response", "decision", "delegation", "escalation", "error", "lifecycle")
OUTCOMES = ("success", "failure", "timeout", "denied", "escalated")
TRUST_LEVELS = ("L0", "L1", "L2", "L3", "L4")
MANDATORY = ("record_id", "timestamp", "agent_id", "agent_version", "session_id", "action_type",
             "action_detail", "outcome", "trust_level", "parent_record_id", "prev_hash")

# omega → AAT (lossy, declared)
_ACTION_MAP = {"tool_call": "tool_call", "tool_response": "tool_response", "decision": "decision",
               "delegation": "delegation", "escalation": "escalation", "error": "error", "lifecycle": "lifecycle",
               "file_write": "tool_call", "file_read": "tool_call", "command_exec": "tool_call", "network": "tool_call"}
_OUTCOME_MAP = {"executed": "success", "blocked": "denied", "pending_approval": "escalated"}


# ── JCS (RFC 8785), subset ───────────────────────────────────────────────────────────────────
def jcs(obj: Any) -> bytes:
    """JSON Canonicalization Scheme for the AAT subset: keys sorted by UTF-16 code units, no whitespace,
    strings with the JSON.stringify escapes, integers only (floats refused, NaN/Infinity refused)."""
    def enc(x: Any) -> str:
        if x is None:
            return "null"
        if x is True:
            return "true"
        if x is False:
            return "false"
        if isinstance(x, int):
            if abs(x) > 2 ** 53:
                raise ValueError("JCS subset: integers beyond 2^53 are not exactly representable (RFC 8785 relies on IEEE 754)")
            return str(x)
        if isinstance(x, float):
            if x != x or x in (float("inf"), float("-inf")) or not x.is_integer() or abs(x) > 2 ** 53:
                raise ValueError("JCS subset: only integral numbers within 2^53 are supported here")
            return str(int(x))
        if isinstance(x, str):
            return json.dumps(x, ensure_ascii=False)
        if isinstance(x, (list, tuple)):
            return "[" + ",".join(enc(i) for i in x) + "]"
        if isinstance(x, dict):
            keys = sorted(x.keys(), key=lambda k: k.encode("utf-16-be"))
            return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + enc(x[k]) for k in keys) + "}"
        raise TypeError(f"JCS: unsupported type {type(x).__name__}")
    return enc(obj).encode("utf-8")


def record_hash(rec: Dict[str, Any]) -> str:
    """prev_hash of the NEXT record = hex(SHA-256(JCS(this record, all fields)))."""
    return hashlib.sha256(jcs(rec)).hexdigest()


# ── export from an omega AgentEvidenceLog ledger ─────────────────────────────────────────────
def _rfc3339(ts: str) -> str:
    try:
        d = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(f"omega record has an unparsable timestamp_utc: {ts!r} — an evidence export never invents a time") from None
    if d.tzinfo is None:
        raise ValueError(f"omega record timestamp_utc lacks a UTC offset: {ts!r}")
    d = d.astimezone(timezone.utc)
    return d.strftime("%Y-%m-%dT%H:%M:%S.") + f"{d.microsecond // 1000:03d}Z"


def _uuid4_from(seed: str) -> str:
    """UUID with version 4 / RFC 4122 variant bits, derived DETERMINISTICALLY from a digest of `seed`:
    the draft asks for the v4 format; reproducibility asks for determinism. Both, declared."""
    b = bytearray(hashlib.sha256(seed.encode("utf-8")).digest()[:16])
    b[6] = (b[6] & 0x0F) | 0x40
    b[8] = (b[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(b)))


def from_omega(entries: List[Dict[str, Any]], agent_version: str, trust_level: str = "L0",
               session_ids: Optional[Dict[str, str]] = None, private_key_pem: Optional[bytes] = None) -> List[Dict[str, Any]]:
    """Map omega `agent_governance_action` entries to an AAT chain. Every omega field that AAT has no
    slot for goes into `action_detail` (policy_rule, decision, resource, reason, attestation, record_sha3).
    `trust_level` is DECLARED by the caller (the draft's L0..L4 are about identity verification, which this
    ledger does not perform by itself). Identifiers: `record_id` = v4-format UUID derived from the omega
    `self_hash`, `session_id` = the omega session id if it is already a v4 UUID, else a v4-format UUID derived
    from it. Unknown action/outcome, missing agent id or unparsable timestamp → ValueError (never guessed).
    With `private_key_pem` every record is signed BEFORE the next prev_hash is computed (draft: hash over ALL fields)."""
    if trust_level not in TRUST_LEVELS:
        raise ValueError(f"trust_level must be one of {TRUST_LEVELS}")
    out: List[Dict[str, Any]] = []
    prev: Optional[Dict[str, Any]] = None
    sess = dict(session_ids or {})
    for e in entries:
        if e.get("kind") != "agent_governance_action":
            continue
        sid = str(e.get("session_id", ""))
        try:
            ok_v4 = uuid.UUID(sid).version == 4
        except ValueError:
            ok_v4 = False
        if not ok_v4:
            sess.setdefault(sid, _uuid4_from(f"omega-session:{sid}"))
            sid = sess[sid]
        aid = e.get("agent_id")
        if not aid or not isinstance(aid, str):
            raise ValueError("omega record without agent_id: cannot export (never invented)")
        if str(e.get("action")) not in _ACTION_MAP:
            raise ValueError(f"omega action {e.get('action')!r} has no AAT mapping: refused, not guessed")
        if str(e.get("outcome")) not in _OUTCOME_MAP:
            raise ValueError(f"omega outcome {e.get('outcome')!r} has no AAT mapping: refused, not guessed")
        rec: Dict[str, Any] = {
            "record_id": _uuid4_from(f"omega-record:{e.get('self_hash') or e.get('record_sha3')}"),
            "timestamp": _rfc3339(str(e.get("timestamp_utc", ""))),
            "agent_id": aid if aid.startswith(("urn:", "http://", "https://", "did:")) else f"urn:omega:agent:{aid}",
            "agent_version": agent_version,
            "session_id": sid,
            "action_type": _ACTION_MAP[str(e.get("action"))],
            "action_detail": {"omega_action": e.get("action"), "resource": e.get("resource"),
                              "policy_rule": e.get("policy_rule"), "decision": e.get("decision"),
                              "reason": e.get("reason", ""), "record_sha3": e.get("record_sha3"),
                              "device_attestation": e.get("device_attestation"),
                              "omega_self_hash": e.get("self_hash")},
            "outcome": _OUTCOME_MAP[str(e.get("outcome"))],
            "trust_level": trust_level,
            "parent_record_id": prev["record_id"] if prev else None,
            "prev_hash": record_hash(prev) if prev else None,
        }
        if e.get("human_approver"):
            rec["human_override"] = {"operator_id": e["human_approver"], "reason": e.get("reason", ""),
                                     "original_action": e.get("action")}
        if private_key_pem is not None:
            rec = sign_record(rec, private_key_pem)      # BEFORE the next prev_hash: the hash covers all fields
        out.append(rec)
        prev = rec
    return out


# ── verification (offline, fail-closed) ──────────────────────────────────────────────────────
def verify_chain(records: List[Dict[str, Any]], pubkey_pem: Optional[bytes] = None) -> Dict[str, Any]:
    """Checks: mandatory fields present, enumerations, UUIDs, genesis nulls, `parent_record_id` and
    `prev_hash` linking (hash over ALL fields of the previous record, JCS), and — when `pubkey_pem` is given —
    every `signature` (ECDSA P-256, IEEE P1363 r||s, base64url) over SHA-256(JCS(record without signature)).
    A record without signature while a key is given is reported as unsigned (not valid)."""
    problems: List[Dict[str, Any]] = []
    prev: Optional[Dict[str, Any]] = None
    signed_ok = 0
    if not records:
        problems.append({"i": -1, "why": "empty chain: nothing to verify (not a valid audit trail)"})
    for i, r in enumerate(records):
        if not isinstance(r, dict):
            problems.append({"i": i, "why": "record is not an object"}); prev = None; continue
        for f in MANDATORY:
            if f not in r:
                problems.append({"i": i, "why": f"missing mandatory field {f}"})
        if r.get("action_type") not in ACTION_TYPES:
            problems.append({"i": i, "why": f"action_type not in vocabulary: {r.get('action_type')!r}"})
        if r.get("outcome") not in OUTCOMES:
            problems.append({"i": i, "why": f"outcome not in vocabulary: {r.get('outcome')!r}"})
        if r.get("trust_level") not in TRUST_LEVELS:
            problems.append({"i": i, "why": f"trust_level not in L0..L4: {r.get('trust_level')!r}"})
        if not isinstance(r.get("action_detail"), dict):
            problems.append({"i": i, "why": "action_detail is not an object"})
        for f in ("record_id", "session_id"):
            try:
                if uuid.UUID(str(r.get(f))).version != 4:
                    problems.append({"i": i, "why": f"{f} is not a UUID v4 (draft requires v4)"})
            except ValueError:
                problems.append({"i": i, "why": f"{f} is not a UUID"})
        try:
            _rfc3339(str(r.get("timestamp", "")))
        except ValueError:
            problems.append({"i": i, "why": "timestamp is not RFC 3339 with UTC offset"})
        if not str(r.get("agent_id", "")).startswith(("urn:", "http://", "https://", "did:")):
            problems.append({"i": i, "why": "agent_id is not a URI"})
        if i == 0:
            if r.get("parent_record_id") is not None or r.get("prev_hash") is not None:
                problems.append({"i": i, "why": "genesis record must have null parent_record_id and prev_hash"})
        else:
            if prev is None:
                problems.append({"i": i, "why": "previous record unusable"})
            else:
                if r.get("parent_record_id") != prev.get("record_id"):
                    problems.append({"i": i, "why": "parent_record_id does not link to the previous record"})
                try:
                    exp = record_hash(prev)
                except (ValueError, TypeError) as ex:
                    exp = None
                    problems.append({"i": i, "why": f"previous record not canonicalizable: {type(ex).__name__}"})
                if exp is not None and r.get("prev_hash") != exp:
                    problems.append({"i": i, "why": "prev_hash mismatch (previous record altered or reordered)"})
        if pubkey_pem is not None:
            if "signature" not in r:
                problems.append({"i": i, "why": "unsigned record while a verification key was given"})
            else:
                ok, why = verify_signature(r, pubkey_pem)
                if ok:
                    signed_ok += 1
                else:
                    problems.append({"i": i, "why": f"signature invalid: {why}"})
        prev = r
    return {"ok": not problems, "records": len(records), "problems": problems, "signatures_verified": signed_ok,
            "draft": AAT_DRAFT,
            "scope": ("chain + vocabulary + optional ECDSA P-256 signatures, offline; does not prove the truth of "
                      "the actions, only that the sequence was not altered since the hashes were written")}


# ── optional ECDSA P-256 signatures (needs `cryptography`) ───────────────────────────────────
def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64u_dec(s: str) -> bytes:
    if "=" in s or "+" in s or "/" in s:
        raise ValueError("base64url without padding required (RFC 4648 §5)")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _signing_input(rec: Dict[str, Any]) -> bytes:
    return hashlib.sha256(jcs({k: v for k, v in rec.items() if k != "signature"})).digest()


def sign_record(rec: Dict[str, Any], private_key_pem: bytes) -> Dict[str, Any]:
    """Adds `signature` (ECDSA P-256 over SHA-256(JCS(record without signature)), P1363 r||s, base64url).
    Requires `cryptography`. Sign BEFORE computing the next record's prev_hash (the hash covers all fields)."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, Prehashed
    sk = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(sk, ec.EllipticCurvePrivateKey) or sk.curve.name != "secp256r1":
        raise ValueError("AAT signatures require an ECDSA P-256 (secp256r1) key")
    der = sk.sign(_signing_input(rec), ec.ECDSA(Prehashed(hashes.SHA256())))
    r, s = decode_dss_signature(der)
    out = dict(rec)
    out["signature"] = _b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
    return out


def verify_signature(rec: Dict[str, Any], pubkey_pem: bytes) -> Tuple[bool, str]:
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, Prehashed
    except ImportError:
        return False, "cryptography not installed: signature NOT verified"
    try:
        pk = serialization.load_pem_public_key(pubkey_pem)
        raw = _b64u_dec(str(rec.get("signature", "")))
        if len(raw) != 64:
            return False, "signature is not 64 bytes (IEEE P1363 r||s)"
        der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
        pk.verify(der, _signing_input(rec), ec.ECDSA(Prehashed(hashes.SHA256())))
        return True, "ok"
    except Exception as ex:  # noqa: BLE001
        return False, type(ex).__name__


def generate_p256_keypair() -> Tuple[bytes, bytes]:
    """(private_pem, public_pem) — test/pilot helper; production keys belong in an HSM."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    sk = ec.generate_private_key(ec.SECP256R1())
    priv = sk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    pub = sk.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return priv, pub
