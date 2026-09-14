# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""
omega_evidence.interop.aat — Agent Audit Trail (IETF draft-sharif-agent-audit-trail-00) interop.

Why (2026-09-14): the field is converging on the REQUIREMENT (tamper-evident logs of what an AI agent did,
EU AI Act Art. 12 — application scheduled for 2 August 2026, with a deferral pending in the Digital Omnibus
package) but not yet on the RECORD. The first Internet-Draft that proposes a
record is "Agent Audit Trail: A Standard Logging Format for Autonomous AI Systems" (R. Sharif, 29 March
2026, expires 29 September 2026; individual draft, NOT an IETF standard; an IPR disclosure by the author is
on the IETF datatracker — reading/verifying the format is what this module does). This module lets an
`AgentEvidenceLog` ledger be EXPORTED as an AAT chain and lets an AAT chain (ours or foreign, with ES6-serialisable
numbers) be VERIFIED offline — so an
omega evidence pack can be read by tools that adopt that format, and AAT logs from elsewhere can be checked
with the same fail-closed discipline as ours.

What the draft fixes (transcribed): mandatory fields `record_id` (UUID v4), `timestamp` (RFC 3339 UTC),
`agent_id` (URI), `agent_version`, `session_id` (UUID v4), `action_type` in {tool_call, tool_response,
decision, delegation, escalation, error, lifecycle}, `action_detail` (object), `outcome` in {success,
failure, timeout, denied, escalated}, `trust_level` in {L0..L4}, `parent_record_id`, `prev_hash` =
hex(SHA-256(JCS(previous record, ALL fields))) with null at genesis; optional `signature` = ECDSA P-256 over
SHA-256(JCS(record without `signature`)), IEEE P1363 r||s, base64url. Lifecycle (§3, §6.1): ONE chain = ONE
session, and every session MUST begin with a genesis record `action_type = lifecycle`,
`action_detail.event = session_start`.

Honest scope: JCS (RFC 8785) is implemented for objects, arrays, strings, booleans, null and NUMBERS
serialised the ES6 way (integral doubles as integers, shortest round-trip mantissa, exponent without leading
zeros, 1e21 threshold), keys sorted by UTF-16 code units — so foreign AAT chains containing non-integer
numbers verify too; integers beyond 2^53 are refused on EXPORT (they would silently lose precision) and
serialised as doubles on VERIFY, as ES6 does.
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
_OUTCOME_MAP = {"executed": "success", "blocked": "denied", "pending_approval": "escalated",
                "success": "success", "failure": "failure", "timeout": "timeout", "denied": "denied", "escalated": "escalated"}


# ── JCS (RFC 8785), subset ───────────────────────────────────────────────────────────────────
def _es6_number(f: float) -> str:
    """ES6 Number::toString (ECMA-262 §6.1.6.1.20, as required by RFC 8785 §3.2.2.3): shortest round-trip
    digits (Python repr provides them), then ES6 placement rules — fixed notation for 1e-7 <= |x| < 1e21
    (e.g. 0.000001, 295147905179352830000), exponential outside ('1e+21', '1e-7'), '-0' → '0'.
    Checked against RFC 8785 Appendix B vectors in the tests (review of 2026-09-14 round 3)."""
    if f == 0:
        return "0"
    sign = "-" if f < 0 else ""
    r = repr(abs(f))                                   # shortest round-trip, e.g. '1e-07', '2.9514790517935283e+20', '0.1'
    if "e" in r:
        mant, exp = r.split("e")
        exp = int(exp)
    else:
        mant, exp = r, 0
    if "." in mant:
        ip, fp = mant.split(".")
    else:
        ip, fp = mant, ""
    fp = fp.rstrip("0") if fp != "0" else ""
    digits = (ip + fp).lstrip("0")
    # n = position of the decimal point relative to the digit string (ES6 "n")
    n = len(ip.lstrip("0")) + exp if ip.lstrip("0") else exp - (len(fp) - len(fp.lstrip("0")))
    if not ip.lstrip("0"):
        digits = fp.lstrip("0")
    digits = digits.rstrip("0") or "0"
    k = len(digits)
    if k <= n <= 21:
        out = digits + "0" * (n - k)
    elif 0 < n <= 21:
        out = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        out = (digits[0] + ("." + digits[1:] if k > 1 else "")) + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return sign + out


def jcs(obj: Any, strict: bool = True) -> bytes:
    """JSON Canonicalization Scheme (RFC 8785): keys sorted by UTF-16 code units, no whitespace, JSON.stringify
    string escapes, ES6 number serialisation. `strict=True` (export) refuses integers beyond 2^53; verification
    uses strict=False and serialises them as doubles, as ES6 would."""
    def enc(x: Any) -> str:
        if x is None:
            return "null"
        if x is True:
            return "true"
        if x is False:
            return "false"
        if isinstance(x, int):
            if abs(x) > 2 ** 53:
                if strict:
                    raise ValueError("JCS: integers beyond 2^53 lose precision in ES6 — refused on export")
                return _es6_number(float(x))
            return str(x)
        if isinstance(x, float):
            if x != x or x in (float("inf"), float("-inf")):
                raise ValueError("JCS: NaN/Infinity are not JSON")
            return _es6_number(x)
        if isinstance(x, str):
            return json.dumps(x, ensure_ascii=False)
        if isinstance(x, (list, tuple)):
            return "[" + ",".join(enc(i) for i in x) + "]"
        if isinstance(x, dict):
            keys = sorted(x.keys(), key=lambda k: k.encode("utf-16-be"))
            return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + enc(x[k]) for k in keys) + "}"
        raise TypeError(f"JCS: unsupported type {type(x).__name__}")
    return enc(obj).encode("utf-8")


def record_hash(rec: Dict[str, Any], strict: bool = True) -> str:
    """prev_hash of the NEXT record = hex(SHA-256(JCS(this record, all fields)))."""
    return hashlib.sha256(jcs(rec, strict=strict)).hexdigest()


_RFC3339 = __import__("re").compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$")
_URI = __import__("re").compile(r"^[A-Za-z][A-Za-z0-9+.\-]*:.+")


# ── export from an omega AgentEvidenceLog ledger ─────────────────────────────────────────────
def _rfc3339(ts: str) -> str:
    """Strict RFC 3339 (extended format with 'T', '-' and ':', numeric offset or 'Z'); output normalised to UTC
    with MILLISECOND precision (finer fractions are truncated — declared)."""
    t = str(ts)
    if not _RFC3339.match(t):
        raise ValueError(f"not RFC 3339 (extended format with offset required): {t!r} — an evidence export never invents a time")
    d = datetime.fromisoformat(t.replace("Z", "+00:00")).astimezone(timezone.utc)
    return d.strftime("%Y-%m-%dT%H:%M:%S.") + f"{d.microsecond // 1000:03d}Z"


def _uuid4_from(seed: str) -> str:
    """UUID with version 4 / RFC 4122 variant bits, derived DETERMINISTICALLY from a digest of `seed`:
    the draft asks for the v4 format; reproducibility asks for determinism. Both, declared."""
    b = bytearray(hashlib.sha256(seed.encode("utf-8")).digest()[:16])
    b[6] = (b[6] & 0x0F) | 0x40
    b[8] = (b[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(b)))


def from_omega(entries: List[Dict[str, Any]], agent_version: str, trust_level: str = "L0",
               session_ids: Optional[Dict[str, str]] = None, private_key_pem: Optional[bytes] = None) -> Dict[str, List[Dict[str, Any]]]:
    """Map omega `agent_governance_action` entries to an AAT chain. Every omega field that AAT has no
    slot for goes into `action_detail` (policy_rule, decision, resource, reason, attestation, record_sha3).
    `trust_level` is DECLARED by the caller (the draft's L0..L4 are about identity verification, which this
    ledger does not perform by itself). Identifiers: `record_id` = v4-format UUID derived from the omega
    `self_hash`, `session_id` = the omega session id if it is already a v4 UUID, else a v4-format UUID derived
    from it. Unknown action/outcome, missing agent id or unparsable timestamp → ValueError (never guessed).
    With `private_key_pem` every record is signed BEFORE the next prev_hash is computed (draft: hash over ALL fields).
    Returns {session_id: chain}: ONE chain per session (draft §3), each opened by a synthesised genesis record
    `lifecycle` / `action_detail.event = session_start` (draft §6.1) stamped with the first action's time and
    marked `synthesised_by: omega_evidence.interop.aat` — declared, not hidden."""
    if trust_level not in TRUST_LEVELS:
        raise ValueError(f"trust_level must be one of {TRUST_LEVELS}")
    chains: Dict[str, List[Dict[str, Any]]] = {}
    prevs: Dict[str, Dict[str, Any]] = {}
    sess = dict(session_ids or {})
    for k, v in sess.items():
        try:
            u = uuid.UUID(str(v))
        except ValueError:
            raise ValueError(f"session_ids[{k!r}] is not a UUID") from None
        if u.version != 4 or str(u) != str(v):
            raise ValueError(f"session_ids[{k!r}] must be a canonical UUID v4")
    for e in entries:
        if e.get("kind") != "agent_governance_action":
            continue
        sid = str(e.get("session_id", ""))
        try:
            u = uuid.UUID(sid)
            ok_v4 = u.version == 4 and str(u) == sid       # canonical 8-4-4-4-12 lowercase only
        except ValueError:
            ok_v4 = False
        if not ok_v4:
            sess.setdefault(sid, _uuid4_from(f"omega-session:{sid}"))
            sid = sess[sid]
        aid = e.get("agent_id")
        if not aid or not isinstance(aid, str):
            raise ValueError("omega record without agent_id: cannot export (never invented)")
        seed = e.get("self_hash") or e.get("record_sha3")
        if not seed:
            raise ValueError("omega record without self_hash/record_sha3: no stable identity, cannot export")
        if str(e.get("action")) not in _ACTION_MAP:
            raise ValueError(f"omega action {e.get('action')!r} has no AAT mapping: refused, not guessed")
        if str(e.get("outcome")) not in _OUTCOME_MAP:
            raise ValueError(f"omega outcome {e.get('outcome')!r} has no AAT mapping: refused, not guessed")
        rec: Dict[str, Any] = {
            "record_id": _uuid4_from(f"omega-record:{seed}"),
            "timestamp": _rfc3339(str(e.get("timestamp_utc", ""))),
            "agent_id": aid if _URI.match(aid) else f"urn:omega:agent:{aid}",
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
        }
        if sid not in chains:
            gen = {"record_id": _uuid4_from(f"omega-genesis:{sid}"), "timestamp": rec["timestamp"],
                   "agent_id": rec["agent_id"], "agent_version": agent_version, "session_id": sid,
                   "action_type": "lifecycle",
                   "action_detail": {"event": "session_start", "synthesised_by": "omega_evidence.interop.aat",
                                     "note": "omega ledgers have no explicit session start; genesis stamped with the first action's time"},
                   "outcome": "success", "trust_level": trust_level, "parent_record_id": None, "prev_hash": None}
            if private_key_pem is not None:
                gen = sign_record(gen, private_key_pem)
            chains[sid] = [gen]
            prevs[sid] = gen
        prev = prevs[sid]
        rec["parent_record_id"] = prev["record_id"]
        rec["prev_hash"] = record_hash(prev)
        if e.get("human_approver"):
            rec["human_override"] = {"operator_id": e["human_approver"], "reason": e.get("reason", ""),
                                     "original_action": e.get("action")}
        if private_key_pem is not None:
            rec = sign_record(rec, private_key_pem)      # BEFORE the next prev_hash: the hash covers all fields
        chains[sid].append(rec)
        prevs[sid] = rec
    return chains


# ── verification (offline, fail-closed) ──────────────────────────────────────────────────────
def verify_chain(records: List[Dict[str, Any]], pubkey_pem: Optional[bytes] = None) -> Dict[str, Any]:
    """Checks: mandatory fields present, enumerations, UUIDs, genesis nulls, `parent_record_id` and
    `prev_hash` linking (hash over ALL fields of the previous record, JCS), and — when `pubkey_pem` is given —
    every `signature` (ECDSA P-256, IEEE P1363 r||s, base64url) over SHA-256(JCS(record without signature)).
    A record without signature while a key is given is reported as unsigned (not valid)."""
    problems: List[Dict[str, Any]] = []
    prev: Optional[Dict[str, Any]] = None
    signed_ok = 0
    seen_ids: set = set()
    if not records:
        problems.append({"i": -1, "why": "empty chain: nothing to verify (not a valid audit trail)"})
    session0 = None
    last_ts = None
    for i, r in enumerate(records):
        if not isinstance(r, dict):
            problems.append({"i": i, "why": "record is not an object"}); continue      # prev is NOT reset (no genesis mid-chain)
        rid = str(r.get("record_id"))
        if rid in seen_ids:
            problems.append({"i": i, "why": "duplicate record_id"})
        seen_ids.add(rid)
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
                u = uuid.UUID(str(r.get(f)))
                if u.version != 4:
                    problems.append({"i": i, "why": f"{f} is not a UUID v4 (draft requires v4)"})
                elif str(u) != str(r.get(f)):
                    problems.append({"i": i, "why": f"{f} is not in canonical 8-4-4-4-12 lowercase form"})
            except ValueError:
                problems.append({"i": i, "why": f"{f} is not a UUID"})
        ts = str(r.get("timestamp", ""))
        if not _RFC3339.match(ts):
            problems.append({"i": i, "why": "timestamp is not RFC 3339 (extended format with offset)"})
        elif not (ts.endswith("Z") or ts.endswith("+00:00")):
            problems.append({"i": i, "why": "timestamp is not UTC (draft: UTC offset)"})
        else:
            d = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if last_ts is not None and d < last_ts:
                problems.append({"i": i, "why": "timestamp earlier than the previous record (not monotonic)"})
            last_ts = d
        if session0 is None:
            session0 = r.get("session_id")
        elif r.get("session_id") != session0:
            problems.append({"i": i, "why": "session_id differs: one chain must be one session (draft §3)"})
        if not _URI.match(str(r.get("agent_id", ""))):
            problems.append({"i": i, "why": "agent_id is not a URI (scheme:...)"})
        if i == 0:
            if r.get("parent_record_id") is not None or r.get("prev_hash") is not None:
                problems.append({"i": i, "why": "genesis record must have null parent_record_id and prev_hash"})
            if r.get("action_type") != "lifecycle" or (r.get("action_detail") or {}).get("event") != "session_start":
                problems.append({"i": i, "why": "genesis must be action_type=lifecycle with action_detail.event=session_start (draft §6.1)"})
        else:
            if prev is None:
                problems.append({"i": i, "why": "previous record unusable"})
            else:
                if r.get("parent_record_id") != prev.get("record_id"):
                    problems.append({"i": i, "why": "parent_record_id does not link to the previous record"})
                try:
                    exp = record_hash(prev, strict=False)      # foreign chains: ES6 numbers, never refused
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
            "scope": ("chain + vocabulary + lifecycle + optional ECDSA P-256 signatures, offline; does not prove the truth "
                      "of the actions, only that the sequence was not altered since the hashes were written. DECLARED "
                      "LIMIT: without signatures the LAST record can be altered undetected (nothing hashes it yet) and a "
                      "whole chain can be regenerated from scratch — signatures or an external anchor of the last hash "
                      "close that")}


# ── optional ECDSA P-256 signatures (needs `cryptography`) ───────────────────────────────────
def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64u_dec(s: str) -> bytes:
    if "=" in s or "+" in s or "/" in s:
        raise ValueError("base64url without padding required (RFC 4648 §5)")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _signing_input(rec: Dict[str, Any]) -> bytes:
    return hashlib.sha256(jcs({k: v for k, v in rec.items() if k != "signature"}, strict=False)).digest()


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
