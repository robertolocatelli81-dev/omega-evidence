# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""
omega_evidence.interop.aat — Agent Audit Trail (IETF draft-sharif-agent-audit-trail-04) interop.

Why (2026-09-14, brought to -04 on 2026-09-19): the field is converging on the REQUIREMENT (tamper-evident logs
of what an AI agent did, EU AI Act Art. 12) but not yet on the RECORD. The Internet-Draft that proposes one is
"Agent Audit Trail: A Standard Logging Format for Autonomous AI Systems" (R. Sharif; -00 of 29 March 2026,
-04 of 15 September 2026, expires 19 March 2027; individual draft, NOT an IETF standard; an IPR disclosure by
the author is on the IETF datatracker — reading, writing and verifying the format is what this module does).
This module EXPORTS an `AgentEvidenceLog` ledger as AAT chains and VERIFIES an AAT chain (ours or foreign)
offline, fail-closed.

What -04 fixes and this module implements (transcribed from the draft, section numbers are the draft's):
  §3.1 mandatory fields incl. `record_phase` (pre_execution | post_execution | concurrent; mandatory since -01);
  §3.2 optional fields: `signature` + `sig_alg` (ES256 default, ML-DSA-65) + `signer_kid` (RFC 7638 JWK
       thumbprint — for ML-DSA-65 the AKP thumbprint of draft-ietf-cose-dilithium-11 §6 over {alg, kty, pub}),
       hybrid `signature_classical` + `signer_kid_classical`, `nonce`, `deny_reasons`, `external_timestamp`
       (RFC 3161), `content_fingerprint`, `recording_component`, `trust_assignment`, detached `batch`;
  §3.3 size bounds (64 KB SHOULD, 256 KB MUST), reserved `aat_` prefix in action_detail;
  §4.2 phase rules (decision/denied, decision/escalated, delegation/denied MUST be pre_execution);
  §5   recording independence (self vs independent; the recorder's key MUST differ from the agent's);
  §5.3 fail-safe trust level for consequential actions (delegation is explicit; tool_call/decision through a
       caller-supplied predicate — the draft's "payment, deletion, deployment, egress" are semantics of the
       action_detail this verifier cannot know by itself);
  §6.1 prev_hash = hex(SHA-256(JCS(previous record without `batch`))); §6.2 signed message =
       SHA-256(JCS(record without signature-value fields and `batch`)), ES256 as IEEE P1363 r||s, ML-DSA-65 raw
       (FIPS 204, empty context — the draft names no context; draft-ietf-cose-dilithium says it MUST be empty);
  §6.3 chain verification incl. nonce uniqueness (enforced, the draft says MAY/MUST for untrusted sources);
  §6.4 Merkle batch anchoring with the RFC 6962 construction (leaf 0x00, node 0x01) and audit paths;
  §7   per-action_type REQUIRED action_detail fields; §8 genesis / ordered chain / session close with
       `session_hash`; §9.3 tombstones with `tombstone_hash`; §10.1 JSONL and §10.3 CSV (lossy, declared);
  §13  `reproducibility_class` = "reproducible" only with a closed attestation (weights, tokenizer, chat
       template, engine build digested; inference_config; environment; sealed input).

Declared choices where the draft is silent or ambiguous (each is also reported to the author):
  * §13 field placement: accepted at the record top level or inside action_detail.
  * `external_timestamp` on a record: the token's messageImprint is checked against
    SHA-256(JCS(record without external_timestamp, signature-value fields and batch)) — the draft does not say
    what the token covers; a token whose imprint is something else is a problem. A token over an epoch root cannot
    be carried inside a record of that epoch (it would change the record's leaf hash): such tokens live in the epoch
    anchor and are checked by `verify_epochs`.
  * Epoch anchors: the draft says the RFC 3161 token over an epoch root "MAY be carried in the epoch's genesis
    record" — but every field except `batch` is inside the chain hash, so a token computed after the epoch is
    built cannot be inserted into an already-chained record without breaking prev_hash. Epoch anchors are
    therefore kept in a separate epoch record ({epoch_id, merkle_root, leaf_count, tsa}) that
    `verify_epochs` checks.
  * Merkle trees: the draft's "promote the odd last node" wording is applied as RFC 6962's MTH (split at the
    largest power of two below n); the two coincide (tested against cryptovalid's RFC 6962 implementation).
  * A hybrid record whose `signature_classical` fails is a problem (the record claims hybrid, the claim is
    false), although the draft only says a verifier MAY check it.
  * Records of -00 (no `record_phase`) are refused with an explicit reason: re-export them.

Honest scope: JCS (RFC 8785) is implemented for objects, arrays, strings, booleans, null and NUMBERS serialised
the ES6 way; integers beyond 2^53 are refused on EXPORT and serialised as doubles on VERIFY, as ES6 does. The
mapping from omega records is lossy by design but never FABRICATES: an unknown omega action/outcome, a missing
agent id, an unparsable timestamp, or an omega action whose §7 REQUIRED detail fields cannot be derived raise
instead of being guessed. Identifiers are UUID v4-FORMAT values derived deterministically from the omega
digests (RFC 9562 reserves v4 for random generation; determinism is what makes the export reproducible — both
stated). `trust_level` is what the caller declares. Signing happens INSIDE the export. The chain verifier does
not prove the truth of the actions, only that the sequence was not altered since the hashes were written; the
LAST record of an unsigned, unanchored chain can be altered undetected. The draft may change: `AAT_DRAFT`.
"""
from __future__ import annotations
import base64
import hashlib
import json
import uuid
from datetime import datetime, timezone
import csv
import io
import re
from typing import Any, Callable, Dict, List, Optional, Tuple


AAT_DRAFT = "draft-sharif-agent-audit-trail-04 (2026-09-15, expires 2027-03-19; individual Internet-Draft)"
ACTION_TYPES = ("tool_call", "tool_response", "decision", "delegation", "escalation", "error", "lifecycle")
OUTCOMES = ("success", "failure", "timeout", "denied", "escalated")
TRUST_LEVELS = ("L0", "L1", "L2", "L3", "L4")
RECORD_PHASES = ("pre_execution", "post_execution", "concurrent")
SIG_ALGS = ("ES256", "ML-DSA-65")
MANDATORY = ("record_id", "timestamp", "agent_id", "agent_version", "session_id", "action_type",
             "action_detail", "outcome", "trust_level", "parent_record_id", "prev_hash", "record_phase")
DENY_REASONS = ("INSUFFICIENT_TRUST_LEVEL", "CAPABILITY_NOT_GRANTED", "REPLAY_DETECTED", "NONCE_REUSED",
                "TIMESTAMP_STALE", "AGENT_REVOKED", "SANCTIONS_HIT", "SEQUENCE_VIOLATION", "ACTION_UNKNOWN")
LIFECYCLE_EVENTS = ("session_start", "session_end", "pause", "resume", "configuration_change", "key_rotation",
                    "trust_level_change", "record_deleted")
ERROR_CATEGORIES = ("transport", "authentication", "authorization", "validation", "timeout", "internal", "external")
ESCALATION_URGENCY = ("low", "medium", "high", "critical")
REPRODUCIBILITY_CLASSES = ("reproducible", "reconstructable")
# §7: REQUIRED action_detail fields per action_type, with the JSON type the draft gives them
DETAIL_REQUIRED: Dict[str, Tuple[Tuple[str, type], ...]] = {
    "tool_call": (("tool_name", str), ("parameters_hash", str)),
    "tool_response": (("tool_name", str), ("response_hash", str), ("parent_call_id", str)),
    "decision": (("decision_type", str),),
    "delegation": (("delegate_agent_id", str), ("delegate_trust_level", str), ("task_description_hash", str)),
    "escalation": (("escalation_reason", str), ("escalation_target", str)),
    "error": (("error_code", str), ("error_message", str), ("error_category", str), ("recoverable", bool)),
    "lifecycle": (("event", str),),
}
# §4.2: (action_type, outcome) combinations whose record_phase MUST be pre_execution
PRE_EXECUTION_REQUIRED = (("decision", "denied"), ("decision", "escalated"), ("delegation", "denied"))
CLOSURE_DIGESTS = ("model_weights_digest", "tokenizer_digest", "chat_template_digest", "engine_build_digest")
SIGNATURE_VALUE_FIELDS = ("signature", "signature_classical")
RECORD_SHOULD_BYTES = 64 * 1024
RECORD_MAX_BYTES = 256 * 1024
_SESSION_HASH_NOTE = "hex(SHA-256(prev_hash(1) || ... || prev_hash(N))) over the raw 32-byte digests, N = the close record"

# omega → AAT (lossy, declared)
_ACTION_MAP = {"tool_call": "tool_call", "decision": "decision",                       # the two whose §7 fields are derivable
               "file_write": "tool_call", "file_read": "tool_call", "command_exec": "tool_call", "network": "tool_call"}
_OUTCOME_MAP = {"executed": "success", "blocked": "denied", "pending_approval": "escalated"}   # the three the runtime writes
# §4.1: record_phase is DERIVED from the omega outcome (blocked / pending_approval = an enforcement decision, executed = a
# completed action). AgentEvidenceLog records what the caller reports and gates nothing: the phase is the caller's
# discipline, and the exporter says so in every action_detail.
_PHASE_MAP = {"blocked": "pre_execution", "pending_approval": "pre_execution", "executed": "post_execution"}


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


JCS_MAX_DEPTH = 512


def jcs(obj: Any, strict: bool = True) -> bytes:
    """JSON Canonicalization Scheme (RFC 8785): keys sorted by UTF-16 code units, no whitespace, JSON.stringify
    string escapes, ES6 number serialisation. `strict=True` (export) refuses integers beyond 2^53; verification
    uses strict=False and serialises them as doubles, as ES6 would. Nesting deeper than JCS_MAX_DEPTH (512, the
    acceptance profile shared with the pack verifiers) is refused with ValueError, never a RecursionError."""
    def enc(x: Any, depth: int = 0) -> str:
        if depth > JCS_MAX_DEPTH:
            raise ValueError("JCS: nesting deeper than 512 refused")
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
                try:
                    return _es6_number(float(x))
                except OverflowError:
                    raise ValueError("JCS: integer beyond the double range (ES6 would give Infinity, which JCS forbids)") from None
            return str(x)
        if isinstance(x, float):
            if x != x or x in (float("inf"), float("-inf")):
                raise ValueError("JCS: NaN/Infinity are not JSON")
            return _es6_number(x)
        if isinstance(x, str):
            return json.dumps(x, ensure_ascii=False)
        if isinstance(x, (list, tuple)):
            parts = []
            for i in x:                                   # a loop, not a generator: one frame per nesting level
                parts.append(enc(i, depth + 1))
            return "[" + ",".join(parts) + "]"
        if isinstance(x, dict):
            if not all(isinstance(k, str) for k in x):
                raise TypeError("JCS: object keys must be strings")
            keys = sorted(x.keys(), key=lambda k: k.encode("utf-16-be"))
            parts = []
            for k in keys:
                parts.append(json.dumps(k, ensure_ascii=False) + ":" + enc(x[k], depth + 1))
            return "{" + ",".join(parts) + "}"
        raise TypeError(f"JCS: unsupported type {type(x).__name__}")
    try:
        return enc(obj).encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("JCS: lone surrogate is not encodable as UTF-8") from None



def _no_batch(rec: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in rec.items() if k != "batch"}


def record_hash(rec: Dict[str, Any], strict: bool = True) -> str:
    """prev_hash of the NEXT record = hex(SHA-256(JCS(this record, all fields, the detached `batch` removed)))."""
    return hashlib.sha256(jcs(_no_batch(rec), strict=strict)).hexdigest()


def leaf_hash(rec: Dict[str, Any], strict: bool = False) -> bytes:
    """§6.4: SHA-256(0x00 || JCS(record without batch))."""
    return hashlib.sha256(b"\x00" + jcs(_no_batch(rec), strict=strict)).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_root(leaves: List[bytes]) -> bytes:
    """RFC 6962 §2.1 MTH (split at the largest power of two < n); one leaf = its own hash; no leaves = SHA-256('')."""
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return leaves[0]
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    return _node(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def audit_path(leaves: List[bytes], index: int) -> List[Dict[str, str]]:
    """RFC 6962 §2.1.1 PATH(m, D[n]) as the draft's ordered [{hash, side}] list (side = where the SIBLING sits)."""
    if not 0 <= index < len(leaves):
        raise ValueError("leaf index out of range")
    if len(leaves) == 1:
        return []
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    if index < k:
        return audit_path(leaves[:k], index) + [{"hash": merkle_root(leaves[k:]).hex(), "side": "right"}]
    return audit_path(leaves[k:], index - k) + [{"hash": merkle_root(leaves[:k]).hex(), "side": "left"}]


def merkle_levels(leaves: List[bytes]) -> List[List[bytes]]:
    """Bottom-up levels of the RFC 6962 tree (an unpaired last node is promoted unchanged, which gives the same
    tree as the recursive MTH — tested): levels[0] = leaves, levels[-1] = [root]. O(n) hashes."""
    if not leaves:
        return [[hashlib.sha256(b"").digest()]]
    levels = [list(leaves)]
    while len(levels[-1]) > 1:
        cur = levels[-1]
        levels.append([_node(cur[j], cur[j + 1]) if j + 1 < len(cur) else cur[j] for j in range(0, len(cur), 2)])
    return levels


def audit_paths(leaves: List[bytes]) -> List[List[Dict[str, str]]]:
    """Every leaf's audit path from one bottom-up tree build: O(n log n) in total instead of O(n²) (review round 4).
    Identical to audit_path(leaves, i) for each i (tested for n = 1..64)."""
    levels = merkle_levels(leaves)
    out: List[List[Dict[str, str]]] = []
    for i in range(len(leaves)):
        path: List[Dict[str, str]] = []
        pos = i
        for lvl in levels[:-1]:
            sib = pos ^ 1
            if sib < len(lvl):                       # an unpaired node was promoted: no sibling, no step
                path.append({"hash": lvl[sib].hex(), "side": "left" if sib < pos else "right"})
            pos //= 2
        out.append(path)
    return out


def index_from_path(path: List[Dict[str, Any]], n: int) -> int:
    """The leaf index an RFC 6962 audit path of a tree with n leaves proves (descending from the root: the last
    step says whether the leaf is in the left [0, k) or right [k, n) subtree, k = largest power of two < n)."""
    lo, size = 0, n
    for step in reversed(path):
        if size <= 1:
            raise ValueError("audit path longer than the tree depth")
        k = 1
        while k * 2 < size:
            k *= 2
        if step["side"] == "right":
            size = k
        else:
            lo, size = lo + k, size - k
    if size != 1:
        raise ValueError("audit path shorter than the tree depth")
    return lo


def root_from_path(leaf: bytes, path: List[Dict[str, Any]]) -> bytes:
    h = leaf
    for step in path:
        sib = bytes.fromhex(step["hash"])
        h = _node(sib, h) if step["side"] == "left" else _node(h, sib)
    return h


# `$` would accept a trailing newline: every format check uses fullmatch semantics (\Z)
_RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})\Z")
_URI = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*:[^\s]+\Z")      # RFC 3986: no whitespace
_HEX64 = re.compile(r"^[0-9a-f]{64}\Z")
_NONCE = re.compile(r"^[0-9a-f]{32,}\Z")
_SHA256_PREFIXED = re.compile(r"^sha256:[0-9a-f]{64}\Z")
_B64U = re.compile(r"^[A-Za-z0-9_\-]+\Z")
_ISO2 = re.compile(r"^[A-Z]{2}\Z")
_B64_STD = re.compile(r"^[A-Za-z0-9+/]+={0,2}\Z")


def _hex64(v: Any) -> bool:
    return isinstance(v, str) and bool(_HEX64.match(v))


def _num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _uuid4_ok(v: Any) -> bool:
    try:
        u = uuid.UUID(str(v))
        return isinstance(v, str) and u.version == 4 and str(u) == v
    except ValueError:
        return False


# ── export from an omega AgentEvidenceLog ledger ─────────────────────────────────────────────
def _rfc3339(ts: str) -> str:
    """Strict RFC 3339 (extended format with 'T', '-' and ':', numeric offset or 'Z'); output normalised to UTC
    with MILLISECOND precision (finer fractions are truncated — declared)."""
    t = str(ts)
    if not _RFC3339.match(t):
        raise ValueError(f"not RFC 3339 (extended format with offset required): {t!r} — an evidence export never invents a time")
    if t[17:19] == "60":
        raise ValueError(f"leap second {t!r} cannot be exported without moving the instant: refused")
    try:
        d = _parse_ts(t).astimezone(timezone.utc)
    except (OverflowError, ValueError):
        raise ValueError(f"not a representable instant: {t!r}") from None
    return f"{d.year:04d}-" + d.strftime("%m-%dT%H:%M:%S.") + f"{d.microsecond // 1000:03d}Z"


def _parse_ts(ts: str) -> datetime:
    """RFC 3339 → aware datetime for COMPARISON: fraction truncated/padded to 6 digits (Python < 3.11 parses only 3 or 6),
    a leap second (:60) compared as 59.999999, lowercase t/z accepted."""
    t = str(ts)
    t = t[:10] + "T" + t[11:] if len(t) > 10 else t
    t = re.sub(r"\.(\d+)", lambda m: "." + (m.group(1) + "000000")[:6], t, count=1)
    if t[17:19] == "60":
        t = t[:17] + "59.999999" + t[26:] if t[19:20] == "." else t[:17] + "59.999999" + t[19:]
    return datetime.fromisoformat(t[:-1] + "+00:00" if t.endswith(("Z", "z")) else t)


def _uuid4_from(seed: str) -> str:
    """UUID with version 4 / RFC 4122 variant bits, derived DETERMINISTICALLY from a digest of `seed`:
    the draft asks for the v4 format; reproducibility asks for determinism. Both, declared."""
    b = bytearray(hashlib.sha256(seed.encode("utf-8")).digest()[:16])
    b[6] = (b[6] & 0x0F) | 0x40
    b[8] = (b[8] & 0x3F) | 0x80
    return str(uuid.UUID(bytes=bytes(b)))


def _detail_for(e: Dict[str, Any], aat_type: str, omega_action: str) -> Dict[str, Any]:
    """§7 REQUIRED action_detail fields, DERIVED from what the omega record carries — never invented.
    tool_call: tool_name = the omega action (file_write, command_exec, network, ...) and parameters_hash =
    SHA-256(JCS({"resource": resource})) with the pre-image declared; decision: decision_type = the omega decision.
    Any other action_type needs fields an omega governance record does not have → ValueError."""
    resource = e.get("resource")
    base = {"omega_action": omega_action, "resource": resource, "policy_rule": e.get("policy_rule"),
            "decision": e.get("decision"), "reason": e.get("reason", ""), "record_sha3": e.get("record_sha3"),
            "device_attestation": e.get("device_attestation"), "omega_self_hash": e.get("self_hash"),
            "record_phase_basis": "DERIVED by the exporter from the omega outcome (blocked/pending_approval → pre_execution, executed → post_execution); "
                                  "the omega library records the outcome the caller reports and does not itself gate execution"}
    if aat_type == "tool_call":
        if not isinstance(resource, str) or not resource:
            raise ValueError("omega tool_call record without a string resource: parameters_hash cannot be derived")
        base.update({"tool_name": omega_action,
                     "parameters_hash": hashlib.sha256(jcs({"resource": resource})).hexdigest(),
                     "parameters_hash_over": "sha256(JCS({\"resource\": <resource>}))"})
        if e.get("policy_rule"):
            base["authorization"] = "policy:" + str(e["policy_rule"])
    elif aat_type == "decision":
        if not isinstance(e.get("decision"), str) or not e.get("decision"):
            raise ValueError("omega decision record without a decision value: decision_type cannot be derived")
        base["decision_type"] = e["decision"]
        if e.get("policy_rule"):
            base["policy_ref"] = str(e["policy_rule"])
    else:
        raise ValueError(f"omega action {omega_action!r} → AAT {aat_type!r}: the §7 REQUIRED action_detail fields "
                         f"({', '.join(n for n, _ in DETAIL_REQUIRED[aat_type])}) are not derivable from an omega "
                         "governance record — refused, not guessed")
    return base


def from_omega(entries: List[Dict[str, Any]], agent_version: str, trust_level: str = "L0",
               session_ids: Optional[Dict[str, str]] = None, private_key_pem: Optional[bytes] = None,
               pq_signer: Any = None, recording_component: Optional[str] = None,
               close: bool = False) -> Dict[str, List[Dict[str, Any]]]:
    """Map omega `agent_governance_action` entries to AAT (-04) chains, ONE chain per session (§8), each opened by a
    synthesised genesis record (§8.1: lifecycle/session_start, record_phase concurrent, recording_mode declared) and,
    with `close=True`, closed by a synthesised session_end record carrying `session_hash` (§8.3).
    `trust_level` is DECLARED by the caller. `recording_component` (a URI) declares INDEPENDENT recording (§5.2):
    every record then carries it and the signing key is the recorder's; without it the export is self-recording.
    Signing (§6.2): `private_key_pem` (ECDSA P-256) → ES256; `pq_signer` (an object with `.sign(bytes)` and
    `.public_key_b64`, e.g. `pqbackends.mldsa.MlDsaFileSigner`) → ML-DSA-65; BOTH → hybrid mode (ML-DSA-65 in
    `signature`, ES256 in `signature_classical`, two distinct keys and kids). Every record is signed BEFORE the next
    prev_hash is computed. Unknown action/outcome, missing agent id, unparsable timestamp, or §7 fields that cannot
    be derived → ValueError (never guessed)."""
    if trust_level not in TRUST_LEVELS:
        raise ValueError(f"trust_level must be one of {TRUST_LEVELS}")
    if not isinstance(agent_version, str) or not agent_version:
        raise ValueError("agent_version must be a non-empty string (§3.1)")
    if recording_component is not None and not _URI.match(str(recording_component)):
        raise ValueError("recording_component must be a URI (scheme:...)")
    if recording_component is not None and private_key_pem is None and pq_signer is None:
        raise ValueError("independent recording MUST be signed by the recorder (§5.2): pass private_key_pem and/or pq_signer")
    chains: Dict[str, List[Dict[str, Any]]] = {}
    prevs: Dict[str, Dict[str, Any]] = {}
    seeds_seen: set = set()
    sess = dict(session_ids or {})
    for k, v in sess.items():
        try:
            u = uuid.UUID(str(v))
        except ValueError:
            raise ValueError(f"session_ids[{k!r}] is not a UUID") from None
        if u.version != 4 or str(u) != str(v):
            raise ValueError(f"session_ids[{k!r}] must be a canonical UUID v4")

    def _sign(rec: Dict[str, Any]) -> Dict[str, Any]:
        if private_key_pem is not None and pq_signer is not None:
            return sign_record_hybrid(rec, pq_signer, private_key_pem)
        if pq_signer is not None:
            return sign_record(rec, pq_signer)
        if private_key_pem is not None:
            return sign_record(rec, private_key_pem)
        return rec

    for e in entries:
        if e.get("kind") != "agent_governance_action":
            continue
        sid = e.get("session_id")
        if not isinstance(sid, str) or not sid:
            raise ValueError("omega record without session_id: cannot export (a session is never invented)")
        try:
            u = uuid.UUID(sid)
            ok_v4 = u.version == 4
        except ValueError:
            ok_v4 = False
        if ok_v4:
            sid = str(u)                                    # canonical 8-4-4-4-12 lowercase (uppercase/braces = same session)
        else:
            sess.setdefault(sid, _uuid4_from(f"omega-session:{sid}"))
            sid = sess[sid]
        aid = e.get("agent_id")
        if not aid or not isinstance(aid, str):
            raise ValueError("omega record without agent_id: cannot export (never invented)")
        seed = e.get("self_hash") or e.get("record_sha3")
        if not seed:
            raise ValueError("omega record without self_hash/record_sha3: no stable identity, cannot export")
        if seed in seeds_seen:
            raise ValueError("two omega records with the same self_hash: the export would carry a duplicate record_id")
        seeds_seen.add(seed)
        if recording_component is not None and recording_component in (aid, f"urn:omega:agent:{aid}"):
            raise ValueError("recording_component equals the agent: that is self-recording, not independent (§5.1)")
        if e.get("consistent") is False:
            raise ValueError("omega record whose decision and outcome contradict each other (consistent=false): refused, not exported")
        oa, oo = str(e.get("action")), str(e.get("outcome"))
        if oa not in _ACTION_MAP:
            raise ValueError(f"omega action {oa!r} has no AAT mapping: refused, not guessed")
        if oo not in _OUTCOME_MAP:
            raise ValueError(f"omega outcome {oo!r} has no AAT mapping: refused, not guessed")
        aat_type = _ACTION_MAP[oa]
        rec: Dict[str, Any] = {
            "record_id": _uuid4_from(f"omega-record:{seed}"),
            "timestamp": _rfc3339(str(e.get("timestamp_utc", ""))),
            "agent_id": aid if _URI.match(aid) else f"urn:omega:agent:{aid}",
            "agent_version": agent_version,
            "session_id": sid,
            "action_type": aat_type,
            "action_detail": _detail_for(e, aat_type, oa),
            "outcome": _OUTCOME_MAP[oo],
            "trust_level": trust_level,
            "record_phase": _PHASE_MAP[oo],
        }
        if recording_component is not None:
            rec["recording_component"] = recording_component
        if sid not in chains:
            gd = {"event": "session_start", "new_state": "active",
                  "recording_mode": "independent" if recording_component is not None else "self",
                  "synthesised_by": "omega_evidence.interop.aat",
                  "note": "omega ledgers have no explicit session start; genesis stamped with the first action's time"}
            if recording_component is not None:
                gd["recording_component_id"] = recording_component
            gen = {"record_id": _uuid4_from(f"omega-genesis:{sid}"), "timestamp": rec["timestamp"],
                   "agent_id": rec["agent_id"], "agent_version": agent_version, "session_id": sid,
                   "action_type": "lifecycle", "action_detail": gd, "outcome": "success", "trust_level": trust_level,
                   "record_phase": "concurrent", "parent_record_id": None, "prev_hash": None}
            if recording_component is not None:
                gen["recording_component"] = recording_component
            gen = _sign(gen)
            chains[sid] = [gen]
            prevs[sid] = gen
        prev = prevs[sid]
        if rec["agent_id"] != prev["agent_id"]:
            raise ValueError("two agents in one omega session: an AAT chain is one session of one agent — refused, not merged")
        rec["parent_record_id"] = prev["record_id"]
        rec["prev_hash"] = record_hash(prev)
        if e.get("human_approver"):
            rec["human_override"] = {"operator_id": e["human_approver"], "reason": e.get("reason", ""),
                                     "original_action": {"omega_action": oa, "resource": e.get("resource")}}
        if _parse_ts(rec["timestamp"]) < _parse_ts(prev["timestamp"]):
            raise ValueError("omega entries are not in time order within the session: the export never reorders evidence")
        rec = _sign(rec)      # BEFORE the next prev_hash: the hash covers all fields
        if len(jcs(rec)) > RECORD_MAX_BYTES:
            raise ValueError("exported record exceeds 256 KB (§3.3 MUST): the resource/reason fields are too large")
        chains[sid].append(rec)
        prevs[sid] = rec
    if close:
        for sid, chain in chains.items():
            chain.append(_sign(close_record(chain, synthesised=True)))
    return chains


def close_record(chain: List[Dict[str, Any]], synthesised: bool = False, timestamp: Optional[str] = None,
                 trigger: Optional[str] = None) -> Dict[str, Any]:
    """§8.3 session close record for `chain` (unsigned; sign it before appending if the chain is signed).
    `session_hash` = hex(SHA-256(prev_hash(1) || ... || prev_hash(N))) over the raw digests, N being the close
    record itself — so it includes the hash of the last existing record. Timestamp = the last record's unless given."""
    if not chain or not all(isinstance(r, dict) and isinstance(r.get("timestamp"), str) and "record_id" in r for r in chain):
        raise ValueError("cannot close: empty chain or entries that are not records")
    last = chain[-1]
    prev_hashes = [bytes.fromhex(r["prev_hash"]) for r in chain[1:]] + [bytes.fromhex(record_hash(last, strict=False))]
    ts = _rfc3339(timestamp) if timestamp else last["timestamp"]
    if _parse_ts(ts) < _parse_ts(last["timestamp"]):
        raise ValueError("close record timestamp earlier than the last record (§3.3: timestamps MUST NOT be backdated)")
    dur = int((_parse_ts(ts) - _parse_ts(chain[0]["timestamp"])).total_seconds() * 1000)
    # a close written at export time cannot claim how the session ended: trigger "export", state unknown (never task_complete)
    # DECLARED: `outcome` is the outcome of the close ACTION (the chain was sealed), not of the session; the draft's synthetic
    # close for orphaned sessions (§8.3: outcome "failure", trigger "crash_recovery") describes a crash a monitor detected —
    # an export knows neither a crash nor a completion, so it says "unknown" in session_outcome and "export" in trigger.
    detail = {"event": "session_end", "previous_state": "unknown" if synthesised else "active", "new_state": "closed",
              "trigger": trigger or ("export" if synthesised else "task_complete"),
              "session_outcome": "unknown" if synthesised else "completed",
              "session_hash": hashlib.sha256(b"".join(prev_hashes)).hexdigest(),
              "record_count": len(chain) + 1, "duration_ms": dur}
    if synthesised:
        detail["synthesised_by"] = "omega_evidence.interop.aat"
        detail["close_basis"] = "synthesised at export: the omega ledger carries no session end; this record only seals the chain"
    rec = {"record_id": _uuid4_from(f"omega-close:{last['session_id']}:{record_hash(last, strict=False)}"),
           "timestamp": ts, "agent_id": last["agent_id"], "agent_version": last["agent_version"],
           "session_id": last["session_id"], "action_type": "lifecycle", "action_detail": detail,
           "outcome": "success", "trust_level": last["trust_level"], "record_phase": "post_execution",
           "parent_record_id": last["record_id"], "prev_hash": record_hash(last, strict=False)}
    if "recording_component" in last:
        rec["recording_component"] = last["recording_component"]
    return rec


def tombstone(rec: Dict[str, Any], deletion_reason: str, deleted_at: str, key: Any = None,
              classical_private_key_pem: Optional[bytes] = None) -> Dict[str, Any]:
    """§9.3: replace `rec` by a tombstone that keeps record_id, timestamp, parent_record_id, prev_hash,
    content_fingerprint and record_phase, sets lifecycle/record_deleted with `tombstone_hash` = the original record's
    chain hash, so the NEXT record's prev_hash keeps verifying. DECLARED DEVIATION from the draft's "retains the
    signature field": a signature kept over changed content verifies nothing and would let anyone replace any record
    with a tombstone that "has a signature" (review of 2026-09-19). The original signature fields are moved into
    action_detail.original_signature (evidence, not verified) and the tombstone is signed ANEW by the deleting
    authority's `key` (ES256 PEM or ML-DSA-65 signer; with `classical_private_key_pem` too → hybrid). An unsigned
    tombstone is accepted only in an unsigned chain, and the verifier says so."""
    out = {k: rec[k] for k in ("record_id", "timestamp", "agent_id", "agent_version", "session_id",
                               "parent_record_id", "prev_hash", "trust_level", "record_phase") if k in rec}
    for k in ("content_fingerprint", "recording_component"):
        if k in rec:
            out[k] = rec[k]
    out["action_type"] = "lifecycle"
    out["action_detail"] = {"event": "record_deleted", "deletion_reason": str(deletion_reason),
                            "deleted_at": _rfc3339(deleted_at), "original_action_type": rec.get("action_type")}
    orig = {k: rec[k] for k in ("signature", "sig_alg", "signer_kid", "signature_classical", "signer_kid_classical") if k in rec}
    if orig:
        out["action_detail"]["original_signature"] = orig
    out["outcome"] = "success"
    prev_d = rec.get("action_detail") if isinstance(rec.get("action_detail"), dict) else {}
    if rec.get("action_type") == "lifecycle" and prev_d.get("event") == "record_deleted" and _hex64(rec.get("tombstone_hash")):
        out["tombstone_hash"] = rec["tombstone_hash"]                 # re-tombstoning keeps the ORIGINAL record's hash
        out["action_detail"]["original_action_type"] = prev_d.get("original_action_type")
    else:
        out["tombstone_hash"] = record_hash(rec, strict=False)
    if key is not None and classical_private_key_pem is not None:
        return sign_record_hybrid(out, key, classical_private_key_pem)
    if key is not None:
        return sign_record(out, key)
    return out


# ── §6.4 Merkle batch anchoring ──────────────────────────────────────────────────────────────
def anchor_epoch(records: List[Dict[str, Any]], epoch_id: Optional[str] = None,
                 tsa_url: Optional[str] = None) -> Dict[str, Any]:
    """Attach a detached `batch` object (epoch_id, merkle_root, leaf_index, inclusion_proof) to every record of
    ONE epoch (records are modified in place, in order) and return the epoch anchor record
    {epoch_id, merkle_root, leaf_count, hash: "RFC 6962/SHA-256", tsa}. With `tsa_url` the root is timestamped
    (RFC 3161 over SHA-256 of the raw 32-byte root — declared; `openssl` needed) and the token travels in `tsa`."""
    if not records:
        raise ValueError("an epoch needs at least one record")
    eid = epoch_id or str(uuid.uuid4())
    try:
        u = uuid.UUID(eid)
        if u.version != 4 or str(u) != eid:
            raise ValueError
    except ValueError:
        raise ValueError("epoch_id must be a canonical UUID v4") from None
    for r in records:
        r.pop("batch", None)
    leaves = [leaf_hash(r, strict=True) for r in records]      # export: integers beyond 2^53 refused, as for prev_hash
    root = merkle_root(leaves)
    paths = audit_paths(leaves)
    for i, r in enumerate(records):
        r["batch"] = {"epoch_id": eid, "merkle_root": root.hex(), "leaf_index": i, "inclusion_proof": paths[i]}
    anchor: Dict[str, Any] = {"epoch_id": eid, "merkle_root": root.hex(), "leaf_count": len(records),
                              "hash": "RFC 6962 / SHA-256 (leaf 0x00 || JCS(record without batch), node 0x01)"}
    if tsa_url:
        from .. import timestamp as _ts
        imprint = hashlib.sha256(root).hexdigest()
        st = _ts.stamp(imprint, tsa_url)
        if not st.get("anchored") or not st.get("tsr_b64"):
            raise RuntimeError(f"TSA anchoring requested and failed: {st.get('note')} — no anchor is returned without a token")
        anchor["tsa"] = {"tsa_url": tsa_url, "message_imprint_sha256": imprint, "over": "SHA-256(raw 32-byte merkle_root)",
                         "token": st["tsr_b64"], "anchored": True}
    return anchor


def verify_epochs(records: List[Dict[str, Any]], anchors: List[Dict[str, Any]],
                  tsa_ca_file: Optional[str] = None, require_complete: bool = False) -> Dict[str, Any]:
    """Check every `batch` object against its epoch anchor: root equality, inclusion proof (OPTIONAL in the draft: a
    record without one is fine when the whole epoch is present and rebuilds the root, a problem otherwise), leaf_index consistency
    (no two records at one index, every index below the anchor's leaf_count, never more distinct leaves than
    leaf_count) and, when every leaf of an epoch is in `records`, the tree rebuilt from them must give the anchored
    root; with `tsa_ca_file` the RFC 3161 token over the root is verified with openssl (without it: recorded, NOT
    verified — never green: `tsa` carries verified None and a warning). Epochs with fewer leaves in `records` than
    the anchor's leaf_count are listed in `incomplete` (a warning; a problem with `require_complete=True` — an epoch
    may legitimately span sessions, but a record stripped of its `batch` or deleted looks exactly the same)."""
    problems: List[Dict[str, Any]] = []
    warnings: List[Dict[str, Any]] = []
    by_id = {}
    if not isinstance(anchors, list):
        problems.append({"why": "anchors is not a list"})
        anchors = []
    for a in anchors:
        if not isinstance(a, dict) or not _HEX64.match(str(a.get("merkle_root", ""))) or not isinstance(a.get("epoch_id"), str) \
                or not (isinstance(a.get("leaf_count"), int) and not isinstance(a.get("leaf_count"), bool) and a["leaf_count"] > 0) \
                or ("tsa" in a and not (isinstance(a["tsa"], dict) and isinstance(a["tsa"].get("token"), str) and a["tsa"]["token"])):
            problems.append({"epoch": a.get("epoch_id") if isinstance(a, dict) else None,
                             "why": "anchor malformed (epoch_id string, merkle_root hex, leaf_count positive integer, tsa object with a non-empty token)"})
            continue
        if a["epoch_id"] in by_id and by_id[a["epoch_id"]] != a:
            problems.append({"epoch": a["epoch_id"], "why": "conflicting anchors for the same epoch_id"})
            continue
        by_id[a["epoch_id"]] = a
    seen: Dict[str, Dict[int, str]] = {}
    leaves_by_epoch: Dict[str, Dict[int, bytes]] = {}
    no_proof: Dict[str, List[int]] = {}
    for i, r in enumerate(records):
        if not isinstance(r, dict):
            problems.append({"i": i, "why": "record is not an object"}); continue
        b = r.get("batch")
        if b is None:
            continue
        if not isinstance(b, dict) or not _HEX64.match(str(b.get("merkle_root", ""))) or not isinstance(b.get("leaf_index"), int) \
                or isinstance(b.get("leaf_index"), bool) or b["leaf_index"] < 0 or not isinstance(b.get("epoch_id"), str):
            problems.append({"i": i, "why": "batch object malformed"}); continue
        try:
            lh = leaf_hash(r)
        except (ValueError, TypeError, RecursionError) as ex:
            problems.append({"i": i, "why": f"record not canonicalizable: {type(ex).__name__}"}); continue
        a = by_id.get(b.get("epoch_id"))
        if a is None:
            problems.append({"i": i, "why": f"no anchor for epoch {b.get('epoch_id')}"}); continue
        if a["merkle_root"] != b["merkle_root"]:
            problems.append({"i": i, "why": "batch merkle_root differs from the epoch anchor"})
        path = b.get("inclusion_proof")
        if path is None:
            no_proof.setdefault(b["epoch_id"], []).append((i, b["leaf_index"], lh))   # OPTIONAL (§3.2): decided once the epoch is rebuilt
        else:
            try:
                ok = isinstance(path, list) and all(isinstance(s, dict) and _HEX64.match(str(s.get("hash", ""))) and s.get("side") in ("left", "right") for s in path)
                if not ok or root_from_path(lh, path).hex() != b["merkle_root"]:
                    problems.append({"i": i, "why": "inclusion_proof does not lead to merkle_root"})
                elif isinstance(a.get("leaf_count"), int) and not isinstance(a.get("leaf_count"), bool) and a["leaf_count"] > 0 \
                        and index_from_path(path, a["leaf_count"]) != b["leaf_index"]:
                    problems.append({"i": i, "why": f"inclusion_proof proves leaf index {index_from_path(path, a['leaf_count'])}, record says {b['leaf_index']}"})
            except (ValueError, TypeError, RecursionError) as ex:
                problems.append({"i": i, "why": f"inclusion_proof unusable: {type(ex).__name__}"})
        idx = seen.setdefault(b["epoch_id"], {})
        if b["leaf_index"] in idx and idx[b["leaf_index"]] != lh:
            problems.append({"i": i, "why": "two DIFFERENT records claim the same leaf_index in one epoch"})
        idx[b["leaf_index"]] = lh
        lc = a.get("leaf_count")
        if isinstance(lc, int) and not isinstance(lc, bool) and b["leaf_index"] >= lc:
            problems.append({"i": i, "why": f"leaf_index {b['leaf_index']} >= leaf_count {lc} of the epoch anchor"})
        lv_epoch = leaves_by_epoch.setdefault(b["epoch_id"], {})
        if b["leaf_index"] not in lv_epoch or path is not None:       # a proven leaf wins the slot over a proof-less one
            lv_epoch[b["leaf_index"]] = lh
    incomplete: Dict[str, Dict[str, int]] = {}
    for eid, lv in leaves_by_epoch.items():
        a = by_id[eid]
        lc = a.get("leaf_count")
        if isinstance(lc, int) and not isinstance(lc, bool):
            if len(lv) > lc:
                problems.append({"epoch": eid, "why": f"{len(lv)} distinct leaves seen, anchor says leaf_count {lc}"})
            elif len(lv) == lc and sorted(lv) == list(range(lc)):          # every leaf present: rebuild the tree
                if merkle_root([lv[k] for k in range(lc)]).hex() != a["merkle_root"]:
                    problems.append({"epoch": eid, "why": "all leaves present but they do not rebuild the anchored merkle_root"})
                elif eid in no_proof:
                    bad = [i_ for i_, li, lh_ in no_proof[eid] if lv[li] != lh_]
                    for i_ in bad:
                        problems.append({"i": i_, "why": "record without inclusion_proof is NOT the leaf at its leaf_index of the rebuilt epoch"})
                    if len(bad) < len(no_proof[eid]):
                        warnings.append({"epoch": eid, "why": f"{len(no_proof[eid]) - len(bad)} records without inclusion_proof: membership proven by rebuilding the whole epoch, not per record"})
                    no_proof.pop(eid)
            elif len(lv) < lc:
                incomplete[eid] = {"seen": len(lv), "leaf_count": lc}
                (problems if require_complete else warnings).append(
                    {"epoch": eid, "why": f"{lc - len(lv)} of {lc} anchored leaves are not in these records (deleted, stripped of batch, or in another session)"})
    for eid, entries_ in no_proof.items():
        problems.append({"epoch": eid, "why": f"records {[e[0] for e in entries_]} carry no inclusion_proof and the epoch cannot be rebuilt from these records: membership not verifiable"})
    for eid in by_id:
        if eid not in leaves_by_epoch:
            lc = by_id[eid]["leaf_count"]
            incomplete[eid] = {"seen": 0, "leaf_count": lc}
            (problems if require_complete else warnings).append(
                {"epoch": eid, "why": f"{lc} of {lc} anchored leaves are not in these records: epoch unaccounted for (whole-epoch truncation or another session)"})
    if leaves_by_epoch and any(r.get("batch") is None for r in records if isinstance(r, dict)):
        warnings.append({"why": "some records carry no batch object while others are anchored: they are outside every epoch checked here"})
    tsa: Dict[str, Any] = {}
    for eid, a in by_id.items():
        t = a.get("tsa")
        if isinstance(t, dict) and t.get("token"):
            from .. import timestamp as _ts
            imprint = hashlib.sha256(bytes.fromhex(a["merkle_root"])).hexdigest()
            if t.get("message_imprint_sha256") not in (None, imprint):
                problems.append({"epoch": eid, "why": "tsa.message_imprint_sha256 is not SHA-256(root)"})
            v = _ts.verify(t["token"], imprint, ca_file=tsa_ca_file)
            tsa[eid] = v
            if v.get("verified") is False:
                problems.append({"epoch": eid, "why": f"RFC 3161 token over the root does not verify: {v.get('note')}"})
            elif v.get("verified") is None:
                warnings.append({"epoch": eid, "why": "RFC 3161 token recorded, NOT verified (no tsa_ca_file / openssl): the anchor's time is unproven"})
    return {"ok": not problems, "problems": problems, "warnings": warnings, "epochs": len(by_id), "incomplete": incomplete, "tsa": tsa,
            "time_verified": bool(tsa) and all(v.get("verified") is True for v in tsa.values()),
            "scope": "batch/inclusion proofs against the anchors given; an anchor is only as good as what it is "
                     "anchored to (a verified TSA token with tsa_ca_file, WORM storage, or a transparency log)"}


# ── verification (offline, fail-closed) ──────────────────────────────────────────────────────
def _check_detail(i: int, r: Dict[str, Any], problems: List[Dict[str, Any]], warnings: List[Dict[str, Any]]) -> None:
    at = r.get("action_type")
    d = r.get("action_detail")
    if not isinstance(d, dict):
        return
    if not d:
        problems.append({"i": i, "why": "action_detail is empty (§3.3: at least one relevant field)"})
    for k in d:
        if str(k).startswith("aat_"):
            problems.append({"i": i, "why": f"action_detail key {k!r} uses the reserved aat_ prefix (§3.3)"})
    for name, typ in DETAIL_REQUIRED.get(at if isinstance(at, str) else "", ()):
        v = d.get(name)
        if name not in d:
            problems.append({"i": i, "why": f"action_detail.{name} REQUIRED for {at} (§7) is missing"})
        elif typ is bool and not isinstance(v, bool):
            problems.append({"i": i, "why": f"action_detail.{name} must be a boolean (§7)"})
        elif typ is str and (not isinstance(v, str) or not v):
            problems.append({"i": i, "why": f"action_detail.{name} must be a non-empty string (§7)"})
    if at == "error" and d.get("error_category") not in ERROR_CATEGORIES and isinstance(d.get("error_category"), str):
        problems.append({"i": i, "why": f"error_category not in vocabulary: {d.get('error_category')!r} (§7.6)"})
    if at == "lifecycle" and isinstance(d.get("event"), str) and d["event"] not in LIFECYCLE_EVENTS:
        problems.append({"i": i, "why": f"lifecycle event not in vocabulary: {d['event']!r} (§7.7/§9.3)"})
    if at == "escalation" and "urgency" in d and d["urgency"] not in ESCALATION_URGENCY:
        problems.append({"i": i, "why": "escalation urgency not in vocabulary (§7.5)"})
    if at == "delegation" and isinstance(d.get("delegate_trust_level"), str) and d["delegate_trust_level"] not in TRUST_LEVELS:
        problems.append({"i": i, "why": "delegate_trust_level not in L0..L4 (§7.4)"})
    for name in ("parameters_hash", "response_hash", "reasoning_hash", "task_description_hash", "context_hash", "stack_hash"):
        if name in d and not _hex64(d[name]):
            problems.append({"i": i, "why": f"action_detail.{name} is not a lowercase hex SHA-256"})
    if "confidence" in d and not (isinstance(d["confidence"], (int, float)) and not isinstance(d["confidence"], bool)
                                  and 0.0 <= d["confidence"] <= 1.0):
        problems.append({"i": i, "why": "decision confidence is not a number in [0,1] (§7.3)"})
    # §13: a decision marked reproducible needs a CLOSED attestation; fields at top level or in action_detail
    s13 = CLOSURE_DIGESTS + ("inference_config", "environment", "reproducibility_class", "output_digest", "environment_attestation",
                             "margin_reproducible", "decision_margin", "margin_epsilon")
    if at != "decision":
        top = [k for k in s13 if k in r]
        if top:
            problems.append({"i": i, "why": f"reproducibility fields {top} on a non-decision record (§13.3: decision records only)"})
        if any(k in d for k in s13):
            warnings.append({"i": i, "why": "action_detail of a non-decision record uses §13 field names (preserved as unknown fields, not checked)"})
        return
    src = {**d, **{k: r[k] for k in r if k in s13}}
    rc = src.get("reproducibility_class")
    if "environment_attestation" in src and not (isinstance(src["environment_attestation"], str) and src["environment_attestation"]
                                                and (_URI.match(src["environment_attestation"]) or _B64_STD.match(src["environment_attestation"]))):
        problems.append({"i": i, "why": "environment_attestation must be a base64 attestation or a URI (§13.3)"})
    if rc is not None and rc not in REPRODUCIBILITY_CLASSES:
        problems.append({"i": i, "why": f"reproducibility_class not in {REPRODUCIBILITY_CLASSES} (§13.3)"})
    for name in CLOSURE_DIGESTS:
        if name in src and not (isinstance(src[name], str) and _SHA256_PREFIXED.match(src[name])):
            problems.append({"i": i, "why": f"{name} is not 'sha256:<64 lowercase hex>' (§13.3)"})
    if "output_digest" in src and not _hex64(src["output_digest"]):
        problems.append({"i": i, "why": "output_digest is not a lowercase hex SHA-256 (§13.3)"})
    if rc == "reproducible":
        missing = [n for n in CLOSURE_DIGESTS if n not in src]
        ic, env = src.get("inference_config"), src.get("environment")
        if not isinstance(ic, dict) or any(k not in ic for k in ("temperature", "top_k", "top_p", "seed", "max_tokens")):
            missing.append("inference_config{temperature,top_k,top_p,seed,max_tokens}")
        if not isinstance(env, dict) or any(k not in env for k in ("engine", "engine_version", "hardware", "batch_size", "num_threads")):
            missing.append("environment{engine,engine_version,hardware,batch_size,num_threads}")
        if not _hex64(r.get("content_fingerprint")) and not _hex64(r.get("input_hash")):
            missing.append("sealed input (content_fingerprint or input_hash)")
        if missing:
            problems.append({"i": i, "why": "reproducibility_class=reproducible with an OPEN attestation (§13.6 MUST NOT): "
                                            "missing " + ", ".join(missing)})
    for name in ("decision_margin", "margin_epsilon"):
        if name in src and not _num(src[name]):
            problems.append({"i": i, "why": f"{name} must be a number (§13.3)"})
    if "margin_reproducible" in src:
        dm, me = src.get("decision_margin"), src.get("margin_epsilon")
        if not isinstance(src["margin_reproducible"], bool):
            problems.append({"i": i, "why": "margin_reproducible must be a boolean (§13.8)"})
        elif not (_num(dm) and _num(me)):
            problems.append({"i": i, "why": "margin_reproducible without decision_margin and margin_epsilon (§13.3)"})
        elif me < 0:
            problems.append({"i": i, "why": "margin_epsilon is a bound on a perturbation: it cannot be negative (§13.3)"})
        elif bool(src["margin_reproducible"]) != (dm > 2 * me):
            problems.append({"i": i, "why": "margin_reproducible contradicts decision_margin > 2·margin_epsilon (§13.8)"})


def _check_optional(i: int, r: Dict[str, Any], problems: List[Dict[str, Any]], warnings: List[Dict[str, Any]]) -> None:
    if "recording_component" in r and not _URI.match(str(r["recording_component"])):
        problems.append({"i": i, "why": "recording_component is not a URI (§3.2)"})
    if "nonce" in r and not (isinstance(r["nonce"], str) and _NONCE.match(r["nonce"])):
        problems.append({"i": i, "why": "nonce is not lowercase hex of at least 32 characters (§3.2)"})
    for name in ("input_hash", "output_hash", "content_fingerprint"):
        if name in r and not _hex64(r[name]):
            problems.append({"i": i, "why": f"{name} is not a lowercase hex SHA-256 (§3.2)"})
    if "risk_score" in r and not (isinstance(r["risk_score"], (int, float)) and not isinstance(r["risk_score"], bool)
                                  and 0.0 <= r["risk_score"] <= 1.0):
        problems.append({"i": i, "why": "risk_score is not a number in [0,1] (§3.2)"})
    if "deny_reasons" not in r and r.get("outcome") == "denied" and r.get("trust_level") in ("L2", "L3", "L4"):
        warnings.append({"i": i, "why": "denied at L2+ without deny_reasons (§3.2 RECOMMENDED)"})
    if "deny_reasons" in r:
        dr = r["deny_reasons"]
        if not isinstance(dr, list) or not all(isinstance(x, str) and x for x in dr):
            problems.append({"i": i, "why": "deny_reasons is not an array of strings (§3.2)"})
        else:
            if r.get("outcome") != "denied":
                warnings.append({"i": i, "why": "deny_reasons present while outcome is not denied"})
            for x in dr:
                if x not in DENY_REASONS and "_" not in x.strip("_"):
                    warnings.append({"i": i, "why": f"deny_reasons code {x!r} neither registered nor prefixed (SHOULD)"})
    if "jurisdiction" in r and not (isinstance(r["jurisdiction"], str) and _ISO2.match(r["jurisdiction"])):
        problems.append({"i": i, "why": "jurisdiction is not an ISO 3166-1 alpha-2 code (§3.2)"})
    ho = r.get("human_override")
    if ho is not None and not (isinstance(ho, dict) and isinstance(ho.get("operator_id"), str)):
        problems.append({"i": i, "why": "human_override needs operator_id (§3.2)"})
    sc = r.get("sanctions_check")
    if sc is not None:
        if not isinstance(sc, dict) or not isinstance(sc.get("provider"), str) or sc.get("result") not in ("clear", "match", "error") \
                or not _RFC3339.match(str(sc.get("checked_at", ""))):
            problems.append({"i": i, "why": "sanctions_check malformed (provider, checked_at RFC 3339, result clear|match|error) (§3.2)"})
    ta = r.get("trust_assignment")
    if ta is not None:
        if not isinstance(ta, dict) or not _URI.match(str(ta.get("classifier_id", ""))) or not isinstance(ta.get("policy_version"), str) \
                or not isinstance(ta.get("downgraded"), bool):
            problems.append({"i": i, "why": "trust_assignment needs classifier_id (URI), policy_version, downgraded (boolean) (§3.2)"})
        elif "policy_digest" in ta and not _hex64(ta["policy_digest"]):
            problems.append({"i": i, "why": "trust_assignment.policy_digest is not a lowercase hex SHA-256"})
    et = r.get("external_timestamp")
    if et is not None:
        if not isinstance(et, dict) or not isinstance(et.get("tsa_url"), str) or not isinstance(et.get("token"), str) \
                or not _RFC3339.match(str(et.get("anchored_at", ""))):
            problems.append({"i": i, "why": "external_timestamp needs tsa_url, token, anchored_at (RFC 3339) (§3.2)"})
    b = r.get("batch")
    if b is not None:
        if not (isinstance(b, dict) and _hex64(b.get("merkle_root")) and _uuid4_ok(b.get("epoch_id"))
                and _num(b.get("leaf_index")) and isinstance(b.get("leaf_index"), int) and b["leaf_index"] >= 0):
            problems.append({"i": i, "why": "batch needs epoch_id (UUID v4), merkle_root (hex), leaf_index (non-negative integer) (§3.2)"})
        elif "inclusion_proof" in b and not (isinstance(b["inclusion_proof"], list) and all(
                isinstance(st, dict) and _hex64(st.get("hash")) and st.get("side") in ("left", "right") for st in b["inclusion_proof"])):
            problems.append({"i": i, "why": "inclusion_proof must be an array of {hash: 64 lowercase hex, side: left|right} (§3.2)"})
    if "sig_alg" in r and r["sig_alg"] not in SIG_ALGS:
        problems.append({"i": i, "why": f"sig_alg not in the registry {SIG_ALGS} (§15.3)"})
    for k in ("signer_kid", "signer_kid_classical"):
        if k in r and not (isinstance(r[k], str) and _B64U.match(r[k]) and len(r[k]) == 43):
            problems.append({"i": i, "why": f"{k} is not a base64url SHA-256 thumbprint without padding (RFC 7638)"})
    if "signature_classical" in r:
        if r.get("sig_alg") != "ML-DSA-65":
            problems.append({"i": i, "why": "signature_classical only in hybrid mode with sig_alg ML-DSA-65 (§6.2)"})
        if "signer_kid_classical" not in r:
            problems.append({"i": i, "why": "signature_classical without signer_kid_classical (§3.2)"})
        elif r.get("signer_kid_classical") == r.get("signer_kid"):
            problems.append({"i": i, "why": "hybrid mode needs two DISTINCT keys (§6.2)"})
    if "signer_kid_classical" in r and "signature_classical" not in r:
        problems.append({"i": i, "why": "signer_kid_classical without signature_classical: hybrid claimed, classical half missing"})


def verify_chain(records: List[Dict[str, Any]], pubkey_pem: Optional[bytes] = None,
                 keys: Optional[Dict[str, Any]] = None, agent_kid: Optional[str] = None,
                 require_signatures: bool = False, consequential: Optional[Callable[[Dict[str, Any]], bool]] = None,
                 external_timestamp_ca_file: Optional[str] = None, allow_legacy_03: bool = False,
                 tombstone_kids: Optional[List[str]] = None) -> Dict[str, Any]:
    """Verify one AAT (-04) chain offline, fail-closed. Checks (draft sections): mandatory fields and vocabularies
    (§3.1), UUID v4 identifiers, RFC 3339 UTC monotonic timestamps, sizes and the aat_ prefix (§3.3), §7 REQUIRED
    action_detail fields, record_phase rules (§4.2, §8.1, §8.3), recording independence (§5.1/5.2 — with
    `agent_kid`, the RFC 7638 thumbprint of the agent's key, an independently recorded record signed by that key
    is a problem), §5.3 fail-safe trust level (delegation; plus `consequential(record)` for tool_call/decision),
    genesis nulls, parent_record_id and prev_hash linking (§6.1/6.3), tombstones (§9.3), nonce uniqueness, the
    session close `session_hash` (§8.3), §13 closure, and every signature present: the key is resolved from
    `keys` = {signer_kid: key} (key = P-256 public PEM bytes, or the raw 1952-byte ML-DSA-65 public key as bytes or
    strict base64) — `pubkey_pem` is also matched by its thumbprint; a signed record WITHOUT `signer_kid` violates §3.3 (MUST) and is a
    problem unless `allow_legacy_03=True`, which then resolves it with `pubkey_pem` (the -03 rule). A signature that cannot be verified on this host (no `cryptography`, or no ML-DSA in it)
    is a problem, never a pass. `require_signatures=True` makes an unsigned record a problem. `external_timestamp`
    tokens are verified with openssl when `external_timestamp_ca_file` is given (else recorded, NOT verified).
    With `agent_kid`, a self-recorded record signed by another key is a problem (§6.3 step 3a; a key rotation mid-session
    therefore needs a new session). Independence (§5.2) is decided for the whole session (genesis `recording_mode`, or any
    record naming a recording component other than the agent) and then required of every record. DECLARED DEVIATION: a
    tombstone must carry a valid signature of the deleting authority over the tombstone content (`tombstone(..., key=)`);
    the draft's retained original signature cannot verify and is reported as such; a tombstoned genesis is refused
    (§8.1 wins over §9.3's "any record"). WHO may delete: a tombstone's signer must be the agent (`agent_kid`) in a
    self-recorded session, or one of `tombstone_kids` (the deleting authorities the relying party names); a tombstone by any
    other key in `keys` is a problem, and without `agent_kid`/`tombstone_kids` a signed tombstone is accepted with a warning
    naming its signer (the authority is not pinned). With `keys` (even empty) or `pubkey_pem`, every record must be signed.
    Returns {ok, records, problems, warnings, signatures_verified, hybrid_verified, tombstones, keys_rejected, draft, scope}."""
    problems: List[Dict[str, Any]] = []
    warnings: List[Dict[str, Any]] = []
    if not isinstance(records, list):
        return {"ok": False, "records": 0, "problems": [{"i": -1, "why": "records is not a list"}], "warnings": [],
                "signatures_verified": 0, "hybrid_verified": 0, "tombstones": 0, "keys_rejected": [], "draft": AAT_DRAFT, "scope": ""}
    keyset = _KeySet(keys, pubkey_pem)
    keyset.allow_legacy = allow_legacy_03
    prev: Optional[Dict[str, Any]] = None
    signed_ok = hybrid_ok = tombstones = 0
    seen_ids: set = set()
    seen_nonces: set = set()
    if not records:
        problems.append({"i": -1, "why": "empty chain: nothing to verify (not a valid audit trail)"})
    session0 = None
    agent0 = None
    last_ts = None
    recording_mode = None
    # §5.2 independence is a property of the SESSION, decided fail-closed before the loop: the genesis says so, or any
    # record names a recording component other than the agent (a forger cannot opt a record out by omitting the field)
    g0 = records[0] if records and isinstance(records[0], dict) else {}
    gd0 = g0.get("action_detail") if isinstance(g0.get("action_detail"), dict) else {}
    recorders = {r["recording_component"] for r in records if isinstance(r, dict) and isinstance(r.get("recording_component"), str)
                 and r["recording_component"] != r.get("agent_id")}
    if isinstance(gd0.get("recording_component_id"), str) and gd0.get("recording_mode") == "independent":
        recorders.add(gd0["recording_component_id"])
    session_independent = gd0.get("recording_mode") == "independent" or bool(recorders)
    keys_given = keys is not None or pubkey_pem is not None
    prev_hashes_raw: List[bytes] = []
    for i, r in enumerate(records):
        if not isinstance(r, dict):
            problems.append({"i": i, "why": "record is not an object"}); continue      # prev is NOT reset (no genesis mid-chain)
        rid = r.get("record_id") if isinstance(r.get("record_id"), str) else repr(type(r.get("record_id")))
        if rid in seen_ids:
            problems.append({"i": i, "why": "duplicate record_id"})
        seen_ids.add(rid)
        for f in MANDATORY:
            if f not in r:
                problems.append({"i": i, "why": f"missing mandatory field {f}" +
                                 (" (mandatory since -01: a -00 chain must be re-exported)" if f == "record_phase" else "")})
        if r.get("action_type") not in ACTION_TYPES:
            problems.append({"i": i, "why": f"action_type not in vocabulary: {r.get('action_type')!r}"})
        if r.get("outcome") not in OUTCOMES:
            problems.append({"i": i, "why": f"outcome not in vocabulary: {r.get('outcome')!r}"})
        if r.get("trust_level") not in TRUST_LEVELS:
            problems.append({"i": i, "why": f"trust_level not in L0..L4: {r.get('trust_level')!r}"})
        if "record_phase" in r and r.get("record_phase") not in RECORD_PHASES:
            problems.append({"i": i, "why": f"record_phase not in vocabulary: {r.get('record_phase')!r} (§3.1)"})
        if not isinstance(r.get("action_detail"), dict):
            problems.append({"i": i, "why": "action_detail is not an object"})
        if not isinstance(r.get("agent_version"), str) or not r.get("agent_version"):
            problems.append({"i": i, "why": "agent_version is not a non-empty string"})
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
        else:
            if not (ts.endswith(("Z", "z")) or ts.endswith("+00:00")):
                warnings.append({"i": i, "why": "timestamp not in UTC (§3.1 SHOULD use UTC)"})
            try:
                d = _parse_ts(ts)
            except ValueError:
                d = None
                problems.append({"i": i, "why": "timestamp is not a valid calendar date/time"})
            if d is not None:
                if last_ts is not None and d < last_ts:
                    problems.append({"i": i, "why": "timestamp earlier than the previous record (not monotonic)"})
                last_ts = d
        if session0 is None:
            session0 = r.get("session_id")
        elif r.get("session_id") != session0:
            problems.append({"i": i, "why": "session_id differs: one chain must be one session (§8)"})
        if agent0 is None:
            agent0 = r.get("agent_id")
        elif r.get("agent_id") != agent0:
            problems.append({"i": i, "why": "agent_id differs from the genesis record: one chain is one session of one agent (§3.1/§8)"})
        if not _URI.match(str(r.get("agent_id", ""))):
            problems.append({"i": i, "why": "agent_id is not a URI (scheme:...)"})
        canonical_ok = True
        try:
            size = len(jcs(r, strict=False))
            if size > RECORD_MAX_BYTES:
                problems.append({"i": i, "why": f"record is {size} bytes > 256 KB (§3.3 MUST reject)"})
            elif size > RECORD_SHOULD_BYTES:
                warnings.append({"i": i, "why": f"record is {size} bytes > 64 KB (§3.3 SHOULD NOT)"})
        except (ValueError, TypeError, RecursionError) as ex:
            canonical_ok = False
            problems.append({"i": i, "why": f"record not canonicalizable: {type(ex).__name__}"})
        _check_detail(i, r, problems, warnings)
        _check_optional(i, r, problems, warnings)
        d = r.get("action_detail") if isinstance(r.get("action_detail"), dict) else {}
        is_tomb = r.get("action_type") == "lifecycle" and d.get("event") == "record_deleted"
        # §4.2 / §8 phase rules
        if (r.get("action_type"), r.get("outcome")) in PRE_EXECUTION_REQUIRED and r.get("record_phase") != "pre_execution":
            problems.append({"i": i, "why": f"{r.get('action_type')}/{r.get('outcome')} MUST be record_phase pre_execution (§4.2)"})
        if r.get("action_type") == "lifecycle" and d.get("event") == "session_start" and r.get("record_phase") != "concurrent":
            problems.append({"i": i, "why": "genesis record_phase MUST be concurrent (§8.1)"})
        if r.get("action_type") == "lifecycle" and d.get("event") == "session_end" and r.get("record_phase") != "post_execution":
            problems.append({"i": i, "why": "close record_phase MUST be post_execution (§8.3)"})
        # §5.3 fail-safe trust level
        low = r.get("trust_level") in ("L0", "L1")
        ta = r.get("trust_assignment") if isinstance(r.get("trust_assignment"), dict) else None
        downgraded = bool(ta and ta.get("downgraded") is True)
        if low and (r.get("action_type") == "delegation" or (consequential is not None and r.get("action_type") in ("tool_call", "decision")
                                                              and _safe_pred(consequential, r))) and not downgraded:
            problems.append({"i": i, "why": "consequential action below L2 without trust_assignment.downgraded=true (§5.3)"})
        # §5 recording independence
        if i == 0:
            recording_mode = d.get("recording_mode")
            if recording_mode not in (None, "self", "independent"):
                problems.append({"i": i, "why": "genesis recording_mode must be self or independent (§5)"})
            if recording_mode == "independent" and not _URI.match(str(d.get("recording_component_id", ""))):
                problems.append({"i": i, "why": "independent recording: genesis needs recording_component_id (URI) (§5.2)"})
        if session_independent and "recording_component" not in r:
            problems.append({"i": i, "why": "independent recording: every record MUST carry recording_component (§5.2)"})
        if session_independent and "recording_component" in r and r["recording_component"] == r.get("agent_id"):
            problems.append({"i": i, "why": "independent recording declared but recording_component equals agent_id (§5.1/§5.2)"})
        if session_independent and len(recorders) > 1 and isinstance(r.get("recording_component"), str) \
                and r["recording_component"] != min(recorders, key=lambda x: (x != gd0.get("recording_component_id"), x)):
            problems.append({"i": i, "why": f"a second recording component in one session ({r['recording_component']!r}; the session's is "
                                            f"{min(recorders, key=lambda x: (x != gd0.get('recording_component_id'), x))!r}) (§5.2: one independent recorder)"})
        if session_independent:
            if "signature" not in r:
                problems.append({"i": i, "why": "independent recording: the recorder MUST sign every record with its own key (§5.2)"})
            elif "signer_kid" not in r:
                problems.append({"i": i, "why": "independent recording: signed record without signer_kid — the -03 fallback (the agent's key) does not apply to an independent recorder (§5.2)"})
            elif agent_kid is not None and agent_kid in (r.get("signer_kid"), r.get("signer_kid_classical")):
                problems.append({"i": i, "why": "independently recorded record signed with the AGENT's key (§5.2)"})
            elif agent_kid is None and i == 0:
                warnings.append({"i": i, "why": "independent recording: pass agent_kid to check that the recorder's key differs from the agent's (§5.2)"})
            if recording_mode is None and i == 0:
                warnings.append({"i": i, "why": "records name a recording component other than the agent but the genesis declares no recording_mode (§8.1 SHOULD)"})
        if recording_mode == "self" and session_independent:
            problems.append({"i": i, "why": "self-recording declared but records name another recording component (§5.1)"})
        if not session_independent and agent_kid is not None and "signature" in r and not is_tomb \
                and isinstance(r.get("signer_kid"), str) and agent_kid not in (r["signer_kid"], r.get("signer_kid_classical")):
            problems.append({"i": i, "why": "self-recorded record not signed by the agent's key (§6.3 step 3a)"})
        if is_tomb and "signature" in r and isinstance(r.get("signer_kid"), str):
            allowed = set(tombstone_kids or [])
            if not session_independent and agent_kid is not None:
                allowed.add(agent_kid)
            if allowed and r["signer_kid"] not in allowed and r.get("signer_kid_classical") not in allowed:
                problems.append({"i": i, "why": f"tombstone signed by {r['signer_kid']!r}, not a deleting authority (agent_kid / tombstone_kids)"})
            elif not allowed:
                warnings.append({"i": i, "why": f"tombstone signed by {r['signer_kid']!r}: deleting authority not pinned (pass agent_kid or tombstone_kids)"})
        if not low and i == 0 and not session_independent:
            warnings.append({"i": i, "why": "L2+ session recorded by the agent itself (§5.2 SHOULD: independent recording)"})
        if low is False and ta is not None and ta.get("downgraded") is True:
            warnings.append({"i": i, "why": "trust_assignment.downgraded true on an L2+ record (§3.2: true only below the fail-safe default)"})
        # nonce uniqueness (§14.5)
        n = r.get("nonce")
        if isinstance(n, str):
            if n in seen_nonces:
                problems.append({"i": i, "why": "duplicate nonce within the session (§14.5)"})
            seen_nonces.add(n)
        # chain linking
        if i == 0:
            if r.get("parent_record_id") is not None or r.get("prev_hash") is not None:
                problems.append({"i": i, "why": "genesis record must have null parent_record_id and prev_hash"})
            if r.get("action_type") != "lifecycle" or d.get("event") != "session_start":
                problems.append({"i": i, "why": "genesis must be action_type=lifecycle with action_detail.event=session_start (§8.1)"})
        else:
            if prev is None:
                problems.append({"i": i, "why": "previous record unusable"})
            else:
                if r.get("parent_record_id") != prev.get("record_id"):
                    problems.append({"i": i, "why": "parent_record_id does not link to the previous record"})
                if not _hex64(r.get("prev_hash")):
                    problems.append({"i": i, "why": "prev_hash is not a 64-character lowercase hex string"})
                else:
                    try:
                        exp = record_hash(prev, strict=False)      # foreign chains: ES6 numbers, never refused
                    except (ValueError, TypeError, RecursionError) as ex:
                        exp = None
                        problems.append({"i": i, "why": f"previous record not canonicalizable: {type(ex).__name__}"})
                    pd = prev.get("action_detail") if isinstance(prev.get("action_detail"), dict) else {}
                    prev_tomb = prev.get("action_type") == "lifecycle" and pd.get("event") == "record_deleted"
                    if exp is not None and r.get("prev_hash") != exp:
                        if prev_tomb and r.get("prev_hash") == prev.get("tombstone_hash"):
                            pass                                     # §9.3: the chain break is accepted through tombstone_hash
                        else:
                            problems.append({"i": i, "why": "prev_hash mismatch (previous record altered or reordered)"})
                    prev_hashes_raw.append(bytes.fromhex(r["prev_hash"]))
            if r.get("action_type") == "lifecycle" and d.get("event") == "session_start":
                problems.append({"i": i, "why": "session_start after the genesis record (§8.1: one genesis per session)"})
        if is_tomb:
            tombstones += 1
            if not _hex64(r.get("tombstone_hash")):
                problems.append({"i": i, "why": "tombstone without tombstone_hash (§9.3 MUST)"})
            if not _RFC3339.match(str(d.get("deleted_at", ""))) or not isinstance(d.get("deletion_reason"), str):
                problems.append({"i": i, "why": "tombstone needs deletion_reason and deleted_at (RFC 3339) (§9.3)"})
            if d.get("original_action_type") not in ACTION_TYPES:
                problems.append({"i": i, "why": "tombstone original_action_type not in vocabulary (§9.3)"})
            try:
                if _RFC3339.match(str(d.get("deleted_at", ""))) and _RFC3339.match(ts) and _parse_ts(d["deleted_at"]) < _parse_ts(ts):
                    problems.append({"i": i, "why": "tombstone deleted_at earlier than the record's own timestamp"})
            except ValueError:
                pass
            if r.get("outcome") != "success":
                problems.append({"i": i, "why": "tombstone outcome MUST be success (§9.3)"})
        elif "tombstone_hash" in r:
            problems.append({"i": i, "why": "tombstone_hash on a record that is not a tombstone"})
        # §8.3 close
        if r.get("action_type") == "lifecycle" and d.get("event") == "session_end":
            if i != len(records) - 1:
                problems.append({"i": i, "why": "session_end is not the last record (§8.3)"})
            if i > 0 and prev is not None:
                if not _hex64(d.get("session_hash")):
                    problems.append({"i": i, "why": "close record without session_hash (§8.3 MUST)"})
                elif len(prev_hashes_raw) == i:
                    exp_sh = hashlib.sha256(b"".join(prev_hashes_raw)).hexdigest()
                    if d["session_hash"] != exp_sh:
                        problems.append({"i": i, "why": f"session_hash mismatch (expected {_SESSION_HASH_NOTE})"})
                if "record_count" in d and d["record_count"] != len(records):
                    warnings.append({"i": i, "why": f"record_count {d['record_count']} != {len(records)} records in the chain (§8.3 SHOULD)"})
        # signatures — a tombstone is verified like any record (its signature must be the deleting authority's, over
        # the tombstone content); an UNSIGNED tombstone is accepted only when nothing asked for signatures, with a warning
        if "signature" in r:
            if not canonical_ok:
                problems.append({"i": i, "why": "signature not verifiable: record not canonicalizable"})
            else:
                ok, why, hyb = _verify_record_signatures(r, keyset)
                if ok:
                    signed_ok += 1
                    hybrid_ok += 1 if hyb else 0
                    if "high-S" in why:
                        warnings.append({"i": i, "why": "ES256 signature in high-S form: malleable (r, n−s) — an outsider can change this record's hash, not its content"})
                elif is_tomb:
                    problems.append({"i": i, "why": f"tombstone signature does not verify over the tombstone content ({why}): either the draft's "
                                                    "retained original signature (unverifiable — this module requires the deleting authority's) or a forgery"})
                else:
                    problems.append({"i": i, "why": f"signature invalid: {why}"})
        elif require_signatures or keys_given:
            problems.append({"i": i, "why": ("tombstone without a signature of the deleting authority while the chain is verified with keys (§9.3 + review 2026-09-19)"
                                             if is_tomb else "unsigned record while signatures are required / a verification key was given "
                                                             "(a signed prefix with an unsigned continuation is a rewrite)")})
        elif is_tomb:
            warnings.append({"i": i, "why": "unsigned tombstone accepted on tombstone_hash alone (§9.3): in an unsigned chain any record can be replaced this way"})
        et = r.get("external_timestamp")
        if isinstance(et, dict) and isinstance(et.get("token"), str) and not external_timestamp_ca_file:
            warnings.append({"i": i, "why": "external_timestamp recorded, NOT verified (no external_timestamp_ca_file): its time is unproven"})
        if isinstance(et, dict) and isinstance(et.get("token"), str) and external_timestamp_ca_file and canonical_ok:
            from .. import timestamp as _ts
            # ONE pre-image: the record's own digest. A token over an epoch root cannot sit inside a record of that epoch
            # (adding it changes the record's leaf hash, so no inclusion proof can bind the two — measured, review round 4):
            # epoch-root tokens live in the epoch anchor and are checked by verify_epochs.
            imprint = hashlib.sha256(jcs({k: v for k, v in r.items() if k not in SIGNATURE_VALUE_FIELDS + ("batch", "external_timestamp")},
                                         strict=False)).hexdigest()
            verdicts = [_ts.verify(et["token"], imprint, ca_file=external_timestamp_ca_file)]
            if not any(v.get("verified") is True for v in verdicts):
                problems.append({"i": i, "why": "external_timestamp token not verified over this record's digest: " + str(verdicts[0].get("note"))})
        prev = r
    ld = records[-1].get("action_detail") if records and isinstance(records[-1], dict) and isinstance(records[-1].get("action_detail"), dict) else {}
    if records and isinstance(records[-1], dict) and not (records[-1].get("action_type") == "lifecycle" and ld.get("event") == "session_end"):
        warnings.append({"i": len(records) - 1, "why": "no session close: the session is orphaned or the chain was truncated to a valid prefix (§8.3) — undetectable without the close or an external anchor"})
    if keyset.bad:
        problems.append({"i": -1, "why": f"keys rejected (not a P-256 PEM / 1952-byte ML-DSA-65 key, or kid != thumbprint of the key): {keyset.bad}"})
    return {"ok": not problems, "records": len(records), "problems": problems, "warnings": warnings,
            "signatures_verified": signed_ok, "hybrid_verified": hybrid_ok, "tombstones": tombstones,
            "keys_rejected": list(keyset.bad), "draft": AAT_DRAFT,
            "scope": ("chain + vocabularies + §4.2/§5/§7/§8/§9/§13 rules + every signature present (ES256, ML-DSA-65, hybrid), "
                      "offline; does not prove the truth of the actions, only that the sequence was not altered since the "
                      "hashes were written. DECLARED LIMIT: without signatures the LAST record can be altered undetected "
                      "and a whole chain can be regenerated from scratch, and any record can be replaced by an unsigned "
                      "tombstone (§9.3); even with signatures, truncation to a valid prefix is undetectable here — a session close "
                      "carried elsewhere, or an external anchor (verify_epochs with a verified TSA token and require_complete) "
                      "make it detectable. §4.3 (a pre-execution record before every state-changing action of a high-risk "
                      "system) is not checked: which actions change state is not in the record. Batch objects are checked by verify_epochs "
                      "against their anchors, not here.")}


def _safe_pred(fn: Callable[[Dict[str, Any]], bool], r: Dict[str, Any]) -> bool:
    try:
        return bool(fn(r))
    except Exception:  # noqa: BLE001 — a failing predicate never silently clears a record
        return True


# ── keys, thumbprints (RFC 7638 / AKP) and signatures (§6.2) ─────────────────────────────────
def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64u_dec(s: str) -> bytes:
    if "=" in s or "+" in s or "/" in s or not s:
        raise ValueError("base64url without padding required (RFC 4648 §5)")
    raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    if _b64u(raw) != s:
        raise ValueError("base64url not canonical")
    return raw


def _thumbprint(members: Dict[str, str]) -> str:
    """RFC 7638 §3: SHA-256 over the UTF-8 of the JSON object with ONLY the required members, keys in lexicographic
    order, no whitespace, then base64url without padding."""
    return _b64u(hashlib.sha256(json.dumps(members, separators=(",", ":"), sort_keys=True).encode()).digest())


def p256_thumbprint(pubkey_pem: bytes) -> str:
    """RFC 7638 JWK thumbprint of an EC P-256 key: {"crv":"P-256","kty":"EC","x":...,"y":...}."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    pk = serialization.load_pem_public_key(pubkey_pem)
    if not isinstance(pk, ec.EllipticCurvePublicKey) or pk.curve.name != "secp256r1":
        raise ValueError("ES256 needs an ECDSA P-256 (secp256r1) public key")
    nums = pk.public_numbers()
    return _thumbprint({"crv": "P-256", "kty": "EC", "x": _b64u(nums.x.to_bytes(32, "big")), "y": _b64u(nums.y.to_bytes(32, "big"))})


def mldsa65_thumbprint(public_key: bytes) -> str:
    """AKP JWK thumbprint (draft-ietf-cose-dilithium-11 §6): {"alg":"ML-DSA-65","kty":"AKP","pub":b64url(raw key)};
    reproduces the kid of the draft's own ML-DSA-65 JWK example (tested)."""
    if len(public_key) != 1952:
        raise ValueError("ML-DSA-65 public key is 1952 bytes")
    return _thumbprint({"alg": "ML-DSA-65", "kty": "AKP", "pub": _b64u(public_key)})


def _signing_input(rec: Dict[str, Any]) -> bytes:
    """§6.2 step 3: SHA-256(JCS(record without the signature-VALUE fields and the detached batch))."""
    return hashlib.sha256(jcs({k: v for k, v in rec.items() if k not in SIGNATURE_VALUE_FIELDS and k != "batch"}, strict=False)).digest()


def _pq_pub_raw(pq_signer: Any) -> bytes:
    pk = getattr(pq_signer, "public_key_b64", None)
    raw = base64.b64decode(pk, validate=True) if isinstance(pk, str) else b""
    if len(raw) != 1952:
        raise ValueError("pq_signer must expose a strict base64 ML-DSA-65 public_key_b64 (1952 bytes)")
    return raw


P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _es256_sign(msg: bytes, private_key_pem: bytes) -> Tuple[str, str]:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, Prehashed
    sk = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(sk, ec.EllipticCurvePrivateKey) or sk.curve.name != "secp256r1":
        raise ValueError("ES256 signatures require an ECDSA P-256 (secp256r1) key")
    der = sk.sign(msg, ec.ECDSA(Prehashed(hashes.SHA256())))
    r, s = decode_dss_signature(der)
    s = min(s, P256_ORDER - s)                     # low-S: one canonical signature per (key, message) — see _es256_verify
    pub = sk.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return _b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big")), p256_thumbprint(pub)


def sign_record(rec: Dict[str, Any], key: Any) -> Dict[str, Any]:
    """§6.2: `key` = ECDSA P-256 private PEM bytes → ES256 (IEEE P1363 r||s, base64url), or an ML-DSA-65 signer object
    (`.sign(bytes)`, `.public_key_b64`) → ML-DSA-65 raw signature (empty context) over the 32-byte hash. Sets `sig_alg`
    and `signer_kid` BEFORE signing (they are covered). Sign BEFORE computing the next record's prev_hash."""
    out = {k: v for k, v in rec.items() if k not in SIGNATURE_VALUE_FIELDS + ("signer_kid_classical",)}
    if isinstance(key, (bytes, bytearray)):
        out["sig_alg"] = "ES256"
        from cryptography.hazmat.primitives import serialization
        sk = serialization.load_pem_private_key(bytes(key), password=None)
        out["signer_kid"] = p256_thumbprint(sk.public_key().public_bytes(serialization.Encoding.PEM,
                                                                          serialization.PublicFormat.SubjectPublicKeyInfo))
        out["signature"], _ = _es256_sign(_signing_input(out), bytes(key))
        return out
    out["sig_alg"] = "ML-DSA-65"
    out["signer_kid"] = mldsa65_thumbprint(_pq_pub_raw(key))
    sig = key.sign(_signing_input(out))
    if len(sig) != 3309:
        raise ValueError("ML-DSA-65 signature is 3309 bytes")
    out["signature"] = _b64u(sig)
    return out


def sign_record_hybrid(rec: Dict[str, Any], pq_signer: Any, classical_private_key_pem: bytes) -> Dict[str, Any]:
    """§6.2 hybrid mode: `signature` = ML-DSA-65 under `signer_kid`, `signature_classical` = ES256 under a DISTINCT
    `signer_kid_classical`, both over the single signed message (which covers sig_alg and both kids)."""
    out = {k: v for k, v in rec.items() if k not in SIGNATURE_VALUE_FIELDS}
    out["sig_alg"] = "ML-DSA-65"
    out["signer_kid"] = mldsa65_thumbprint(_pq_pub_raw(pq_signer))
    from cryptography.hazmat.primitives import serialization
    sk = serialization.load_pem_private_key(classical_private_key_pem, password=None)
    out["signer_kid_classical"] = p256_thumbprint(sk.public_key().public_bytes(serialization.Encoding.PEM,
                                                                                 serialization.PublicFormat.SubjectPublicKeyInfo))
    if out["signer_kid_classical"] == out["signer_kid"]:
        raise ValueError("hybrid mode needs two distinct keys")
    msg = _signing_input(out)
    sig = pq_signer.sign(msg)
    if len(sig) != 3309:
        raise ValueError("ML-DSA-65 signature is 3309 bytes")
    out["signature"] = _b64u(sig)
    out["signature_classical"], _ = _es256_sign(msg, classical_private_key_pem)
    return out


class _KeySet:
    """kid → ("ES256", pem bytes) | ("ML-DSA-65", raw 1952 bytes), each kid CHECKED to be the RFC 7638 / AKP thumbprint of
    its key (a poisoned map cannot relabel a key as the agent's or the recorder's — review round 5); `pubkey_pem` doubles
    as the -03 fallback key."""

    def __init__(self, keys: Optional[Dict[str, Any]], pubkey_pem: Optional[bytes]):
        self.by_kid: Dict[str, Tuple[str, bytes]] = {}
        self.fallback: Optional[bytes] = pubkey_pem
        self.allow_legacy = False
        self.bad: List[str] = []
        if keys is not None and not isinstance(keys, dict):
            self.bad.append("<keys is not a dict>")
            keys = {}
        for kid, k in (keys or {}).items():
            try:
                if isinstance(k, str):
                    k = k.encode() if k.lstrip().startswith("-----") else base64.b64decode(k, validate=True)
                if isinstance(k, (bytes, bytearray)) and bytes(k).lstrip().startswith(b"-----"):
                    alg, tp = "ES256", p256_thumbprint(bytes(k))
                elif isinstance(k, (bytes, bytearray)) and len(k) == 1952:
                    alg, tp = "ML-DSA-65", mldsa65_thumbprint(bytes(k))
                else:
                    self.bad.append(str(kid)); continue
                if tp != str(kid):                        # signer_kid is self-certifying: a mislabelled key set is not a key set
                    self.bad.append(str(kid)); continue
                self.by_kid[str(kid)] = (alg, bytes(k))
            except Exception:  # noqa: BLE001 — unparsable key, or no cryptography: rejected, reported
                self.bad.append(str(kid))
        if pubkey_pem is not None:
            try:
                self.by_kid.setdefault(p256_thumbprint(pubkey_pem), ("ES256", pubkey_pem))
            except Exception:  # noqa: BLE001 — no cryptography, or not a P-256 key: reported, never silent
                self.bad.append("<pubkey_pem is not a P-256 public PEM>")
                self.fallback = None

    def resolve(self, kid: Optional[str], alg: str) -> Optional[Tuple[str, bytes]]:
        if kid is None:
            return ("ES256", self.fallback) if (self.allow_legacy and alg == "ES256" and self.fallback is not None) else None
        return self.by_kid.get(kid)


def _es256_verify(rec: Dict[str, Any], sig_b64u: str, pubkey_pem: bytes, msg: bytes) -> Tuple[bool, str]:
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, Prehashed
    except ImportError:
        return False, "cryptography not installed: signature NOT verified"
    try:
        raw = _b64u_dec(sig_b64u)
    except ValueError as ex:
        return False, str(ex)
    try:
        pk = serialization.load_pem_public_key(pubkey_pem)
        if not isinstance(pk, ec.EllipticCurvePublicKey) or pk.curve.name != "secp256r1":
            return False, "key is not P-256"
        if len(raw) != 64:
            return False, "signature is not 64 bytes (IEEE P1363 r||s)"
        r_, s_ = int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
        der = encode_dss_signature(r_, s_)
        pk.verify(der, msg, ec.ECDSA(Prehashed(hashes.SHA256())))
        # ECDSA malleability: (r, n−s) verifies too, and `signature` is inside the next prev_hash / the Merkle leaf, so a
        # third party can change a record's HASH (not its content) — the draft mandates no low-S; this module emits low-S
        # and reports a high-S signature (declared, review round 5) rather than refusing foreign chains
        return True, ("ok" if s_ <= P256_ORDER // 2 else "ok (high-S: malleable ECDSA form, the record's hash is not unique)")
    except Exception as ex:  # noqa: BLE001
        return False, type(ex).__name__


def _mldsa_verify(sig_b64u: str, pub_raw: bytes, msg: bytes) -> Tuple[bool, str]:
    try:
        from ..pqbackends import mldsa as _m
    except ImportError:
        return False, "ML-DSA-65 backend not present in this build: NOT verified"
    if not _m.available():
        return False, "ML-DSA-65 not verifiable on this host (cryptography >= 48 needed): NOT verified"
    try:
        raw = _b64u_dec(sig_b64u)
    except ValueError as ex:
        return False, str(ex)
    if len(raw) != 3309:
        return False, "signature is not 3309 bytes (ML-DSA-65)"
    return (True, "ok") if _m.verify_raw(pub_raw, msg, raw) else (False, "ML-DSA-65 verification failed")


def _verify_record_signatures(rec: Dict[str, Any], keyset: _KeySet) -> Tuple[bool, str, bool]:
    """(ok, reason, hybrid_ok). §6.3 step 3 with -03 fallback; hybrid: both must pass (declared, stricter than MAY).
    Never raises: a record that cannot be canonicalized or a malformed field is (False, reason, False)."""
    try:
        return _verify_record_signatures_inner(rec, keyset)
    except (ValueError, TypeError, RecursionError) as ex:
        return False, f"not verifiable: {type(ex).__name__}", False


def _verify_record_signatures_inner(rec: Dict[str, Any], keyset: _KeySet) -> Tuple[bool, str, bool]:
    alg = rec.get("sig_alg", "ES256")
    if alg not in SIG_ALGS:
        return False, "sig_alg not in the registry", False
    kid = rec.get("signer_kid")
    if kid is not None and not isinstance(kid, str):
        return False, "signer_kid is not a string", False
    key = keyset.resolve(kid, alg)
    if key is None:
        return False, (f"no key for signer_kid {kid!r}" if kid is not None else
                       "signed record without signer_kid (§3.3 MUST; allow_legacy_03 with pubkey_pem accepts the -03 form)"), False
    if key[0] != alg:
        return False, f"key for {kid!r} is {key[0]}, record says {alg}", False
    msg = _signing_input(rec)
    if not isinstance(rec.get("signature"), str):
        return False, "signature is not a string", False
    ok, why = _es256_verify(rec, rec["signature"], key[1], msg) if alg == "ES256" else _mldsa_verify(rec["signature"], key[1], msg)
    if not ok:
        return False, why, False
    if "signature_classical" in rec:
        ck = keyset.resolve(rec.get("signer_kid_classical"), "ES256") if isinstance(rec.get("signer_kid_classical"), str) else None
        if ck is None or ck[0] != "ES256":
            return False, "hybrid: no ES256 key for signer_kid_classical", False
        if not isinstance(rec["signature_classical"], str):
            return False, "hybrid: signature_classical is not a string", False
        cok, cwhy = _es256_verify(rec, rec["signature_classical"], ck[1], msg)
        if not cok:
            return False, f"hybrid: signature_classical invalid: {cwhy}", False
        return True, cwhy, True
    return True, why, False


def verify_signature(rec: Dict[str, Any], pubkey_pem: bytes) -> Tuple[bool, str]:
    """Back-compatible single-key check (ES256; a record without signer_kid is accepted with the -03 rule)."""
    ks = _KeySet(None, pubkey_pem)
    ks.allow_legacy = True
    ok, why, _ = _verify_record_signatures(rec, ks)
    return ok, why


def generate_p256_keypair() -> Tuple[bytes, bytes]:
    """(private_pem, public_pem) — test/pilot helper; production keys belong in an HSM."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    sk = ec.generate_private_key(ec.SECP256R1())
    priv = sk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    pub = sk.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return priv, pub


# ── §10 export formats ───────────────────────────────────────────────────────────────────────
def to_jsonl(records: List[Dict[str, Any]]) -> str:
    """§10.1: one JSON object per line, chain order, UTF-8 without BOM, '\n' separators (the JSON is the JCS form so
    the file re-reads to the same hashes)."""
    return "".join(jcs(r, strict=False).decode() + "\n" for r in records)


def from_jsonl(text: str) -> List[Dict[str, Any]]:
    out = []
    for n, line in enumerate(text.split("\n")):
        if line == "":
            continue
        try:
            obj = json.loads(line, parse_constant=_no_constant, parse_float=_finite_float, object_pairs_hook=_no_dup_keys)
        except json.JSONDecodeError as ex:
            raise ValueError(f"JSONL line {n + 1}: {ex.msg}") from None
        except ValueError as ex:
            raise ValueError(f"JSONL line {n + 1}: {ex}") from None
        except RecursionError:
            raise ValueError(f"JSONL line {n + 1}: nesting too deep") from None
        if not isinstance(obj, dict):
            raise ValueError(f"JSONL line {n + 1}: not a JSON object")
        out.append(obj)
    return out


def _no_constant(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def _finite_float(text: str) -> float:
    f = float(text)
    if f != f or f in (float("inf"), float("-inf")):
        raise ValueError(f"number {text} is not representable as a finite double")
    return f


def _no_dup_keys(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    d: Dict[str, Any] = {}
    for k, v in pairs:
        if k in d:
            raise ValueError(f"duplicate key {k!r} (first-wins and last-wins parsers would read different evidence)")
        d[k] = v
    return d


CSV_COLUMNS = ("record_id", "timestamp", "agent_id", "agent_version", "session_id", "action_type", "outcome",
               "trust_level", "record_phase", "parent_record_id", "prev_hash", "action_detail")


def to_csv(records: List[Dict[str, Any]]) -> str:
    """§10.3: RFC 4180 CSV with the draft's header row; action_detail as JSON. LOSSY (optional fields, signatures and
    batch objects are not exported) and MUST NOT be the authoritative record — keep the JSONL."""
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n")
    w.writerow(CSV_COLUMNS)
    for r in records:
        w.writerow([_csv_safe(json.dumps(r.get(c), separators=(",", ":"), sort_keys=True, allow_nan=False) if c == "action_detail"
                              else ("" if r.get(c) is None else str(r.get(c)))) for c in CSV_COLUMNS])
    return buf.getvalue()


def _csv_safe(v: str) -> str:
    """A cell starting with = + - @ or a tab/CR would be run as a formula by spreadsheet tools (CSV injection): prefixed
    with a single quote, as OWASP recommends. The CSV is for human review, never the authoritative record (§10.3)."""
    return "'" + v if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v


# ── CLI ─────────────────────────────────────────────────────────────────────────────────────
def _load_key_arg(spec: str) -> Tuple[str, Any]:
    """`kid=path` → (kid, key bytes): a PEM file is an ES256 key, a 1952-byte file (raw) or a base64 text file is
    ML-DSA-65."""
    if "=" not in spec:
        raise ValueError("--key expects kid=path")
    kid, path = spec.split("=", 1)
    with open(path, "rb") as f:
        data = f.read()
    if data.lstrip().startswith(b"-----"):
        return kid, data
    if len(data) == 1952:
        return kid, data
    return kid, base64.b64decode(data.strip(), validate=True)


def main(argv: Optional[List[str]] = None) -> int:
    """`python -m omega_evidence.interop.aat verify <chain.jsonl> [--key kid=file ...] [--pubkey pem] [--agent-kid KID]
    [--require-signatures] [--epochs anchors.json] [--tsa-ca pem]` prints the verdict as JSON (exit 0 only when ok);
    `... csv <chain.jsonl>` prints the §10.3 CSV."""
    import argparse
    p = argparse.ArgumentParser(prog="omega-evidence-aat")
    sub = p.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify", help="verify an AAT (-04) chain offline")
    v.add_argument("chain", help="JSONL, one record per line, genesis first")
    v.add_argument("--key", action="append", default=[], help="kid=path (P-256 PEM, or raw/base64 ML-DSA-65 public key)")
    v.add_argument("--pubkey", help="P-256 public PEM: -03 fallback key (records without signer_kid)")
    v.add_argument("--agent-kid", help="RFC 7638 thumbprint of the agent's key (independent recording check)")
    v.add_argument("--require-signatures", action="store_true")
    v.add_argument("--epochs", help="JSON array of epoch anchors (from anchor_epoch) to check batch objects against")
    v.add_argument("--tsa-ca", help="PEM trust anchor for RFC 3161 tokens (epoch anchors and external_timestamp)")
    v.add_argument("--allow-legacy-03", action="store_true", help="accept signed records without signer_kid, resolved with --pubkey (-03 rule)")
    v.add_argument("--epochs-complete", action="store_true", help="an epoch with anchored leaves missing from the chain is a problem")
    v.add_argument("--tombstone-kid", action="append", default=[], help="kid of a deleting authority allowed to sign tombstones (repeatable)")
    c = sub.add_parser("csv", help="print the chain as §10.3 CSV (lossy, not authoritative)")
    c.add_argument("chain")
    a = p.parse_args(argv)
    try:
        with open(a.chain, encoding="utf-8") as f:
            records = from_jsonl(f.read())
    except (OSError, ValueError, UnicodeDecodeError) as ex:
        print(json.dumps({"ok": False, "error": f"{type(ex).__name__}: {ex}"})); return 2
    if a.cmd == "csv":
        print(to_csv(records), end=""); return 0
    try:
        keys = dict(_load_key_arg(k) for k in a.key)
        pub = open(a.pubkey, "rb").read() if a.pubkey else None
    except (OSError, ValueError) as ex:
        print(json.dumps({"ok": False, "error": f"{type(ex).__name__}: {ex}"})); return 2
    try:
        out = verify_chain(records, pubkey_pem=pub, keys=keys or None, agent_kid=a.agent_kid, require_signatures=a.require_signatures,
                           external_timestamp_ca_file=a.tsa_ca, allow_legacy_03=a.allow_legacy_03, tombstone_kids=a.tombstone_kid or None)
    except Exception as ex:  # noqa: BLE001 — a verifier prints a verdict, never a traceback
        print(json.dumps({"ok": False, "error": f"verifier error: {type(ex).__name__}: {ex}"})); return 2
    if a.epochs:
        try:
            with open(a.epochs, encoding="utf-8") as f:
                anchors = json.load(f, parse_constant=_no_constant)
            if not isinstance(anchors, list):
                raise ValueError("epochs file must be a JSON array")
        except (OSError, ValueError, RecursionError) as ex:
            print(json.dumps({"ok": False, "error": f"{type(ex).__name__}: {ex}"})); return 2
        try:
            out["epochs"] = verify_epochs(records, anchors, tsa_ca_file=a.tsa_ca, require_complete=a.epochs_complete)
        except Exception as ex:  # noqa: BLE001
            print(json.dumps({"ok": False, "error": f"verifier error: {type(ex).__name__}: {ex}"})); return 2
        out["ok"] = bool(out["ok"] and out["epochs"]["ok"])
    print(json.dumps(out, indent=1))
    return 0 if out["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
