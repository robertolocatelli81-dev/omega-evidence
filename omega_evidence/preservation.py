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
omega_evidence.preservation — long-term evidence records with renewal, in the
SEMANTICS of RFC 4998 (Evidence Record Syntax) / eIDAS LTA.

WHY. Records outlive the cryptography that signs them (30-year mortgages,
pensions, land registries). When an algorithm becomes forgeable (e.g. a quantum
threat), every piece of evidence resting on it collapses RETROACTIVELY: you can
no longer tell a genuine old signature from a forged, back-dated one. The known
fix (NOT our invention — RFC 4998 Hash-Tree/Timestamp Renewal; eIDAS LTA /
PAdES-LTA) is to renew the evidence with a STRONGER archive timestamp WHILE the
previous one is still trusted, chaining them. As long as each renewal happens
before the previous algorithm breaks, the chain proves the evidence existed and
was valid at that moment.

HONEST SCOPE (mandatory, embedded in every record):
  * NOT a qualified preservation service / QTSP; NOT a conformity assessment.
  * NOT the ASN.1/DER wire format of RFC 4998 — this is the renewal SEMANTICS in
    a self-describing JSON record a QTSP would RE-ENCODE, not ingest directly.
  * The pivot is the TIME ORACLE, not the chain of hashes: "the evidence existed
    before the break" holds only if the renewal TIME comes from an independent
    trusted source (RFC 3161 TSA / public anchor) that is itself still trustworthy
    at renewal. Where no TSA is available the timestamp is `asserted` and the
    record says so (fail-open is flagged, not hidden) — an asserted time is NOT
    proof of time.

Self-contained: Python stdlib (+ optional openssl via `timestamp`). Apache-2.0.
The structural verification (Merkle roots + renewal chaining) is fully OFFLINE.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .canonical import canonical_json

_SUPPORTED_HASH = ("sha256", "sha512", "sha3_256", "sha3_512")
RECORD_KIND = "omega_evidence_record"
HONEST_SCOPE = ("long-term evidence with RFC 4998-style renewal SEMANTICS; NOT a "
                "qualified preservation service/QTSP, NOT the ASN.1/DER ERS wire "
                "format, NOT proof of time by itself (an asserted timestamp proves "
                "nothing — trusted time must come from a TSA/anchor)")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _hnew(alg: str):
    if alg not in _SUPPORTED_HASH:
        raise ValueError(f"unsupported hash alg: {alg} (use one of {_SUPPORTED_HASH})")
    return hashlib.new(alg)


def _digest(alg: str, data: bytes) -> str:
    h = _hnew(alg)
    h.update(data)
    return h.hexdigest()


def _merkle_root(leaf_hexes: List[str], alg: str) -> str:
    """Binary Merkle root over leaf digests (odd node duplicated), in `alg`."""
    if not leaf_hexes:
        return _digest(alg, b"")
    level = [bytes.fromhex(h) for h in leaf_hexes]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            a = level[i]
            b = level[i + 1] if i + 1 < len(level) else level[i]
            h = _hnew(alg)
            h.update(a + b)
            nxt.append(h.digest())
        level = nxt
    return level[0].hex()


def _pack_sha3_of(pack_path: str) -> str:
    import json
    d = json.loads(Path(pack_path).read_text(encoding="utf-8"))
    v = d.get("pack_sha3", "")
    if not v:
        raise ValueError(f"{pack_path}: not an evidence pack (no pack_sha3)")
    return v


def _leaves(pack_sha3_list: List[str], alg: str) -> List[str]:
    return [_digest(alg, s.encode()) for s in pack_sha3_list]


def _timestamp_root(root_hex: str, tsa_url: Optional[str]) -> Dict[str, Any]:
    """RFC 3161 timestamp of the Merkle root if a TSA (and openssl) is available;
    otherwise an explicit `asserted` time (flagged, never a silent claim of time)."""
    if tsa_url:
        from .timestamp import stamp
        r = stamp(root_hex, tsa_url)
        if r.get("anchored"):
            return {"time_source": "rfc3161", "tsa": r.get("tsa", ""),
                    "tsr_b64": r.get("tsr_b64", ""), "stamped_utc": _now()}
        return {"time_source": "asserted", "note": r.get("note", "TSA unavailable"),
                "stamped_utc": _now()}
    return {"time_source": "asserted", "note": "no TSA supplied", "stamped_utc": _now()}


def _finalize(record: Dict[str, Any]) -> Dict[str, Any]:
    record["record_sha3"] = _digest(
        "sha3_256", canonical_json({k: v for k, v in record.items() if k != "record_sha3"}))
    return record


def build_evidence_record(pack_paths: List[str], tsa_url: Optional[str] = None,
                          hash_alg: str = "sha256") -> Dict[str, Any]:
    """Seal a set of evidence packs into a renewable long-term record: a Merkle
    root over their pack_sha3 values, timestamped (RFC 3161 if available)."""
    pack_sha3 = [_pack_sha3_of(p) for p in pack_paths]
    leaves = _leaves(pack_sha3, hash_alg)
    root = _merkle_root(leaves, hash_alg)
    ats0 = {"seq": 0, "type": "initial", "hash_alg": hash_alg,
            "leaves": leaves, "merkle_root": root, "covers": "data-objects",
            "timestamp": _timestamp_root(root, tsa_url), "created_utc": _now()}
    return _finalize({"kind": RECORD_KIND, "honest_scope": HONEST_SCOPE,
                      "data_objects": [{"pack_sha3": s} for s in pack_sha3],
                      "archive_timestamps": [ats0]})


def _prev_binding(prev_ats: Dict[str, Any], alg: str) -> str:
    """Digest of the previous archive-timestamp entry, binding the chain."""
    return _digest(alg, canonical_json(prev_ats))


def renew_timestamp(record: Dict[str, Any], tsa_url: Optional[str] = None) -> Dict[str, Any]:
    """Timestamp Renewal (RFC 4998): re-timestamp the previous entry with a fresh
    token, BEFORE the old token's algorithm/TSA weakens. Same hash algorithm —
    it renews the TIME, chaining the new token over the old one."""
    prev = record["archive_timestamps"][-1]
    alg = prev["hash_alg"]
    binding = _prev_binding(prev, alg)
    ats = {"seq": prev["seq"] + 1, "type": "timestamp-renewal", "hash_alg": alg,
           "covers": "previous-archive-timestamp", "prev_binding": binding,
           "timestamp": _timestamp_root(binding, tsa_url), "created_utc": _now()}
    record["archive_timestamps"].append(ats)
    return _finalize(record)


def renew_hash_tree(record: Dict[str, Any], pack_paths: List[str], new_hash_alg: str,
                    tsa_url: Optional[str] = None) -> Dict[str, Any]:
    """Hash-Tree Renewal (RFC 4998): when the data hash weakens, rebuild the tree
    with a STRONGER algorithm over the data objects AND all previous evidence, and
    timestamp the new root. This carries the proof of existence across the
    algorithm change so the chain of custody stays verifiable offline."""
    if new_hash_alg not in _SUPPORTED_HASH:
        raise ValueError(f"unsupported hash alg: {new_hash_alg}")
    prev = record["archive_timestamps"][-1]
    pack_sha3 = [d["pack_sha3"] for d in record["data_objects"]]
    if pack_paths is not None:
        # bind to the real data objects: they must still hash to the record
        if [_pack_sha3_of(p) for p in pack_paths] != pack_sha3:
            raise ValueError("pack_paths do not match the record's data objects")
    # new leaves = data objects re-hashed with the stronger alg, PLUS a binding to
    # the whole previous archive-timestamp chain (so nothing is dropped)
    leaves = _leaves(pack_sha3, new_hash_alg)
    chain_binding = _digest(new_hash_alg, canonical_json(record["archive_timestamps"]))
    leaves = leaves + [chain_binding]
    root = _merkle_root(leaves, new_hash_alg)
    ats = {"seq": prev["seq"] + 1, "type": "hash-tree-renewal", "hash_alg": new_hash_alg,
           "leaves": leaves, "merkle_root": root, "covers": "data-objects+previous-chain",
           "chain_binding": chain_binding,
           "timestamp": _timestamp_root(root, tsa_url), "created_utc": _now()}
    record["archive_timestamps"].append(ats)
    return _finalize(record)


def renewal_due(record: Dict[str, Any], weak_algs: List[str]) -> Dict[str, Any]:
    """Flag whether the latest archive timestamp uses an algorithm now considered
    weak — i.e. a renewal is due before it breaks."""
    last = record["archive_timestamps"][-1]
    due = last["hash_alg"] in set(weak_algs)
    return {"due": due, "current_hash_alg": last["hash_alg"],
            "reason": "current hash algorithm flagged weak" if due else "current algorithm not flagged"}


def verify_evidence_record(record: Dict[str, Any],
                           pack_paths: Optional[List[str]] = None) -> Dict[str, Any]:
    """Verify a long-term evidence record OFFLINE: record integrity, the initial
    Merkle root, and every renewal binding across algorithm changes. Optionally
    bind to the real packs. RFC 3161 tokens are reported (SKIP without openssl;
    an `asserted` time is reported as NOT trusted-time)."""
    layers: List[Dict[str, str]] = []

    def add(name, ok, detail="", skip=False):
        layers.append({"layer": name, "status": "SKIP" if skip else ("PASS" if ok else "FAIL"),
                       "detail": detail})

    # 1) record self-integrity
    recomputed = _digest("sha3_256", canonical_json(
        {k: v for k, v in record.items() if k != "record_sha3"}))
    add("record-sha3", record.get("record_sha3") == recomputed)

    ats = record.get("archive_timestamps", [])
    add("has-archive-timestamps", bool(ats), f"{len(ats)} entr{'y' if len(ats)==1 else 'ies'}")

    pack_sha3 = [d.get("pack_sha3", "") for d in record.get("data_objects", [])]
    if pack_paths is not None:
        add("data-objects-bound", [_pack_sha3_of(p) for p in pack_paths] == pack_sha3,
            "packs match the record's data objects")

    # 2) initial Merkle root
    if ats:
        a0 = ats[0]
        expect = _merkle_root(_leaves(pack_sha3, a0["hash_alg"]), a0["hash_alg"])
        add("initial-merkle-root", a0.get("merkle_root") == expect and
            a0.get("leaves") == _leaves(pack_sha3, a0["hash_alg"]),
            f"seq0 {a0['hash_alg']}")

    # 3) renewal chain — every entry binds the previous one
    for i in range(1, len(ats)):
        cur, prev = ats[i], ats[i - 1]
        alg = cur["hash_alg"]
        if cur.get("type") == "timestamp-renewal":
            ok = cur.get("prev_binding") == _prev_binding(prev, alg)
            add(f"renewal[{i}]-timestamp", ok, "binds previous archive timestamp")
        elif cur.get("type") == "hash-tree-renewal":
            data_leaves = _leaves(pack_sha3, alg)
            chain_binding = _digest(alg, canonical_json(ats[:i]))
            expect_leaves = data_leaves + [chain_binding]
            ok = (cur.get("chain_binding") == chain_binding and
                  cur.get("leaves") == expect_leaves and
                  cur.get("merkle_root") == _merkle_root(expect_leaves, alg))
            add(f"renewal[{i}]-hash-tree", ok, f"re-hashed to {alg}, carries previous chain")
        else:
            add(f"renewal[{i}]-type", False, f"unknown renewal type: {cur.get('type')}")

    # 4) time source — trusted vs asserted (never a false claim of time)
    for i, a in enumerate(ats):
        ts = a.get("timestamp", {})
        if ts.get("time_source") == "rfc3161":
            from .timestamp import verify as ts_verify
            covered = a.get("merkle_root") or a.get("prev_binding") or ""
            r = ts_verify(ts.get("tsr_b64", ""), covered)
            st = r.get("status", "")
            if st == "unavailable":
                add(f"time[{i}]-rfc3161", True, "openssl absent — token present, not verified here", skip=True)
            else:
                add(f"time[{i}]-rfc3161", st == "valid", ts.get("tsa", ""))
        else:
            add(f"time[{i}]-asserted", True, "asserted time — NOT trusted time", skip=True)

    checked = [x for x in layers if x["status"] in ("PASS", "FAIL")]
    valid = bool(checked) and all(x["status"] == "PASS" for x in checked)
    return {"valid": valid, "layers": layers, "verified_utc": _now()}
