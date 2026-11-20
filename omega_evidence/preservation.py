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
    """The pack's digest recomputed from its body, which must equal the declared `pack_sha3` (ValueError otherwise) —
    the rule of `pack.sign_pack` and `pack.anchor_pack`. Until 35e8c40 the declared field was returned as read: a pack
    file whose `pack_sha3` named another pack's body was preserved, renewed and reported `data-objects-bound` PASS as
    that other pack (measured 20/11/2026)."""
    from .pack import _recomputed_digest
    return _recomputed_digest(pack_path, "evidence record")


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
                           pack_paths: Optional[List[str]] = None,
                           tsa_ca_file: Optional[str] = None) -> Dict[str, Any]:
    """Verify a long-term evidence record OFFLINE: record integrity, the initial
    Merkle root, and every renewal binding across algorithm changes. Optionally
    bind to the real packs. An RFC 3161 token is verified with openssl against `tsa_ca_file`
    (the TSA's trusted roots) and is PASS or FAIL; without openssl or without `tsa_ca_file` it is
    SKIP, not verified (timestamp.verify returns verified: None, never a green); with openssl present but not
    runnable here (not started, no answer within the timeout, no temporary file) timestamp.CheckNotRun is raised,
    never a PASS or a FAIL of the token (0.11.4). An entry that declares
    `time_source: rfc3161` without a token (`tsr_b64` missing, empty or not a string) is a FAIL, with or
    without `tsa_ca_file`: the claim of trusted time has no proof to verify, now or later (RFC 4998 §4.1).
    A pack of `pack_paths` that cannot be read as an evidence pack is a FAIL of
    `data-objects-bound`, not of the record. An
    `asserted` time is reported as NOT trusted-time; a `time_source` that is neither `rfc3161` nor `asserted` (or none) is a
    FAIL (20/11/2026). A malformed record (missing
    or unsupported hash_alg, wrong types) is `valid: false` with a FAIL layer, never
    an exception (audit V2 #6, 30/09/2026)."""
    if not isinstance(record, dict):
        return {"valid": False, "layers": [{"layer": "record-malformed", "status": "FAIL",
                                             "detail": "record is not a JSON object"}], "verified_utc": _now()}
    try:
        return _verify_evidence_record(record, pack_paths, tsa_ca_file)
    except (KeyError, TypeError, AttributeError, ValueError, IndexError, RecursionError) as e:
        return {"valid": False, "layers": [{"layer": "record-malformed", "status": "FAIL",
                                             "detail": f"{type(e).__name__}: {e}"[:200]}], "verified_utc": _now()}


def _verify_evidence_record(record: Dict[str, Any], pack_paths: Optional[List[str]],
                            tsa_ca_file: Optional[str] = None) -> Dict[str, Any]:
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
        try:
            bound = [_pack_sha3_of(p) for p in pack_paths] == pack_sha3
            add("data-objects-bound", bound, "packs match the record's data objects" if bound
                else "packs do NOT match the record's data objects")
        except (OSError, ValueError, AttributeError, RecursionError) as e:   # a bad PACK is not a malformed record
            add("data-objects-bound", False, f"a pack could not be read as an evidence pack: {type(e).__name__}: {e}"[:200])

    # 2) initial Merkle root
    if ats:
        a0 = ats[0]
        expect = _merkle_root(_leaves(pack_sha3, a0["hash_alg"]), a0["hash_alg"])
        add("initial-merkle-root", a0.get("merkle_root") == expect and
            a0.get("leaves") == _leaves(pack_sha3, a0["hash_alg"]),
            f"seq0 {a0['hash_alg']}")

    # 3) renewal chain — every entry binds the previous one
    bound: Dict[int, bool] = {}            # entry i binds entry i-1 (read by step 4: no time crosses a broken link)
    for i in range(1, len(ats)):
        cur, prev = ats[i], ats[i - 1]
        alg = cur["hash_alg"]
        if cur.get("type") == "timestamp-renewal":
            ok = cur.get("prev_binding") == _prev_binding(prev, alg)
            add(f"renewal[{i}]-timestamp", ok, "binds previous archive timestamp")
            bound[i] = ok
        elif cur.get("type") == "hash-tree-renewal":
            data_leaves = _leaves(pack_sha3, alg)
            chain_binding = _digest(alg, canonical_json(ats[:i]))
            expect_leaves = data_leaves + [chain_binding]
            ok = (cur.get("chain_binding") == chain_binding and
                  cur.get("leaves") == expect_leaves and
                  cur.get("merkle_root") == _merkle_root(expect_leaves, alg))
            add(f"renewal[{i}]-hash-tree", ok, f"re-hashed to {alg}, carries previous chain")
            bound[i] = ok
        else:
            add(f"renewal[{i}]-type", False, f"unknown renewal type: {cur.get('type')}")

    # 4) time source — trusted vs asserted (never a false claim of time). RFC 4998 section 5.3 step 2: "Each Archive
    # Timestamp MUST be valid relative to the time of the following Archive Timestamp"; only the last one "has to be
    # valid at the time the verification is performed". So the entries are checked from the last to the first: an RFC
    # 3161 token is checked at the genTime of the NEXT RFC 3161 token (asserted entries in between prove no time and are
    # passed over), or now when there is none, when that token is not verified (FAIL, SKIP, no token), or when an entry
    # between them does not bind the one before it (step 3). A next genTime earlier than this entry's makes it FAIL. A
    # token whose own TSA chain does not verify at its own genTime is FAIL and lends no time (openssl ts -verify does not
    # compare genTime with the signer's validity period). Up to 0.11.4 every token was checked now,
    # so the expiry of a TSA certificate turned a record renewed in time into valid: false (measured 14/11/2026).
    from .timestamp import gen_time_of, verify as ts_verify
    time_layers: List[tuple] = []
    later_gen: Optional[int] = None          # genTime of the nearest later token that verified; None = check now
    for i in range(len(ats) - 1, -1, -1):
        a = ats[i]
        if i + 1 < len(ats) and not bound.get(i + 1, False):   # entry i+1 does not bind this one: its time says nothing
            later_gen = None
        ts = a.get("timestamp", {})
        if ts.get("time_source") == "rfc3161":
            tok = ts.get("tsr_b64")
            if not isinstance(tok, str) or not tok:
                # a declared RFC 3161 time without its token is a malformed entry, not an unverified one: the claim can
                # never be verified, with or without a trust anchor (RFC 4998 §4.1: timeStamp is the one field of
                # ArchiveTimeStamp that is not OPTIONAL; the producer writes it only from a granted reply). Until 0.10.0
                # it was SKIP with valid: true without tsa_ca_file and FAIL with it (audit V2 decision, 04/10/2026).
                time_layers.append((f"time[{i}]-rfc3161", False,
                                    "time_source rfc3161 declared but no token recorded (tsr_b64 missing, empty or not "
                                    "a string)", False))
                later_gen = None
                continue
            # what the token must cover, by entry type: a timestamp renewal covers prev_binding (the previous entry), the
            # initial entry and a hash-tree renewal their merkle_root. Up to the review of 14/11/2026 it was merkle_root
            # first for every type, so a timestamp renewal carrying an extra merkle_root was checked against that value
            # and a token over other data lent its genTime to the entries before it.
            covered = (a.get("prev_binding") if a.get("type") == "timestamp-renewal" else a.get("merkle_root")) or ""
            r = ts_verify(tok, covered, ca_file=tsa_ca_file, at_time=later_gen)
            # timestamp.verify's contract: verified None = recorded, NOT verified (no openssl / no trust anchor);
            # True / False = verified. Until 0.10.0 this read a "status" key that verify() never returns, so every
            # record with an RFC 3161 token was FAIL (audit V2 final round, 02/10/2026).
            if r.get("verified") is None:
                time_layers.append((f"time[{i}]-rfc3161", True, r.get("note", "token recorded, not verified"), True))
                later_gen = None
                continue
            ok = r.get("verified") is True
            when = "checked at " + str(r.get("validated_at", "now")) + (
                " (genTime of the following trusted archive timestamp, RFC 4998 5.3)" if later_gen is not None else "")
            detail = "; ".join(x for x in (ts.get("tsa", "") or r.get("note", ""), when,
                                           "" if ok else str(r.get("reason", ""))) if x)
            gen = gen_time_of(tok) if ok else None
            if ok and gen is not None and not 0 <= gen <= 253402300799:
                ok, detail = False, detail + "; genTime outside 1970-01-01 to 9999-12-31"
                gen = None
            if ok and gen is not None:
                # its genTime is used as a time only if the TSA certificate chain was valid then (RFC 5280 4.1.2.5):
                # openssl ts -verify does not compare genTime with the signer's validity period (measured 14/11/2026)
                own = ts_verify(tok, covered, ca_file=tsa_ca_file, at_time=gen)
                if own.get("verified") is not True:
                    ok, detail = False, detail + "; the TSA certificate chain is not valid at the token's own genTime (" \
                        + str(own.get("reason", "") or own.get("note", "")) + ")"
                    gen = None
            if ok and later_gen is not None and gen is None:     # the order with the following entry cannot be read
                ok, detail = False, detail + "; genTime not readable from the token"
            if ok and later_gen is not None and gen > later_gen:
                ok, detail = False, detail + "; the following archive timestamp is dated before this one"
            time_layers.append((f"time[{i}]-rfc3161", ok, detail, False))
            later_gen = gen if ok else None
        elif ts.get("time_source") == "asserted":
            time_layers.append((f"time[{i}]-asserted", True, "asserted time — NOT trusted time", True))
        else:
            # the producer writes "rfc3161" or "asserted" only (_timestamp_root): any other value, or none, is a malformed
            # entry, never read as "asserted" (20/11/2026: "bogus", "RFC3161" with a token, or no time_source at all gave an
            # asserted SKIP and valid: true)
            time_layers.append((f"time[{i}]-source", False,
                                f"time_source is neither rfc3161 nor asserted: {str(ts.get('time_source'))[:40]!r}", False))
            later_gen = None
    for name, ok, detail, skip in reversed(time_layers):
        add(name, ok, detail, skip=skip)

    checked = [x for x in layers if x["status"] in ("PASS", "FAIL")]
    valid = bool(checked) and all(x["status"] == "PASS" for x in checked)
    return {"valid": valid, "layers": layers, "verified_utc": _now()}
