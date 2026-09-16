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
omega_evidence.trust — TOFU trust registry binding signer_id to public key.

Trust-on-first-use: the same key is idempotent, a different key for the same id
raises, rotation and revocation are explicit. A revoked key is not trusted even
with a valid signature; a revoked key is not silently re-trusted. State is
rebuilt from a hash-chained ledger (provenance). NOT a CA/PKI.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from .ledger import Ledger


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class TrustRegistry:
    def __init__(self, ledger_path: str):
        try:
            self._ledger = Ledger(ledger_path)
        except RuntimeError as e:                  # a broken chain is a broken store, one exception type for callers
            raise ValueError(f"trust store broken: {e}") from e
        self._lock = threading.Lock()
        self._state: Dict[str, Dict[str, Any]] = {}
        # council 16/09 (r1): the registry is replayed only from a chain that passes the STRICT verifier (duplicate
        # keys, floats, idx, links) — the loose loader let a line with two "pubkey" keys trust the second one
        ok, bad = self._ledger.verify()
        if not ok:
            raise ValueError(f"trust store broken: bad line(s) {bad[:5]}")
        for d in self._ledger.entries():
            self._apply(d)

    @staticmethod
    def _key(v: Any, what: str) -> str:
        if not isinstance(v, str) or not v.strip() or v != v.strip():
            raise ValueError(f"{what} must be a non-empty string")
        return v

    def _apply(self, d: Dict[str, Any]) -> None:
        act, sid = d.get("action"), d.get("signer_id")
        if not sid:
            return
        if act == "trust":
            cur = self._state.get(sid)
            if cur and cur.get("revoked"):
                # mirror the live trust() guard on the authoritative reload path:
                # a revoked signer is NOT silently re-trusted by a 'trust' entry
                # (rotate() is the explicit way to re-establish).
                return
            self._state[sid] = {"pubkey": d.get("pubkey"), "pq_pubkey": d.get("pq_pubkey"), "revoked": False, "since": d.get("ts")}
        elif act == "rotate":
            self._state[sid] = {"pubkey": d.get("pubkey"), "pq_pubkey": d.get("pq_pubkey"), "revoked": False, "since": d.get("ts")}
        elif act == "revoke" and sid in self._state:
            self._state[sid]["revoked"] = True
            self._state[sid]["reason"] = d.get("reason")

    def trust(self, signer_id: str, pubkey: str, pq_pubkey: Optional[str] = None) -> Dict[str, Any]:
        """Bind signer_id to its Ed25519 key and, optionally (0.7.0), to its ML-DSA-65 key: the pinned PQ key is
        what lets the verifier report a hybrid pack as pq-protected (a key inside the sidecar proves nothing)."""
        self._key(signer_id, "signer_id"); self._key(pubkey, "pubkey")
        if pq_pubkey is not None:
            self._key(pq_pubkey, "pq_pubkey")
        with self._lock:
            cur = self._state.get(signer_id)
            if cur and cur.get("revoked"):
                raise ValueError(f"signer revoked: {signer_id!r}; use rotate() to re-establish")
            if cur and cur["pubkey"] != pubkey:
                raise ValueError(f"signer already trusted with a different key: {signer_id!r}")
            if cur and cur.get("pq_pubkey") and pq_pubkey and cur["pq_pubkey"] != pq_pubkey:
                raise ValueError(f"signer already trusted with a different post-quantum key: {signer_id!r}")
            if cur and cur["pubkey"] == pubkey and (pq_pubkey is None or cur.get("pq_pubkey") == pq_pubkey):
                return {"trusted": True, "idempotent": True}
            rec = {"action": "trust", "signer_id": signer_id, "pubkey": pubkey, "ts": _now()}
            if pq_pubkey:
                rec["pq_pubkey"] = pq_pubkey
            self._ledger.append(rec)
            self._state[signer_id] = {"pubkey": pubkey, "pq_pubkey": pq_pubkey or (cur or {}).get("pq_pubkey"),
                                      "revoked": False, "since": _now()}
            return {"trusted": True}

    def rotate(self, signer_id: str, pubkey: str, pq_pubkey: Optional[str] = None,
               drop_pq: bool = False) -> Dict[str, Any]:
        """Replace the classical key (also re-establishes a revoked signer). The pinned post-quantum key is KEPT
        unless a new one is given or `drop_pq=True` (council 16/09 r1: a routine Ed25519 rotation silently
        downgraded every hybrid pack of the signer to unpinned). The kept key is written into the record, so an
        independent replay (Go/Java/JS) reads the same state."""
        self._key(signer_id, "signer_id"); self._key(pubkey, "pubkey")
        if pq_pubkey is not None:
            self._key(pq_pubkey, "pq_pubkey")
        with self._lock:
            cur = self._state.get(signer_id) or {}
            kept = None if drop_pq else (pq_pubkey or cur.get("pq_pubkey"))
            rec = {"action": "rotate", "signer_id": signer_id, "pubkey": pubkey, "ts": _now()}
            if kept:
                rec["pq_pubkey"] = kept
            self._ledger.append(rec)
            self._state[signer_id] = {"pubkey": pubkey, "pq_pubkey": kept, "revoked": False, "since": _now()}
            return {"rotated": True, "pq_pubkey_kept": bool(kept and not pq_pubkey)}

    def pq_pubkey(self, signer_id: str) -> Optional[str]:
        """The pinned ML-DSA-65 key of a trusted, non-revoked signer, or None."""
        e = self._state.get(signer_id)
        return e.get("pq_pubkey") if e and not e.get("revoked") else None

    def revoke(self, signer_id: str, reason: str = "") -> Dict[str, Any]:
        with self._lock:
            if signer_id not in self._state:
                raise KeyError(signer_id)
            self._ledger.append({"action": "revoke", "signer_id": signer_id,
                                 "reason": reason, "ts": _now()})
            self._state[signer_id]["revoked"] = True
            self._state[signer_id]["reason"] = reason
            return {"revoked": True}

    def is_trusted(self, signer_id: str, pubkey: str) -> bool:
        e = self._state.get(signer_id)
        return bool(e and not e.get("revoked") and e.get("pubkey") == pubkey)

    def status(self, signer_id: str) -> Dict[str, Any]:
        e = self._state.get(signer_id)
        return {"known": False} if not e else {
            "known": True, "revoked": bool(e.get("revoked")), "reason": e.get("reason")}
