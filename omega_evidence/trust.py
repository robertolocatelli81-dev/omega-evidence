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
from typing import Any, Dict

from .ledger import Ledger


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class TrustRegistry:
    def __init__(self, ledger_path: str):
        self._ledger = Ledger(ledger_path)
        self._lock = threading.Lock()
        self._state: Dict[str, Dict[str, Any]] = {}
        for d in self._ledger.entries():
            self._apply(d)

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
            self._state[sid] = {"pubkey": d.get("pubkey"), "revoked": False, "since": d.get("ts")}
        elif act == "rotate":
            self._state[sid] = {"pubkey": d.get("pubkey"), "revoked": False, "since": d.get("ts")}
        elif act == "revoke" and sid in self._state:
            self._state[sid]["revoked"] = True
            self._state[sid]["reason"] = d.get("reason")

    def trust(self, signer_id: str, pubkey: str) -> Dict[str, Any]:
        with self._lock:
            cur = self._state.get(signer_id)
            if cur and cur.get("revoked"):
                raise ValueError(f"signer revoked: {signer_id!r}; use rotate() to re-establish")
            if cur and cur["pubkey"] != pubkey:
                raise ValueError(f"signer already trusted with a different key: {signer_id!r}")
            if cur and cur["pubkey"] == pubkey:
                return {"trusted": True, "idempotent": True}
            self._ledger.append({"action": "trust", "signer_id": signer_id,
                                 "pubkey": pubkey, "ts": _now()})
            self._state[signer_id] = {"pubkey": pubkey, "revoked": False, "since": _now()}
            return {"trusted": True}

    def rotate(self, signer_id: str, pubkey: str) -> Dict[str, Any]:
        with self._lock:
            self._ledger.append({"action": "rotate", "signer_id": signer_id,
                                 "pubkey": pubkey, "ts": _now()})
            self._state[signer_id] = {"pubkey": pubkey, "revoked": False, "since": _now()}
            return {"rotated": True}

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
