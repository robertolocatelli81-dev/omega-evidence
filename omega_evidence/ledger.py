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
omega_evidence.ledger — append-only, SHA-256 hash-chained ledger.

Guarantees: atomic append (tmp+fsync+rename), each entry links the previous by
hash, GENESIS anchor, and FAIL-CLOSED verification — a tampered file raises on
load rather than being silently accepted. Self-contained (stdlib only).
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from typing import Any, Dict, List, Tuple

GENESIS = "0" * 64


def _hash_entry(entry: Dict) -> str:
    d = {k: v for k, v in entry.items() if k != "self_hash"}
    return hashlib.sha256(
        json.dumps(d, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


class Ledger:
    """Append-only hash-chained JSONL ledger.

    Durability modes:
      - "sync"  (default): fsync on EVERY append — maximum durability, the safe
        default; a power loss loses at most the in-flight entry.
      - "batch": fsync every `batch_size` appends (and on flush()/close()) with a
        persistent file handle — much higher throughput at the cost of a small
        CRASH WINDOW: a power loss can lose up to the last `batch_size-1`
        un-fsynced entries. The hash-chain of what survived on disk stays valid
        (append-only). Use flush()/close() or the context manager to force the
        final fsync. Trade-off DECLARED, not hidden.
    """

    def __init__(self, path: str, durability: str = "sync", batch_size: int = 256):
        if durability not in ("sync", "batch"):
            raise ValueError("durability must be 'sync' or 'batch'")
        self.path = path
        self.durability = durability
        self.batch_size = max(1, int(batch_size))
        self._lock = threading.Lock()
        self._count = 0
        self._last = GENESIS
        self._fh = None            # persistent handle in batch mode
        self._pending = 0          # appends written but not yet fsynced
        self._load()

    # ── context manager: garantisce il flush finale in batch mode ─────────
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def flush(self) -> None:
        """Forza il fsync di quanto è in sospeso (no-op in modalità sync)."""
        with self._lock:
            self._flush_locked()

    def _flush_locked(self) -> None:
        # il buffer Python è già svuotato ad ogni append; qui il fsync → disco.
        if self._fh is not None and self._pending:
            os.fsync(self._fh.fileno())
            self._pending = 0

    def close(self) -> None:
        with self._lock:
            self._flush_locked()
            if self._fh is not None:
                self._fh.close()
                self._fh = None

    def _load(self) -> None:
        if not os.path.exists(self.path):
            return
        prev = GENESIS
        with open(self.path, encoding="utf-8") as fh:
            for i, line in enumerate(fh):
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                if entry.get("prev_hash") != prev or entry.get("self_hash") != _hash_entry(entry):
                    raise RuntimeError(f"ledger corrotto alla riga {i + 1}: catena rotta")
                prev = entry["self_hash"]
                self._count += 1
        self._last = prev

    def append(self, data: Dict) -> Dict:
        with self._lock:
            entry = {"idx": self._count,
                     "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                     "data": data, "prev_hash": self._last, "self_hash": ""}
            entry["self_hash"] = _hash_entry(entry)
            line = json.dumps(entry, separators=(",", ":"), allow_nan=False) + "\n"
            if self.durability == "sync":
                # comportamento di default INVARIATO: open+write+flush+fsync per entry
                os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(line)
                    f.flush()
                    os.fsync(f.fileno())
            else:
                # batch: handle persistente, fsync ogni batch_size (o su flush/close)
                if self._fh is None:
                    os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
                    self._fh = open(self.path, "a", encoding="utf-8")
                self._fh.write(line)
                # flush del buffer Python → OS ad ogni append (economico): garantisce
                # che verify()/entries(), che riaprono il file in lettura, vedano TUTTO.
                # Il fsync → disco (costoso, la durabilità) è batchato.
                self._fh.flush()
                self._pending += 1
                if self._pending >= self.batch_size:
                    self._flush_locked()
            self._last = entry["self_hash"]
            self._count += 1
            return entry

    def verify(self) -> Tuple[bool, List[int]]:
        bad: List[int] = []
        prev = GENESIS
        if not os.path.exists(self.path):
            return True, bad
        with open(self.path, encoding="utf-8") as fh:
            for i, line in enumerate(fh):
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except ValueError:
                    bad.append(i)
                    continue
                if e.get("prev_hash") != prev or e.get("self_hash") != _hash_entry(e):
                    bad.append(i)
                prev = e.get("self_hash", prev)
        return (not bad), bad

    @property
    def count(self) -> int:
        return self._count

    def entries(self):
        if not os.path.exists(self.path):
            return
        with open(self.path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield json.loads(line).get("data", {})
