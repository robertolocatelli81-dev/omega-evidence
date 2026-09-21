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
from typing import Dict, List, Tuple

GENESIS = "0" * 64


_SAFE_INT = (1 << 53) - 1
_MAX_DEPTH = 512


def _no_float(x):
    raise ValueError("floats are not portable in a ledger entry (use a string)")


def _bounded_int(x):
    v = int(x)
    if abs(v) > _SAFE_INT:
        raise ValueError("integer outside the portable range +/-(2^53-1)")
    return v


def _reject_dup(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError(f"duplicate key {k!r}")
        d[k] = v
    return d


def _nesting_depth(text: str) -> int:
    depth = mx = 0
    in_str = esc = False
    for c in text:
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
        elif c in "[{":
            depth += 1
            mx = max(mx, depth)
        elif c in "]}":
            depth -= 1
    return mx


def _hex4(s: str, i: int):
    try:
        return int(s[i:i + 4], 16) if len(s[i:i + 4]) == 4 else None
    except ValueError:
        return None


def _has_lone_surrogate(text: str) -> bool:
    """Linear scan of the raw JSON text for a \\uD800-\\uDBFF escape not followed by \\uDC00-\\uDFFF, or a low
    surrogate escape on its own — the rule Go/Java/Node apply (prescan.go HasLoneSurrogate). 0.8.3 review r2 (Opus):
    the Python reference had no such rule, so an anchored pack holding "\\ud800" was PASS here and FAIL in the three."""
    i, n = 0, len(text)
    while i < n:
        if text[i] != "\\":
            i += 1
            continue
        if i + 1 < n and text[i + 1] == "u" and i + 5 < n:
            cp = _hex4(text, i + 2)
            if cp is None:            # malformed escape: the decoder refuses it, not this rule
                i += 2
                continue
            if 0xD800 <= cp <= 0xDBFF:
                if i + 7 >= n or text[i + 6] != "\\" or text[i + 7] != "u":
                    return True
                lo = _hex4(text, i + 8)
                if lo is None or not (0xDC00 <= lo <= 0xDFFF):
                    return True
                i += 12
                continue
            if 0xDC00 <= cp <= 0xDFFF:
                return True
            i += 6
            continue
        i += 2                        # any other escape (\\", \\\\, \\n ...): skip the pair
    return False


def loads_strict(text: str):
    """The family's acceptance profile (cryptovalid CONFORMANCE): no duplicate keys, no floats, integers within
    ±(2^53-1), nesting <= 512 by linear pre-scan, no NaN/Infinity, no lone UTF-16 surrogate escape. Same rule as the
    Go/Java/JS verifiers."""
    if _nesting_depth(text) > _MAX_DEPTH:
        raise ValueError(f"json_too_deep: nesting exceeds {_MAX_DEPTH}")
    if _has_lone_surrogate(text):
        raise ValueError("lone_surrogate: unpaired UTF-16 surrogate escape is outside the acceptance profile")
    return json.loads(text, object_pairs_hook=_reject_dup, parse_float=_no_float, parse_int=_bounded_int,
                      parse_constant=lambda c: (_ for _ in ()).throw(ValueError(f"JSON constant {c}")))


def _check_portable(obj) -> None:
    if isinstance(obj, float):
        raise ValueError("floats are not portable in a ledger entry (use a string)")
    if isinstance(obj, str) and any(0xD800 <= ord(ch) <= 0xDFFF for ch in obj):
        raise ValueError("lone surrogate in a string is outside the acceptance profile (the three other verifiers refuse it)")
    if isinstance(obj, int) and not isinstance(obj, bool) and abs(obj) > _SAFE_INT:
        raise ValueError("integer outside the portable range +/-(2^53-1)")
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise ValueError("non-string key")
            _check_portable(v)
    elif isinstance(obj, (list, tuple, set, frozenset)):
        for v in obj:
            _check_portable(v)


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
        try:   # 0.8.3 review: a non-UTF-8 byte (UnicodeDecodeError), an unreadable file (OSError) — one exception type out
            with open(self.path, "rb") as fh:   # of here, RuntimeError, for every caller (verifier, trust store, agent, pack)
                lines = fh.read().decode("utf-8").split("\n")   # LF only, like verify(): splitlines() would also split on U+2028
        except (OSError, UnicodeDecodeError) as e:
            raise RuntimeError(f"ledger unreadable: {e}") from e
        for i, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue
            try:   # 0.8.3 review (Opus): a non-object line raised AttributeError, a non-JSON line JSONDecodeError
                entry = loads_strict(line)
                if not isinstance(entry, dict):
                    raise ValueError("ledger line is not a JSON object")
            except (ValueError, RecursionError) as e:
                raise RuntimeError(f"ledger corrotto alla riga {i + 1}: {e}") from e
            if entry.get("prev_hash") != prev or entry.get("self_hash") != _hash_entry(entry):
                raise RuntimeError(f"ledger corrotto alla riga {i + 1}: catena rotta")
            prev = entry["self_hash"]
            self._count += 1
        self._last = prev

    def append(self, data: Dict) -> Dict:
        _check_portable(data)   # 0.7.0: what cannot be verified byte-for-byte elsewhere is refused at write time
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
        # 0.7.0: the same acceptance profile as the cryptovalid verifiers (Python/JS/Go/Rust/Java agree):
        # LF-only lines, blank = ASCII space/tab/CR, strict JSON, sequential idx, content → self_hash → prev link
        n = 0
        try:   # r5 (Sonnet): strict decode here too (surrogateescape never raised); a non-UTF-8 file is a broken chain
            with open(self.path, "rb") as fh:
                lines = fh.read().decode("utf-8").split("\n")
        except (OSError, UnicodeDecodeError):
            return False, [0]
        if True:
            for i, line in enumerate(lines):
                if not line.strip(" \t\r\n"):
                    continue
                try:
                    e = loads_strict(line.strip(" \t\r\n"))
                    if not isinstance(e, dict):
                        raise ValueError("entry is not an object")
                except (ValueError, RecursionError):
                    bad.append(i)
                    n += 1
                    continue
                idx = e.get("idx")
                sh = e.get("self_hash")
                if (isinstance(idx, bool) or idx != n or e.get("prev_hash") != prev
                        or not isinstance(sh, str) or sh != _hash_entry(e)):
                    bad.append(i)
                prev = sh if isinstance(sh, str) else prev
                n += 1
        return (not bad), bad

    @property
    def count(self) -> int:
        return self._count

    def entries(self):
        if not os.path.exists(self.path):
            return
        with open(self.path, encoding="utf-8", newline="\n") as fh:
            for line in fh:
                line = line.strip(" \t\r\n")
                if line:
                    e = loads_strict(line)          # 0.7.0: the strict profile also on replay (no duplicate keys)
                    if not isinstance(e, dict):
                        raise ValueError("ledger line is not a JSON object")
                    yield e.get("data")     # 0.8.3 r4: no default — an entry without "data" is what it is (the trust store
                                            # treats it as broken, like Go/Java/Node; Python used to skip it silently)

    def raw_entries(self):
        """The whole entries (idx, ts, data, prev_hash, self_hash, and any extra key), strict profile. The anchoring rule
        reads the ENTRY (`anchored_pack_sha3` top-level or under `data`), as the three other verifiers do — 0.8.3 r4 (Opus):
        the reference read `data` instead, so a top-level anchor was PASS in the three and FAIL here, and a
        `data.data.anchored_pack_sha3` the reverse."""
        if not os.path.exists(self.path):
            return
        with open(self.path, encoding="utf-8", newline="\n") as fh:
            for line in fh:
                line = line.strip(" \t\r\n")
                if line:
                    e = loads_strict(line)
                    if not isinstance(e, dict):
                        raise ValueError("ledger line is not a JSON object")
                    yield e
