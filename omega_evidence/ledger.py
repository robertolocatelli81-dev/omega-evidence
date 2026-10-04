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
import stat
import threading
import time
from typing import Dict, List, Tuple

try:
    import fcntl                       # POSIX: the cross-process lock below
except ImportError:                    # Windows: no flock; see _lock_file
    fcntl = None

GENESIS = "0" * 64


def _lock_file(fd: int, shared: bool = False) -> None:
    """Advisory lock on the OPEN ledger file (POSIX flock), exclusive for a writer, shared for a reader. Held for one
    append (or one load), so N processes appending to the same ledger serialize and each one re-reads what the others
    wrote before it writes (28/09/2026: measured before this lock, 4 processes x 200 appends to one file left 401 lines
    of 801, verify() FAIL, 200 duplicate idx, two processes refused to open the file mid-write). The threading.Lock of
    the instance covers threads of ONE process sharing ONE instance; this covers everything else on the same inode.
    Advisory: a writer that does not use this module is not stopped. Not on Windows (no fcntl: single writer process
    per ledger there), not reliable on NFS. Module-level on purpose: a test disables it to show the failure it prevents."""
    if fcntl is not None:
        fcntl.flock(fd, fcntl.LOCK_SH if shared else fcntl.LOCK_EX)


def _unlock_file(fd: int) -> None:
    if fcntl is not None:
        fcntl.flock(fd, fcntl.LOCK_UN)

# One bound for every file a verifier reads (pack, .sig.json, .tsr.json, ledger, trust store) — and so for any single
# ledger line — the same number in the Python, Node, Go and Java verifiers (25/09/2026). Chosen where the peak memory of
# every one of them, measured at the bound on the shapes the README lists, stays far from its runtime's limit — which
# needed the ledger to be read one line at a time as well (26/09/2026: many short lines exhausted memory under the same
# bound when every line was materialized first). NOT covered: one valid container with tens of millions of elements
# still costs ~30x its size (README, "Still open"); above the bound every verifier refuses the file
# the way it refuses an unreadable one. It bounds what a VERIFIER accepts, not what Ledger.append may write.
MAX_INPUT_BYTES = 64 * 1024 * 1024


def read_input(path: str, limit: int = MAX_INPUT_BYTES) -> bytes:
    """Read one verifier input without letting the file decide how long or how much. Opened O_NONBLOCK, so a FIFO put
    in place of a sidecar does not block the open; accepted only when fstat says the OPENED file is regular (a FIFO, a
    device such as a symlink to /dev/zero, a directory: refused); read to at most `limit` + 1 bytes, so a file beyond
    the bound is refused, never exhausted. Every refusal is an OSError, which the verifier already reports as the FAIL of
    the layer that reads the file (25/09/2026, NEMESIS: a FIFO blocked all four verifiers, /dev/zero exhausted memory)."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(f"{path}: not a regular file")
        chunks, total = [], 0
        while total <= limit:
            b = os.read(fd, min(1 << 20, limit + 1 - total))
            if not b:
                break
            chunks.append(b)
            total += len(b)
        if total > limit:
            raise OSError(f"{path}: input exceeds {limit} bytes")
        return b"".join(chunks)
    finally:
        os.close(fd)


from .canonical import _SAFE_INT   # noqa: E402 — ±(2^53-1): ONE integer bound for the whole package (0.10.0; it was a second copy of the same number)
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
    h = s[i:i + 4]
    if len(h) != 4 or any(c not in "0123456789abcdefABCDEF" for c in h):   # r6: int(x, 16) would take " d80" / "+d80" / "d_80"
        return None
    return int(h, 16)


def _has_lone_surrogate(text: str) -> bool:
    """Linear scan of the raw JSON text for a \\uD800-\\uDBFF escape not followed by \\uDC00-\\uDFFF, or a low
    surrogate escape on its own — the rule Go/Java/Node apply (prescan.go HasLoneSurrogate). 0.8.3 review r2:
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


def loads_bounded(text, **kw):
    """json.loads with the nesting bound of loads_strict checked FIRST, by a linear pre-scan: refusing deep input must not
    depend on RecursionError, whose depth varies with the Python version and, since 3.14, with the C stack of the host
    (a 100000-deep SD-JWT payload raised on Python 3.13 and on 3.14 here, and parsed on the 3.14 of a CI runner).
    Raises ValueError("json_too_deep: ...") beyond 512 levels; otherwise json.loads(text, **kw)."""
    if isinstance(text, (bytes, bytearray)):
        text = text.decode("utf-8")
    if _nesting_depth(text) > _MAX_DEPTH:
        raise ValueError(f"json_too_deep: nesting exceeds {_MAX_DEPTH}")
    return json.loads(text, **kw)


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

    Concurrency (28/09/2026): threads sharing one instance are serialized by the instance lock; instances in other
      threads or other PROCESSES appending to the same file are serialized by an advisory POSIX file lock (flock) held
      for one append, under which the instance first replays what the others appended since its last write, so every
      entry links to the last hash on disk and carries the next idx. A file truncated by someone else is refused. Not
      on Windows (no fcntl: one writer process per ledger), advisory only, not reliable on NFS. Measured in
      tests/test_toolkit.py (TestConcurrentAppend20260928) with the lock disabled as the positive control.
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
        self._size = 0             # bytes of the file that _count/_last account for (other processes may add more)
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
        try:   # 0.8.3 review: a non-UTF-8 byte (UnicodeDecodeError), an unreadable file (OSError) — one exception type out
            with open(self.path, "rb") as fh:   # of here, RuntimeError, for every caller (verifier, trust store, agent, pack)
                _lock_file(fh.fileno(), shared=True)   # 28/09/2026: never read a line another process is still writing
                try:
                    raw = fh.read()
                finally:
                    _unlock_file(fh.fileno())
        except OSError as e:
            raise RuntimeError(f"ledger unreadable: {e}") from e
        self._count, self._last = self._replay(raw, 0, GENESIS, 0)
        self._size = len(raw)

    @staticmethod
    def _replay(raw: bytes, count: int, prev: str, first_line: int) -> Tuple[int, str]:
        """Walk `raw` (whole file, or the bytes appended after the ones already accounted for) from the known state
        (count, prev); RuntimeError on the first line that does not continue the chain."""
        try:
            lines = raw.decode("utf-8").split("\n")   # LF only, like verify(): splitlines() would also split on U+2028
        except UnicodeDecodeError as e:
            raise RuntimeError(f"ledger unreadable: {e}") from e
        for i, line in enumerate(lines, first_line):
            line = line.strip(" \t\r\n")   # blank = ASCII space/tab/CR only, the rule of verify() and of the three (r6)
            if not line:
                continue
            try:   # 0.8.3 review: a non-object line raised AttributeError, a non-JSON line JSONDecodeError
                entry = loads_strict(line)
                if not isinstance(entry, dict):
                    raise ValueError("ledger line is not a JSON object")
            except (ValueError, RecursionError) as e:
                raise RuntimeError(f"ledger corrotto alla riga {i + 1}: {e}") from e
            if entry.get("prev_hash") != prev or entry.get("self_hash") != _hash_entry(entry):
                raise RuntimeError(f"ledger corrotto alla riga {i + 1}: catena rotta")
            prev = entry["self_hash"]
            count += 1
        return count, prev

    def _resync_locked(self, fd: int) -> None:
        """Under the exclusive file lock: if the file grew past what this instance accounts for, another process (or
        another instance) appended — replay those bytes so the next entry links to THEIR last hash and carries the right
        idx. A file shorter than accounted for was truncated under us: refused (the chain on disk is not ours any more)."""
        size = os.fstat(fd).st_size
        if size == self._size:
            return
        if size < self._size:
            raise RuntimeError(f"ledger truncated by another writer: {size} < {self._size} bytes")
        with open(self.path, "rb") as fh:
            fh.seek(self._size)
            raw = fh.read(size - self._size)
        # the line number reported is approximate here (a count of LF up to _size would cost a scan of the file)
        self._count, self._last = self._replay(raw, self._count, self._last, self._count)
        self._size = size

    def append(self, data: Dict) -> Dict:
        _check_portable(data)   # 0.7.0: what cannot be verified byte-for-byte elsewhere is refused at write time
        with self._lock:
            if self.durability == "sync":
                # comportamento di default INVARIATO: open+write+flush+fsync per entry
                os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
                with open(self.path, "a", encoding="utf-8") as f:
                    _lock_file(f.fileno())          # 28/09/2026: one writer at a time on this inode, across processes
                    try:
                        self._resync_locked(f.fileno())
                        entry, line = self._entry_locked(data)
                        f.write(line)
                        f.flush()
                        os.fsync(f.fileno())
                    finally:
                        _unlock_file(f.fileno())
            else:
                # batch: handle persistente, fsync ogni batch_size (o su flush/close)
                if self._fh is None:
                    os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
                    self._fh = open(self.path, "a", encoding="utf-8")
                _lock_file(self._fh.fileno())
                try:
                    self._resync_locked(self._fh.fileno())
                    entry, line = self._entry_locked(data)
                    self._fh.write(line)
                    # flush del buffer Python → OS ad ogni append (economico): garantisce
                    # che verify()/entries(), che riaprono il file in lettura, vedano TUTTO —
                    # e che un altro processo, preso il lock, legga la riga intera.
                    # Il fsync → disco (costoso, la durabilità) è batchato.
                    self._fh.flush()
                    self._pending += 1
                    if self._pending >= self.batch_size:
                        self._flush_locked()
                finally:
                    _unlock_file(self._fh.fileno())
            self._last = entry["self_hash"]
            self._count += 1
            self._size += len(line.encode("utf-8"))
            return entry

    def _entry_locked(self, data: Dict) -> Tuple[Dict, str]:
        """The next entry from the state re-synced under the file lock, and its line."""
        entry = {"idx": self._count,
                 "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                 "data": data, "prev_hash": self._last, "self_hash": ""}
        entry["self_hash"] = _hash_entry(entry)
        return entry, json.dumps(entry, separators=(",", ":"), allow_nan=False) + "\n"

    def verify(self) -> Tuple[bool, List[int]]:
        if not os.path.exists(self.path):
            return True, []
        # 0.7.0: the same acceptance profile as the cryptovalid verifiers (Python/JS/Go/Rust/Java agree):
        # LF-only lines, blank = ASCII space/tab/CR, strict JSON, sequential idx, content → self_hash → prev link
        try:   # r5: strict decode here too (surrogateescape never raised); a non-UTF-8 file is a broken chain
            with open(self.path, "rb") as fh:
                _lock_file(fh.fileno(), shared=True)   # 28/09/2026: a whole snapshot, never a line another process is writing
                try:
                    text = fh.read().decode("utf-8")
                finally:
                    _unlock_file(fh.fileno())
        except (OSError, UnicodeDecodeError):
            return False, [0]
        return verify_text(text)

    @property
    def count(self) -> int:
        return self._count

    def _snapshot(self) -> str:
        """The file as ONE read under the shared file lock — the same snapshot rule as _load() and verify() (0.10.0, code
        review 29/09/2026 D7: the two iterators read line by line with no lock, so a reader could in principle see a line
        another process was still writing). The lock is released BEFORE any entry is yielded: a generator that held it
        while the caller appends (`for d in lg.entries(): lg.append(...)`) would block on its own exclusive lock. Cost: the
        text is held in memory while iterating, as verify() already does."""
        try:
            with open(self.path, "rb") as fh:
                _lock_file(fh.fileno(), shared=True)
                try:
                    raw = fh.read()
                finally:
                    _unlock_file(fh.fileno())
            return raw.decode("utf-8")
        except (OSError, UnicodeDecodeError) as e:   # one exception type out of here, RuntimeError, like _load()
            raise RuntimeError(f"ledger unreadable: {e}") from e

    def entries(self):
        if not os.path.exists(self.path):
            return
        for line in _lines(self._snapshot()):
            line = line.strip(" \t\r\n")
            if line:
                e = loads_strict(line)          # 0.7.0: the strict profile also on replay (no duplicate keys)
                if not isinstance(e, dict):
                    raise ValueError("ledger line is not a JSON object")
                yield e.get("data")     # 0.8.3 r4: no default — an entry without "data" is what it is (the trust store
                                        # treats it as broken, like Go/Java/Node; Python used to skip it silently)

    def raw_entries(self):
        """The whole entries (idx, ts, data, prev_hash, self_hash, and any extra key), strict profile. The anchoring rule
        reads the ENTRY (`anchored_pack_sha3` top-level or under `data`), as the three other verifiers do — 0.8.3 r4:
        the reference read `data` instead, so a top-level anchor was PASS in the three and FAIL here, and a
        `data.data.anchored_pack_sha3` the reverse."""
        if not os.path.exists(self.path):
            return
        for line in _lines(self._snapshot()):
            line = line.strip(" \t\r\n")
            if line:
                e = loads_strict(line)
                if not isinstance(e, dict):
                    raise ValueError("ledger line is not a JSON object")
                yield e


def _lines(text: str):
    """LF-separated lines, one at a time. `text.split("\\n")` built every line first: 64 MiB of empty lines became 64 M
    string objects (612 MiB measured 26/09/2026; Go 1.7 GB, Node 1 GB, Java out of memory with the same shape)."""
    start = 0
    while True:
        end = text.find("\n", start)
        if end < 0:
            yield text[start:]
            return
        yield text[start:end]
        start = end + 1


BAD_KEPT = 1000     # at most this many bad line numbers are reported, and the reading STOPS there: the chain is broken
                    # all the same. Before (26/09/2026), 22 M lines "{}" were all parsed: 100-154 s where the other
                    # three verifiers stop at the first break (independent review). Library callers of Ledger.verify()
                    # get at most BAD_KEPT numbers; agent.verify() says so with bad_entries_truncated.


def verify_text(text: str) -> Tuple[bool, List[int]]:
    """Ledger.verify() over a text already read — the verifier reads each file once, through read_input()."""
    bad: List[int] = []
    broken = False
    prev = GENESIS
    n = 0

    def mark(i: int) -> None:
        nonlocal broken
        broken = True
        if len(bad) < BAD_KEPT:
            bad.append(i)
    for i, line in enumerate(_lines(text)):
        if len(bad) >= BAD_KEPT:
            break
        if not line.strip(" \t\r\n"):
            continue
        try:
            e = loads_strict(line.strip(" \t\r\n"))
            if not isinstance(e, dict):
                raise ValueError("entry is not an object")
        except (ValueError, RecursionError):
            mark(i)
            n += 1
            continue
        idx = e.get("idx")
        sh = e.get("self_hash")
        if (isinstance(idx, bool) or idx != n or e.get("prev_hash") != prev
                or not isinstance(sh, str) or sh != _hash_entry(e)):
            mark(i)
        prev = sh if isinstance(sh, str) else prev
        n += 1
    return (not broken), bad


def entries_text(text: str) -> List[Dict]:
    """Ledger.raw_entries() over a text already read (strict profile; a line that is not an object raises ValueError)."""
    out = []
    for line in _lines(text):
        line = line.strip(" \t\r\n")
        if line:
            e = loads_strict(line)
            if not isinstance(e, dict):
                raise ValueError("ledger line is not a JSON object")
            out.append(e)
    return out
