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
omega_evidence.canonical — deterministic canonical hashing.

Canonical JSON: sorted keys, tight separators, ASCII, no NaN/Infinity, and
INJECTIVE type-tagging for non-JSON-native types (Decimal/datetime/date/bytes/
set) so a Decimal never collapses onto its string form before hashing. Anything
not injectively tag-able raises rather than collapse silently.

Self-contained (Python stdlib only): the open toolkit does not import the
proprietary OMEGA core.
"""

from __future__ import annotations

import hashlib
import json
from datetime import date, datetime
from decimal import Decimal
from typing import Any


# Reserved type-tag key. Safety does NOT rest on the key being unguessable:
# ANY input dict that contains this key is rejected (see _reject_reserved), so a
# caller cannot forge {tag: "Decimal", ...} to collide with a genuine Decimal --
# the forgery raises instead of colliding.
_TAG = "__omega_reserved_type__"


def _default(o: Any) -> Any:
    if isinstance(o, bool):
        return o
    if isinstance(o, Decimal):
        return {_TAG: "Decimal", "value": str(o)}
    if isinstance(o, datetime):
        return {_TAG: "datetime", "value": o.isoformat()}
    if isinstance(o, date):
        return {_TAG: "date", "value": o.isoformat()}
    if isinstance(o, (bytes, bytearray)):
        return {_TAG: "bytes", "value": bytes(o).hex()}
    if isinstance(o, (set, frozenset)):
        return {_TAG: "set",
                "value": sorted(o, key=lambda x: json.dumps(x, sort_keys=True, default=_default))}
    raise TypeError(f"canonical_json: type not injectively serialisable: {type(o).__name__!r}")


def _reject_reserved(obj: Any) -> None:
    """Refuse any input dict that carries the reserved type-tag key: it is reserved
    for the toolkit's own injective type-tagging, so a forged tag dict raises rather
    than silently colliding with a genuine typed value."""
    if isinstance(obj, dict):
        if _TAG in obj:
            raise ValueError("canonical_json: input uses the reserved type-tag key")
        for k, v in obj.items():
            # FIX NEMESIS re-attack: JSON coerces non-string keys to strings
            # ({1:'x'} and {'1':'x'} → identical bytes). Reject non-string keys
            # rather than let them collapse — keeps hashing injective.
            if not isinstance(k, str):
                raise ValueError(f"canonical_json: non-string key {k!r} is not injective")
            _reject_reserved(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _reject_reserved(v)


def canonical_json(obj: Any) -> bytes:
    """Deterministic canonical serialisation of a JSON-like object."""
    _reject_reserved(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False, default=_default).encode("utf-8")


def sha3(obj: Any) -> str:
    """SHA3-256 of the canonical serialisation (hex)."""
    return hashlib.sha3_256(canonical_json(obj)).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
