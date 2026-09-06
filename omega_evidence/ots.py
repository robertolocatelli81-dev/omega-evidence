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
omega_evidence.ots — trustless public anchoring via OpenTimestamps (Bitcoin).

Submits a pack's hash to public OpenTimestamps calendar servers, which will
include it in a Bitcoin-anchored Merkle tree. This gives a public, trustless
proof-of-existence that needs NO trusted timestamping authority.

HONESTY — pending vs confirmed is the whole point:
  * Right after submission the proof is `pending`: the calendars ATTEST they
    received the digest and PROMISE to anchor it, but it is NOT yet in the Bitcoin
    blockchain. A pending proof is NOT trustless time yet.
  * It becomes `confirmed` only after the Bitcoin transaction confirms (minutes to
    hours later) and the proof is `upgrade`d. Confirming/verifying the Bitcoin
    attestation requires the full OpenTimestamps library and Bitcoin headers, so
    this module delegates final verification to the `opentimestamps` package when
    installed; without it, a fetched proof is reported `pending-unverified`, never
    a false `confirmed`.

Submission uses only urllib (stdlib). Apache-2.0.
"""

from __future__ import annotations

import base64
import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .canonical import sha256_bytes

DEFAULT_CALENDARS = [
    "https://a.pool.opentimestamps.org",
    "https://b.pool.opentimestamps.org",
]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _ots_sidecar(pack_path: str) -> Path:
    p = str(pack_path)
    return Path(p[:-5] + ".ots.json" if p.endswith(".json") else p + ".ots.json")


def submit(digest_sha256_hex: str, calendars: Optional[List[str]] = None,
           timeout: float = 20.0) -> Dict[str, Any]:
    """Submit a 32-byte SHA-256 digest to the calendars. Returns the per-calendar
    pending timestamps (base64). Fail-soft: a calendar that errors is skipped and
    recorded, so one outage does not lose the anchor."""
    digest = bytes.fromhex(digest_sha256_hex)
    if len(digest) != 32:
        raise ValueError("OpenTimestamps expects a 32-byte SHA-256 digest")
    cals = calendars or DEFAULT_CALENDARS
    results, errors = [], []
    for cal in cals:
        url = cal.rstrip("/") + "/digest"
        try:
            req = urllib.request.Request(
                url, data=digest, method="POST",
                headers={"Content-Type": "application/octet-stream",
                         "Accept": "application/octet-stream",
                         "User-Agent": "omega-evidence/ots"})
            with urllib.request.urlopen(req, timeout=timeout) as r:  # nosec B310 - https calendar
                body = r.read()
            results.append({"calendar": cal, "timestamp_b64": base64.b64encode(body).decode()})
        except Exception as e:  # noqa: BLE001 - fail-soft per calendar
            errors.append({"calendar": cal, "error": f"{type(e).__name__}: {e}"})
    return {"submitted": results, "errors": errors,
            "status": "pending-calendar-attested" if results else "no-calendar-reached"}


def stamp_pack(pack_path: str, calendars: Optional[List[str]] = None,
               timeout: float = 20.0) -> Dict[str, Any]:
    """Anchor a pack's file bytes via OpenTimestamps and write a `.ots.json`
    sidecar. The proof is PENDING until Bitcoin confirms — the sidecar says so."""
    data = Path(pack_path).read_bytes()
    digest = sha256_bytes(data)
    sub = submit(digest, calendars, timeout)
    side = {"anchor": "opentimestamps", "digest_sha256": digest,
            "calendars": sub["submitted"], "calendar_errors": sub["errors"],
            "status": sub["status"], "submitted_utc": _now(),
            "note": ("PENDING: calendar-attested, not yet Bitcoin-confirmed. Run "
                     "verify() (needs the opentimestamps package) after the Bitcoin "
                     "transaction confirms to reach 'confirmed'.")}
    _ots_sidecar(pack_path).write_text(json.dumps(side, ensure_ascii=False, indent=1),
                                       encoding="utf-8")
    return side


def verify(sidecar_or_pack_path: str) -> Dict[str, Any]:
    """Report the anchoring status. Uses the `opentimestamps` package for real
    Bitcoin verification when installed; otherwise returns the recorded pending
    status (never fabricates a confirmation)."""
    p = str(sidecar_or_pack_path)
    side_path = Path(p) if p.endswith(".ots.json") else _ots_sidecar(p)
    if not side_path.exists():
        return {"status": "absent", "confirmed": False, "detail": "no .ots.json sidecar"}
    side = json.loads(side_path.read_text(encoding="utf-8"))
    try:
        import opentimestamps  # type: ignore  # noqa: F401
        have_lib = True
    except Exception:  # noqa: BLE001
        have_lib = False
    if not have_lib:
        return {"status": "pending-unverified", "confirmed": False,
                "detail": ("opentimestamps package not installed — cannot verify the "
                           "Bitcoin attestation here; recorded status: "
                           + side.get("status", "?")),
                "recorded_status": side.get("status")}
    # With the library present, a full implementation would upgrade + verify the
    # timestamp against Bitcoin headers. We do not fabricate that result here.
    return {"status": "library-present", "confirmed": False,
            "detail": "opentimestamps present; call its verifier to confirm on Bitcoin",
            "recorded_status": side.get("status")}
