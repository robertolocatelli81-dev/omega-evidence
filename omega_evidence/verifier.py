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
omega_evidence.verifier — one offline verifier for any evidence pack.

Layers (each PASS / FAIL / SKIP; SKIP is honest, never a false green):
  pack-json · honest-scope · pack-sha3 · ledger-chain · rfc3161 · producer-
  signature · trusted-signer · authenticity.

Graduated authenticity (strongest first):
  trusted-signed  — producer signature valid AND key trusted in the registry
  signed          — producer signature valid (identity not checked)
  anchored        — valid ledger chain OR valid TSA timestamp (integrity/time)
  none            — internal consistency only  →  FAIL, cannot authenticate

A bare fabricated pack (no ledger, no timestamp, no signature) cannot pass.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .canonical import sha3, sha256_bytes
from .ledger import Ledger
from .signing import verify_signature
from .trust import TrustRegistry


def _layer(name: str, status: str, detail: str = "") -> Dict[str, str]:
    return {"layer": name, "status": status, "detail": detail}


def _rollup(layers: List[Dict[str, str]]) -> Dict[str, Any]:
    checked = [x for x in layers if x["status"] in ("PASS", "FAIL")]
    valid = bool(checked) and all(x["status"] == "PASS" for x in checked)
    return {"valid": valid, "layers": layers,
            "verified_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}


def _ledger_sidecar(path: str) -> Optional[str]:
    cand = path[:-5] + ".ledger.jsonl" if path.endswith(".json") else path + ".ledger.jsonl"
    return cand if os.path.exists(cand) else None


def _check_ledger(path: str, ledger_path: Optional[str], layers: List) -> bool:
    lp = ledger_path or _ledger_sidecar(path)
    if not lp:
        layers.append(_layer("ledger-chain", "SKIP", "no ledger beside pack"))
        return False
    try:
        ok, bad = Ledger(lp).verify()
    except RuntimeError as e:
        layers.append(_layer("ledger-chain", "FAIL", str(e)))
        return False
    layers.append(_layer("ledger-chain", "PASS" if ok else "FAIL", f"{lp}"))
    return ok


def _check_timestamp(path: str, layers: List) -> str:
    ts_side = path[:-5] + ".tsr.json" if path.endswith(".json") else path + ".tsr.json"
    if not os.path.exists(ts_side):
        layers.append(_layer("rfc3161", "SKIP", "no RFC 3161 sidecar"))
        return "SKIP"
    try:
        side = json.loads(open(ts_side, encoding="utf-8").read())
    except ValueError as e:
        layers.append(_layer("rfc3161", "FAIL", f"malformed sidecar: {e}"))
        return "FAIL"
    current = sha256_bytes(open(path, "rb").read())
    if current != side.get("digest_sha256"):
        layers.append(_layer("rfc3161", "FAIL", "pack changed after stamping"))
        return "FAIL"
    from .timestamp import verify
    r = verify(side.get("tsr_b64", ""), current)
    st = "PASS" if r.get("verified") is True else ("SKIP" if r.get("verified") is None else "FAIL")
    layers.append(_layer("rfc3161", st, side.get("tsa", "")))
    return st


def _check_signature_and_trust(path: str, trust_store: Optional[str], layers: List):
    sig_side = path[:-5] + ".sig.json" if path.endswith(".json") else path + ".sig.json"
    if not os.path.exists(sig_side):
        layers.append(_layer("producer-signature", "SKIP", "pack not signed"))
        return "SKIP", False, False
    try:
        side = json.loads(open(sig_side, encoding="utf-8").read())
    except ValueError as e:
        layers.append(_layer("producer-signature", "FAIL", f"malformed sidecar: {e}"))
        return "FAIL", False, False
    pack = json.loads(open(path, encoding="utf-8").read())
    current = pack.get("pack_sha3", "")
    if current != side.get("signed_pack_sha3") or not verify_signature(
            side.get("public_key_b64", ""), side.get("signature_b64", ""), current.encode()):
        layers.append(_layer("producer-signature", "FAIL", "signature invalid or pack changed"))
        return "FAIL", False, False
    layers.append(_layer("producer-signature", "PASS", f"signed by {side.get('signer_id')}"))
    if not trust_store:
        return "PASS", False, False
    tr = TrustRegistry(trust_store)
    sid, pk = side.get("signer_id"), side.get("public_key_b64")
    if tr.is_trusted(sid, pk):
        layers.append(_layer("trusted-signer", "PASS", f"{sid} in trust registry"))
        return "PASS", True, False
    st = tr.status(sid)
    detail = (f"{sid}: key revoked" if st.get("known") and st.get("revoked")
              else f"{sid}: key differs" if st.get("known") else f"{sid}: not in trust registry")
    layers.append(_layer("trusted-signer", "FAIL", detail))
    return "PASS", False, True


def _decide_authenticity(layers, sig_status, trusted, trust_failed, ledger_ok, ts_status):
    if sig_status == "FAIL":
        layers.append(_layer("authenticity", "FAIL", "producer signature present but invalid"))
    elif trust_failed:
        layers.append(_layer("authenticity", "FAIL", "valid signature but signer not trusted/revoked"))
    elif trusted:
        layers.append(_layer("authenticity", "PASS", "trusted-signed"))
    elif sig_status == "PASS":
        layers.append(_layer("authenticity", "PASS", "signed (identity not checked against a registry)"))
    elif ledger_ok or ts_status == "PASS":
        layers.append(_layer("authenticity", "PASS",
                             "anchored (integrity/time, not identity) — "
                             + ("ledger" if ledger_ok else "TSA")))
    else:
        layers.append(_layer("authenticity", "FAIL", "no anchor and no signature: cannot authenticate"))


def verify_pack(path: str, ledger_path: Optional[str] = None,
                trust_store: Optional[str] = None) -> Dict[str, Any]:
    """Verify an evidence pack across all layers. Returns {valid, layers, ...}."""
    layers: List[Dict[str, str]] = []
    try:
        pack = json.loads(open(path, encoding="utf-8").read())
        layers.append(_layer("pack-json", "PASS"))
    except (OSError, ValueError) as e:
        return _rollup([_layer("pack-json", "FAIL", str(e))])

    scope = pack.get("honest_scope", "")
    layers.append(_layer("honest-scope", "PASS" if "NOT" in scope else "FAIL",
                         "limit declared" if "NOT" in scope else "no explicit honest_scope"))

    declared = pack.get("pack_sha3", "")
    computed = sha3({k: v for k, v in pack.items() if k != "pack_sha3"})
    layers.append(_layer("pack-sha3", "PASS" if declared and declared == computed else "FAIL"))

    ledger_ok = _check_ledger(path, ledger_path, layers)
    ts_status = _check_timestamp(path, layers)
    sig_status, trusted, trust_failed = _check_signature_and_trust(path, trust_store, layers)
    _decide_authenticity(layers, sig_status, trusted, trust_failed, ledger_ok, ts_status)
    return _rollup(layers)
