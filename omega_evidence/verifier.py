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

A bare fabricated pack (no ledger, no timestamp, no signature) cannot pass. A SELF-MADE
  ledger anchor, however, only proves integrity/time — read `authenticated` (not just `valid`)
  and the RFC 3161 layer, which is verified ONLY against a supplied TSA trust anchor (ca_file).
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .canonical import sha3, sha256_bytes
from .pack import _honest_scope_declares_limit
from .ledger import Ledger
from .signing import verify_pq_alg, verify_with_alg
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


def _anchors_pack(entry: Any, digest: str) -> bool:
    """True only if the entry is a DELIBERATE anchor for this pack: the pack_sha3
    appears in the dedicated `anchored_pack_sha3` field (top-level or under a
    `data` wrapper). FIX NEMESIS re-attack: a value-search over ALL fields let an
    attacker anchor a fabricated pack by logging its pack_sha3 in a junk field of
    an unrelated entry — a dedicated field cannot be triggered incidentally."""
    def _field(e):
        if isinstance(e, dict):
            if e.get("anchored_pack_sha3") == digest:
                return True
            data = e.get("data")
            if isinstance(data, dict) and data.get("anchored_pack_sha3") == digest:
                return True
        return False
    return _field(entry)


def _check_ledger(path: str, ledger_path: Optional[str], layers: List) -> bool:
    lp = ledger_path or _ledger_sidecar(path)
    if not lp:
        layers.append(_layer("ledger-chain", "SKIP", "no ledger beside pack"))
        return False
    try:
        lg = Ledger(lp)
        ok, bad = lg.verify()
    except RuntimeError as e:
        layers.append(_layer("ledger-chain", "FAIL", str(e)))
        return False
    if not ok:
        layers.append(_layer("ledger-chain", "FAIL", f"{lp}: broken chain"))
        return False
    # A valid chain is not enough: the pack must actually be RECORDED in the ledger.
    # An empty or unrelated ledger must NOT anchor a fabricated pack.
    try:
        pk = json.loads(open(path, encoding="utf-8").read())
    except (OSError, ValueError):
        pk = {}
    pack_sha3 = pk.get("pack_sha3", "")
    entries = list(lg.entries())
    if not entries:
        layers.append(_layer("ledger-chain", "FAIL", f"{lp}: ledger empty — nothing anchored"))
        return False
    if not pack_sha3 or not any(_anchors_pack(e, pack_sha3) for e in entries):
        layers.append(_layer("ledger-chain", "FAIL",
                             "valid chain but this pack is not anchored (no anchored_pack_sha3 entry)"))
        return False
    layers.append(_layer("ledger-chain", "PASS", f"{lp}: pack_sha3 recorded"))
    return True


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
    vm = side.get("validation_material")     # LTV material captured at stamping time
    if isinstance(vm, dict) and vm.get("available"):
        crls = [c for c in vm.get("crls_b64", []) if "crl_b64" in c]
        layers.append(_layer("ltv-material", "SKIP",
                             f"captured: {vm.get('cert_count', 0)} cert(s), {len(crls)} CRL(s) "
                             "— TSA chain preserved for long-term validation"))
    return st


def _check_pq_cosignature(side: dict, digest: str, layers: List) -> None:
    """Report a post-quantum co-signature (hybrid pack). Honest states, never a
    false green: pq-protected only if a real PQ backend verifies it; a present-
    but-unverifiable PQ signature is SKIP (pq-present-unverified); a present PQ
    signature that a backend rejects is FAIL (fail-closed — the pack claims hybrid
    but the PQ part does not hold)."""
    palg = side.get("pq_sig_alg")
    if not palg:
        return
    # resolve ONLY against the post-quantum registry: a classical alg (e.g.
    # ed25519) declared as pq_sig_alg must NEVER be reported as pq-protected.
    r = verify_pq_alg(palg, side.get("pq_public_key_b64", ""),
                      side.get("pq_signature_b64", ""), digest.encode())
    if r is None:
        layers.append(_layer("pq-signature", "SKIP",
                             f"{palg} is not a registered PQ backend (pq-present-unverified)"))
    elif r:
        layers.append(_layer("pq-signature", "PASS", f"pq-protected ({palg})"))
    else:
        layers.append(_layer("pq-signature", "FAIL", f"{palg} co-signature invalid"))


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
    alg = side.get("sig_alg", "ed25519")                 # crypto-agility: default legacy
    result = verify_with_alg(alg, side.get("public_key_b64", ""),
                             side.get("signature_b64", ""), current.encode())
    if result is None:                                   # unknown alg -> honest SKIP
        layers.append(_layer("producer-signature", "SKIP", f"unsupported sig_alg: {alg}"))
        return "SKIP", False, False
    if current != side.get("signed_pack_sha3") or not result:
        layers.append(_layer("producer-signature", "FAIL", "signature invalid or pack changed"))
        return "FAIL", False, False
    layers.append(_layer("producer-signature", "PASS",
                         f"signed by {side.get('signer_id')} ({alg})"))
    _check_pq_cosignature(side, current, layers)         # hybrid PQ, informational + fail-closed
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
        pack = json.loads(open(path, encoding="utf-8").read(),
                          parse_constant=lambda c: (_ for _ in ()).throw(ValueError(f"JSON constant {c}")))
        if not isinstance(pack, dict):
            raise ValueError("pack is not a JSON object")
        layers.append(_layer("pack-json", "PASS"))
    except (OSError, ValueError, RecursionError) as e:
        return _rollup([_layer("pack-json", "FAIL", str(e))])

    scope = pack.get("honest_scope", "")
    _hs_ok = _honest_scope_declares_limit(scope)
    layers.append(_layer("honest-scope", "PASS" if _hs_ok else "FAIL",
                         "limit declared" if _hs_ok else
                         "no explicit honest_scope (or overclaim without a real NOT-limit)"))

    declared = pack.get("pack_sha3", "")
    try:
        computed = sha3({k: v for k, v in pack.items() if k != "pack_sha3"})
    except (ValueError, TypeError, RecursionError) as e:
        computed = None
        layers.append(_layer("pack-sha3", "FAIL", f"not canonicalisable: {e.__class__.__name__}"))
    if computed is not None:
        layers.append(_layer("pack-sha3", "PASS" if declared and declared == computed else "FAIL"))

    ledger_ok = _check_ledger(path, ledger_path, layers)
    ts_status = _check_timestamp(path, layers)
    sig_status, trusted, trust_failed = _check_signature_and_trust(path, trust_store, layers)
    _decide_authenticity(layers, sig_status, trusted, trust_failed, ledger_ok, ts_status)
    roll = _rollup(layers)
    auth = next((ly for ly in layers if ly["layer"] == "authenticity"), {})
    # `valid` = integrity + intactness. `authenticated` = a real producer identity signed it
    # (a self-made ledger anchor proves integrity/time, NOT authenticity — read this field).
    roll["authenticated"] = auth.get("status") == "PASS" and (
        "signed" in auth.get("detail", "") or "trusted" in auth.get("detail", ""))
    return roll
