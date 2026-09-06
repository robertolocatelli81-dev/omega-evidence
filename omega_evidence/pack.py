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
omega_evidence.pack — self-describing evidence pack.

An evidence pack is a JSON object that MUST declare its own limits
(`honest_scope`, containing an explicit "NOT ..." disclaimer) and carries a
`pack_sha3` recomputed over the body (everything except pack_sha3 itself). A
pack that omits or overclaims its limits is rejected by the verifier.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from .canonical import sha3
from .signing import Identity


import re as _re

_SCOPE_LIMIT = _re.compile(r"\bNOT\b")   # standalone word, not NOTE/NOTHING/CANNOT
_SCOPE_OVERCLAIM = _re.compile(r"\b(accredited|certified|qualified|guaranteed)\b", _re.I)


def _honest_scope_declares_limit(scope: str) -> bool:
    """A real disclaimer: contains a standalone 'NOT' AND does not simultaneously assert
    accreditation/certification (an honesty gate must not be satisfied by an overclaim)."""
    if not isinstance(scope, str) or not _SCOPE_LIMIT.search(scope):
        return False
    # 'NOT accredited' is fine; a bare positive 'fully accredited' with no negation of it is not
    if _SCOPE_OVERCLAIM.search(scope) and not _re.search(r"\bNOT\b[^.]{0,40}(accredit|certif|qualif|guarant)", scope, _re.I):
        return False
    return True


def build_pack(kind: str, body: Dict[str, Any], honest_scope: str) -> Dict[str, Any]:
    """Assemble a pack with a mandatory honest_scope and a recomputable hash.
    Raises if honest_scope does not declare a limit ('NOT ...')."""
    if not _honest_scope_declares_limit(honest_scope):
        raise ValueError("honest_scope must declare a real limitation: a standalone 'NOT ...' "
                         "clause, and it must not simultaneously assert accreditation/certification")
    pack = {"kind": kind,
            "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "honest_scope": honest_scope, **body}
    pack["pack_sha3"] = sha3({k: v for k, v in pack.items() if k != "pack_sha3"})
    return pack


def write_pack(path: str, pack: Dict[str, Any]) -> str:
    Path(path).write_text(json.dumps(pack, ensure_ascii=False, indent=1), encoding="utf-8")
    return path


def anchor_pack(pack_path: str, ledger_path: str) -> Dict[str, Any]:
    """Record the pack's pack_sha3 in a hash-chained ledger, so the verifier's
    'anchored' tier actually binds THIS pack to the ledger (not just 'a ledger
    exists beside it'). Returns the ledger entry."""
    from .ledger import Ledger
    pack = json.loads(Path(pack_path).read_text(encoding="utf-8"))
    entry = {"anchored_pack_sha3": pack.get("pack_sha3", ""),
             "anchored_utc": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    Ledger(ledger_path).append(entry)
    return entry


def _sig_sidecar(pack_path: str) -> Path:
    p = str(pack_path)
    return Path(p[:-5] + ".sig.json" if p.endswith(".json") else p + ".sig.json")


def _ts_sidecar(pack_path: str) -> Path:
    p = str(pack_path)
    return Path(p[:-5] + ".tsr.json" if p.endswith(".json") else p + ".tsr.json")


def sign_pack(pack_path: str, identity: Identity) -> Dict[str, Any]:
    """Sign the pack's pack_sha3 and write the signature sidecar. The sidecar
    declares `sig_alg` (crypto-agility) so the format can migrate to post-quantum
    without breaking existing packs; a legacy sidecar without it reads as ed25519."""
    pack = json.loads(Path(pack_path).read_text(encoding="utf-8"))
    digest = pack.get("pack_sha3", "")
    side = {"signer_id": identity.name, "sig_alg": getattr(identity, "sig_alg", "ed25519"),
            "public_key_b64": identity.public_key_b64,
            "fingerprint": identity.fingerprint, "signed_pack_sha3": digest,
            "signature_b64": identity.sign(digest.encode()),
            "signed_utc": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    _sig_sidecar(pack_path).write_text(json.dumps(side, ensure_ascii=False, indent=1),
                                       encoding="utf-8")
    return side


def add_pq_signature(pack_path: str, pq_sig_alg: str, pq_public_key_b64: str,
                     pq_signature_b64: str) -> Dict[str, Any]:
    """Attach a post-quantum co-signature to an already-signed pack, making it a
    HYBRID (classical Ed25519 + PQ). The PQ signature must have been produced by a
    real validated backend over the same pack_sha3 hex. The verifier reports the
    pack as pq-protected only if this PQ signature actually verifies — never for
    mere presence of the fields."""
    side_path = _sig_sidecar(pack_path)
    side = json.loads(side_path.read_text(encoding="utf-8"))
    side["pq_sig_alg"] = pq_sig_alg
    side["pq_public_key_b64"] = pq_public_key_b64
    side["pq_signature_b64"] = pq_signature_b64
    side_path.write_text(json.dumps(side, ensure_ascii=False, indent=1), encoding="utf-8")
    return side


def stamp_pack(pack_path: str, tsa_url: str, capture_ltv: bool = False,
               fetch_crl: bool = False) -> Dict[str, Any]:
    """Timestamp the pack file bytes via an RFC 3161 TSA and write the sidecar.
    With `capture_ltv=True`, also embed LTV validation material (the TSA cert chain,
    and with `fetch_crl=True` the CRL bytes at stamping time) so the timestamp stays
    validatable long after the certificates expire — RFC 4998 / eIDAS LTA spirit."""
    from .canonical import sha256_bytes
    from .timestamp import extract_validation_material, stamp
    data = Path(pack_path).read_bytes()
    digest = sha256_bytes(data)
    r = stamp(digest, tsa_url)
    if r.get("anchored"):
        side = {"digest_sha256": digest, "tsa": r["tsa"], "tsr_b64": r["tsr_b64"],
                "stamped_utc": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        if capture_ltv:
            side["validation_material"] = extract_validation_material(
                r["tsr_b64"], fetch_crl=fetch_crl)
        _ts_sidecar(pack_path).write_text(json.dumps(side, ensure_ascii=False, indent=1),
                                          encoding="utf-8")
    return r
