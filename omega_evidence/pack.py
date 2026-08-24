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


def build_pack(kind: str, body: Dict[str, Any], honest_scope: str) -> Dict[str, Any]:
    """Assemble a pack with a mandatory honest_scope and a recomputable hash.
    Raises if honest_scope does not declare a limit ('NOT ...')."""
    if "NOT" not in honest_scope:
        raise ValueError("honest_scope must declare a limit (contain 'NOT ...')")
    pack = {"kind": kind,
            "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "honest_scope": honest_scope, **body}
    pack["pack_sha3"] = sha3({k: v for k, v in pack.items() if k != "pack_sha3"})
    return pack


def write_pack(path: str, pack: Dict[str, Any]) -> str:
    Path(path).write_text(json.dumps(pack, ensure_ascii=False, indent=1), encoding="utf-8")
    return path


def _sig_sidecar(pack_path: str) -> Path:
    p = str(pack_path)
    return Path(p[:-5] + ".sig.json" if p.endswith(".json") else p + ".sig.json")


def _ts_sidecar(pack_path: str) -> Path:
    p = str(pack_path)
    return Path(p[:-5] + ".tsr.json" if p.endswith(".json") else p + ".tsr.json")


def sign_pack(pack_path: str, identity: Identity) -> Dict[str, Any]:
    """Sign the pack's pack_sha3 and write the signature sidecar."""
    pack = json.loads(Path(pack_path).read_text(encoding="utf-8"))
    digest = pack.get("pack_sha3", "")
    side = {"signer_id": identity.name, "public_key_b64": identity.public_key_b64,
            "fingerprint": identity.fingerprint, "signed_pack_sha3": digest,
            "signature_b64": identity.sign(digest.encode()),
            "signed_utc": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    _sig_sidecar(pack_path).write_text(json.dumps(side, ensure_ascii=False, indent=1),
                                       encoding="utf-8")
    return side


def stamp_pack(pack_path: str, tsa_url: str) -> Dict[str, Any]:
    """Timestamp the pack file bytes via an RFC 3161 TSA and write the sidecar."""
    from .canonical import sha256_bytes
    from .timestamp import stamp
    data = Path(pack_path).read_bytes()
    digest = sha256_bytes(data)
    r = stamp(digest, tsa_url)
    if r.get("anchored"):
        side = {"digest_sha256": digest, "tsa": r["tsa"], "tsr_b64": r["tsr_b64"],
                "stamped_utc": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        _ts_sidecar(pack_path).write_text(json.dumps(side, ensure_ascii=False, indent=1),
                                          encoding="utf-8")
    return r
