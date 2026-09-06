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
omega_evidence.chip_registry — a self-updating registry of AI-chip confidential-
computing attestation classes, so evidence stays current as NEW vendors and NEW
technologies appear, without a code release and without opening a security hole.

Two paths, kept strictly separate — this is the whole design:

  DISCOVERY (online, automatic, NEVER trusted)
    `discover_online(url)` fetches a candidate feed of chips seen in the wild and
    records each new one as an UNVERIFIED candidate. A candidate is *never* known
    and *never* trustworthy — it is a lead for a human to review, nothing more.

  TRUST (signed, fail-closed)
    `apply_signed_update(pack, trust_store)` — a new class becomes `known` and
    mapped to its attestation service ONLY through an evidence-pack update that is
    trusted-signed by a signer in the operator's trust registry (verified by this
    toolkit's own verifier). Network error, bad signature, or an untrusted signer
    → nothing changes (fail-closed). `fetch_signed_update_online(url, trust_store)`
    does the same over HTTP.

Immutable safety rules a feed can NEVER bend, no matter who signs it:
  * `self-asserted` and `none` are never promotable — they stay untrustworthy.
  * the code-rooted baseline is never overridden by a feed (only extended).
  * `trustworthy` is still computed from the vendor service's own verification;
    a signed update only supplies the class→service *mapping*, it can never
    declare something trustworthy.

Honest scope: a trusted-signed update proves only that the class→service mapping
comes from a source the operator chose to trust — NOT that the chip is secure.
The chip's real security still lives in the vendor's attestation service.

Self-contained: Python stdlib + this toolkit. Apache-2.0.
"""

from __future__ import annotations

import json
import os
import tempfile
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .pack import build_pack, sign_pack, write_pack
from .signing import Identity
from .verifier import verify_pack

# The code-rooted baseline: every commercial confidential-computing AI chip known
# at release, each with the vendor service that does the real crypto verification.
# A signed update EXTENDS this with future vendors; it can never override it.
_BASELINE: Dict[str, str] = {
    "nvidia-hopper-cc": "nvidia-nras",
    "nvidia-blackwell-cc": "nvidia-nras",
    "amd-sev-snp": "amd-kds",
    "aws-nitro": "aws-nitro-attestation",
    "aws-trainium": "aws-nitro-attestation",
    "intel-tdx": "intel-trust-authority",
    "google-cc": "google-cloud-attestation",
    "arm-cca": "arm-cca-verifier",
    "npu-cc": "vendor-npu-attestation",
}
# Never promotable to a trusted class — immutable, whatever a feed claims.
UNTRUSTED_CLASSES = frozenset({"self-asserted", "none"})
UPDATE_KIND = "chip_attestation_registry_update"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _http_get(url: str, timeout: float) -> bytes:
    if not (url.startswith("http://") or url.startswith("https://")):
        raise ValueError("only http(s) URLs are allowed")
    req = urllib.request.Request(url, headers={"User-Agent": "omega-evidence/chip_registry"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec - explicit scheme check
        return resp.read()


class ChipRegistry:
    """Class→attestation-service registry that self-updates online, fail-closed."""

    def __init__(self) -> None:
        self._services: Dict[str, str] = dict(_BASELINE)
        self._sources: List[Dict[str, Any]] = []     # provenance of applied updates
        self._candidates: Dict[str, Dict[str, Any]] = {}   # discovered, UNVERIFIED

    # ---- read ---------------------------------------------------------------
    def service_for(self, cls: str) -> str:
        return self._services.get(cls, "")

    def is_known(self, cls: str) -> bool:
        return cls in self._services

    def classes(self) -> Dict[str, str]:
        return dict(self._services)

    def candidates(self) -> Dict[str, Dict[str, Any]]:
        """Discovered-but-unverified classes. NEVER known, NEVER trustworthy."""
        return dict(self._candidates)

    def sources(self) -> List[Dict[str, Any]]:
        return list(self._sources)

    # ---- TRUST path: signed update, fail-closed -----------------------------
    def apply_signed_update(self, pack_path: str, trust_store: str) -> Dict[str, Any]:
        """Extend the registry from a trusted-signed update pack. Applies ONLY if
        the pack verifies as trusted-signed against `trust_store`; otherwise the
        registry is left untouched (fail-closed)."""
        v = verify_pack(pack_path, trust_store=trust_store)
        auth = next((ly for ly in v["layers"] if ly["layer"] == "authenticity"), {})
        if not v["valid"] or "trusted-signed" not in auth.get("detail", ""):
            return {"applied": False, "reason": "update is not trusted-signed",
                    "authenticity": auth.get("detail", ""), "added": [], "rejected": []}
        pack = json.loads(open(pack_path, encoding="utf-8").read())
        if pack.get("kind") != UPDATE_KIND:
            return {"applied": False, "reason": f"wrong kind: {pack.get('kind')}",
                    "added": [], "rejected": []}
        added, rejected = self._merge(pack.get("chip_classes", {}))
        signer = self._signer_of(pack_path)
        self._sources.append({"signer_id": signer, "pack_sha3": pack.get("pack_sha3", ""),
                              "kind": pack["kind"], "added": added, "rejected": rejected,
                              "applied_utc": _now()})
        return {"applied": True, "added": added, "rejected": rejected, "signer_id": signer}

    def _merge(self, classes: Dict[str, Any]):
        added, rejected = [], []
        for cls, svc in classes.items():
            if cls in UNTRUSTED_CLASSES or cls in _BASELINE:
                # untrusted classes are never promotable; the baseline is code-rooted
                rejected.append(cls)
                continue
            self._services[cls] = str(svc)
            self._candidates.pop(cls, None)   # a candidate that got a trusted mapping
            added.append(cls)
        return added, rejected

    @staticmethod
    def _signer_of(pack_path: str) -> str:
        side = pack_path[:-5] + ".sig.json" if pack_path.endswith(".json") else pack_path + ".sig.json"
        try:
            return json.loads(open(side, encoding="utf-8").read()).get("signer_id", "")
        except (OSError, ValueError):
            return ""

    def fetch_signed_update_online(self, pack_url: str, trust_store: str,
                                   timeout: float = 10.0) -> Dict[str, Any]:
        """Download a signed update pack + its `.sig.json` sidecar and apply it.
        Fail-closed: any network/parse error → registry unchanged."""
        sig_url = pack_url[:-5] + ".sig.json" if pack_url.endswith(".json") else pack_url + ".sig.json"
        try:
            body = _http_get(pack_url, timeout)
            sig = _http_get(sig_url, timeout)
        except Exception as e:   # noqa: BLE001 - fail-closed on any fetch failure
            return {"applied": False, "reason": f"fetch failed: {e}", "added": [], "rejected": []}
        with tempfile.TemporaryDirectory() as tmp:
            pp = os.path.join(tmp, "update.json")
            with open(pp, "wb") as f:
                f.write(body)
            with open(os.path.join(tmp, "update.sig.json"), "wb") as f:
                f.write(sig)
            return self.apply_signed_update(pp, trust_store)

    # ---- DISCOVERY path: online, never trusted ------------------------------
    def discover_online(self, url: str, timeout: float = 10.0) -> Dict[str, Any]:
        """Fetch a candidate feed of chips seen in the wild and record NEW ones as
        UNVERIFIED candidates. A candidate is never known and never trustworthy —
        it is a lead a human reviews and, if real, issues a trusted-signed update
        for. Fail-closed on network error."""
        try:
            data = json.loads(_http_get(url, timeout).decode("utf-8"))
        except Exception as e:   # noqa: BLE001 - fail-closed
            return {"discovered": [], "reason": f"fetch failed: {e}"}
        return self.ingest_candidates(data.get("candidates", []), source=url)

    def ingest_candidates(self, entries: List[Dict[str, Any]], source: str) -> Dict[str, Any]:
        """Record candidate classes from an already-fetched list (offline-testable).
        New vendors / technologies land here as UNVERIFIED; known/untrusted skipped."""
        found = []
        for e in entries:
            cls = (e or {}).get("attestation_class", "")
            if not cls or cls in UNTRUSTED_CLASSES or cls in self._services:
                continue
            self._candidates[cls] = {"vendor": e.get("vendor", ""),
                                     "technology": e.get("technology", ""),
                                     "proposed_service": e.get("service", ""),
                                     "source": source, "seen_utc": _now(),
                                     "status": "UNVERIFIED"}
            found.append(cls)
        return {"discovered": found,
                "note": "UNVERIFIED candidates — a trusted-signed update is required "
                        "before any of these becomes known/trustworthy"}


def publish_signed_update(path: str, chip_classes: Dict[str, str], signer: Identity,
                          honest_scope: Optional[str] = None) -> str:
    """Build + sign a chip-registry update pack (used by a curator, and in tests).
    The update carries only class→service mappings for NEW vendors/technologies."""
    scope = honest_scope or (
        "class->attestation-service mapping for new AI-chip vendors/technologies; "
        "proves the mapping's provenance, NOT that any chip is secure (that stays "
        "with the vendor attestation service)")
    pk = build_pack(UPDATE_KIND, {"chip_classes": dict(chip_classes)}, scope)
    write_pack(path, pk)
    sign_pack(path, signer)
    return path
