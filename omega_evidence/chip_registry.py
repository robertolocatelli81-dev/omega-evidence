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

Replay (0.14.0): the update pack carries `update_seq`, an integer from 1 to 2^53-1 inside the signed body, and the
kind is `chip_attestation_registry_update_v2`. A registry applies an update only when its `update_seq` is greater than
the last one it applied from the same signing key (`last_seq()`, keyed by the `public_key_b64` that verified; give it
back to `ChipRegistry(last_seq=...)` to keep the order across restarts). The order is kept per key, not per `signer_id`:
`signer_id` is a label the signature does not cover, and a trust store may bind one key to two labels — an old update
re-labelled with the other one was applied after the newer (measured 21/11/2026: `service-NEW`, then `service-OLD`).
Until 0.13.0 the kind `chip_attestation_registry_update` had no sequence, so an older signed
update applied after a newer one put the old mapping back (measured 20/11/2026: `service-NEW`, then `service-OLD`);
such a pack is now refused with its reason (re-issue it as v2).

Honest scope: a trusted-signed update proves only that the class→service mapping
comes from a source the operator chose to trust — NOT that the chip is secure.
The chip's real security still lives in the vendor's attestation service.

Self-contained: Python stdlib + this toolkit. Apache-2.0.
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from . import _crl_fetch
from .ledger import MAX_INPUT_BYTES, loads_bounded, loads_strict, read_input
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
UPDATE_KIND = "chip_attestation_registry_update_v2"     # carries update_seq (0.14.0)
UPDATE_KIND_V1 = "chip_attestation_registry_update"     # no sequence: refused, a replay cannot be told from it
MAX_UPDATE_SEQ = 2 ** 53 - 1                            # the portable integer bound of the strict JSON profile


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _http_get(url: str, timeout: float) -> bytes:
    if not (url.startswith("http://") or url.startswith("https://")):
        raise ValueError("only http(s) URLs are allowed")
    # no redirect, at most the bound of every verifier input (_crl_fetch.ask; until 0.12.0 a redirect was followed)
    return _crl_fetch.ask(url, headers={"User-Agent": "omega-evidence/chip_registry"}, timeout=timeout,
                          max_bytes=MAX_INPUT_BYTES)


class ChipRegistry:
    """Class→attestation-service registry that self-updates online, fail-closed."""

    def __init__(self, last_seq: Optional[Dict[str, int]] = None) -> None:
        self._last_seq: Dict[str, int] = {}
        if last_seq is not None and not isinstance(last_seq, dict):
            raise ValueError("last_seq: {public_key_b64: integer from 0 to 2^53-1}")
        for key, n in (last_seq or {}).items():
            if not isinstance(key, str) or isinstance(n, bool) or not isinstance(n, int) or not 0 <= n <= MAX_UPDATE_SEQ:
                raise ValueError("last_seq: {public_key_b64: integer from 0 to 2^53-1}")
            self._last_seq[key] = n
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

    def last_seq(self) -> Dict[str, int]:
        """{public_key_b64: the update_seq of the last update applied that this signing key verified}"""
        return dict(self._last_seq)

    # ---- TRUST path: signed update, fail-closed -----------------------------
    def apply_signed_update(self, pack_path: str, trust_store: str) -> Dict[str, Any]:
        """Extend the registry from a trusted-signed update pack. Applies ONLY if
        the pack verifies as trusted-signed against `trust_store`; otherwise the
        registry is left untouched (fail-closed).

        The bytes applied are the bytes verified. The pack and the files the verifier reads beside it (the signature,
        timestamp and ledger sidecars) are each read ONCE with `ledger.read_input` (a regular file, at most 64 MiB,
        opened without blocking) into a directory only this user can enter; `verify_pack` judges that copy, and the
        classes, the `pack_sha3` and the `signer_id` recorded come from the same bytes, parsed with the verifier's
        strict profile (`loads_strict`). A file beside the pack that is there but cannot be read is a refusal, as it
        is a FAIL for the verifier. Until 0.12.0 the pack was verified from its path and then read again from the same
        path, with `loads_bounded` (duplicate keys and floats accepted), and the sidecar a third time for `signer_id`:
        a pack replaced between the two reads was applied without ever having been verified (measured 20/11/2026,
        tests/test_sentry_20261120.py). `chip_classes` that is not a JSON object is a refusal, not a traceback."""
        def refused(reason: str, authenticity: Optional[str] = None) -> Dict[str, Any]:
            out = {"applied": False, "reason": reason, "added": [], "rejected": []}
            if authenticity is not None:
                out["authenticity"] = authenticity
            return out
        stem = pack_path[:-5] if pack_path.endswith(".json") else pack_path
        try:
            with tempfile.TemporaryDirectory() as tmp:   # mode 0700: nobody else replaces what is verified here
                read: Dict[str, bytes] = {}
                for name, src in (("update.json", pack_path), ("update.sig.json", stem + ".sig.json"),
                                  ("update.tsr.json", stem + ".tsr.json"), ("update.ledger.jsonl", stem + ".ledger.jsonl")):
                    try:
                        read[name] = read_input(src)
                    except FileNotFoundError:
                        continue                         # absent: absent in the copy too (the pack: pack-json FAIL)
                    with open(os.path.join(tmp, name), "wb") as f:
                        f.write(read[name])
                v = verify_pack(os.path.join(tmp, "update.json"), trust_store=trust_store)
        except OSError as e:   # there but not readable (a FIFO, a directory, beyond the bound), or no temporary file
            return refused(f"update not read: {type(e).__name__}: {str(e)[:120]}")
        auth = next((ly for ly in v["layers"] if ly["layer"] == "authenticity"), {})
        if not v["valid"] or "trusted-signed" not in auth.get("detail", ""):
            return refused("update is not trusted-signed", auth.get("detail", ""))
        pack = loads_strict(read["update.json"].decode("utf-8").strip(" \t\r\n"))   # as the verifier parsed them
        if pack.get("kind") == UPDATE_KIND_V1:
            return refused(f"unsequenced update (kind {UPDATE_KIND_V1}): a replay of an older update cannot be told from "
                           f"it; re-issue it as {UPDATE_KIND} with update_seq")
        if pack.get("kind") != UPDATE_KIND:
            return refused(f"wrong kind: {pack.get('kind')}")
        classes = pack.get("chip_classes", {})
        if not isinstance(classes, dict):
            return refused("chip_classes is not a JSON object")
        seq = pack.get("update_seq")
        if isinstance(seq, bool) or not isinstance(seq, int) or not 1 <= seq <= MAX_UPDATE_SEQ:
            return refused("update_seq is not an integer from 1 to 2^53-1")
        signer = self._signer_in(read.get("update.sig.json", b""))
        # the order is kept per signing KEY (the verifier took it only as canonical base64 of 32 bytes, so one key is
        # one string): signer_id is an unsigned label, and one key under two labels would have two sequences
        key = self._field_in(read.get("update.sig.json", b""), "public_key_b64")
        if seq <= self._last_seq.get(key, 0):
            return refused(f"update_seq {seq} is not after the last applied from the key of {signer!r} "
                           f"({self._last_seq[key]}): an older or repeated update is not applied")
        added, rejected = self._merge(classes)
        self._last_seq[key] = seq
        self._sources.append({"signer_id": signer, "pack_sha3": pack.get("pack_sha3", ""),
                              "kind": pack["kind"], "update_seq": seq, "added": added, "rejected": rejected,
                              "applied_utc": _now()})
        return {"applied": True, "added": added, "rejected": rejected, "signer_id": signer, "update_seq": seq}

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
    def _field_in(sig_bytes: bytes, name: str) -> str:
        """The string member `name` of the signature sidecar whose bytes were verified ("" when it is not a string)."""
        try:
            side = loads_strict(sig_bytes.decode("utf-8").strip(" \t\r\n"))
        except ValueError:
            return ""
        got = side.get(name, "") if isinstance(side, dict) else ""
        return got if isinstance(got, str) else ""

    @staticmethod
    def _signer_in(sig_bytes: bytes) -> str:
        """`signer_id` of the signature sidecar whose bytes were verified ("" when it is not a string)."""
        return ChipRegistry._field_in(sig_bytes, "signer_id")

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
            data = loads_bounded(_http_get(url, timeout).decode("utf-8"))
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
                          honest_scope: Optional[str] = None, *, update_seq: int) -> str:
    """Build + sign a chip-registry update pack (used by a curator, and in tests).
    The update carries only class→service mappings for NEW vendors/technologies, and `update_seq` (an integer from 1 to
    2^53-1, greater than the curator's previous update: a registry applies the updates of one signing key in that order only)."""
    if isinstance(update_seq, bool) or not isinstance(update_seq, int) or not 1 <= update_seq <= MAX_UPDATE_SEQ:
        raise ValueError("update_seq: an integer from 1 to 2^53-1")
    scope = honest_scope or (
        "class->attestation-service mapping for new AI-chip vendors/technologies; "
        "proves the mapping's provenance, NOT that any chip is secure (that stays "
        "with the vendor attestation service)")
    pk = build_pack(UPDATE_KIND, {"chip_classes": dict(chip_classes), "update_seq": update_seq}, scope)
    write_pack(path, pk)
    sign_pack(path, signer)
    return path
