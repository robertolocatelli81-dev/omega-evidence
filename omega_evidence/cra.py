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
omega_evidence.cra — firm-side evidence for the EU Cyber Resilience Act
(Regulation (EU) 2024/2847).

Two obligations, two evidence kinds (verified against primary sources on
2026-08-25 — digital-strategy.ec.europa.eu, ENISA, EUR-Lex 32024R2847):

  * VULNERABILITY / INCIDENT REPORTING — the 24h early-warning to the CSIRT /
    ENISA Single Reporting Platform applies from **11 September 2026**.
    `vuln_report_evidence(...)` records WHAT and WHEN a manufacturer reported.
  * SBOM — a "commonly used, machine-readable" SBOM of the top-level dependencies
    (Annex I, Part II) is required from **11 December 2027**. `sbom_evidence(...)`
    records WHICH SBOM accompanied WHICH build, hash-chained.

HONEST SCOPE (embedded in every pack):
  * NOT the ENISA Single Reporting Platform and NOT an official channel — this is
    after-the-fact proof of WHAT the manufacturer recorded and (only if the time
    is anchored) WHEN, NOT proof it was RECEIVED by ENISA nor that it was sent.
  * Does NOT validate the SBOM's completeness/correctness — it is NOT a CRA
    conformity assessment.
  * "When" is proof of time ONLY if anchored (RFC 3161 TSA or ledger). A bare
    self-asserted timestamp is recorded as such and is NOT proof of time.

Self-contained: Python stdlib + this toolkit. Apache-2.0.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from .ledger import Ledger
from .pack import build_pack

# Primary-source application dates (Regulation (EU) 2024/2847).
CRA_REPORTING_APPLIES = "2026-09-11"     # 24h reporting via ENISA SRP
CRA_SBOM_APPLIES = "2027-12-11"          # machine-readable SBOM (Annex I, Part II)

SBOM_KIND = "cra_sbom_evidence_pack"
VULN_KIND = "cra_vuln_report_evidence_pack"

_SBOM_SCOPE = ("proves WHICH SBOM accompanied WHICH build (format + sha256 + "
               "top-level count, hash-chained to product+version); does NOT "
               "validate the SBOM's completeness/correctness and is NOT a CRA "
               "conformity assessment")
_VULN_SCOPE = ("after-the-fact proof of WHAT a manufacturer recorded and (only if "
               "anchored) WHEN; NOT the ENISA Single Reporting Platform, NOT proof "
               "of receipt nor that it was sent, NOT an official reporting channel")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _detect_format_and_count(raw: bytes):
    """Best-effort SBOM format + top-level component count. Honest: a count, not a
    validation. Recognises CycloneDX (`components`) and SPDX (`packages`)."""
    try:
        doc = json.loads(raw)
    except ValueError:
        return "unknown", None
    if "bomFormat" in doc or "components" in doc:
        return "CycloneDX", len(doc.get("components", []))
    if "spdxVersion" in doc or "packages" in doc:
        return "SPDX", len(doc.get("packages", []))
    return "unknown", None


def sbom_evidence(product: str, version: str, sbom_path: str,
                  sbom_format: Optional[str] = None,
                  ledger_path: Optional[str] = None) -> Dict[str, Any]:
    """Record which SBOM accompanied a build, bound in a hash-chain to
    product+version. `ledger_path` appends a tamper-evident entry."""
    raw = Path(sbom_path).read_bytes()
    sbom_sha256 = hashlib.sha256(raw).hexdigest()
    detected_fmt, count = _detect_format_and_count(raw)
    body = {"product": product, "version": version,
            "sbom_format": sbom_format or detected_fmt,
            "sbom_sha256": sbom_sha256, "top_level_count": count,
            "cra_sbom_applies": CRA_SBOM_APPLIES, "recorded_utc": _now()}
    if ledger_path:
        Ledger(ledger_path).append({"kind": SBOM_KIND, **body})
    return build_pack(SBOM_KIND, body, _SBOM_SCOPE)


def vuln_report_evidence(cve: str, product: str, version: str, reported_utc: str,
                         recipient: str = "CSIRT/ENISA-SRP",
                         severity: str = "", summary: str = "",
                         time_anchored: bool = False,
                         ledger_path: Optional[str] = None) -> Dict[str, Any]:
    """Record a vulnerability/incident report a manufacturer made. `time_anchored`
    must be True ONLY if the time is backed by a TSA/ledger anchor; otherwise the
    record is explicit that the timestamp is self-asserted and NOT proof of time."""
    # A producer boolean can NEVER turn an unverifiable claim into a fact: even
    # when the producer claims anchoring, the time stays a CLAIM until a verifier
    # confirms a real TSA/ledger anchor. The honesty caveat is never removed.
    time_basis = "producer-claimed-anchored" if time_anchored else "self-asserted"
    body = {"cve": cve, "product": product, "version": version,
            "reported_utc": reported_utc, "recipient": recipient,
            "severity": severity, "summary": summary, "time_basis": time_basis,
            "cra_reporting_applies": CRA_REPORTING_APPLIES, "recorded_utc": _now()}
    if ledger_path:
        Ledger(ledger_path).append({"kind": VULN_KIND, **body})
    if time_anchored:
        scope = _VULN_SCOPE + ("; time_basis is a PRODUCER CLAIM of anchoring — this "
                               "pack alone does NOT prove it; verify it independently "
                               "against a real TSA/ledger anchor with the verifier")
    else:
        scope = _VULN_SCOPE + ("; this record's time is SELF-ASSERTED (not anchored) "
                               "— NOT proof of when")
    return build_pack(VULN_KIND, body, scope)
