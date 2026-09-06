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
omega_evidence.agent — verifiable evidence for AI agent governance.

Records what an AI agent did, which policy decision applied, its outcome, human
approvals, and (optionally) the hardware attestation of the chip it ran on —
into a tamper-evident, offline-verifiable evidence pack.

Positioned honestly against the 2026 market: this is NOT a policy engine and NOT
a runtime enforcer (that is what NVIDIA OpenShell and kernel sandboxes do). Like
Asqav and nono.sh it is an evidence layer — but it is **cross-domain and
offline-first**: an agent's evidence lives in the *same* self-describing pack
format this toolkit uses for any other domain, verified by the same offline
verifier, without trusting the producer. Enforcement stays in the runtime; this
proves, after the fact, what happened — for a regulator, an auditor, or a court.

Self-contained: Python stdlib + this toolkit only. Apache-2.0.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional

from .canonical import sha3
from .ledger import Ledger
from .pack import build_pack


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"                      # deny-by-default: the safe base case
    ALLOW_WITH_APPROVAL = "allow_with_approval"


class Outcome(str, Enum):
    EXECUTED = "executed"
    BLOCKED = "blocked"
    PENDING_APPROVAL = "pending_approval"


# Hardware attestation provenance — DECLARED, never flattened. The set of known
# chip classes is self-updating: `chip_registry.ChipRegistry` extends it online
# (fail-closed, trusted-signed) as NEW vendors/technologies appear. ATTESTATION_
# SERVICE is the code-rooted baseline; each vendor has its own attestation service
# that does the real crypto verification.
from .chip_registry import _BASELINE as ATTESTATION_SERVICE  # noqa: E402
from .chip_registry import UNTRUSTED_CLASSES as _UNTRUSTED_ATTESTATION  # noqa: E402


def check_attestation(attestation: Optional[Dict[str, Any]],
                      registry: "Any" = None) -> Dict[str, Any]:
    """Bind a chip attestation to the evidence. Honest: this toolkit does NOT
    re-verify the attestation cryptography — that is each vendor's attestation
    service's job (NVIDIA NRAS, AMD KDS, AWS Nitro, Intel Trust Authority, Google
    Cloud, ARM CCA). It RECORDS the declared class + claim; it never asserts
    `trustworthy=True`, because every field (the boolean, a token, a report) is
    caller-controlled and unverified here — trust requires an EXTERNAL check
    against the vendor service. (FIX NEMESIS re-attack: propagates the same
    hardening as the private agent_governance_bridge twin.)

    `registry` (a ChipRegistry) lets a FUTURE chip — added online via a trusted-
    signed update — be recognised as a known class; without one, the code-rooted
    baseline is used."""
    a = attestation or {}
    cls = a.get("attestation_class", "none")
    verified = bool(a.get("verified_by_service"))
    service_token = a.get("service_attestation_token") or a.get("service_quote")
    has_report = bool(a.get("report_sha256"))
    if registry is not None:
        known = registry.is_known(cls)
        expected = registry.service_for(cls)
    else:
        known = cls in ATTESTATION_SERVICE
        expected = ATTESTATION_SERVICE.get(cls, "")
    if cls in _UNTRUSTED_ATTESTATION or not known:
        status = "untrusted-class"
    elif verified and service_token and has_report:
        status = "service-token-recorded-UNVERIFIED"
    elif verified:
        status = "producer-claimed"
    else:
        status = "none"
    return {
        "attestation_class": cls,
        "known_class": known,
        "verified_by_service": verified,
        "service_token_present": bool(service_token),
        "attestation_service": a.get("service") or expected,
        "expected_service": expected,
        "device_id": a.get("device_id", ""),
        # never asserted here: the toolkit does not verify the vendor crypto, and
        # every input field is caller-controlled/forgeable.
        "trustworthy": False,
        "verified_here": False,
        "attestation_status": status,
        "requires_service_verification": True,
    }


@dataclass(frozen=True)
class AgentAction:
    """One governed agent action — immutable, canonically hashable."""
    agent_id: str
    session_id: str
    action: str                       # e.g. tool_call, file_write, command_exec, network
    resource: str
    policy_rule: str
    decision: str
    outcome: str
    human_approver: Optional[str] = None
    device_attestation: Optional[Dict[str, Any]] = None
    reason: str = ""
    timestamp_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    def digest(self) -> str:
        return sha3(asdict(self))

    def consistent(self) -> bool:
        """decision↔outcome coherence (made visible, not hidden)."""
        if self.decision == Decision.DENY.value:
            return self.outcome == Outcome.BLOCKED.value
        if self.decision == Decision.ALLOW.value:
            return self.outcome == Outcome.EXECUTED.value
        if self.decision == Decision.ALLOW_WITH_APPROVAL.value:
            return bool(self.human_approver) and self.outcome in (
                Outcome.EXECUTED.value, Outcome.PENDING_APPROVAL.value)
        return False


class AgentEvidenceLog:
    """Append-only, hash-chained, offline-verifiable log of agent governance."""

    def __init__(self, ledger_path: str, runtime_id: str = "agent-runtime",
                 chip_registry: "Any" = None):
        self.runtime_id = runtime_id
        self.ledger_path = ledger_path        # anchor the pack to this ledger
        self.chip_registry = chip_registry    # optional self-updating chip registry
        self._ledger = Ledger(ledger_path)
        self._lock = threading.Lock()

    def record(self, agent_id: str, session_id: str, action: str, resource: str,
               policy_rule: str, decision: Decision, outcome: Outcome,
               human_approver: Optional[str] = None,
               device_attestation: Optional[Dict[str, Any]] = None,
               reason: str = "") -> AgentAction:
        rec = AgentAction(
            agent_id=agent_id, session_id=session_id, action=action,
            resource=resource, policy_rule=policy_rule, decision=decision.value,
            outcome=outcome.value, human_approver=human_approver,
            device_attestation=(check_attestation(device_attestation, self.chip_registry)
                                if device_attestation else None),
            reason=reason)
        with self._lock:
            self._ledger.append({"kind": "agent_governance_action",
                                 "runtime_id": self.runtime_id, **asdict(rec),
                                 "record_sha3": rec.digest(),
                                 "consistent": rec.consistent()})
        return rec

    def verify(self) -> Dict[str, Any]:
        ok, bad = self._ledger.verify()
        return {"chain_ok": ok, "bad_entries": bad, "entries": self._ledger.count}

    def stats(self) -> Dict[str, Any]:
        st = {"total": 0, "allow": 0, "deny": 0, "allow_with_approval": 0,
              "attestation_recorded": 0, "inconsistent": []}
        for d in self._ledger.entries():
            if d.get("kind") != "agent_governance_action":
                continue
            st["total"] += 1
            st[d.get("decision", "?")] = st.get(d.get("decision", "?"), 0) + 1
            da = d.get("device_attestation")
            # count attestations RECORDED (never 'trustworthy' — not verified here)
            if isinstance(da, dict) and da.get("attestation_status") in (
                    "service-token-recorded-UNVERIFIED", "producer-claimed"):
                st["attestation_recorded"] += 1
            if not d.get("consistent", True):
                st["inconsistent"].append(d.get("record_id", d.get("timestamp_utc", "?")))
        st["all_consistent"] = not st["inconsistent"]
        return st

    def evidence_pack(self) -> Dict[str, Any]:
        """A self-describing evidence pack — the SAME format this toolkit uses for
        any other domain (cross-domain uniformity: one verifier for agents and for
        everything else)."""
        return build_pack(
            "agent_governance_evidence_pack",
            {"runtime_id": self.runtime_id, "verification": self.verify(),
             "stats": self.stats()},
            honest_scope=("firm-side agent-governance evidence, offline-verifiable; "
                          "NOT a policy engine, NOT runtime enforcement (that stays "
                          "in the runtime, e.g. OpenShell); hardware attestation "
                          "crypto is verified by the vendor service, not here"))
