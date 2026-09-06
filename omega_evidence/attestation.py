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
SCOPE: salted digests protect UNLINKABILITY across records (different salts). They do NOT
hide a LOW-ENTROPY value: the per-record salt is stored IN the record and `matches()` is a
public oracle, so an enumerable attribute (a birthdate, an over18 flag, a formatted ID) is
brute-forceable in milliseconds. For real value-hiding use a keyed HMAC/commitment whose key
is NOT in the record. This is a linkability primitive, not value confidentiality.

omega_evidence.attestation — PII-free attestation primitive.

Records THAT an attribute was presented and verified, without ever storing the
value in the clear. Each attribute value becomes a per-record SALTED SHA3
digest: the same value in two records yields different digests (no linkability).
Suited to self-sovereign identity (eIDAS/EUDI) and privacy-by-design.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

from .canonical import sha3


def _salted(value: str, salt: str) -> str:
    return hashlib.sha3_256((salt + "|" + value).encode()).hexdigest()


@dataclass(frozen=True)
class Attestation:
    """A PII-free record of an attribute presentation."""
    subject_ref: str                 # opaque reference, NOT an identifier value
    attribute_names: List[str]
    attribute_digests: Dict[str, str]
    salt: str
    outcome: str = "accepted"
    issued_utc: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))

    def digest(self) -> str:
        return sha3({"subject_ref": self.subject_ref, "names": sorted(self.attribute_names),
                     "digests": self.attribute_digests, "outcome": self.outcome,
                     "issued_utc": self.issued_utc})


def attest(subject_ref: str, attributes: Dict[str, str],
           outcome: str = "accepted", salt: Optional[str] = None) -> Attestation:
    """Build a PII-free attestation. `attributes` = {name: value}; the value is
    digested here and never stored in the clear."""
    s = salt or secrets.token_hex(16)
    return Attestation(
        subject_ref=subject_ref, attribute_names=sorted(attributes.keys()),
        attribute_digests={k: _salted(v, s) for k, v in attributes.items()},
        salt=s, outcome=outcome)


def matches(att: Attestation, name: str, candidate_value: str) -> bool:
    """Check a candidate value against a stored digest (needs the record's salt)."""
    return att.attribute_digests.get(name) == _salted(candidate_value, att.salt)
