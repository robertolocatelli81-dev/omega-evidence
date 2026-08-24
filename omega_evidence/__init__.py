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
OMEGA Open Evidence — an open, standard toolkit for verifiable, long-term
compliance evidence. Apache-2.0. Self-contained (Python stdlib + cryptography).

Building blocks:
  canonical    — deterministic canonical SHA3 hashing
  ledger       — append-only, hash-chained, fail-closed ledger
  pack         — self-describing evidence pack (honest_scope mandatory)
  signing      — Ed25519 producer identity and signatures
  trust        — TOFU trust registry (rotation, revocation)
  timestamp    — RFC 3161 trusted timestamping
  attestation  — PII-free attestation primitive (no linkability)
  verifier     — one offline verifier with graduated authenticity

Honest scope: firm-side, verifiable evidence and open standards — NOT a
conformity-assessment body, not a QTSP, not a CA/PKI, not legal advice.
"""

from . import (attestation, canonical, ledger, pack, signing, timestamp,  # noqa: F401
               trust, verifier)
from .verifier import verify_pack  # noqa: F401

__version__ = "0.1.0"
__all__ = ["canonical", "ledger", "pack", "signing", "trust", "timestamp",
           "attestation", "verifier", "verify_pack"]
