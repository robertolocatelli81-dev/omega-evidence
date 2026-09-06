# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""omega-evidence — open toolkit for verifiable, long-term compliance evidence.

Public subset backing the declared capabilities: canonical hashing, append-only
ledger, self-describing packs (honest_scope mandatory), Ed25519 signing with an
HONEST pure-Python fallback (BACKEND declared; Ed25519 only — hybrid/PQ sealing
requires the audited `cryptography` backend), TOFU trust registry, RFC 3161
timestamps, OpenTimestamps, RFC 4998 crypto-agile preservation, PII-free
attestation, agent-governance evidence lane with honest chip-attestation
recording, CRA evidence, DSSE/in-toto and SD-JWT interop.
"""
from . import (agent, attestation, canonical, chip_registry, cra,  # noqa: F401
               ledger, ots, pack, pqbackends, preservation,
               signing, timestamp, trust)
from . import interop  # noqa: F401  (dsse, sdjwt)
from .verifier import verify_pack  # noqa: F401

__all__ = ["agent", "attestation", "canonical", "chip_registry", "cra", "ledger",
           "ots", "pack", "pqbackends", "preservation", "signing", "timestamp",
           "trust", "interop", "verify_pack"]
