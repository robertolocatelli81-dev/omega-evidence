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
omega_evidence.signing — Ed25519 producer identity and signatures.

Runs on ANY machine that runs Python — Windows, Linux, macOS, any CPU — because
the crypto backend is chosen automatically:

  * if the `cryptography` package is installed, it is used (fast, native,
    side-channel-hardened) — `BACKEND == "cryptography"`;
  * otherwise a pure-Python Ed25519 (RFC 8032, stdlib only) is used, so the
    toolkit never fails for lack of a native wheel — `BACKEND == "pure-python"`.

Both backends implement the SAME standard: a signature made on one machine
verifies on the other. An Identity is a 32-byte seed; production key material
belongs in an HSM/KMS — the in-memory identity here is for reference/testing.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from typing import Optional

try:                                              # prefer the native backend
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey)
    BACKEND = "cryptography"
except Exception:                                 # noqa: BLE001 - any import failure -> fallback
    from . import _ed25519_pure as _pure
    BACKEND = "pure-python"


def _seed_to_public(seed: bytes) -> bytes:
    if BACKEND == "cryptography":
        sk = Ed25519PrivateKey.from_private_bytes(seed)
        return sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return _pure.secret_to_public(seed)


def _seed_sign(seed: bytes, message: bytes) -> bytes:
    if BACKEND == "cryptography":
        return Ed25519PrivateKey.from_private_bytes(seed).sign(message)
    return _pure.sign(seed, message)


class Identity:
    """An Ed25519 producer identity, backed by a 32-byte seed."""

    def __init__(self, name: str, seed: Optional[bytes] = None):
        self.name = name
        # A failed key fetch returning b"" must NOT silently mint a throwaway random key
        # (evidence continuity depends on the real key). Only seed=None means "generate".
        if seed is None:
            self._seed = secrets.token_bytes(32)
        else:
            if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
                raise ValueError("seed must be exactly 32 bytes (got "
                                 f"{len(seed) if isinstance(seed, (bytes, bytearray)) else type(seed).__name__})")
            self._seed = bytes(seed)

    @property
    def public_key_b64(self) -> str:
        return base64.b64encode(_seed_to_public(self._seed)).decode()

    @property
    def fingerprint(self) -> str:
        h = hashlib.sha256(_seed_to_public(self._seed)).hexdigest()
        return f"ed25519:{h[:8]}…{h[-8:]}"

    def sign(self, message: bytes) -> str:
        return base64.b64encode(_seed_sign(self._seed, message)).decode()


def verify_signature(public_key_b64: str, signature_b64: str, message: bytes) -> bool:
    """Verify an Ed25519 signature. Works regardless of which backend produced it."""
    try:
        pk_raw = base64.b64decode(public_key_b64)
        sig = base64.b64decode(signature_b64)
    except (ValueError, TypeError):
        return False
    if BACKEND == "cryptography":
        try:
            Ed25519PublicKey.from_public_bytes(pk_raw).verify(sig, message)
            return True
        except (InvalidSignature, ValueError):
            return False
    return _pure.verify(pk_raw, message, sig)


# --- Crypto-agility ----------------------------------------------------------
# Signatures declare their algorithm (`sig_alg`) so the format can migrate to
# post-quantum without breaking existing packs. Ed25519 is the built-in default;
# a post-quantum backend (e.g. SLH-DSA / FIPS 205, ML-DSA / FIPS 204) registers
# itself here when installed. There is deliberately NO home-grown PQ crypto: a PQ
# verifier is trusted only if a real, validated backend provides it.
DEFAULT_SIG_ALG = "ed25519"
SIG_ALGS = {"ed25519": verify_signature}     # alg -> (pub_b64, sig_b64, msg)->bool
PQ_SIG_ALGS: dict = {}                        # post-quantum algs, populated by a backend


def register_sig_alg(alg: str, verifier, post_quantum: bool = False) -> None:
    """Register a signature-verification backend for `alg`. `post_quantum=True`
    marks it as PQ so a hybrid pack can be reported as pq-protected once it
    actually verifies. Never registers unvalidated home-grown crypto."""
    SIG_ALGS[alg] = verifier
    if post_quantum:
        PQ_SIG_ALGS[alg] = verifier


def verify_with_alg(alg: str, public_key_b64: str, signature_b64: str,
                    message: bytes):
    """Verify using the backend for `alg`. Returns True/False if the alg is
    known, or None if unsupported (honest SKIP, never a false green)."""
    fn = SIG_ALGS.get(alg)
    if fn is None:
        return None
    return fn(public_key_b64, signature_b64, message)


def verify_pq_alg(alg: str, public_key_b64: str, signature_b64: str, message: bytes):
    """Verify using a POST-QUANTUM backend only. Returns True/False if `alg` is a
    registered PQ algorithm, or None if it is not (so a classical alg like ed25519
    can NEVER be reported as pq-protected). This is deliberately separate from
    verify_with_alg, which resolves against the general SIG_ALGS registry."""
    fn = PQ_SIG_ALGS.get(alg)
    if fn is None:
        return None
    return fn(public_key_b64, signature_b64, message)


def pq_backends_available() -> list:
    """Registered post-quantum signature algorithms (empty unless a backend is
    installed) — reported by the doctor so an operator knows what is possible."""
    return sorted(PQ_SIG_ALGS)
