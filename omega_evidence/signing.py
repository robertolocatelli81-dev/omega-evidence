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

A signature binds a payload digest to a key; verification against a DIFFERENT
payload fails. Production key material belongs in an HSM/KMS; the in-memory
identity here is for reference/testing.
"""

from __future__ import annotations

import base64
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)


class Identity:
    """An Ed25519 producer identity."""

    def __init__(self, name: str, sk: Ed25519PrivateKey | None = None):
        self.name = name
        self._sk = sk or Ed25519PrivateKey.generate()

    @property
    def public_key_b64(self) -> str:
        raw = self._sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return base64.b64encode(raw).decode()

    @property
    def fingerprint(self) -> str:
        raw = self._sk.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        h = hashlib.sha256(raw).hexdigest()
        return f"ed25519:{h[:8]}…{h[-8:]}"

    def sign(self, message: bytes) -> str:
        return base64.b64encode(self._sk.sign(message)).decode()


def verify_signature(public_key_b64: str, signature_b64: str, message: bytes) -> bool:
    try:
        pk = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
        pk.verify(base64.b64decode(signature_b64), message)
        return True
    except (InvalidSignature, ValueError):
        return False
