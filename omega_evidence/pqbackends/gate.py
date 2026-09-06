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
omega_evidence.pqbackends.gate — the KAT gate every PQ backend must pass.

A post-quantum signature backend is trusted ONLY if, on a set of known-answer
test (KAT) vectors, it (a) verifies every valid vector AND (b) rejects a tampered
copy of each. This is the anti-Goodhart check: a backend that flags nothing wrong
(accepts a bit-flipped signature) is worthless and must not be registered. Only a
gated backend is wired into signing.register_sig_alg.
"""

from __future__ import annotations

import base64
from typing import Any, Callable, Dict, List

from .. import signing

# Verifier signature: (public_key_b64, signature_b64, message: bytes) -> bool
Verifier = Callable[[str, str, bytes], bool]


def _tamper_b64(sig_b64: str) -> str:
    raw = bytearray(base64.b64decode(sig_b64))
    if raw:
        raw[0] ^= 0x01
    return base64.b64encode(bytes(raw)).decode()


def run_kat(verify_fn: Verifier, kat: List[Dict[str, str]]) -> Dict[str, Any]:
    """Run the KAT gate. Each vector: {public, signature, message_hex}. Returns
    {passed, reason}. Fails closed on the first vector that a correct backend must
    accept but is rejected, or a tampered one that must be rejected but is accepted."""
    if not kat:
        return {"passed": False, "reason": "no KAT vectors supplied"}
    for i, v in enumerate(kat):
        msg = bytes.fromhex(v.get("message_hex", ""))
        try:
            ok = verify_fn(v["public"], v["signature"], msg)
        except Exception as e:                       # noqa: BLE001 - a throwing backend fails the gate
            return {"passed": False, "reason": f"vector {i}: backend raised {e!r}"}
        if not ok:
            return {"passed": False, "reason": f"vector {i}: valid signature rejected"}
        if verify_fn(v["public"], _tamper_b64(v["signature"]), msg):
            return {"passed": False, "reason": f"vector {i}: tampered signature accepted"}
    return {"passed": True, "reason": f"{len(kat)} KAT vector(s) passed"}


def register_pq_backend(alg: str, verify_fn: Verifier,
                        kat: List[Dict[str, str]]) -> Dict[str, Any]:
    """Validate a PQ verifier against its KAT and, only if it passes, register it
    as a post-quantum signature algorithm usable by the verifier. Never registers
    an ungated backend."""
    result = run_kat(verify_fn, kat)
    if not result["passed"]:
        return {"registered": False, "alg": alg, "reason": result["reason"]}
    signing.register_sig_alg(alg, verify_fn, post_quantum=True)
    return {"registered": True, "alg": alg, "reason": result["reason"]}
