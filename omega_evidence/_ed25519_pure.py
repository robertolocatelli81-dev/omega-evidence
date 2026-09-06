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
omega_evidence._ed25519_pure — a pure-Python Ed25519 (RFC 8032) used ONLY as a
portability fallback when the `cryptography` package is not installed, so signing
and verification work on ANY machine that runs Python — Windows, Linux, macOS,
any CPU architecture — with zero binary dependencies.

This is the RFC 8032 reference construction. It is byte-for-byte interoperable
with `cryptography`/OpenSSL (same standard). HONEST LIMITATION: being pure Python
it is slower and is NOT hardened against timing/side-channel attacks. When
`cryptography` is present the toolkit uses it instead; this fallback exists so the
toolkit never fails to run for lack of a native wheel. Validated at import-critical
paths against the official RFC 8032 test vectors (see tests)."""

from __future__ import annotations

import hashlib

# Base field Z_p
p = 2 ** 255 - 19
# Group order
q = 2 ** 252 + 27742317777372353535851937790883648493


def _sha512(s: bytes) -> bytes:
    return hashlib.sha512(s).digest()


def _sha512_modq(s: bytes) -> int:
    return int.from_bytes(_sha512(s), "little") % q


def _modp_inv(x: int) -> int:
    return pow(x, p - 2, p)


# Curve constant
d = -121665 * _modp_inv(121666) % p
_modp_sqrt_m1 = pow(2, (p - 1) // 4, p)

# Points are (X, Y, Z, T) extended coords: x = X/Z, y = Y/Z, x*y = T/Z


def _point_add(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % p
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % p
    C = 2 * P[3] * Q[3] * d % p
    D = 2 * P[2] * Q[2] % p
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F, G * H, F * G, E * H)


def _point_mul(s: int, P):
    Q = (0, 1, 1, 0)   # neutral element
    while s > 0:
        if s & 1:
            Q = _point_add(Q, P)
        P = _point_add(P, P)
        s >>= 1
    return Q


def _point_equal(P, Q) -> bool:
    if (P[0] * Q[2] - Q[0] * P[2]) % p != 0:
        return False
    if (P[1] * Q[2] - Q[1] * P[2]) % p != 0:
        return False
    return True


def _recover_x(y: int, sign: int):
    if y >= p:
        return None
    x2 = (y * y - 1) * _modp_inv(d * y * y + 1) % p
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (p + 3) // 8, p)
    if (x * x - x2) % p != 0:
        x = x * _modp_sqrt_m1 % p
    if (x * x - x2) % p != 0:
        return None
    if (x & 1) != sign:
        x = p - x
    return x


_g_y = 4 * _modp_inv(5) % p
_g_x = _recover_x(_g_y, 0)
_G = (_g_x, _g_y, 1, _g_x * _g_y % p)


def _point_compress(P) -> bytes:
    zinv = _modp_inv(P[2])
    x = P[0] * zinv % p
    y = P[1] * zinv % p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _point_decompress(s: bytes):
    if len(s) != 32:
        raise ValueError("invalid input length for decompression")
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % p)


def _secret_expand(secret: bytes):
    if len(secret) != 32:
        raise ValueError("bad size of private key (need 32-byte seed)")
    h = _sha512(secret)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= (1 << 254)
    return a, h[32:]


def secret_to_public(secret: bytes) -> bytes:
    """32-byte seed -> 32-byte raw public key."""
    a, _ = _secret_expand(secret)
    return _point_compress(_point_mul(a, _G))


def sign(secret: bytes, msg: bytes) -> bytes:
    """Deterministic Ed25519 signature (64 bytes) over msg with a 32-byte seed."""
    a, prefix = _secret_expand(secret)
    A = _point_compress(_point_mul(a, _G))
    r = _sha512_modq(prefix + msg)
    R = _point_mul(r, _G)
    Rs = _point_compress(R)
    h = _sha512_modq(Rs + A + msg)
    s = (r + h * a) % q
    return Rs + int.to_bytes(s, 32, "little")


def verify(public: bytes, msg: bytes, signature: bytes) -> bool:
    """Verify a 64-byte Ed25519 signature against a 32-byte raw public key."""
    if len(public) != 32 or len(signature) != 64:
        return False
    A = _point_decompress(public)
    if not A:
        return False
    Rs = signature[:32]
    R = _point_decompress(Rs)
    if not R:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= q:
        return False
    h = _sha512_modq(Rs + public + msg)
    sB = _point_mul(s, _G)
    hA = _point_mul(h, A)
    return _point_equal(sB, _point_add(R, hA))
