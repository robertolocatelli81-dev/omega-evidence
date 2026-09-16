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
omega_evidence.pqbackends.mldsa — ML-DSA-65 (FIPS 204) post-quantum co-signatures, 0.7.0.

Profile (the same as cryptovalid 0.13.0, so the same verifiers apply): pure ML-DSA-65 with the EMPTY context
string (the JDK 24-27 built-in provider has no context API; AWS KMS RAW signing is the empty context); message =
the UTF-8 bytes of the pack's `pack_sha3` hex string (the same bytes the Ed25519 sidecar signs); signature 3309
bytes and public key 1952 bytes, both standard base64 with padding, decoded STRICTLY. Verification needs
`cryptography` >= 50; without it the layer is reported present-but-unverifiable, never a pass.

The backend is registered only after the KAT gate (`gate.run_kat`) passes on the NIST ACVP ML-DSA-65 sigVer
vectors shipped next to this file (`vectors/acvp_mldsa65_sigver.txt`, FIPS 204 external/pure, contexts as given
by NIST) — a backend that accepts a tampered signature is never wired in.

Signers: `MlDsaFileSigner` (PKCS#8 DER base64 on disk, 0600) and `AwsKmsMlDsaSigner` (KeySpec ML_DSA_65,
ML_DSA_SHAKE_256, MessageType RAW; the private key never enters process memory; the Sign response's KeyId must
match the key whose public key was read). The key MUST be dedicated to this profile: with no context, any other
application signing a 64-hex string with the same key would produce a valid pack co-signature.
"""
from __future__ import annotations

import base64
import binascii
import os
from typing import Any, Dict, Optional

from .. import signing
from . import gate

ALG = "ml-dsa-65"
SIG_LEN, PK_LEN = 3309, 1952
_HERE = os.path.dirname(os.path.abspath(__file__))
KAT_FILE = os.path.join(_HERE, "vectors", "acvp_mldsa65_sigver.txt")
MLDSA65_SPKI_OID = bytes.fromhex("0609608648016503040312")   # id-ml-dsa-65 (RFC 9881)
MLDSA65_SPKI_LEN = 1974


def _mldsa():
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa  # cryptography >= 50
        return mldsa
    except Exception:  # noqa: BLE001 — absent or too old: the layer is unverifiable, declared
        return None


def available() -> bool:
    return _mldsa() is not None


def b64_strict(s: Any, n: int) -> Optional[bytes]:
    """Strict standard base64 of exactly n bytes (canonical re-encoding), or None."""
    if not isinstance(s, str) or len(s) != ((n + 2) // 3) * 4:
        return None
    try:
        raw = base64.b64decode(s, validate=True)
    except (ValueError, binascii.Error):
        return None
    return raw if len(raw) == n and base64.b64encode(raw).decode() == s else None


def verify_raw(pk_raw: bytes, message: bytes, sig_raw: bytes, context: bytes = b"") -> bool:
    m = _mldsa()
    if m is None:
        raise RuntimeError("ML-DSA-65 needs cryptography >= 50")
    try:
        m.MLDSA65PublicKey.from_public_bytes(pk_raw).verify(sig_raw, message, context=context or None)
        return True
    except Exception:  # noqa: BLE001 — any failure is one verdict
        return False


def verify_fn(public_key_b64: str, signature_b64: str, message: bytes) -> bool:
    """The registry verifier: strict decoders, pure ML-DSA-65, empty context. Fail-closed on any malformation."""
    pk, sig = b64_strict(public_key_b64, PK_LEN), b64_strict(signature_b64, SIG_LEN)
    if pk is None or sig is None:
        return False
    return verify_raw(pk, message, sig)


def load_kat() -> list:
    """NIST ACVP sigVer vectors (tcId|expect|reason|pk|message|context|signature, hex) → the gate's shape.
    Only the vectors NIST expects to PASS are given to the gate (it tampers each itself); their contexts are
    carried through, so the gate exercises the real FIPS 204 context handling."""
    out = []
    with open(KAT_FILE, encoding="utf-8") as f:
        for ln in f:
            if not ln.strip() or ln.startswith("#"):
                continue
            tc, expect, _reason, pk, msg, ctx, sig = ln.rstrip("\n").split("|")
            if expect != "P":
                continue
            out.append({"public": base64.b64encode(bytes.fromhex(pk)).decode(),
                        "signature": base64.b64encode(bytes.fromhex(sig)).decode(),
                        "message_hex": msg, "context_hex": ctx})
    return out


def _kat_verify(public_key_b64: str, signature_b64: str, message: bytes, context_hex: str = "") -> bool:
    pk, sig = b64_strict(public_key_b64, PK_LEN), b64_strict(signature_b64, SIG_LEN)
    if pk is None or sig is None:
        return False
    return verify_raw(pk, message, sig, bytes.fromhex(context_hex) if context_hex else b"")


def try_load() -> Dict[str, Any]:
    """Register ml-dsa-65 as a post-quantum algorithm if cryptography >= 50 is present AND the KAT gate passes.
    Returns {registered, alg, reason}. Idempotent."""
    if not available():
        return {"registered": False, "alg": ALG, "reason": "cryptography >= 50 (ML-DSA) not available"}
    kat = load_kat()
    # the gate calls verify_fn(public, signature, message): bind each vector's context through a closure
    ctx_by_msg = {v["message_hex"].lower(): v.get("context_hex", "") for v in kat}   # bytes.hex() is lowercase
    res = gate.run_kat(lambda p, s, m: _kat_verify(p, s, m, ctx_by_msg.get(m.hex(), "")), kat)
    if not res.get("passed"):
        return {"registered": False, "alg": ALG, "reason": "KAT gate failed: " + str(res.get("reason"))}
    signing.register_sig_alg(ALG, verify_fn, post_quantum=True)
    return {"registered": True, "alg": ALG, "reason": f"KAT gate passed on {len(kat)} NIST ACVP vectors"}


# ── signers ─────────────────────────────────────────────────────────────────────────────────────────────────────
class MlDsaFileSigner:
    """ML-DSA-65 private key on disk (PKCS#8 DER, base64, mode 0600). `keygen(path)` creates it (O_EXCL)."""
    alg = ALG

    def __init__(self, path: str):
        m = _mldsa()
        if m is None:
            raise RuntimeError("ML-DSA-65 needs cryptography >= 50")
        from cryptography.hazmat.primitives import serialization as ser
        with open(path, encoding="utf-8") as f:
            sk = ser.load_der_private_key(base64.b64decode(f.read().strip()), password=None)
        if not isinstance(sk, m.MLDSA65PrivateKey):
            raise ValueError("not an ML-DSA-65 private key")
        self._sk = sk
        self.public_key_b64 = base64.b64encode(sk.public_key().public_bytes_raw()).decode()

    @staticmethod
    def keygen(path: str) -> Dict[str, Any]:
        m = _mldsa()
        if m is None:
            raise RuntimeError("ML-DSA-65 needs cryptography >= 50")
        from cryptography.hazmat.primitives import serialization as ser
        sk = m.MLDSA65PrivateKey.generate()
        der = sk.private_bytes(ser.Encoding.DER, ser.PrivateFormat.PKCS8, ser.NoEncryption())
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(base64.b64encode(der).decode() + "\n")
        return {"path": path, "alg": ALG, "public_key_b64": base64.b64encode(sk.public_key().public_bytes_raw()).decode()}

    def sign(self, message: bytes) -> bytes:
        return self._sk.sign(message)

    def describe(self) -> Dict[str, Any]:
        return {"pq_backend": "file", "alg": ALG, "key_in_process_memory": True}


def _mldsa65_raw_from_spki(der: bytes) -> bytes:
    if len(der) != MLDSA65_SPKI_LEN or MLDSA65_SPKI_OID not in der[:32] or der[-PK_LEN - 1] != 0:
        raise RuntimeError("the AWS KMS key is not an ML-DSA-65 SubjectPublicKeyInfo (use KeySpec ML_DSA_65)")
    return der[-PK_LEN:]


class AwsKmsMlDsaSigner:
    """AWS KMS ML-DSA-65 (KeySpec ML_DSA_65, ML_DSA_SHAKE_256, MessageType RAW = empty context). boto3."""
    alg = ALG

    def __init__(self, key_id: str, region: Optional[str] = None, profile: Optional[str] = None, client=None):
        self._key_id = key_id
        if client is not None:
            self._client = client
        else:  # pragma: no cover - needs boto3 + real credentials
            try:
                import boto3
            except ImportError as e:
                raise RuntimeError("AwsKmsMlDsaSigner needs boto3 (pip install boto3)") from e
            session = boto3.Session(profile_name=profile) if profile else boto3.Session()
            self._client = session.client("kms", region_name=region)
        try:
            r = self._client.get_public_key(KeyId=key_id)
        except Exception as e:  # noqa: BLE001
            raise RuntimeError(f"AWS KMS GetPublicKey failed for {key_id}: {type(e).__name__}: {str(e)[:200]}") from e
        self.key_arn = str(r.get("KeyId") or key_id)
        self.public_key_b64 = base64.b64encode(_mldsa65_raw_from_spki(bytes(r["PublicKey"]))).decode()

    def sign(self, message: bytes) -> bytes:
        if not isinstance(message, (bytes, bytearray)):
            raise TypeError("message must be bytes")
        if len(message) > 4096:
            raise ValueError("AWS KMS RAW signing takes at most 4096 bytes")
        try:
            r = self._client.sign(KeyId=self._key_id, Message=bytes(message), MessageType="RAW", SigningAlgorithm="ML_DSA_SHAKE_256")
        except Exception as e:  # noqa: BLE001
            raise RuntimeError(f"AWS KMS Sign failed for {self._key_id}: {type(e).__name__}: {str(e)[:200]}") from e
        if r.get("SigningAlgorithm", "ML_DSA_SHAKE_256") != "ML_DSA_SHAKE_256":
            raise RuntimeError(f"AWS KMS signed with {r.get('SigningAlgorithm')}, not ML_DSA_SHAKE_256")
        if r.get("KeyId") and r["KeyId"] != self.key_arn:
            raise RuntimeError("AWS KMS signed with a different key than the one whose public key was read (alias re-pointed?)")
        sig = bytes(r["Signature"])
        if len(sig) != SIG_LEN:
            raise RuntimeError(f"expected a {SIG_LEN}-byte ML-DSA-65 signature, got {len(sig)}")
        return sig

    def describe(self) -> Dict[str, Any]:
        return {"pq_backend": "awskms", "alg": ALG, "key_id": self._key_id, "key_spec": "ML_DSA_65",
                "signing_algorithm": "ML_DSA_SHAKE_256", "message_type": "RAW", "key_in_process_memory": False}
