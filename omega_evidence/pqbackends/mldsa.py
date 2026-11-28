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
`cryptography` >= 48 (ML-DSA on the OpenSSL 3.5 wheels since 48.0.0, 2026-05-04; 47.0.0 only on AWS-LC/BoringSSL
builds — measured on 48.0.0 and 50.0.1, 16/09/2026); without it the layer is reported present-but-unverifiable, never a pass.

The backend is registered only after the KAT gate (`gate.run_kat`) passes on the NIST ACVP ML-DSA-65 vectors shipped
next to this file (`vectors/nist_acvp_mldsa65.jsonl`, 0.12.0: built by tools/build_nist_acvp_mldsa65.py from the NIST
ACVP-Server JSON at a pinned commit and SHA-256; the sigVer cases NIST expects to pass, with their contexts, and the
sigGen known-answer signatures with the EMPTY context — the path this profile actually uses — checked through the
very function registered) — a backend that accepts a tampered signature is never wired in. Until 0.11.4 the vectors
were `vectors/acvp_mldsa65_sigver.txt` and the wheel did not carry them, so an installed package never registered the
backend (measured on the 0.11.4 wheel: "KAT vector file unusable: FileNotFoundError").

Signers: `MlDsaFileSigner` (PKCS#8 DER base64 on disk, 0600) and `AwsKmsMlDsaSigner` (KeySpec ML_DSA_65,
ML_DSA_SHAKE_256, MessageType RAW; the private key never enters process memory; the Sign response's KeyId must
match the key whose public key was read). The key MUST be dedicated to this profile: with no context, any other
application signing a 64-hex string with the same key would produce a valid pack co-signature.
"""
from __future__ import annotations

import base64
import binascii
import errno
import json
import os
import subprocess
import sys
import tempfile
from typing import Any, Dict, Optional

from .. import signing
from . import gate

ALG = "ml-dsa-65"
SIG_LEN, PK_LEN = 3309, 1952
_HERE = os.path.dirname(os.path.abspath(__file__))
KAT_FILE = os.path.join(_HERE, "vectors", "nist_acvp_mldsa65.jsonl")
_KAT_HEAD_KEYS = {"kind", "source", "commit", "sha256", "group", "rule", "built_by"}
_KAT_CASE_KEYS = {"kind", "file", "tgId", "tcId", "testPassed", "reason", "pk", "message", "context", "signature"}
MLDSA65_SPKI_OID = bytes.fromhex("0609608648016503040312")   # id-ml-dsa-65 (RFC 9881)
MLDSA65_SPKI_LEN = 1974


def _mldsa():
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa  # cryptography >= 48 (wheels) / 47 (AWS-LC)
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
        raise RuntimeError("ML-DSA-65 needs cryptography >= 48")
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


def _hex(v: Any, n: Optional[int] = None) -> bytes:
    if not isinstance(v, str) or v != v.lower() or len(v) % 2:
        raise ValueError("KAT vector file: a value is not lowercase hex")
    b = bytes.fromhex(v)
    if n is not None and len(b) != n:
        raise ValueError(f"KAT vector file: {len(b)} bytes where {n} are expected")
    return b


def load_cases() -> list:
    """Every case of the vector file, read closed: line 1 the provenance object, each other line a case object with
    exactly the keys of _KAT_CASE_KEYS (hex lowercase; pk 1952 bytes, signature 3309). ValueError otherwise."""
    cases = []
    with open(KAT_FILE, encoding="utf-8") as f:
        lines = [ln for ln in f.read().split("\n") if ln]
    if not lines:
        raise ValueError("KAT vector file: empty")
    head = json.loads(lines[0])
    if not isinstance(head, dict) or set(head) != _KAT_HEAD_KEYS or head["kind"] != "provenance":
        raise ValueError("KAT vector file: the first line is not the provenance object")
    for ln in lines[1:]:
        c = json.loads(ln)
        if not isinstance(c, dict) or set(c) != _KAT_CASE_KEYS or c["kind"] != "case" or c["file"] not in ("sigVer", "sigGen") \
                or not isinstance(c["testPassed"], bool):
            raise ValueError("KAT vector file: a case line is not a closed case object")
        _hex(c["pk"], PK_LEN), _hex(c["signature"], SIG_LEN), _hex(c["message"]), _hex(c["context"])
        cases.append(c)
    return cases


def load_kat() -> list:
    """The cases NIST expects to PASS, in the gate's shape (it tampers each itself); their contexts are carried through,
    so the gate exercises the real FIPS 204 context handling."""
    out = [{"public": base64.b64encode(bytes.fromhex(c["pk"])).decode(),
            "signature": base64.b64encode(bytes.fromhex(c["signature"])).decode(),
            "message_hex": c["message"], "context_hex": c["context"]} for c in load_cases() if c["testPassed"]]
    keys = [(v["public"], v["message_hex"]) for v in out]
    if len(set(keys)) != len(keys):        # council r2: a hand-grown file must not silently under-test (last-wins)
        raise ValueError("KAT vector file: duplicate (key, message) pair")
    return out


def _kat_verify(public_key_b64: str, signature_b64: str, message: bytes, context_hex: str = "") -> bool:
    pk, sig = b64_strict(public_key_b64, PK_LEN), b64_strict(signature_b64, SIG_LEN)
    if pk is None or sig is None:
        return False
    return verify_raw(pk, message, sig, bytes.fromhex(context_hex) if context_hex else b"")


def try_load() -> Dict[str, Any]:
    """Register ml-dsa-65 as a post-quantum algorithm if cryptography >= 48 is present AND the KAT gate passes.
    Returns {registered, alg, reason}. Idempotent."""
    if not available():
        return {"registered": False, "alg": ALG, "reason": "cryptography >= 48 (ML-DSA) not available"}
    try:
        kat = load_kat()
    except (OSError, ValueError) as e:      # council r3: a broken vector file is {registered: False, reason}, never a crash
        return {"registered": False, "alg": ALG, "reason": f"KAT vector file unusable: {type(e).__name__}: {e}"}
    # council 16/09 (r1): the function that gets REGISTERED (empty context) must itself pass a NIST known answer —
    # the empty-context vectors go through verify_fn as is; the sigVer vectors with a context go through the same
    # decoder with their context bound by (key, signature, message), never by message alone
    empty = [v for v in kat if not v.get("context_hex")]
    ctxed = [v for v in kat if v.get("context_hex")]
    if not empty:
        return {"registered": False, "alg": ALG, "reason": "KAT gate: no empty-context vector for the registered function"}
    res = gate.run_kat(verify_fn, empty)
    if not res.get("passed"):
        return {"registered": False, "alg": ALG, "reason": "KAT gate failed (empty context): " + str(res.get("reason"))}
    if ctxed:
        # bound by (key, message) so the gate's tampered-SIGNATURE negative still runs with the vector's context
        ctx_by_vec = {(v["public"], v["message_hex"]): v["context_hex"] for v in ctxed}
        res = gate.run_kat(lambda p, s, m: _kat_verify(p, s, m, ctx_by_vec.get((p, m.hex()), "")), ctxed)
        if not res.get("passed"):
            return {"registered": False, "alg": ALG, "reason": "KAT gate failed (with context): " + str(res.get("reason"))}
    signing.register_sig_alg(ALG, verify_fn, post_quantum=True)
    return {"registered": True, "alg": ALG,
            "reason": f"KAT gate passed on {len(kat)} NIST ACVP vectors ({len(empty)} with the empty context)"}


# ── signers ─────────────────────────────────────────────────────────────────────────────────────────────────────
class MlDsaFileSigner:
    """ML-DSA-65 private key on disk (PKCS#8 DER, base64, mode 0600). `keygen(path)` creates it (O_EXCL)."""
    alg = ALG

    def __init__(self, path: str):
        m = _mldsa()
        if m is None:
            raise RuntimeError("ML-DSA-65 needs cryptography >= 48")
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
            raise RuntimeError("ML-DSA-65 needs cryptography >= 48")
        from cryptography.hazmat.primitives import serialization as ser
        sk = m.MLDSA65PrivateKey.generate()
        der = sk.private_bytes(ser.Encoding.DER, ser.PrivateFormat.PKCS8, ser.NoEncryption())
        text = base64.b64encode(der).decode() + "\n"
        if os.name == "nt":
            _write_owner_only_windows(path, text)
        else:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(text)
        return {"path": path, "alg": ALG, "public_key_b64": base64.b64encode(sk.public_key().public_bytes_raw()).decode()}

    def sign(self, message: bytes) -> bytes:
        return self._sk.sign(message)

    def describe(self) -> Dict[str, Any]:
        return {"pq_backend": "file", "alg": ALG, "key_in_process_memory": True}


def _write_owner_only_windows(path: str, text: str) -> None:
    """Windows: the key is never in a file another account could open. A private folder is made beside the target,
    owner-only FROM ITS CREATION on every Python (`_private_folder_windows`), the key file is created INSIDE it and so
    inherits that ACL at its creation, then it is moved to its name (a move on one volume keeps the ACL; os.rename
    refuses an existing target, as O_EXCL does) and given the ACL explicitly, so that a later change to the parent
    folder does not reach it. A failure removes what was made and raises. (0.14.1 first set the ACL on the created file:
    a handle opened by another account between creation and icacls kept its access; then the folder got its ACL from
    icacls after mkdtemp, a window in which, before Python 3.13, an account with Modify on the parent could put a
    junction in its place.) Not covered: an account with full control of the key's folder can move entries in it."""
    target = os.path.abspath(path)
    if os.path.lexists(target):
        raise FileExistsError(errno.EEXIST, "the key file already exists")
    folder = _private_folder_windows(os.path.dirname(target))
    tmp = os.path.join(folder, "key")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.rename(tmp, target)
        try:
            _owner_only_acl(target)
        except Exception:
            os.remove(target)
            raise
    finally:
        try:
            if os.path.lexists(tmp):
                os.remove(tmp)
        finally:
            os.rmdir(folder)


# the security descriptor CPython 3.13 gives os.mkdir(path, 0o700) on Windows (Modules/posixmodule.c): protected DACL,
# full control to SYSTEM, Administrators and OWNER RIGHTS, inherited by files and folders made inside
_SDDL_0700 = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;OW)"


def _private_folder_windows(parent: str) -> str:
    """A new folder in `parent`, owner-only from its creation. Python 3.13+: mkdtemp (its 0o700 is that ACL). Before
    3.13 mkdtemp's folder takes the inherited ACL until changed, so it is made by CreateDirectoryW with the descriptor
    above: there is no moment in which another account has rights on it."""
    if sys.version_info >= (3, 13):
        return tempfile.mkdtemp(prefix=".mldsa-key-", dir=parent)
    import ctypes
    import secrets
    from ctypes import wintypes

    class _SecurityAttributes(ctypes.Structure):
        _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p),
                    ("bInheritHandle", wintypes.BOOL)]
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    k32.CreateDirectoryW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(_SecurityAttributes)]
    k32.CreateDirectoryW.restype = wintypes.BOOL
    k32.LocalFree.argtypes = [ctypes.c_void_p]
    sd = ctypes.c_void_p()
    if not adv.ConvertStringSecurityDescriptorToSecurityDescriptorW(_SDDL_0700, 1, ctypes.byref(sd), None):   # SDDL_REVISION_1
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        sa = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), sd, False)
        for _ in range(100):
            folder = os.path.join(parent, ".mldsa-key-" + secrets.token_hex(8))
            if k32.CreateDirectoryW(folder, ctypes.byref(sa)):
                return folder
            err = ctypes.get_last_error()
            if err != 183:   # ERROR_ALREADY_EXISTS: another name
                raise ctypes.WinError(err)
        raise FileExistsError(errno.EEXIST, "no free name for the private folder of the key")
    finally:
        k32.LocalFree(sd)


def _owner_only_acl(path: str) -> None:
    """Windows equivalent of mode 0o600 (0.14.1; before, the key file kept the ACL inherited from its folder):
    inheritance removed and full control granted to the file's owner (OWNER RIGHTS, S-1-3-4), SYSTEM and Administrators
    only — the set CPython 3.13 itself applies on Windows for mode 0o700 (os.mkdir: OW, SY, BA), SYSTEM and Administrators
    being able to take any file anyway. The owner is set by Windows from the token of the process that created the
    file — its user, or the Administrators group for an elevated administrator whose default owner is that group (then
    that account reads the key only from an elevated process, as every other administrator) — never from
    USERNAME/USERDOMAIN, which the environment can set to another account. icacls ships with every Windows since Vista. A failure raises."""
    r = subprocess.run(["icacls", path, "/inheritance:r", "/grant:r", "*S-1-3-4:F", "*S-1-5-18:F", "*S-1-5-32-544:F"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise OSError(f"{path}: icacls could not make the key file owner-only: {(r.stdout + r.stderr).strip()[-300:]}")


def _mldsa65_raw_from_spki(der: bytes) -> bytes:
    """Raw 1952-byte key out of a SubjectPublicKeyInfo — parsed as ASN.1 by cryptography and type-checked
    (council 16/09 r1: the previous byte-offset check was fail-closed but not a structural parse); the fixed
    length and OID (RFC 9881) are still required as a belt."""
    m = _mldsa()
    if m is None:
        raise RuntimeError("ML-DSA-65 needs cryptography >= 48")
    from cryptography.hazmat.primitives import serialization as ser
    if len(der) != MLDSA65_SPKI_LEN or MLDSA65_SPKI_OID not in der[:32]:
        raise RuntimeError("the AWS KMS key is not an ML-DSA-65 SubjectPublicKeyInfo (use KeySpec ML_DSA_65)")
    try:
        pk = ser.load_der_public_key(bytes(der))
    except Exception as e:  # noqa: BLE001
        raise RuntimeError(f"the AWS KMS public key is not a valid SubjectPublicKeyInfo: {type(e).__name__}") from e
    if not isinstance(pk, m.MLDSA65PublicKey):
        raise RuntimeError("the AWS KMS key is not ML-DSA-65 (use KeySpec ML_DSA_65)")
    raw = pk.public_bytes_raw()
    if len(raw) != PK_LEN:
        raise RuntimeError(f"unexpected ML-DSA-65 public key length {len(raw)}")
    return raw


def _kms_reason(e: BaseException) -> str:
    """The type of a KMS client error and its AWS error code (botocore ClientError: "AccessDeniedException", ...), never
    its text nor the KeyId given, which can be a secret typed in its place (0.14.1)."""
    code = getattr(e, "response", None)
    code = code.get("Error", {}).get("Code") if isinstance(code, dict) else None
    ok = isinstance(code, str) and 0 < len(code) <= 64 and code.isascii() and code.isalnum()
    return type(e).__name__ + (f" ({code})" if ok else "")


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
            raise RuntimeError(f"AWS KMS GetPublicKey failed: {_kms_reason(e)}") from None
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
            raise RuntimeError(f"AWS KMS Sign failed: {_kms_reason(e)}") from None
        if r.get("SigningAlgorithm", "") != "ML_DSA_SHAKE_256":      # a response without the field is refused
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
