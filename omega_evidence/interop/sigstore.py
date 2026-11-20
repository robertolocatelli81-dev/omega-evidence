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
omega_evidence.interop.sigstore — read a sigstore bundle and verify OFFLINE what can be verified offline (0.12.0).

Format: sigstore protobuf-specs v0.5.2, `Bundle` in its JSON form (protos/sigstore_bundle.proto, sigstore_common.proto,
sigstore_rekor.proto), media types application/vnd.dev.sigstore.bundle.v0.3+json and
application/vnd.dev.sigstore.bundle+json;version=0.1 / 0.2 / 0.3 — the four the proto says clients must accept. GitHub
artifact attestations (`gh api repos/<o>/<r>/attestations/<digest>`, the `bundle` member) are such bundles.

What is VERIFIED here, each reported in `checks`:
  * signature   — the DSSE envelope (exactly one signature, as the proto requires; PAE, interop.dsse) or the message
                  signature, with the key of the bundle's leaf certificate (or the caller's `public_key`), Ed25519 or
                  ECDSA P-256 / SHA-256;
  * artifact    — when the caller gives the artifact (bytes) or its SHA-256: a DSSE statement must name that digest
                  among its subjects; a message signature must carry that digest and verify over it;
  * rfc3161[i]  — each RFC 3161 token, over the SHA-256 of the signature bytes, with timestamp.verify and the caller's
                  TSA anchors (`tsa_ca_file`, `tsa_untrusted`), at the token's genTime by default (sigstore's rule);
                  with `tsa_ca_file` given and no token in the bundle, the check `rfc3161` is made and is False
                  (Unreleased: the caller asked for a verified time and there is none);
  * signing_time_in_certificate — a verified token's genTime inside the leaf certificate's validity (the proto: "a
                  verifier MUST verify that the signature was computed at the time the certificate was valid").
                  genTime is read to the whole second: a fraction of a second is dropped, so a token made within
                  the second after notAfter counts as inside.

What is NOT verified here, and always listed in `not_verified`: the leaf certificate's chain to Fulcio or to GitHub's
CA; the identity in the certificate (SAN, OIDC issuer, workflow, repository); the Rekor entries (inclusion proof,
checkpoint signature, inclusion promise / SET, that the entry's body matches); revocation; the valid_for window a
trusted root gives each timestamp authority (only the caller's TSA certificates are used); and, for a bundle with no
RFC 3161 token, the time of signing (it would come from the log entry). So `verified: True` means
"the signature, and the artifact and timestamps asked for, check out with the key in the bundle", NOT "sigstore
verified": anyone can make a self-signed certificate and a bundle that pass these checks. For that, use
`gh attestation verify`, `cosign verify-blob` or a sigstore client with the trusted root.

Closed: the bundle is a protobuf message in its JSON form, whose parsers "should reject unknown fields by default"
(protobuf ProtoJSON format); so a field the proto does not define (at each level read), a field given twice (camelCase and proto name), a
oneof with two members, a media type outside the four, a cosign "legacy" bundle (`base64Signature`) — each is an
`error` with its reason, `verified: False`, never ignored. A bundle given as text is also refused when one JSON object
names a member twice, holds NaN/Infinity or nests beyond 512 levels.
"""

from __future__ import annotations

import base64
import binascii
import datetime
import hashlib
import re
from typing import Any, Dict, Optional

from . import dsse
from .. import timestamp
from ..ledger import loads_bounded

MEDIA_TYPES = {"application/vnd.dev.sigstore.bundle.v0.3+json": "0.3",
               "application/vnd.dev.sigstore.bundle+json;version=0.1": "0.1",
               "application/vnd.dev.sigstore.bundle+json;version=0.2": "0.2",
               "application/vnd.dev.sigstore.bundle+json;version=0.3": "0.3"}
NOT_VERIFIED = ("the leaf certificate's chain to Fulcio or to GitHub's CA (no trusted root is read here)",
                "the identity in the certificate (SAN, OIDC issuer, workflow, repository)",
                "the transparency log entries (Rekor inclusion proof, checkpoint, inclusion promise, entry body)",
                "revocation of any certificate",
                "the validity window (valid_for) that a trusted root gives each timestamp authority: an RFC 3161 "
                "token is checked against the caller's TSA certificates only (sigstore_trustroot.proto: clients "
                "MUST check timestamps against both valid_for and the certificate chain)")
_HASHES = {"SHA2_256": "sha256", "SHA2_384": "sha384", "SHA2_512": "sha512"}

# the JSON names of each message read here (proto3 JSON: lowerCamelCase, the proto name also accepted)
_FIELDS = {
    "Bundle": {"mediaType", "verificationMaterial", "messageSignature", "dsseEnvelope"},
    "VerificationMaterial": {"publicKey", "x509CertificateChain", "certificate", "tlogEntries",
                             "timestampVerificationData"},
    "TimestampVerificationData": {"rfc3161Timestamps"},
    "RFC3161SignedTimestamp": {"signedTimestamp"},
    "MessageSignature": {"messageDigest", "signature"},
    "HashOutput": {"algorithm", "digest"},
    "X509Certificate": {"rawBytes"},
    "X509CertificateChain": {"certificates"},
    "PublicKeyIdentifier": {"hint"},
    "Envelope": {"payload", "payloadType", "signatures"},
    "Signature": {"sig", "keyid"},
    "TransparencyLogEntry": {"logIndex", "logId", "kindVersion", "integratedTime", "inclusionPromise",
                             "inclusionProof", "canonicalizedBody"},
    "LogId": {"keyId"},
    "KindVersion": {"kind", "version"},
    "InclusionPromise": {"signedEntryTimestamp"},
    "InclusionProof": {"logIndex", "rootHash", "treeSize", "hashes", "checkpoint"},
    "Checkpoint": {"envelope"},
}


class _Bad(ValueError):
    pass


def _no_duplicates(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise _Bad(f"member {k!r} given twice in one JSON object")
        out[k] = v
    return out


def _no_constant(c):
    raise _Bad(f"non-standard JSON constant {c}")


def _snake(name: str) -> str:
    return re.sub(r"[A-Z]", lambda m: "_" + m.group(0).lower(), name)


def _obj(v: Any, msg: str) -> Dict[str, Any]:
    """the members of one message, under their lowerCamelCase names; unknown or repeated names are refused"""
    if not isinstance(v, dict):
        raise _Bad(f"{msg} is not a JSON object")
    known = _FIELDS[msg]
    by_snake = {_snake(k): k for k in known}
    out: Dict[str, Any] = {}
    for k, val in v.items():
        name = k if k in known else by_snake.get(k)
        if name is None:
            raise _Bad(f"unknown field {k!r} in {msg} (not in sigstore protobuf-specs v0.5.2)")
        if name in out:
            raise _Bad(f"field {name!r} given twice in {msg}")
        out[name] = val
    return out


def _bytes(v: Any, what: str) -> bytes:
    """proto3 JSON bytes: standard or URL-safe base64, padding optional"""
    if not isinstance(v, str) or not re.fullmatch(r"[A-Za-z0-9+/_-]*={0,2}", v) or ("-" in v or "_" in v) and (
            "+" in v or "/" in v):
        raise _Bad(f"{what} is not base64")
    s = v.rstrip("=")
    if len(s) % 4 == 1:
        raise _Bad(f"{what} is not base64")
    try:
        return base64.b64decode(s + "=" * (-len(s) % 4), altchars=b"-_" if ("-" in s or "_" in s) else None,
                                validate=True)
    except (ValueError, binascii.Error):
        raise _Bad(f"{what} is not base64") from None


def _int(v: Any, what: str) -> int:
    """proto3 JSON int64: a number or a decimal string"""
    if isinstance(v, bool) or not isinstance(v, (int, str)):
        raise _Bad(f"{what} is not an integer")
    if isinstance(v, str):
        if not re.fullmatch(r"-?(0|[1-9][0-9]*)", v):
            raise _Bad(f"{what} is not an integer")
        v = int(v)
    return v


def _pem(der: bytes) -> bytes:
    return b"-----BEGIN CERTIFICATE-----\n" + base64.encodebytes(der) + b"-----END CERTIFICATE-----\n"


def _cert_facts(der: bytes) -> Dict[str, Any]:
    out: Dict[str, Any] = {"sha256": hashlib.sha256(der).hexdigest()}
    try:
        from cryptography import x509
    except ImportError:
        out["read"] = False
        return out
    try:
        c = x509.load_der_x509_certificate(der)
    except Exception as e:  # noqa: BLE001
        raise _Bad(f"leaf certificate is not a DER X.509 certificate: {type(e).__name__}") from None
    nb = getattr(c, "not_valid_before_utc", None) or c.not_valid_before.replace(tzinfo=datetime.timezone.utc)
    na = getattr(c, "not_valid_after_utc", None) or c.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    out.update(read=True, subject=c.subject.rfc4514_string(), issuer=c.issuer.rfc4514_string(),
               not_before=int(nb.timestamp()), not_after=int(na.timestamp()))
    try:
        san = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        out["san"] = [str(n.value) for n in san]
    except x509.ExtensionNotFound:
        out["san"] = []
    return out


def _parse(bundle: Any) -> Dict[str, Any]:
    if isinstance(bundle, (bytes, bytearray, str)):
        # as text: a member name given twice in one object, NaN/Infinity and nesting beyond 512 are refused — Python's
        # json.loads keeps the LAST of two equal names and another parser the first, so the two would read two bundles
        try:
            bundle = loads_bounded(bytes(bundle) if isinstance(bundle, bytearray) else bundle,
                                   object_pairs_hook=_no_duplicates, parse_constant=_no_constant)
        except _Bad:
            raise
        except UnicodeDecodeError:
            raise _Bad("bundle is not UTF-8") from None
        except (ValueError, RecursionError) as e:
            raise _Bad("bundle nesting exceeds 512" if str(e).startswith("json_too_deep") else "bundle is not JSON") from None
    if isinstance(bundle, dict) and "base64Signature" in bundle:
        raise _Bad("a cosign legacy bundle (base64Signature, rekorBundle) is not read here: only sigstore "
                   "protobuf-specs bundles")
    b = _obj(bundle, "Bundle")
    mt = b.get("mediaType")
    if not isinstance(mt, str) or mt not in MEDIA_TYPES:
        raise _Bad(f"mediaType {mt!r} is not a sigstore bundle media type read here ({', '.join(MEDIA_TYPES)})")
    if ("messageSignature" in b) == ("dsseEnvelope" in b):
        raise _Bad("a bundle carries exactly one of messageSignature and dsseEnvelope")
    if "verificationMaterial" not in b:
        raise _Bad("verificationMaterial missing")
    vm = _obj(b["verificationMaterial"], "VerificationMaterial")
    forms = [k for k in ("publicKey", "x509CertificateChain", "certificate") if k in vm]
    if len(forms) != 1:
        raise _Bad("verificationMaterial carries exactly one of publicKey, x509CertificateChain, certificate")
    p: Dict[str, Any] = {"media_type": mt, "bundle_version": MEDIA_TYPES[mt], "key_form": forms[0], "leaf_der": None,
                         "key_hint": None}
    if forms[0] == "certificate":
        p["leaf_der"] = _bytes(_obj(vm["certificate"], "X509Certificate").get("rawBytes"), "certificate.rawBytes")
    elif forms[0] == "x509CertificateChain":
        certs = _obj(vm["x509CertificateChain"], "X509CertificateChain").get("certificates")
        if not isinstance(certs, list) or not certs:
            raise _Bad("x509CertificateChain.certificates is empty")
        ders = [_bytes(_obj(c, "X509Certificate").get("rawBytes"), "certificates[].rawBytes") for c in certs]
        p["leaf_der"], p["chain_der"] = ders[0], ders[1:]
    else:
        hint = _obj(vm["publicKey"], "PublicKeyIdentifier").get("hint")
        if hint is not None and not isinstance(hint, str):
            raise _Bad("publicKey.hint is not a string")
        p["key_hint"] = hint
    tvd = _obj(vm.get("timestampVerificationData", {}), "TimestampVerificationData")
    toks = tvd.get("rfc3161Timestamps", [])
    if not isinstance(toks, list):
        raise _Bad("rfc3161Timestamps is not a list")
    p["tokens"] = []
    for t in toks:
        raw = _bytes(_obj(t, "RFC3161SignedTimestamp").get("signedTimestamp"), "signedTimestamp")
        p["tokens"].append(base64.standard_b64encode(raw).decode("ascii"))
    entries = vm.get("tlogEntries", [])
    if not isinstance(entries, list):
        raise _Bad("tlogEntries is not a list")
    p["tlog"] = []
    for e in entries:
        e = _obj(e, "TransparencyLogEntry")
        kv = _obj(e.get("kindVersion", {}), "KindVersion")
        lid = _obj(e.get("logId", {}), "LogId")
        if "inclusionPromise" in e:
            _bytes(_obj(e["inclusionPromise"], "InclusionPromise").get("signedEntryTimestamp"), "signedEntryTimestamp")
        if "inclusionProof" in e:
            ip = _obj(e["inclusionProof"], "InclusionProof")
            if "checkpoint" in ip:
                _obj(ip["checkpoint"], "Checkpoint")
        for f in ("kind", "version"):
            if not isinstance(kv.get(f), str):
                raise _Bad(f"kindVersion.{f} is not a string")
        p["tlog"].append({"log_index": _int(e.get("logIndex", 0), "logIndex"),   # proto3 JSON omits a 0
                          "log_id_hex": _bytes(lid.get("keyId"), "logId.keyId").hex(),
                          "kind": kv.get("kind"), "version": kv.get("version"),
                          "integrated_time": _int(e.get("integratedTime", 0), "integratedTime"),
                          "inclusion_proof": "inclusionProof" in e, "inclusion_promise": "inclusionPromise" in e,
                          "verified": None})
    if "dsseEnvelope" in b:
        env = _obj(b["dsseEnvelope"], "Envelope")
        sigs = env.get("signatures")
        if not isinstance(sigs, list) or len(sigs) != 1:
            raise _Bad("a DSSE envelope in a bundle MUST have exactly one signature (sigstore_bundle.proto)")
        sig = _obj(sigs[0], "Signature")
        p["content"] = "dsse"
        p["signature"] = _bytes(sig.get("sig"), "dsseEnvelope.signatures[0].sig")
        payload = _bytes(env.get("payload"), "dsseEnvelope.payload")
        # decoded once here, by the proto3 JSON rule (either alphabet, padding optional), and handed to interop.dsse in
        # standard padded base64: the bytes the signature is checked over and those the RFC 3161 imprint is checked
        # over are the same bytes
        p["envelope"] = {"payload": base64.standard_b64encode(payload).decode("ascii"),
                         "payloadType": env.get("payloadType"),
                         "signatures": [{"sig": base64.standard_b64encode(p["signature"]).decode("ascii")}]}
        keyid = sig.get("keyid")
        if keyid is not None and not isinstance(keyid, str):
            raise _Bad("dsseEnvelope.signatures[0].keyid is not a string")
        p["keyid"] = keyid
    else:
        ms = _obj(b["messageSignature"], "MessageSignature")
        p["content"] = "message_signature"
        p["signature"] = _bytes(ms.get("signature"), "messageSignature.signature")
        p["message_digest"] = None
        if "messageDigest" in ms:
            ho = _obj(ms["messageDigest"], "HashOutput")
            alg = ho.get("algorithm")
            if alg not in _HASHES:
                raise _Bad(f"messageDigest.algorithm {alg!r} is not read here ({', '.join(_HASHES)})")
            p["message_digest"] = (_HASHES[alg], _bytes(ho.get("digest"), "messageDigest.digest"))
    return p


def _key_id(key) -> bytes:
    """the key of a dsse.load_public_key triple, as bytes that are equal exactly when the keys are"""
    kind, k, _src = key
    if kind == "ed25519":
        return b"ed25519:" + base64.b64decode(k)
    from cryptography.hazmat.primitives import serialization
    return b"ecdsa:" + k.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def verify_bundle(bundle: Any, artifact: Optional[bytes] = None, artifact_sha256: Optional[str] = None,
                  public_key=None, tsa_ca_file: Optional[str] = None, tsa_untrusted: Optional[str] = None,
                  tsa_at_gen_time: bool = True, timeout: int = 15) -> Dict[str, Any]:
    """Read a sigstore bundle (dict, JSON text or bytes) and verify offline what can be (module docstring).

    Returns {verified, error, media_type, bundle_version, content, checks, certificate, statement, timestamps,
    tlog_entries, not_verified}. `checks` maps each check made to True/False/None (None = could not be made here, with
    its reason in `error`). `verified` is True only when every check made is True and the signature check was made.
    `public_key` replaces the bundle's certificate as the key (a `publicKey` hint bundle needs it)."""
    res: Dict[str, Any] = {"verified": False, "error": None, "checks": {}, "not_verified": list(NOT_VERIFIED),
                           "statement": None, "timestamps": [], "tlog_entries": [], "certificate": None}
    if not isinstance(tsa_at_gen_time, bool):
        res["error"] = "tsa_at_gen_time must be True or False"
        return res
    for name, v in (("tsa_ca_file", tsa_ca_file), ("tsa_untrusted", tsa_untrusted)):
        if v is not None and (not isinstance(v, str) or not v):
            res["error"] = f"{name} must be the path of a PEM file"
            return res
    if artifact is not None and artifact_sha256 is not None:
        res["error"] = "give artifact or artifact_sha256, not both"
        return res
    if artifact is not None and not isinstance(artifact, (bytes, bytearray)):
        res["error"] = "artifact must be bytes"
        return res
    if artifact_sha256 is not None and (not isinstance(artifact_sha256, str)
                                        or not re.fullmatch(r"[0-9a-f]{64}", artifact_sha256)):
        res["error"] = "artifact_sha256 must be 64 lowercase hexadecimal characters"
        return res
    try:
        p = _parse(bundle)
    except _Bad as e:
        res["error"] = str(e)
        return res
    except (TypeError, AttributeError, KeyError, IndexError, RecursionError) as e:   # a shape not foreseen: a reason
        res["error"] = f"bundle not read: {type(e).__name__}"
        return res
    res.update(media_type=p["media_type"], bundle_version=p["bundle_version"], content=p["content"],
               key_form=p["key_form"])
    res["tlog_entries"] = p["tlog"]
    reasons = []
    try:
        cert = _cert_facts(p["leaf_der"]) if p["leaf_der"] is not None else None
    except _Bad as e:
        res["error"] = str(e)
        return res
    res["certificate"] = cert
    # the key: the caller's, else the leaf certificate
    key_arg = public_key if public_key is not None else (_pem(p["leaf_der"]) if p["leaf_der"] is not None else None)
    if key_arg is None:
        res["checks"]["signature"] = None
        reasons.append("no key: the bundle names its key only by a hint (publicKey); pass public_key=")
        key = None
    else:
        try:
            key = dsse.load_public_key(key_arg)
            if public_key is not None and p["leaf_der"] is not None and _key_id(key) != _key_id(
                    dsse.load_public_key(_pem(p["leaf_der"]))):
                # the certificate (and the signing time checked against it) would describe another key than the one
                # the signature is checked with
                raise ValueError("public_key is not the key of the bundle's certificate")
        except ValueError as e:
            res["checks"]["signature"] = None
            reasons.append(f"signature: {e}")
            key = None
    if (key is not None and p["content"] == "dsse" and p["key_form"] == "publicKey"
            and (p["key_hint"] or "") != (p.get("keyid") or "")):
        # sigstore_bundle.proto: "the key hints MUST be exactly the same in the verification material and in the DSSE
        # envelope"
        res["checks"]["signature"] = None
        reasons.append("signature: the publicKey hint of the verification material is not the keyid of the DSSE "
                       "signature (they MUST be exactly the same)")
        key = None
    sha_hex = (hashlib.sha256(artifact).hexdigest() if artifact is not None else artifact_sha256)
    if p["content"] == "dsse":
        r = dsse.from_dsse(p["envelope"], public_key=key_arg) if key is not None else None
        if r is not None:
            res["checks"]["signature"] = r["verified"]
            res["statement"] = r.get("statement")
            if not r["verified"]:
                reasons.append(f"signature: {r.get('error')}")
        if sha_hex is not None:
            st = res["statement"]
            if st is None:
                res["checks"]["artifact"] = None
                reasons.append("artifact: the statement could not be read")
            else:
                subj = st.get("subject") if isinstance(st, dict) else None
                hits = [s for s in subj if isinstance(s, dict) and isinstance(s.get("digest"), dict)
                        and s["digest"].get("sha256") == sha_hex] if isinstance(subj, list) else []
                res["checks"]["artifact"] = bool(hits)
                if not hits:
                    reasons.append("artifact: its SHA-256 is not a subject of the statement")
    else:
        md = p["message_digest"]
        if md is not None and md[0] != "sha256":
            res["checks"]["signature"] = None
            reasons.append(f"signature: messageDigest {md[0]} is not checked here (SHA-256 only)")
        elif key is not None:
            kind, k, _src = key
            target = None
            if artifact is not None:
                target = ("artifact", bytes(artifact))
            elif md is not None or sha_hex is not None:
                target = ("digest", bytes.fromhex(sha_hex) if sha_hex is not None else md[1])
            if target is None:
                res["checks"]["signature"] = None
                reasons.append("signature: no artifact, no artifact_sha256 and no messageDigest to verify over")
            elif kind != "ecdsa-p256":
                res["checks"]["signature"] = None
                reasons.append("signature: a message signature is read here with ECDSA P-256 only")
            else:
                from cryptography.exceptions import InvalidSignature
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.asymmetric import ec
                from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
                try:
                    if target[0] == "artifact":
                        k.verify(p["signature"], target[1], ec.ECDSA(hashes.SHA256()))
                    else:
                        k.verify(p["signature"], target[1], ec.ECDSA(Prehashed(hashes.SHA256())))
                    res["checks"]["signature"] = True
                except (InvalidSignature, ValueError):
                    res["checks"]["signature"] = False
                    reasons.append(f"signature: does not verify over the {target[0]}")
        if sha_hex is not None:
            ok = md is None or md[1].hex() == sha_hex
            res["checks"]["artifact"] = ok
            if not ok:
                reasons.append("artifact: its SHA-256 differs from the bundle's messageDigest")
    # RFC 3161 tokens over the signature bytes (protobuf-specs: "Clients MUST verify the hashed message in the message
    # imprint against the signature in the bundle")
    imprint = hashlib.sha256(p["signature"]).hexdigest()
    gen_times = []
    for i, tok in enumerate(p["tokens"]):
        name = f"rfc3161[{i}]"
        if not tsa_ca_file:
            res["checks"][name] = None
            reasons.append(f"{name}: no TSA trust anchor (tsa_ca_file): not verified")
            res["timestamps"].append({"verified": None})
            continue
        try:
            v = timestamp.verify(tok, imprint, timeout=timeout, ca_file=tsa_ca_file, untrusted=tsa_untrusted,
                                 at_gen_time=tsa_at_gen_time)
        except timestamp.CheckNotRun as e:
            v = {"verified": None, "reason": f"check not run here: {e}"}
        g = timestamp.gen_time_of(tok, timeout)
        v["gen_time"] = g
        res["timestamps"].append(v)
        res["checks"][name] = v.get("verified")
        if v.get("verified") is True and g is not None:
            gen_times.append(g)
        elif v.get("verified") is not True:
            reasons.append(f"{name}: {v.get('reason') or v.get('note') or 'not verified'}")
    if tsa_ca_file and not p["tokens"]:
        # Unreleased (Decision 5): a TSA trust anchor given asks for a verified time; a bundle with no RFC 3161 token has
        # none to verify, so the check is made and is False (until 0.13.0 it was not made, and verified was True)
        res["checks"]["rfc3161"] = False
        reasons.append("rfc3161: tsa_ca_file given but the bundle carries no RFC 3161 token: no time to verify")
    if gen_times and cert is not None and cert.get("read"):
        inside = all(cert["not_before"] <= g <= cert["not_after"] for g in gen_times)
        res["checks"]["signing_time_in_certificate"] = inside
        if not inside:
            reasons.append("signing time: a verified timestamp falls outside the leaf certificate's validity")
    elif cert is not None and p["tokens"]:
        res["checks"]["signing_time_in_certificate"] = None
        reasons.append("signing time: no verified timestamp, so the certificate's validity at signing is not checked")
    if "signing_time_in_certificate" not in res["checks"] and cert is not None:
        # no RFC 3161 token in the bundle: the time of signing would come from the transparency log entry
        # (integratedTime), which is not verified here — said, not left to be inferred from a missing check
        res["not_verified"].append("the time of signing, hence that the certificate was valid then (the bundle carries "
                                   "no RFC 3161 token; the log entry's integratedTime is not verified)")
    made = res["checks"]
    res["verified"] = made.get("signature") is True and all(v is True for v in made.values())
    if not res["verified"]:
        res["error"] = "; ".join(reasons)[:800] or "not verified"
    return res
