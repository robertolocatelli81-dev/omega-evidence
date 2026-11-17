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
omega_evidence._tsa_keyid — an RFC 3161 token whose SignerInfo names its signer by subjectKeyIdentifier (0.12.0).

RFC 5652 §5.3 allows the SignerInfo `sid` to be issuerAndSerialNumber or subjectKeyIdentifier. `openssl ts` reads the
token as PKCS #7, whose SignerInfo has only issuerAndSerialNumber, and refuses the second form with an ASN.1 error: until
0.12.0 `timestamp.verify` reported a valid token of that kind as `verified: False` (measured on 0.11.4 with OpenSSL
3.0.22, tests/test_tsa_signer_key_id_20261117.py). For that form the checks `openssl ts -verify` makes are made here one
by one, as cryptovalid-opencore does in its SPEC §11 step 7 (same author; ported, not imported):

  (0) the reply, read strictly as DER: status granted (0) or grantedWithMods (1), one token, eContentType id-ct-TSTInfo,
      the messageImprint's hash algorithm in a closed list with its digest length;
  (1) `openssl cms -verify -noverify`: the CMS signature and the messageDigest attribute, with the certificate the
      SignerInfo names, looked up among the token's certificates (as `ts -verify` here, which is given no -untrusted);
  (2) the ESS signingCertificate (RFC 2634 §5.4) or signingCertificateV2 (RFC 5035) attribute: each one present checked,
      at least one present, exactly one ESSCertID whose certHash is the hash of the signer certificate and whose
      issuerSerial, when present, names its issuer and serial number;
  (3) the TSTInfo `tsa` field, when present: the signer's subject or one of its subjectAltName;
  (4) `openssl verify -purpose timestampsign -CAfile <ca_file> -no-CApath -no-CAstore -untrusted <token certificates>`
      on the signer certificate: extended key usage timeStamping (present, critical, the only one), the chain to the
      caller's trust anchors and the validity now, as `openssl ts -verify -CAfile` builds it in `timestamp.verify`.

Names (the tsa field, the ESS issuerSerial) are compared as OpenSSL's X509_NAME_cmp compares them: each string value in
UTF-8, white space trimmed and folded, ASCII letters lowercased; RDNs in order, the attributes of an RDN in any order.
A reply that is not strict DER, or whose signer is named by issuerAndSerialNumber, is not read here: `timestamp.verify`
keeps its `openssl ts -verify` path for it, unchanged.
"""

from __future__ import annotations

import base64
import hashlib
import os
from typing import Callable, Dict, List, Optional, Tuple

OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_TSTINFO = "1.2.840.113549.1.9.16.1.4"
OID_SIGNING_CERTIFICATE = "1.2.840.113549.1.9.16.2.12"      # RFC 2634 §5.4, ESSCertID with SHA-1
OID_SIGNING_CERTIFICATE_V2 = "1.2.840.113549.1.9.16.2.47"   # RFC 5035, ESSCertIDv2
OID_SUBJECT_ALT_NAME = "2.5.29.17"
HASH_ALGORITHMS = {   # the messageImprint's algorithm: a closed list (name, digest length); SHA-1 and others are not read
    "2.16.840.1.101.3.4.2.1": ("sha256", 32), "2.16.840.1.101.3.4.2.2": ("sha384", 48),
    "2.16.840.1.101.3.4.2.3": ("sha512", 64), "2.16.840.1.101.3.4.2.8": ("sha3-256", 32),
    "2.16.840.1.101.3.4.2.9": ("sha3-384", 48), "2.16.840.1.101.3.4.2.10": ("sha3-512", 64)}
ESS_HASHES = {"1.3.14.3.2.26": "sha1", "2.16.840.1.101.3.4.2.4": "sha224", "2.16.840.1.101.3.4.2.1": "sha256",
              "2.16.840.1.101.3.4.2.2": "sha384", "2.16.840.1.101.3.4.2.3": "sha512", "2.16.840.1.101.3.4.2.8": "sha3_256",
              "2.16.840.1.101.3.4.2.9": "sha3_384", "2.16.840.1.101.3.4.2.10": "sha3_512"}


class DerError(ValueError):
    """the bytes are not the strict DER this module reads"""


def _items(buf: bytes, where: str) -> List[Tuple[int, bytes]]:
    """Every TLV of `buf`, in order: [(tag, value)]. DER only: definite length in the shortest form, low tag numbers,
    the elements fill `buf` exactly."""
    out, i, n = [], 0, len(buf)
    while i < n:
        tag = buf[i]
        if tag & 0x1F == 0x1F:
            raise DerError(f"{where}: high tag number")
        if i + 1 >= n:
            raise DerError(f"{where}: truncated")
        first, j = buf[i + 1], i + 2
        if first < 0x80:
            ln = first
        elif first == 0x80:
            raise DerError(f"{where}: indefinite length")
        else:
            k = first & 0x7F
            if k > 4 or j + k > n:
                raise DerError(f"{where}: length of {k} bytes")
            ln = int.from_bytes(buf[j:j + k], "big")
            if buf[j] == 0 or ln < 0x80:
                raise DerError(f"{where}: length not in the shortest form")
            j += k
        if j + ln > n:
            raise DerError(f"{where}: element runs past the end")
        out.append((tag, bytes(buf[j:j + ln])))
        i = j + ln
    return out


def _one(buf: bytes, where: str, tag: int) -> bytes:
    items = _items(buf, where)
    if len(items) != 1 or items[0][0] != tag:
        raise DerError(f"{where}: expected one element of tag 0x{tag:02x}")
    return items[0][1]


def _uint(v: bytes, where: str) -> int:
    if not v or (len(v) > 1 and ((v[0] == 0 and v[1] < 0x80) or (v[0] == 0xFF and v[1] >= 0x80))) or v[0] & 0x80:
        raise DerError(f"{where}: not a non-negative INTEGER in minimal form")
    return int.from_bytes(v, "big")


def _oid(v: bytes, where: str) -> str:
    if not v or v[-1] & 0x80:
        raise DerError(f"{where}: OBJECT IDENTIFIER truncated")
    arcs, cur, start = [], 0, True
    for b in v:
        if start and b == 0x80:
            raise DerError(f"{where}: OBJECT IDENTIFIER arc not in minimal form")
        cur = (cur << 7) | (b & 0x7F)
        start = not (b & 0x80)
        if start:
            arcs.append(cur)
            cur = 0
    first = min(arcs[0] // 40, 2)
    return ".".join(str(a) for a in [first, arcs[0] - 40 * first] + arcs[1:])


def _tlv(tag: int, v: bytes) -> bytes:
    n = len(v)
    ln = bytes([n]) if n < 0x80 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag]) + ln + v


def read_reply(tsr: bytes) -> Optional[Dict]:
    """The facts of a TimeStampResp whose token's signer is named by subjectKeyIdentifier, read as strict DER:
    {"granted", "hash_algorithm", "imprint_hex", "token_der", "certificates", "signer_info", "tst_info"}; None for a reply
    this module does not read (not strict DER, no token, a signer named by issuerAndSerialNumber, an imprint algorithm
    outside the list): the caller then keeps its `openssl ts` path."""
    try:
        kids = _items(_one(bytes(tsr), "TimeStampResp", 0x30), "TimeStampResp")
        if not kids or kids[0][0] != 0x30:
            return None
        status = _items(kids[0][1], "PKIStatusInfo")
        if not status or status[0][0] != 0x02:
            return None
        granted = _uint(status[0][1], "PKIStatus") in (0, 1)
        if len(kids) != 2 or kids[1][0] != 0x30:
            return None
        tok = _tlv(0x30, kids[1][1])
        ci = _items(kids[1][1], "ContentInfo")
        if len(ci) != 2 or ci[0][0] != 0x06 or ci[1][0] != 0xA0 or _oid(ci[0][1], "contentType") != OID_SIGNED_DATA:
            return None
        sd = _items(_one(ci[1][1], "SignedData", 0x30), "SignedData")
        if len(sd) < 4 or [t for t, _ in sd[:3]] != [0x02, 0x31, 0x30] or sd[-1][0] != 0x31:
            return None
        if [t for t, _ in sd[3:-1]] not in ([], [0xA0], [0xA1], [0xA0, 0xA1]):
            return None
        sis = _items(sd[-1][1], "signerInfos")
        if len(sis) != 1 or sis[0][0] != 0x30:
            return None
        si = _items(sis[0][1], "SignerInfo")
        if [t for t, _ in si[:6]] != [0x02, 0x80, 0x30, 0xA0, 0x30, 0x04] or [t for t, _ in si[6:]] not in ([], [0xA1]):
            return None   # sid [0] subjectKeyIdentifier, signedAttrs present (RFC 5652 §5.3); anything else: not here
        eci = _items(sd[2][1], "encapContentInfo")
        if len(eci) != 2 or eci[0][0] != 0x06 or eci[1][0] != 0xA0 or _oid(eci[0][1], "eContentType") != OID_TSTINFO:
            return None
        tst = _items(_one(_one(eci[1][1], "eContent", 0x04), "TSTInfo", 0x30), "TSTInfo")
        if len(tst) < 5 or [t for t, _ in tst[:5]] != [0x02, 0x06, 0x30, 0x02, 0x18] or _uint(tst[0][1], "version") != 1:
            return None
        mi = _items(tst[2][1], "messageImprint")
        if len(mi) != 2 or mi[0][0] != 0x30 or mi[1][0] != 0x04:
            return None
        alg = _items(mi[0][1], "hashAlgorithm")
        if not alg or alg[0][0] != 0x06 or not (len(alg) == 1 or (len(alg) == 2 and alg[1] == (0x05, b""))):
            return None
        name_size = HASH_ALGORITHMS.get(_oid(alg[0][1], "hashAlgorithm"))
        if name_size is None or len(mi[1][1]) != name_size[1]:
            return None
        certs = [_tlv(t, v) for tag, val in sd[3:-1] if tag == 0xA0 for t, v in _items(val, "certificates") if t == 0x30]
        return {"granted": granted, "hash_algorithm": name_size[0], "imprint_hex": mi[1][1].hex(), "token_der": tok,
                "certificates": certs, "signer_info": si, "tst_info": tst}
    except DerError:
        return None


# OpenSSL's canonical form of a Name (crypto/x509/x_name.c x509_name_canon, asn1_string_canon): the comparison that
# X509_NAME_cmp makes and `openssl ts -verify` uses for the tsa field and the ESS issuerSerial
_CANON_STRING = {0x0C: "utf-8", 0x13: "latin-1", 0x14: "latin-1", 0x16: "latin-1", 0x1A: "latin-1",
                 0x1E: "utf-16-be", 0x1C: "utf-32-be"}
_C_SPACE = b" \t\n\v\f\r"


def _canon_value(tag: int, value: bytes):
    enc = _CANON_STRING.get(tag)
    if enc is None:
        return ("raw", tag, value)
    b = value.decode(enc).encode("utf-8").strip(_C_SPACE)   # ValueError when not decodable: the names are not equal
    out, i = bytearray(), 0
    while i < len(b):
        c = b[i]
        if c >= 0x80:
            out.append(c)
            i += 1
        elif c in _C_SPACE:
            out.append(0x20)
            while i < len(b) and b[i] in _C_SPACE:
                i += 1
        else:
            out.append(c + 32 if 0x41 <= c <= 0x5A else c)
            i += 1
    return ("str", bytes(out))


def _name_canon(name_tlv: bytes):
    rdns = []
    for t, rdn in _items(_one(name_tlv, "Name", 0x30), "Name"):
        if t != 0x31:
            raise DerError("Name: an RDN is not a SET")
        attrs = []
        for t2, atv in _items(rdn, "RDN"):
            a = _items(atv, "AttributeTypeAndValue")
            if t2 != 0x30 or len(a) != 2 or a[0][0] != 0x06:
                raise DerError("Name: AttributeTypeAndValue")
            attrs.append((a[0][1], _canon_value(a[1][0], a[1][1])))
        rdns.append(tuple(sorted(attrs, key=repr)))
    return tuple(rdns)


def names_equal(a_tlv: bytes, b_tlv: bytes) -> bool:
    try:
        return _name_canon(a_tlv) == _name_canon(b_tlv)
    except ValueError:   # DerError included
        return False


def _general_names_equal(a: tuple, b: tuple) -> bool:
    """GENERAL_NAME_cmp: the same type; a directoryName compared as a Name, any other type by its bytes"""
    if a[0] != b[0]:
        return False
    return names_equal(a[1], b[1]) if a[0] == 0xA4 else a[1] == b[1]


def _attributes_and_tsa(facts: Dict, signer_der: bytes) -> Optional[str]:
    """steps (2) and (3): None when they hold, else why not"""
    si, tst = facts["signer_info"], facts["tst_info"]
    try:
        cert = _items(_one(signer_der, "certificate", 0x30), "certificate")
        tbs = _items(cert[0][1], "tbsCertificate")
        k = 1 if tbs[0][0] == 0xA0 else 0
        serial, issuer, subject = tbs[k][1], _tlv(0x30, tbs[k + 2][1]), _tlv(0x30, tbs[k + 4][1])
        san = []
        for tag, v in tbs[k + 6:]:
            if tag == 0xA3:
                for _t, ev in _items(_one(v, "extensions", 0x30), "extensions"):
                    e = _items(ev, "Extension")
                    if _oid(e[0][1], "extnID") == OID_SUBJECT_ALT_NAME:
                        san = [_tlv(gt, gv) for gt, gv in _items(_one(e[-1][1], "subjectAltName", 0x30), "GeneralNames")]
        attrs: Dict[str, list] = {}
        for _t, av in _items(si[3][1], "signedAttrs"):
            a = _items(av, "Attribute")
            attrs.setdefault(_oid(a[0][1], "attrType"), []).append(a[1][1])
        found = [o for o in (OID_SIGNING_CERTIFICATE, OID_SIGNING_CERTIFICATE_V2) if o in attrs]
        if not found:
            return "no signingCertificate or signingCertificateV2 attribute (ESS)"
        for o in found:
            vals = attrs[o]
            if len(vals) != 1 or len(_items(vals[0], "attrValues")) != 1:
                return f"ESS attribute {o}: not exactly one value"
            sc = _items(_one(vals[0], "SigningCertificate", 0x30), "SigningCertificate")
            ids = _items(sc[0][1], "certs")
            if len(ids) != 1:
                return f"ESS attribute {o}: {len(ids)} ESSCertIDs (exactly one is evaluated here)"
            cid = _items(ids[0][1], "ESSCertID")
            alg = "sha1"
            if o == OID_SIGNING_CERTIFICATE_V2:
                alg = "sha256"
                if cid and cid[0][0] == 0x30:
                    ai = _items(cid[0][1], "hashAlgorithm")
                    alg = ESS_HASHES.get(_oid(ai[0][1], "hashAlgorithm"))
                    if alg is None or not (len(ai) == 1 or (len(ai) == 2 and ai[1] == (0x05, b""))):
                        return "ESSCertIDv2: hash algorithm not known"
                    cid = cid[1:]
            if not cid or cid[0][0] != 0x04 or len(cid) > 2 or (len(cid) == 2 and cid[1][0] != 0x30):
                return "ESSCertID: not {certHash, issuerSerial?}"
            if cid[0][1] != hashlib.new(alg, signer_der).digest():
                return "ESS certHash is not the hash of the signer certificate"
            if len(cid) == 2:
                iss = _items(cid[1][1], "IssuerSerial")
                names = _items(_one(_tlv(0x30, iss[0][1]), "GeneralNames", 0x30), "GeneralNames") \
                    if iss and iss[0][0] == 0x30 else None
                if not (len(iss) == 2 and iss[1][0] == 0x02 and names is not None and len(names) == 1
                        and names[0][0] == 0xA4 and names_equal(names[0][1], issuer)
                        and int.from_bytes(iss[1][1], "big", signed=True) == int.from_bytes(serial, "big", signed=True)):
                    return "ESS issuerSerial does not name the signer certificate's issuer and serial number"
        tsa = [v for tag, v in tst[5:] if tag == 0xA0]
        if tsa:   # ts_check_signer_name: the subject (a directoryName), then each name of the subjectAltName
            gn = _items(tsa[0], "tsa")
            if len(gn) != 1 or not (_general_names_equal(gn[0], (0xA4, subject))
                                    or any(_general_names_equal(gn[0], _items(n, "GeneralName")[0]) for n in san)):
                return "the TSTInfo tsa field names neither the signer's subject nor one of its subjectAltName"
    except (DerError, IndexError, ValueError) as e:
        return f"signer certificate or attributes not read: {e}"[:160]
    return None


def _pem(der: bytes) -> bytes:
    return b"-----BEGIN CERTIFICATE-----\n" + base64.encodebytes(der) + b"-----END CERTIFICATE-----\n"


def _first_pem_der(pem: bytes) -> Optional[bytes]:
    try:
        body = pem.split(b"-----BEGIN CERTIFICATE-----", 1)[1].split(b"-----END CERTIFICATE-----", 1)[0]
        return base64.b64decode(b"".join(body.split()), validate=True)
    except (IndexError, ValueError):
        return None


def signer(exe: str, facts: Dict, tmp: str, timeout: int, run: Callable,
           write: Callable[[str, bytes], None]) -> Optional[bytes]:
    """step (1): the signer certificate's DER when `openssl cms -verify -noverify` accepts the token's signature, else
    None. `run` is the caller's subprocess.run for openssl (it raises when openssl cannot be run here); `write` writes
    a temporary file."""
    tp, sp = os.path.join(tmp, "ski_token.der"), os.path.join(tmp, "ski_signer.pem")
    write(tp, facts["token_der"])
    p = run([exe, "cms", "-verify", "-noverify", "-binary", "-inform", "DER", "-in", tp, "-signer", sp,
             "-out", os.devnull], capture_output=True, timeout=timeout)
    if p.returncode == 0 and os.path.exists(sp):
        with open(sp, "rb") as f:
            return _first_pem_der(f.read())
    return None


def anchor(exe: str, facts: Dict, signer_der: bytes, ca_file: str, tmp: str, timeout: int, run: Callable,
           write: Callable[[str, bytes], None]) -> Optional[str]:
    """steps (2)-(4) for the signer certificate of step (1): None when the token is established under `ca_file`, else
    why not."""
    why = _attributes_and_tsa(facts, signer_der)
    if why is not None:
        return why
    sp, up = os.path.join(tmp, "ski_signer2.pem"), os.path.join(tmp, "ski_untrusted.pem")
    write(sp, _pem(signer_der))
    write(up, b"".join(_pem(c) for c in facts["certificates"]))
    p = run([exe, "verify", "-purpose", "timestampsign", "-CAfile", ca_file, "-no-CApath", "-no-CAstore",
             "-untrusted", up, sp], capture_output=True, timeout=timeout)
    if p.returncode != 0:
        lines = [ln for ln in (p.stderr or b"").decode("utf-8", "replace").splitlines() if ln.strip()]
        return lines[-1].strip()[:160] if lines else "openssl verify refused the signer certificate"
    return None


def check(exe: str, facts: Dict, ca_file: str, tmp: str, timeout: int, run: Callable,
          write: Callable[[str, bytes], None]) -> Dict:
    """steps (1)-(4) on the facts of read_reply(): {"signature_ok", "anchor_ok", "why"}"""
    signer_der = signer(exe, facts, tmp, timeout, run, write)
    if signer_der is None:
        return {"signature_ok": False, "anchor_ok": False, "why": "openssl cms -verify refused the token's signature"}
    why = anchor(exe, facts, signer_der, ca_file, tmp, timeout, run, write)
    return {"signature_ok": True, "anchor_ok": why is None, "why": why}
