#!/usr/bin/env python3
# Copyright 2026 Roberto Locatelli — Apache-2.0
"""Seeded mutation fuzzer of the omega_evidence verifier and ledger (stdlib only, deterministic per seed).

    python3 tests/fuzz_toolkit.py [--seed S] [--iterations N | --seconds T] [--json OUT] [--findings-dir DIR]
    python3 tests/fuzz_toolkit.py --ablate signature|pack-sha3|ledger-chain|strict-json|sig-alg-canonical|require-signed   (positive control)

Corpus: four VALID cases built with the toolkit itself, byte-deterministic (fixed identity seed, fixed instants; Ed25519 is
deterministic): anchored (pack + ledger), signed (pack + signature sidecar), full (pack + ledger + signature + trust
store), stamped (full + an RFC 3161 sidecar whose token is not verifiable here, so its layer is SKIP). Every case verifies
`valid` before any mutation; if not, the fuzzer refuses to run.

Each iteration picks one case, one of its files and one mutation (bit flips, byte edits, truncation, insertions, invalid
UTF-8, NUL; JSON: key removed / duplicated / renamed / added, type changed, float, huge integer, deep nesting, lone
surrogate, hex case, base64 re-encoded with a flipped byte, reformatting; ledger: line removed / duplicated / swapped /
truncated / junk / blank lines / CRLF; signature sidecar: sig_alg as a non-canonical spelling or an unknown name), writes
the mutant in place and calls the verifier (twice: plain, and with require_signed=True) and the library.

Properties (a violation fails the run, exit 1; the offending files are copied to the findings dir):
  P1  the verdict is PASS (`valid` and `assessed`) ONLY IF the mutation left the SIGNED MATERIAL equivalent to the
      original: pack — the canonical JSON of the whole document (what pack_sha3, and so the signature, covers) is
      identical; ledger / trust store — the sequence of parsed entries is a NON-EMPTY PREFIX of the original (a hash
      chain cut at its tail is still a valid chain: undetectable by construction without a close record or an
      external anchor, as the README says); signature sidecar — the producer-signature LAYER is PASS only if public
      key, signature, signed digest and algorithm are identical, and with a classical (absent / "ed25519") or
      unparseable sig_alg the verdict cannot be PASS on other material; a sidecar whose sig_alg became a genuinely
      UNKNOWN string is SKIP by the declared contract and the pack may still PASS on its ledger anchor with
      authenticated=false — P3 below says what that SKIP must look like. Equivalence is computed HERE with json + a
      duplicate-key / float / constant-refusing hook, not with the library's parser. Metadata-only changes (signer_id,
      signed_utc, a sidecar field the verifier does not sign) may PASS: the property is one-sided on PASS.
  P1b when the signed material of the PACK or of the SIGNATURE SIDECAR differs, `authenticated` must be false as well
      (the ledger and the trust store are not covered by the signature: a broken ledger beside a properly signed pack
      is valid=false, authenticated=true by design — read both fields).
  P2  no undeclared exception: verify_pack never reaches its internal-error receipt (an `internal` layer means an
      exception no layer declared); Ledger(path) raises only RuntimeError; verify_text never raises; entries_text,
      loads_strict raise only ValueError / RecursionError; TrustRegistry raises only ValueError; canonical.sha3 raises
      only ValueError / TypeError / RecursionError.
  P3  NO SILENT DOWNGRADE (0.10.0, 29/09/2026 — the property the 28/09 runs found missing: seeds 1 and 2 produced
      "eD25519" and "ed2 5519", each an "unsupported sig_alg" SKIP and a PASS on the anchor). (a) A sidecar whose sig_alg
      is a NON-CANONICAL spelling of the supported name (folds to "ed25519" — the fold is computed HERE, not with the
      library's) must make the producer-signature layer FAIL and the verdict not PASS. (b) A sidecar whose sig_alg is a
      genuinely unknown string may PASS only if the producer-signature layer is a SKIP that begins "signature present,
      algorithm unsupported, not verified" AND the authenticity layer says "not verified". (c) With
      `require_signed=True` (a second call on every mutant) the verdict is PASS only if the producer-signature layer is
      PASS; that call is under P2 as well.

Positive control (--ablate): the verifier is sabotaged in this process — the producer-signature check, the pack-sha3
recomputation, the ledger-chain check, the strict JSON profile, the canonical-name rule of sig_alg or the
`require_signed` requirement is disabled — and the SAME run must then report violations (exit 0 only if it does). A
fuzzer that cannot see a disabled check is measuring nothing.

Determinism: the mutation sequence is a function of --seed; the corpus is fixed; the summary carries the SHA-256 of
every corpus file and of the sequence of verdicts, so two runs with one seed are comparable byte for byte."""

import argparse
import base64
import hashlib
import json
import os
import platform
import random
import shutil
import sys
import tempfile
import time
import traceback
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from omega_evidence import canonical, ledger, pack, signing, trust, verifier  # noqa: E402

FIXED_UTC = "2026-09-28T00:00:00+00:00"
FIXED_TS = "2026-09-28T00:00:00Z"
SCOPE = "Proves integrity and provenance of this record; it does NOT prove the claim itself."
IDENTITY_SEED = bytes(range(32))


# ── a strict parser of our own (the equivalence oracle must not be the library's parser) ───────────────────────────────
def _dup(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError("duplicate key")
        d[k] = v
    return d


def _raise(what):
    raise ValueError(what)


def canon(text):
    """Canonical string of a JSON text under the family's profile (no duplicate key, no float, no NaN/Infinity, integers
    within ±(2^53-1), no lone surrogate), or None when the text is outside it."""
    try:
        obj = json.loads(text, object_pairs_hook=_dup, parse_float=lambda s: _raise("float"),
                         parse_constant=lambda c: _raise("constant"), parse_int=lambda s: _int(s))
    except (ValueError, RecursionError):
        return None
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    except (ValueError, RecursionError):
        return None


def _int(s):
    v = int(s)
    if abs(v) > (1 << 53) - 1:
        raise ValueError("int out of range")
    return v


def _has_lone_surrogate(s):
    return any(0xD800 <= ord(c) <= 0xDFFF for c in s)


def canon_bytes(b):
    try:
        t = b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return canon(t.strip(" \t\r\n"))   # a lone surrogate survives json.loads and is re-escaped by dumps: it shows in the canon


def canon_lines(b):
    """The sequence of canonical entries of a JSONL file, or None if any non-blank line is outside the profile."""
    try:
        t = b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    out = []
    for ln in t.split("\n"):
        ln = ln.strip(" \t\r\n")
        if not ln:
            continue
        c = canon(ln)
        if c is None:
            return None
        out.append(c)
    return out


def sig_alg_is_classical(b):
    """True when the sidecar declares Ed25519 (absent or "ed25519") or cannot be parsed at all — the shapes on which the
    verifier must judge the signature (PASS/FAIL), never SKIP it. Any other string is judged by P3."""
    try:
        d = json.loads(b.decode("utf-8"), object_pairs_hook=_dup)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return True
    if not isinstance(d, dict):
        return True
    alg = d.get("sig_alg", "ed25519")
    return not isinstance(alg, str) or alg in ("", "ed25519")


def fold_alg(s):
    """The fuzzer's OWN copy of the 0.10.0 fold rule (lowercase ASCII letters, keep ASCII letters and digits only), so
    P3 does not ask the library whether the library is right."""
    return "".join(c.lower() for c in s if c.isascii() and c.isalnum())


def sig_alg_of(b):
    """The sig_alg string of a sidecar that parses as an object (lenient parse, for the shape only), else None."""
    try:
        d = json.loads(b.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None
    return d.get("sig_alg") if isinstance(d, dict) and isinstance(d.get("sig_alg"), str) else None


def sig_material(b):
    """The cryptographically bound fields of a signature sidecar (what P1 calls its signed material), or None."""
    try:
        d = json.loads(b.decode("utf-8"), object_pairs_hook=_dup)
    except (ValueError, UnicodeDecodeError, RecursionError):   # a document json cannot even parse is outside the profile
        return None
    if not isinstance(d, dict):
        return None
    return (d.get("public_key_b64"), d.get("signature_b64"), d.get("signed_pack_sha3"), d.get("sig_alg", "ed25519"))


# ── corpus ──────────────────────────────────────────────────────────────────────────────────────────────────────────────
def write_ledger(path, datas, ts=FIXED_TS):
    """A deterministic ledger (fixed instants) in the exact format Ledger.append writes."""
    prev = ledger.GENESIS
    lines = []
    for i, d in enumerate(datas):
        e = {"idx": i, "ts": ts, "data": d, "prev_hash": prev, "self_hash": ""}
        e["self_hash"] = ledger._hash_entry(e)
        prev = e["self_hash"]
        lines.append(json.dumps(e, separators=(",", ":"), allow_nan=False))
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_corpus(d):
    idt = signing.Identity("fuzz-producer", seed=IDENTITY_SEED)
    body = {"kind": "fuzz_pack", "generated_utc": FIXED_UTC, "honest_scope": SCOPE,
            "claim": "x", "n": 1, "u": "ünï ✓ \U0001F600", "nested": {"a": [1, 2, {"b": "c"}], "e": None, "t": True, "f": False},
            "big": (1 << 53) - 1, "neg": -5, "s": "quote\" back\\ nl\n tab\t", "empty": {}, "list": []}
    body["pack_sha3"] = canonical.sha3(body)
    digest = body["pack_sha3"]
    cases = {}

    def mk(name):
        p = os.path.join(d, name + ".json")
        pack.write_pack(p, dict(body))
        return p

    def anchor(p):
        lp = p[:-5] + ".ledger.jsonl"
        write_ledger(lp, [{"event": "start", "i": 0}, {"event": "note", "text": "before"},
                          {"anchored_pack_sha3": digest, "anchored_utc": FIXED_UTC},
                          {"event": "note", "text": "after", "n": 3}])
        return lp

    def sign(p):
        pack.sign_pack(p, idt)
        sp = p[:-5] + ".sig.json"
        side = json.loads(Path(sp).read_text(encoding="utf-8"))
        side["signed_utc"] = FIXED_UTC
        Path(sp).write_text(json.dumps(side, ensure_ascii=False, indent=1), encoding="utf-8")
        return sp

    def store():
        tp = os.path.join(d, "trust.jsonl")
        write_ledger(tp, [{"action": "trust", "signer_id": "someone-else", "pubkey": signing.Identity("o", seed=bytes([7] * 32)).public_key_b64, "ts": FIXED_UTC},
                          {"action": "trust", "signer_id": "fuzz-producer", "pubkey": idt.public_key_b64, "ts": FIXED_UTC}])
        return tp

    p = mk("anchored"); lp = anchor(p)
    cases["anchored"] = {"pack": p, "ledger": lp, "trust": None, "files": {"pack": p, "ledger": lp}}
    p = mk("signed"); sp = sign(p)
    cases["signed"] = {"pack": p, "ledger": None, "trust": None, "files": {"pack": p, "sig": sp}}
    p = mk("full"); lp = anchor(p); sp = sign(p); tp = store()
    cases["full"] = {"pack": p, "ledger": lp, "trust": tp, "files": {"pack": p, "ledger": lp, "sig": sp, "trust": tp}}
    p = mk("stamped"); lp = anchor(p); sp = sign(p)
    tsp = p[:-5] + ".tsr.json"
    Path(tsp).write_text(json.dumps({"digest_sha256": hashlib.sha256(Path(p).read_bytes()).hexdigest(), "tsa": "fuzz-tsa (not a real token)",
                                     "tsr_b64": base64.b64encode(b"\x30\x03\x02\x01\x00").decode(), "stamped_utc": FIXED_UTC}, indent=1), encoding="utf-8")
    cases["stamped"] = {"pack": p, "ledger": lp, "trust": tp, "files": {"pack": p, "ledger": lp, "sig": sp, "tsr": tsp, "trust": tp}}
    return cases


# ── mutations ───────────────────────────────────────────────────────────────────────────────────────────────────────────
def _pos(r, b):
    return r.randrange(len(b) + 1) if b else 0


def m_bitflip(r, b, _):
    b = bytearray(b)
    for _ in range(r.randint(1, 8)):
        if b:
            i = r.randrange(len(b)); b[i] ^= 1 << r.randrange(8)
    return bytes(b)


def m_byte_set(r, b, _):
    b = bytearray(b)
    for _ in range(r.randint(1, 4)):
        if b:
            b[r.randrange(len(b))] = r.randrange(256)
    return bytes(b)


def m_truncate(r, b, _):
    return b[:r.randrange(len(b))] if b else b


def m_insert(r, b, _):
    i = _pos(r, b)
    return b[:i] + bytes(r.randrange(256) for _ in range(r.randint(1, 16))) + b[i:]


def m_delete(r, b, _):
    if len(b) < 2:
        return b""
    i = r.randrange(len(b)); j = min(len(b), i + r.randint(1, 32))
    return b[:i] + b[j:]


def m_dup_slice(r, b, _):
    if len(b) < 2:
        return b + b
    i = r.randrange(len(b)); j = min(len(b), i + r.randint(1, 64))
    return b[:j] + b[i:j] + b[j:]


def m_nonutf8(r, b, _):
    i = _pos(r, b)
    return b[:i] + r.choice([b"\xff", b"\xc0\x80", b"\xed\xa0\x80", b"\xf5\x80\x80\x80"]) + b[i:]


def m_nul(r, b, _):
    i = _pos(r, b)
    return b[:i] + b"\x00" + b[i:]


def m_empty(r, b, _):
    return r.choice([b"", b"\n", b" ", b"{}", b"[]", b"null", b'""', b"0"])


def m_whitespace(r, b, _):
    i = _pos(r, b)
    return b[:i] + r.choice([b" ", b"\n", b"\t", b"\r\n", b"\f", b"\v", b"\xc2\xa0", b" " * 500]) + b[i:]


def _depth_of(b):
    """Nesting depth of a JSON text on the bytes (brackets outside strings), no parsing."""
    depth = mx = 0; in_str = esc = False
    for c in b:
        if in_str:
            if esc:
                esc = False
            elif c == 0x5C:
                esc = True
            elif c == 0x22:
                in_str = False
        elif c == 0x22:
            in_str = True
        elif c in (0x5B, 0x7B):
            depth += 1; mx = max(mx, depth)
        elif c in (0x5D, 0x7D):
            depth -= 1
    return mx


MUTATOR_MAX_DEPTH = 1000   # the mutators' lenient re-read stops here, whatever the interpreter's recursion limit


def _json_doc(b):
    """Lenient re-read of a mutant for the JSON mutators. Depth-bounded HERE (29/09/2026): json.loads raises RecursionError
    at an interpreter-dependent depth — CPython 3.11 refused a 5 000-deep document made by m_json_deep, 3.13 parsed it — so a
    following mutator consumed random draws on one interpreter and not on the other, and the verdict sequence of seed
    20260928 differed between 3.11 and 3.13 from iteration 796 (measured with --trace). With a fixed bound the mutation
    sequence is a function of the seed alone, on every interpreter."""
    if _depth_of(b) > MUTATOR_MAX_DEPTH:
        return None
    try:
        return json.loads(b.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None


def _dump(r, obj):
    # surrogatepass: a lone surrogate that came back from a previous mutation is written as invalid UTF-8 (ED A0 80…),
    # which is one more hostile shape the verifier must refuse, instead of crashing the fuzzer
    return json.dumps(obj, ensure_ascii=r.random() < 0.5, indent=r.choice([None, 1, 2]), sort_keys=r.random() < 0.5,
                      separators=r.choice([None, (",", ":")])).encode("utf-8", "surrogatepass")


def _paths(obj, prefix=()):
    out = [prefix]
    if isinstance(obj, dict):
        for k, v in obj.items():
            out += _paths(v, prefix + (k,))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out += _paths(v, prefix + (i,))
    return out


def _get(obj, path):
    for p in path:
        obj = obj[p]
    return obj


def _set(obj, path, value):
    if not path:
        return value
    parent = _get(obj, path[:-1])
    parent[path[-1]] = value
    return obj


VALUES = [None, True, False, 0, -1, 1, (1 << 53) - 1, 1 << 53, -(1 << 53), 1 << 63, 1.5, 0.0, "", "x", "0", "NOT", [], {},
          " ", "é", "\U0001F600", "a" * 3000]


def m_json_drop_key(r, b, _):
    o = _json_doc(b)
    if o is None:
        return b
    dicts = [p for p in _paths(o) if isinstance(_get(o, p), dict) and _get(o, p)]
    if not dicts:
        return b
    p = r.choice(dicts); k = r.choice(list(_get(o, p)))
    del _get(o, p)[k]
    return _dump(r, o)


def m_json_type_swap(r, b, _):
    o = _json_doc(b)
    if o is None:
        return b
    p = r.choice(_paths(o))
    v = _get(o, p)
    new = r.choice(VALUES + [[v], {"k": v}, str(v), [v, v]])
    return _dump(r, _set(o, p, new))


def m_json_rename_key(r, b, _):
    o = _json_doc(b)
    if o is None:
        return b
    dicts = [p for p in _paths(o) if isinstance(_get(o, p), dict) and _get(o, p)]
    if not dicts:
        return b
    d = _get(o, r.choice(dicts)); k = r.choice(list(d))
    nk = r.choice([k.upper(), k + "_", " " + k, k[:-1], "pack_sha3", "self_hash", "anchored_pack_sha3", "data", "idx", "prev_hash", k + "\u0000"])
    d[nk] = d.pop(k)
    return _dump(r, o)


def m_json_add_key(r, b, _):
    o = _json_doc(b)
    if o is None:
        return b
    dicts = [p for p in _paths(o) if isinstance(_get(o, p), dict)]
    if not dicts:
        return b
    d = _get(o, r.choice(dicts))
    d[r.choice(["extra", "anchored_pack_sha3", "pack_sha3", "__omega_reserved_type__", "signature_b64", "", "x" * 200])] = r.choice(VALUES)
    return _dump(r, o)


def m_json_dup_key(r, b, _):
    """A duplicated key in the TEXT (same value, or another): the profile refuses it, a lax parser keeps the last one."""
    o = _json_doc(b)
    if not isinstance(o, dict) or not o:
        return b
    k = r.choice(list(o))
    v = o[k] if r.random() < 0.5 else r.choice(VALUES)
    text = json.dumps(o, ensure_ascii=True)
    assert text[0] == "{"
    return ("{" + json.dumps(k) + ":" + json.dumps(v, ensure_ascii=True) + "," + text[1:]).encode("utf-8")


def m_json_float(r, b, _):
    o = _json_doc(b)
    if o is None:
        return b
    ints = [p for p in _paths(o) if isinstance(_get(o, p), int) and not isinstance(_get(o, p), bool)]
    if ints:
        p = r.choice(ints); v = _get(o, p)
        text = json.dumps(_set(o, p, "\u0000FLOAT\u0000"), ensure_ascii=True)
        return text.replace('"\\u0000FLOAT\\u0000"', r.choice([f"{v}.0", f"{v}e0", f"{v}.5", "1E400", "-0", f"0{v}", "NaN", "Infinity", "-Infinity"])).encode("utf-8")
    return _dump(r, _set(o, r.choice(_paths(o)), 1.5))


def m_json_deep(r, b, _):
    o = _json_doc(b)
    if o is None:
        return b
    depth = r.choice([100, 511, 512, 513, 600, 5000, 100000])
    text = json.dumps(_set(o, r.choice(_paths(o)), "\u0000DEEP\u0000"), ensure_ascii=True)   # spliced as text: json cannot build it
    return text.replace('"\\u0000DEEP\\u0000"', r.choice(["[", "{\"k\":"]) * depth + r.choice(["]", "}"]) * depth).encode("utf-8")


def m_json_surrogate(r, b, _):
    o = _json_doc(b)
    if o is None:
        return b
    strs = [p for p in _paths(o) if isinstance(_get(o, p), str)]
    if not strs:
        return b
    p = r.choice(strs)
    text = json.dumps(_set(o, p, "\u0000SUR\u0000"), ensure_ascii=True)
    return text.replace('"\\u0000SUR\\u0000"', r.choice(['"\\ud800"', '"\\udc00x"', '"\\ud83d\\ude00"', '"a\\ud83d"', '"\\uD800\\uDC00"'])).encode("utf-8")


def m_hex_case(r, b, _):
    o = _json_doc(b)
    if o is None:
        return b
    hexes = [p for p in _paths(o) if isinstance(_get(o, p), str) and len(_get(o, p)) == 64 and all(c in "0123456789abcdef" for c in _get(o, p))]
    if not hexes:
        return b
    p = r.choice(hexes); v = _get(o, p)
    return _dump(r, _set(o, p, r.choice([v.upper(), v[:-1], v + "0", v[::-1], "0" * 64, v[:32].upper() + v[32:]])))


def m_b64_tweak(r, b, _):
    """A base64 field re-encoded with one decoded byte flipped (form-valid), or its form damaged."""
    o = _json_doc(b)
    if o is None:
        return b
    fields = [p for p in _paths(o) if isinstance(_get(o, p), str) and p and str(p[-1]).endswith("_b64") and _get(o, p)]
    if not fields:
        return b
    p = r.choice(fields); v = _get(o, p)
    try:
        raw = bytearray(base64.b64decode(v, validate=True))
    except Exception:  # noqa: BLE001
        raw = bytearray(b"\x00" * 32)
    kind = r.randrange(6)
    if kind == 0 and raw:
        raw[r.randrange(len(raw))] ^= 1 << r.randrange(8); nv = base64.b64encode(bytes(raw)).decode()
    elif kind == 1:
        nv = base64.urlsafe_b64encode(bytes(raw)).decode()
    elif kind == 2:
        nv = v.rstrip("=")
    elif kind == 3:
        nv = v[:4] + " " + v[4:]
    elif kind == 4:
        nv = base64.b64encode(bytes(raw) + b"\x00").decode()
    else:
        nv = base64.b64encode(bytes(raw)[:-1]).decode() if raw else ""
    return _dump(r, _set(o, p, nv))


def m_reformat(r, b, _):
    o = _json_doc(b)
    return b if o is None else _dump(r, o)


def m_sig_alg_variant(r, b, _):
    """The sig_alg field as a NON-CANONICAL spelling of the supported name, or as an unknown name (29/09/2026: the first is a
    FAIL of the layer in the four verifiers, the second a SKIP that names the unverified signature; until 0.9.1 both were a
    silent SKIP). Signature sidecars only."""
    o = _json_doc(b)
    if not isinstance(o, dict) or not isinstance(o.get("sig_alg"), str) or not o["sig_alg"]:
        return b
    a = o["sig_alg"]; i = r.randrange(len(a))
    o["sig_alg"] = r.choice([a.upper(), a.capitalize(), a[:i] + a[i].swapcase() + a[i + 1:], a[:i] + " " + a[i:], a[:i] + "-" + a[i:], a[:i] + "_" + a[i:],
                             a + "\n", " " + a, a + " ", a + "​", a.replace("e", "е", 1), "rsa-pss", "ml-dsa-65", "ed25519ph", "x"])
    return _dump(r, o)


def m_line_drop(r, b, _):
    ls = b.split(b"\n")
    if len(ls) > 1:
        del ls[r.randrange(len(ls))]
    return b"\n".join(ls)


def m_line_dup(r, b, _):
    ls = b.split(b"\n")
    i = r.randrange(len(ls)); ls.insert(r.randrange(len(ls) + 1), ls[i])
    return b"\n".join(ls)


def m_line_swap(r, b, _):
    ls = b.split(b"\n")
    if len(ls) > 2:
        i, j = r.randrange(len(ls)), r.randrange(len(ls)); ls[i], ls[j] = ls[j], ls[i]
    return b"\n".join(ls)


def m_line_junk(r, b, _):
    ls = b.split(b"\n")
    ls.insert(r.randrange(len(ls) + 1), r.choice([b"{}", b"[1]", b"null", b"junk", b'{"idx":0}', b"\xff", b"{" * 1000, b'{"a":1,"a":2}']))
    return b"\n".join(ls)


def m_line_blank(r, b, _):
    ls = b.split(b"\n")
    ls.insert(r.randrange(len(ls) + 1), r.choice([b"", b" ", b"\t", b" \t", b"\r"]))
    return b"\n".join(ls)


def m_crlf(r, b, _):
    return b.replace(b"\n", b"\r\n")


def m_line_mutate(r, b, _):
    ls = b.split(b"\n")
    idx = [i for i, ln in enumerate(ls) if ln.strip()]
    if not idx:
        return b
    i = r.choice(idx)
    ls[i] = r.choice(JSON_MUTATORS)(r, ls[i], None)
    return b"\n".join(ls)


BYTE_MUTATORS = [m_bitflip, m_byte_set, m_truncate, m_insert, m_delete, m_dup_slice, m_nonutf8, m_nul, m_empty, m_whitespace]
JSON_MUTATORS = [m_json_drop_key, m_json_type_swap, m_json_rename_key, m_json_add_key, m_json_dup_key, m_json_float, m_json_deep,
                 m_json_surrogate, m_hex_case, m_b64_tweak, m_reformat]
LINE_MUTATORS = [m_line_drop, m_line_dup, m_line_swap, m_line_junk, m_line_blank, m_crlf, m_line_mutate]


def mutators_for(kind):
    return BYTE_MUTATORS + JSON_MUTATORS + (LINE_MUTATORS if kind in ("ledger", "trust") else []) + ([m_sig_alg_variant] if kind == "sig" else [])


# ── the properties ──────────────────────────────────────────────────────────────────────────────────────────────────────
def equivalent(kind, orig, mut):
    if kind == "pack":
        return canon_bytes(orig) is not None and canon_bytes(orig) == canon_bytes(mut)
    if kind in ("ledger", "trust"):
        # a NON-EMPTY PREFIX of the entries is a valid chain by construction (a hash chain has no end marker: tail
        # truncation is undetectable without a close record or an external anchor — README, AAT interop). Criterion
        # refined after the first run of 28/09/2026 (2000 iterations: one PASS on the 3-entry prefix of a 4-entry
        # ledger, the anchor entry kept): the justification is the chain's definition, not the result.
        o, m = canon_lines(orig), canon_lines(mut)
        return o is not None and m is not None and 0 < len(m) <= len(o) and o[:len(m)] == m
    if kind == "sig":
        return sig_material(orig) is not None and sig_material(orig) == sig_material(mut)
    return True   # tsr: its layer cannot PASS here (no trust anchor), so P1 has nothing to say; P2 applies


def library_probe(kind, path):
    """P2 on the library API of the mutated file: the exception types each function declares, nothing else."""
    if kind in ("ledger", "trust"):
        try:
            lg = ledger.Ledger(path)
            lg.verify()
            list(lg.entries())
            list(lg.raw_entries())
        except RuntimeError:
            pass
        except (ValueError, RecursionError):
            pass   # entries()/raw_entries() declare them on a line outside the profile
        text = None
        try:
            text = Path(path).read_bytes().decode("utf-8")
        except UnicodeDecodeError:
            pass
        if text is not None:
            ledger.verify_text(text)          # never raises
            try:
                ledger.entries_text(text)
            except (ValueError, RecursionError):
                pass
        if kind == "trust":
            try:
                trust.TrustRegistry(path)
            except ValueError:
                pass
    if kind == "pack":
        try:
            obj = ledger.loads_strict(Path(path).read_bytes().decode("utf-8"))
        except (ValueError, RecursionError, UnicodeDecodeError):
            return
        try:
            canonical.sha3(obj, from_text=True)
        except (ValueError, TypeError, RecursionError):
            pass


def _ignore_require_signed():
    orig = verifier._check_signature_and_trust
    verifier._check_signature_and_trust = lambda *a, **k: orig(*a, **dict(k, require_signed=False))


ABLATIONS = {
    "signature": lambda: setattr(verifier, "verify_signature", lambda pk, sig, msg: True),
    "pack-sha3": lambda: setattr(verifier, "sha3", lambda obj, from_text=False: _ORIGINAL["digest"]),
    "ledger-chain": lambda: setattr(verifier, "verify_text", lambda text: (True, [])),
    "strict-json": lambda: setattr(verifier, "loads_strict", json.loads),
    "sig-alg-canonical": lambda: setattr(verifier, "_fold_alg", lambda s: s),   # 0.9.1: a variant of "ed25519" is just "unknown" → SKIP
    "require-signed": _ignore_require_signed,                                    # the requirement silently dropped
}
_ORIGINAL = {}
UNVERIFIED_PREFIX = "signature present, algorithm unsupported, not verified"


def run(args):
    r = random.Random(args.seed)
    root = tempfile.mkdtemp(prefix="oe-fuzz-")
    cases = build_corpus(root)
    _ORIGINAL["digest"] = json.loads(Path(cases["signed"]["pack"]).read_text(encoding="utf-8"))["pack_sha3"]
    originals = {(n, k): Path(p).read_bytes() for n, c in cases.items() for k, p in c["files"].items()}
    corpus_sha = {f"{n}/{k}": hashlib.sha256(b).hexdigest() for (n, k), b in sorted(originals.items())}
    for n, c in cases.items():   # the corpus must be valid BEFORE any mutation, else the fuzzer measures nothing
        rr = verifier.verify_pack(c["pack"], c["ledger"], c["trust"])
        if not (rr["valid"] and rr.get("assessed", True)):
            print(json.dumps({"fatal": "corpus case is not valid before mutation", "case": n, "receipt": rr}, indent=1))
            return 2
    if args.ablate:
        ABLATIONS[args.ablate]()
    findings = Path(args.findings_dir) if args.findings_dir else Path(root) / "findings"
    findings.mkdir(parents=True, exist_ok=True)
    stats = {"iterations": 0, "verdicts": {"PASS": 0, "FAIL": 0, "NOT_ASSESSED": 0}, "pass_equivalent": 0, "pass_metadata_only": 0,
             "require_signed_pass": 0, "require_signed_not_pass": 0, "by_mutator": {}, "by_target": {}, "violations": []}
    verdict_seq = hashlib.sha256()
    t0 = time.perf_counter()
    while True:
        if args.iterations and stats["iterations"] >= args.iterations:
            break
        if args.seconds and time.perf_counter() - t0 >= args.seconds:
            break
        i = stats["iterations"]
        name = r.choice(sorted(cases))
        c = cases[name]
        kind = r.choice(sorted(c["files"]))
        path = c["files"][kind]
        orig = originals[(name, kind)]
        mut_fn = r.choice(mutators_for(kind))
        n_mut = r.choice([1, 1, 1, 2, 3])
        mut = orig
        names = []
        for _ in range(n_mut):
            f = mut_fn if not names else r.choice(mutators_for(kind))
            mut = f(r, mut, kind)
            names.append(f.__name__)
        label = "+".join(names)
        stats["by_mutator"][label.split("+")[0]] = stats["by_mutator"].get(label.split("+")[0], 0) + 1
        stats["by_target"][f"{name}/{kind}"] = stats["by_target"].get(f"{name}/{kind}", 0) + 1
        Path(path).write_bytes(mut)
        violation = None
        receipt = None
        try:
            receipt = verifier.verify_pack(c["pack"], c["ledger"], c["trust"])
            layers = {ly["layer"]: ly for ly in receipt.get("layers", [])}
            passed = bool(receipt.get("valid")) and receipt.get("assessed", True)
            verdict = "PASS" if passed else ("FAIL" if receipt.get("assessed", True) else "NOT_ASSESSED")
            stats["verdicts"][verdict] += 1
            verdict_seq.update(verdict.encode())
            if args.trace:
                args.trace.write(f"{i}\t{name}/{kind}\t{label}\t{verdict}\t{hashlib.sha256(mut).hexdigest()[:16]}\n")
            eq = mut == orig or equivalent(kind, orig, mut)
            alg = sig_alg_of(mut) if kind == "sig" else None
            ps = layers.get("producer-signature", {})
            if "internal" in layers:
                violation = f"P2 internal-error receipt: {layers['internal'].get('detail')}"
            elif kind == "sig" and not eq and (ps.get("status") == "PASS" or (passed and sig_alg_is_classical(mut))):
                # the producer-signature layer never PASSES on other material; and with sig_alg absent or "ed25519" the
                # verdict cannot be PASS either. A sidecar whose sig_alg became another string is judged by P3 below.
                violation = "P1 producer-signature PASS (or verdict PASS with a classical sig_alg) on a sidecar whose signed material differs"
            elif kind != "sig" and passed and not eq:
                violation = "P1 PASS on a mutant whose signed material differs from the original"
            elif not eq and kind in ("pack", "sig") and receipt.get("authenticated"):
                # the ledger and the trust store are not what the signature covers: a broken ledger beside a properly
                # signed pack is valid=false, authenticated=true by the verifier's declared reading (the sidecar rules)
                violation = "P1b authenticated on a mutant whose signed material differs"
            elif alg is not None and alg != "ed25519" and fold_alg(alg) == "ed25519" and (passed or ps.get("status") != "FAIL"):
                # 29/09/2026 (0.10.0): "eD25519", "ed2 5519" and the like are refused, never a SKIP the anchor can carry
                violation = f"P3 non-canonical spelling of a supported sig_alg not refused ({alg!r}): silent downgrade"
            elif alg is not None and fold_alg(alg) != "ed25519" and passed and not (
                    ps.get("status") == "SKIP" and str(ps.get("detail", "")).startswith(UNVERIFIED_PREFIX)
                    and "not verified" in str(layers.get("authenticity", {}).get("detail", ""))):
                violation = f"P3 unknown sig_alg ({alg!r}): PASS without the unverified signature being said"
            elif passed:   # allowed: the signed material is the same; say whether unsigned sidecar metadata changed
                stats["pass_metadata_only" if kind == "sig" and canon_bytes(orig) != canon_bytes(mut) else "pass_equivalent"] += 1
            if violation is None:
                # P3 (c): the same mutant under require_signed — PASS only with a verified producer signature; P2 applies too
                rq = verifier.verify_pack(c["pack"], c["ledger"], c["trust"], require_signed=True)
                rq_layers = {ly["layer"]: ly for ly in rq.get("layers", [])}
                if "internal" in rq_layers:
                    violation = f"P2 internal-error receipt under require_signed: {rq_layers['internal'].get('detail')}"
                elif rq.get("valid") and rq.get("assessed", True) and rq_layers.get("producer-signature", {}).get("status") != "PASS":
                    violation = "P3 require_signed: PASS without a verified producer signature"
                elif rq.get("valid") and rq.get("assessed", True) and not passed:
                    violation = "P3 require_signed: PASS where the same mutant was not PASS without the requirement"
                else:
                    stats["require_signed_pass" if rq.get("valid") and rq.get("assessed", True) else "require_signed_not_pass"] += 1
            if violation is None:
                library_probe(kind, path)
        except Exception as e:  # noqa: BLE001 — anything reaching here is an undeclared exception (P2)
            violation = f"P2 undeclared exception {type(e).__name__}: {str(e)[:200]}\n{traceback.format_exc()[-1500:]}"
        if violation:
            fdir = findings / f"{i:06d}-{name}-{kind}-{label}"
            fdir.mkdir(parents=True, exist_ok=True)
            for k2, p2 in c["files"].items():
                shutil.copy(p2, fdir / os.path.basename(p2))
            (fdir / "MUTANT").write_text(f"{kind}: {os.path.basename(path)}\nmutation: {label}\n{violation}\n", encoding="utf-8")
            (fdir / "receipt.json").write_text(json.dumps(receipt, indent=1, default=str), encoding="utf-8")
            stats["violations"].append({"iteration": i, "case": name, "file": kind, "mutation": label, "why": violation.split("\n")[0], "dir": str(fdir)})
            if args.verbose:
                print(f"  [VIOLATION] #{i} {name}/{kind} {label}: {violation.split(chr(10))[0]}")
        Path(path).write_bytes(orig)   # restore for the next iteration
        stats["iterations"] += 1
    elapsed = time.perf_counter() - t0
    summary = {"seed": args.seed, "ablation": args.ablate, "elapsed_s": round(elapsed, 2), "host": {"python": sys.version.split()[0], "platform": platform.platform(), "machine": platform.machine(), "signing_backend": signing.BACKEND},
               "corpus_sha256": corpus_sha, "verdict_sequence_sha256": verdict_seq.hexdigest(), **stats, "findings_dir": str(findings)}
    summary["violations_count"] = len(stats["violations"])
    if args.json:
        Path(args.json).write_text(json.dumps(summary, indent=1), encoding="utf-8")
    short = {k: v for k, v in summary.items() if k != "violations"}
    short["violations"] = stats["violations"][:10]
    print(json.dumps(short, indent=1))
    if args.ablate:
        ok = bool(stats["violations"])
        print(f"POSITIVE CONTROL ({args.ablate} disabled): {len(stats['violations'])} violations in {stats['iterations']} iterations — "
              + ("the fuzzer SEES the disabled check" if ok else "NOT SEEN: the fuzzer is blind to this check"))
        return 0 if ok else 1
    print(f"fuzz: {stats['iterations']} iterations, {len(stats['violations'])} violations, seed {args.seed}, {elapsed:.1f} s")
    if not stats["violations"] and not args.findings_dir:
        shutil.rmtree(root, ignore_errors=True)
    return 1 if stats["violations"] else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--seed", type=int, default=20260928)
    ap.add_argument("--iterations", type=int, default=2000, help="0 = no bound (use --seconds)")
    ap.add_argument("--seconds", type=float, default=0, help="stop after this many seconds (0 = no bound)")
    ap.add_argument("--json", help="write the summary here")
    ap.add_argument("--findings-dir", help="where violating cases are copied (default: under the temp corpus)")
    ap.add_argument("--ablate", choices=sorted(ABLATIONS), help="positive control: disable this check in the verifier; exit 0 only if violations appear")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--trace", type=argparse.FileType("w"), help="write one line per iteration (index, target, mutation, verdict, sha256 of the mutant): to compare two runs or two interpreters")
    args = ap.parse_args(argv)
    if not args.iterations and not args.seconds:
        ap.error("--iterations or --seconds")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
