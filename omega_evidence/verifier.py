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
omega_evidence.verifier — one offline verifier for any evidence pack.

Layers (each PASS / FAIL / SKIP; SKIP is honest, never a false green):
  pack-json · honest-scope · pack-sha3 · ledger-chain · rfc3161 · producer-
  signature · trusted-signer · authenticity.

Graduated authenticity (strongest first):
  trusted-signed  — producer signature valid AND key trusted in the registry
  signed          — producer signature valid (identity not checked)
  anchored        — valid ledger chain OR valid TSA timestamp (integrity/time)
  none            — internal consistency only  →  FAIL, cannot authenticate

A bare fabricated pack (no ledger, no timestamp, no signature) cannot pass. A SELF-MADE
  ledger anchor, however, only proves integrity/time — read `authenticated` (not just `valid`)
  and the RFC 3161 layer, which is verified ONLY against a supplied TSA trust anchor (ca_file).
"""

from __future__ import annotations

import json
import sys
import os
import re as _re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .canonical import sha3, sha256_bytes
from .pack import _honest_scope_declares_limit
from .ledger import Ledger
from .signing import verify_pq_alg, verify_signature
from .trust import TrustRegistry


def _layer(name: str, status: str, detail: str = "") -> Dict[str, str]:
    return {"layer": name, "status": status, "detail": detail}


def _rollup(layers: List[Dict[str, str]]) -> Dict[str, Any]:
    checked = [x for x in layers if x["status"] in ("PASS", "FAIL")]
    valid = bool(checked) and all(x["status"] == "PASS" for x in checked)
    return {"valid": valid, "layers": layers,
            "verified_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}


def _ledger_sidecar(path: str) -> Optional[str]:
    cand = path[:-5] + ".ledger.jsonl" if path.endswith(".json") else path + ".ledger.jsonl"
    return cand if os.path.exists(cand) else None


def _anchors_pack(entry: Any, digest: str) -> bool:
    """True only if the entry is a DELIBERATE anchor for this pack: the pack_sha3
    appears in the dedicated `anchored_pack_sha3` field (top-level or under a
    `data` wrapper). FIX NEMESIS re-attack: a value-search over ALL fields let an
    attacker anchor a fabricated pack by logging its pack_sha3 in a junk field of
    an unrelated entry — a dedicated field cannot be triggered incidentally."""
    def _field(e):
        if isinstance(e, dict):
            if e.get("anchored_pack_sha3") == digest:
                return True
            data = e.get("data")
            if isinstance(data, dict) and data.get("anchored_pack_sha3") == digest:
                return True
        return False
    return _field(entry)


def _check_ledger(path: str, ledger_path: Optional[str], layers: List) -> bool:
    lp = ledger_path or _ledger_sidecar(path)
    if not lp:
        layers.append(_layer("ledger-chain", "SKIP", "no ledger beside pack"))
        return False
    try:
        lg = Ledger(lp)
        ok, bad = lg.verify()
    except (RuntimeError, ValueError, OSError, TypeError, AttributeError, RecursionError) as e:
        # a non-UTF-8 byte, a non-object line or an unreadable file is a FAIL verdict, never a traceback (probe 21/09/2026:
        # UnicodeDecodeError escaped from Ledger.__init__ while Go/JS answered FAIL)
        layers.append(_layer("ledger-chain", "FAIL", f"{lp}: unreadable ledger ({type(e).__name__})"))
        return False
    if not ok:
        layers.append(_layer("ledger-chain", "FAIL", f"{lp}: broken chain"))
        return False
    # A valid chain is not enough: the pack must actually be RECORDED in the ledger.
    # An empty or unrelated ledger must NOT anchor a fabricated pack.
    try:
        from .ledger import loads_strict
        pk = loads_strict(open(path, encoding="utf-8").read())   # r5 (Sonnet): the same parser as the integrity layer
        if not isinstance(pk, dict):
            pk = {}
    except (OSError, ValueError, RecursionError):
        pk = {}
    pack_sha3 = pk.get("pack_sha3", "")
    entries = list(lg.raw_entries())   # r4: the whole entry, as Go/Java/Node read it
    if not entries:
        layers.append(_layer("ledger-chain", "FAIL", f"{lp}: ledger empty — nothing anchored"))
        return False
    if not pack_sha3 or not any(_anchors_pack(e, pack_sha3) for e in entries):
        layers.append(_layer("ledger-chain", "FAIL",
                             "valid chain but this pack is not anchored (no anchored_pack_sha3 entry)"))
        return False
    layers.append(_layer("ledger-chain", "PASS", f"{lp}: pack_sha3 recorded"))
    return True


def _check_timestamp(path: str, layers: List) -> str:
    ts_side = path[:-5] + ".tsr.json" if path.endswith(".json") else path + ".tsr.json"
    if not os.path.exists(ts_side):
        layers.append(_layer("rfc3161", "SKIP", "no RFC 3161 sidecar"))
        return "SKIP"
    try:
        from .ledger import loads_strict
        side = loads_strict(open(ts_side, encoding="utf-8").read())   # 0.8.3 review (Opus): json.loads let a float / duplicate
        if not isinstance(side, dict):                                # key sidecar through (PASS in Python, FAIL in the other three)
            raise ValueError("sidecar is not a JSON object")
    except (OSError, ValueError, RecursionError) as e:
        layers.append(_layer("rfc3161", "FAIL", f"malformed sidecar: {e}"))
        return "FAIL"
    current = sha256_bytes(open(path, "rb").read())
    if current != side.get("digest_sha256"):
        layers.append(_layer("rfc3161", "FAIL", "pack changed after stamping"))
        return "FAIL"
    from .timestamp import verify
    r = verify(side.get("tsr_b64", ""), current)
    st = "PASS" if r.get("verified") is True else ("SKIP" if r.get("verified") is None else "FAIL")
    layers.append(_layer("rfc3161", st, side.get("tsa", "")))
    vm = side.get("validation_material")     # LTV material captured at stamping time
    if isinstance(vm, dict) and vm.get("available"):
        raw_crls = vm.get("crls_b64", [])   # r3 (Opus): an int here was a TypeError traceback, no verdict (the three answered)
        crls = [c for c in (raw_crls if isinstance(raw_crls, list) else []) if isinstance(c, dict) and "crl_b64" in c]
        layers.append(_layer("ltv-material", "SKIP",
                             f"captured: {vm.get('cert_count', 0)} cert(s), {len(crls)} CRL(s) "
                             "— TSA chain preserved for long-term validation"))
    return st


def _check_pq_cosignature(side: dict, digest: str, layers: List, expected_pq: Optional[str] = None,
                          require_pq: bool = False) -> Optional[bool]:
    """Report a post-quantum co-signature (hybrid pack) with PINNED semantics (0.7.0, the cryptovalid 0.13.0 rules):
    - PASS "pq-protected" only when a registered PQ backend verifies it AND the key equals the one the relying
      party pinned (`expected_pq`: given directly or taken from the trust registry);
    - a valid signature by an UNPINNED key is SKIP "pq-present-unpinned" (anyone can add their own layer);
    - present but no backend → SKIP "pq-present-unverified"; a backend that rejects it → FAIL;
    - with `require_pq` (or a pinned key) a missing / foreign / unverifiable layer is FAIL: a required layer that
      cannot be confirmed is not a pass. A classical alg declared as pq_sig_alg is never pq-protected.
    Returns True (protected) / None (present, not confirmed) / False (absent or broken)."""
    from .pqbackends import autoload
    autoload()
    palg = side.get("pq_sig_alg")
    required = bool(require_pq or expected_pq)
    if "pq_sig_alg" in side and not isinstance(palg, str):   # present but not a string: malformed, never "unregistered"
        layers.append(_layer("pq-signature", "FAIL", "pq_sig_alg is not a string"))
        return False
    if not palg:
        if required:
            layers.append(_layer("pq-signature", "FAIL", "post-quantum layer required but absent (stripped or never signed)"))
        return False
    pk = side.get("pq_public_key_b64", "")
    if expected_pq and pk != expected_pq:
        layers.append(_layer("pq-signature", "FAIL", f"{palg} co-signature by a key other than the pinned one"))
        return False
    r = verify_pq_alg(palg, pk, side.get("pq_signature_b64", ""), digest.encode())
    if r is None:
        layers.append(_layer("pq-signature", "FAIL" if required else "SKIP",
                             f"{palg} is not a registered PQ backend (pq-present-unverified"
                             + (": a required layer that cannot be checked is not a pass)" if required else ")")))
        return None
    if not r:
        layers.append(_layer("pq-signature", "FAIL", f"{palg} co-signature invalid"))
        return False
    if not expected_pq:
        layers.append(_layer("pq-signature", "FAIL" if required else "SKIP",
                             f"{palg} co-signature valid against the key INSIDE the sidecar only (pq-present-unpinned): "
                             "pin the signer's post-quantum key in the trust registry or pass expected_pq_public_key_b64"))
        return None
    layers.append(_layer("pq-signature", "PASS", f"pq-protected ({palg}, pinned key)"))
    return True


def _check_signature_and_trust(path: str, trust_store: Optional[str], layers: List,
                               expected_pq: Optional[str] = None, require_pq: bool = False):
    sig_side = path[:-5] + ".sig.json" if path.endswith(".json") else path + ".sig.json"
    if not os.path.exists(sig_side):
        layers.append(_layer("producer-signature", "SKIP", "pack not signed"))
        return "SKIP", False, False
    try:
        from .ledger import loads_strict
        side = loads_strict(open(sig_side, encoding="utf-8").read().strip(" \t\r\n"))
        if not isinstance(side, dict):
            raise ValueError("sidecar is not a JSON object")
    except (OSError, ValueError) as e:              # unreadable (permissions, race) is a FAIL, not a crash (council r2)
        layers.append(_layer("producer-signature", "FAIL", f"malformed sidecar: {e}"))
        return "FAIL", False, False
    try:
        from .ledger import loads_strict
        pack = loads_strict(open(path, encoding="utf-8").read())   # r5 (Sonnet): the same parser as the integrity layer
        current = pack.get("pack_sha3", "") if isinstance(pack, dict) else ""
    except (OSError, ValueError, RecursionError):   # verify_pack returns before this on a bad pack; belt for direct callers
        layers.append(_layer("producer-signature", "FAIL", "pack unreadable"))
        return "FAIL", False, False
    # The classical layer is Ed25519 ONLY — the same rule as the Go/Java/JS verifiers (council 16/09 r1: a
    # registered PQ backend must never be accepted here as the producer signature; a sig_alg that is not a
    # string is a malformed sidecar, an unknown string is an honest SKIP, never a crash)
    alg = side.get("sig_alg", "ed25519")
    if not isinstance(alg, str):
        layers.append(_layer("producer-signature", "FAIL", "malformed sidecar fields: sig_alg is not a string"))
        return "FAIL", False, False
    if alg != "ed25519":
        layers.append(_layer("producer-signature", "SKIP", f"unsupported sig_alg: {alg}"))
        return "SKIP", False, False
    # 0.7.0 (oracle 16/09: Python took a base64 signature with a space that Go/Java/Node refuse): the
    # sidecar fields are decoded STRICTLY — canonical base64 of exactly 32 / 64 bytes, lowercase hex digest
    from .pqbackends.mldsa import b64_strict
    if (b64_strict(side.get("public_key_b64"), 32) is None or b64_strict(side.get("signature_b64"), 64) is None
            or not isinstance(current, str) or not _re.fullmatch(r"[0-9a-f]{64}", current)):
        layers.append(_layer("producer-signature", "FAIL", "malformed sidecar fields (strict base64 32/64, lowercase hex digest)"))
        return "FAIL", False, False
    if not isinstance(side.get("signer_id"), str) or not side["signer_id"]:
        # council r2: a list / missing signer_id gave three outcomes in three verifiers (crash, FAIL, JS coercion PASS)
        layers.append(_layer("producer-signature", "FAIL", "malformed sidecar fields: signer_id must be a non-empty string"))
        return "FAIL", False, False
    result = verify_signature(side["public_key_b64"], side["signature_b64"], current.encode())
    if current != side.get("signed_pack_sha3") or not result:
        layers.append(_layer("producer-signature", "FAIL", "signature invalid or pack changed"))
        return "FAIL", False, False
    layers.append(_layer("producer-signature", "PASS",
                         f"signed by {side.get('signer_id')} ({alg})"))
    sid, pk = side.get("signer_id"), side.get("public_key_b64")
    tr, tr_broken = None, None
    if trust_store:
        try:                                  # the registry replays a STRICT, verified chain (council r1: a broken or
            tr = TrustRegistry(trust_store)   # duplicate-key store must be a FAIL of this layer, never a crash or a pin)
        except (OSError, ValueError, RuntimeError) as e:
            tr_broken = f"{type(e).__name__}: {str(e)[:120]}"
    trusted_now = bool(tr is not None and tr.is_trusted(sid, pk))
    # the pinned PQ key: the caller's, else the one the registry binds to this signer — but ONLY when the classical
    # key that signed is the registered one (council r1: a foreign Ed25519 key under a trusted signer_id must not
    # borrow that signer's PQ pin and be reported pq-protected)
    pinned_pq = expected_pq or (tr.pq_pubkey(sid) if trusted_now else None)
    _check_pq_cosignature(side, current, layers, pinned_pq, require_pq)   # hybrid PQ, pinned, fail-closed
    if not trust_store:
        return "PASS", False, False
    if tr_broken:
        layers.append(_layer("trusted-signer", "FAIL", f"trust store unreadable or broken ({tr_broken})"))
        return "PASS", False, True
    if trusted_now:
        layers.append(_layer("trusted-signer", "PASS", f"{sid} in trust registry"))
        return "PASS", True, False
    st = tr.status(sid)
    detail = (f"{sid}: key revoked" if st.get("known") and st.get("revoked")
              else f"{sid}: key differs" if st.get("known") else f"{sid}: not in trust registry")
    layers.append(_layer("trusted-signer", "FAIL", detail))
    return "PASS", False, True


def _decide_authenticity(layers, sig_status, trusted, trust_failed, ledger_ok, ts_status):
    if sig_status == "FAIL":
        layers.append(_layer("authenticity", "FAIL", "producer signature present but invalid"))
    elif trust_failed:
        layers.append(_layer("authenticity", "FAIL", "valid signature but signer not trusted/revoked"))
    elif trusted:
        layers.append(_layer("authenticity", "PASS", "trusted-signed"))
    elif sig_status == "PASS":
        layers.append(_layer("authenticity", "PASS", "signed (identity not checked against a registry)"))
    elif ledger_ok or ts_status == "PASS":
        layers.append(_layer("authenticity", "PASS",
                             "anchored (integrity/time, not identity) — "
                             + ("ledger" if ledger_ok else "TSA")))
    else:
        layers.append(_layer("authenticity", "FAIL", "no anchor and no signature: cannot authenticate"))


def verify_pack(path: str, ledger_path: Optional[str] = None,
                trust_store: Optional[str] = None, expected_pq_public_key_b64: Optional[str] = None,
                require_pq: bool = False) -> Dict[str, Any]:
    """Verify an evidence pack across all layers. Returns {valid, layers, ...}.
    `expected_pq_public_key_b64` pins the ML-DSA-65 key (and REQUIRES the layer); `require_pq` alone requires the
    layer to be present, valid and pinned through the trust registry. `pq_protected` in the result is the tri-state
    true / null (present, not confirmed) / false (absent or broken) — never true on a self-declared key."""
    layers: List[Dict[str, str]] = []
    try:
        # 0.7.0: the family's strict acceptance profile (no duplicate keys, no floats, bounded integers, nesting
        # <= 512) — the same rule the Go/Java/JS pack verifiers apply, so an ambiguous encoding is refused, not guessed
        from .ledger import loads_strict
        pack = loads_strict(open(path, encoding="utf-8").read().strip(" \t\r\n"))
        if not isinstance(pack, dict):
            raise ValueError("pack is not a JSON object")
        layers.append(_layer("pack-json", "PASS"))
    except (OSError, ValueError, RecursionError) as e:
        roll = _rollup([_layer("pack-json", "FAIL", str(e))])
        roll["pq_protected"] = False       # no pack, no layer: the tri-state is false, not absent
        roll["authenticated"] = False
        return roll

    scope = pack.get("honest_scope", "")
    _hs_ok = _honest_scope_declares_limit(scope)
    layers.append(_layer("honest-scope", "PASS" if _hs_ok else "FAIL",
                         "limit declared" if _hs_ok else
                         "no explicit honest_scope (or overclaim without a real NOT-limit)"))

    declared = pack.get("pack_sha3", "")
    try:
        computed = sha3({k: v for k, v in pack.items() if k != "pack_sha3"}, from_text=True)   # r5: the text as read, like the three
    except (ValueError, TypeError, RecursionError) as e:
        computed = None
        layers.append(_layer("pack-sha3", "FAIL", f"not canonicalisable: {e.__class__.__name__}"))
    if computed is not None:
        layers.append(_layer("pack-sha3", "PASS" if declared and declared == computed else "FAIL"))

    ledger_ok = _check_ledger(path, ledger_path, layers)
    ts_status = _check_timestamp(path, layers)
    sig_status, trusted, trust_failed = _check_signature_and_trust(path, trust_store, layers,
                                                                   expected_pq_public_key_b64, require_pq)
    if (require_pq or expected_pq_public_key_b64) and sig_status != "PASS":
        layers.append(_layer("pq-signature", "FAIL", "post-quantum layer required but the pack carries no valid classical signature (hybrid = both)"))
    _decide_authenticity(layers, sig_status, trusted, trust_failed, ledger_ok, ts_status)
    roll = _rollup(layers)
    pq_layer = next((ly for ly in layers if ly["layer"] == "pq-signature"), None)
    roll["pq_protected"] = (True if pq_layer and pq_layer["status"] == "PASS"
                            else None if pq_layer and pq_layer["status"] == "SKIP" else False)
    auth = next((ly for ly in layers if ly["layer"] == "authenticity"), {})
    # `valid` = integrity + intactness. `authenticated` = a real producer identity signed it
    # (a self-made ledger anchor proves integrity/time, NOT authenticity — read this field).
    # council r2 (Sonnet): a body mutated after signing, pack_sha3 and sidecar intact, gave valid=false but
    # authenticated=true — a single-boolean gate would accept content nobody signed. `authenticated` therefore also
    # requires the pack-sha3 integrity layer to PASS (same in Go/Java/JS).
    integrity = next((ly for ly in layers if ly["layer"] == "pack-sha3"), {}).get("status") == "PASS"
    roll["authenticated"] = integrity and auth.get("status") == "PASS" and (
        "signed" in auth.get("detail", "") or "trusted" in auth.get("detail", ""))
    return roll


def main(argv=None) -> int:
    """`python -m omega_evidence.verifier <pack.json> [--ledger L] [--trust-store T] [--expect-pq-key B64] [--require-pq]`
    prints the receipt as JSON; exit 0 only when `valid` (and, with a PQ requirement, `pq_protected`)."""
    import argparse
    p = argparse.ArgumentParser(allow_abbrev=False, add_help=False, prog="omega-evidence-verify")   # r3: -h/--help exit 0 here, 2 in the three (usage on stderr documents the flags)
    p.add_argument("pack")
    p.add_argument("--ledger")
    p.add_argument("--trust-store")
    p.add_argument("--expect-pq-key", help="pinned ML-DSA-65 public key (base64): requires the hybrid layer")
    p.add_argument("--require-pq", action="store_true", help="require a pinned, valid post-quantum layer (trust registry)")
    raw = list(sys.argv[1:] if argv is None else argv)
    # r4/r5: one dash or two is the same flag in the four CLIs — the EXACT single-dash spellings are mapped here (registering
    # "-ledger" as an option string would let argparse resolve "-l" / "-ledg" by prefix even with allow_abbrev=False)
    ONE_DASH = {"-ledger": "--ledger", "-trust-store": "--trust-store", "-expect-pq-key": "--expect-pq-key", "-require-pq": "--require-pq"}
    raw = [ONE_DASH.get(x.split("=", 1)[0], x.split("=", 1)[0]) + ("=" + x.split("=", 1)[1] if "=" in x else "") if x.split("=", 1)[0] in ONE_DASH else x for x in raw]
    if "--" in raw or any(x.startswith("--require-pq=") for x in raw):   # no "--" terminator, no value on the boolean flag (one grammar in the four)
        p.error("unexpected argument")
    a = p.parse_args(raw)
    if a.pack == "" or a.pack.startswith("-"):   # an unset $PACK must not be read as a path
        p.error(f"pack path needs a value (got {a.pack!r})")
    for flag in ("ledger", "trust_store", "expect_pq_key"):
        v = getattr(a, flag)
        if v is not None and (v == "" or v.startswith("-")):   # "" or a flag as a value would silently mean "not given" (one grammar in the four, 21/09/2026)
            p.error(f"--{flag.replace('_', '-')} needs a value (got {v!r})")
    r = verify_pack(a.pack, a.ledger, a.trust_store, a.expect_pq_key, a.require_pq)
    r["verdict"] = "PASS" if r.get("valid") and (not (a.require_pq or a.expect_pq_key) or r.get("pq_protected") is True) else "FAIL"
    print(json.dumps(r, indent=1))
    return 0 if r["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
