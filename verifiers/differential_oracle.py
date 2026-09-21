#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Differential oracle over the omega-evidence PACK verifiers: the Python reference (python -m omega_evidence), Go
(OEVERIFY_GO or built from verifiers/go), Java (OEVERIFY_JAVA or compiled from verifiers/java with a JDK >= 24) and
Node (verifiers/js/oeverify.mjs) must give the same (verdict, pq_protected, authenticated) on every case — except the declared
Node divergences on a Node whose OpenSSL is < 3.5 (no ML-DSA there: a REQUIRED post-quantum layer is FAIL, an INVALID
ML-DSA co-signature is not detectable); with OpenSSL >= 3.5 (Node >= 24.6, measured also on 22.23) Node verifies ML-DSA-65
and the declared count is 0. Cases are generated with the toolkit itself; ML-DSA cases need cryptography >= 48 (skipped
and SAID otherwise). Exit 1 on any undeclared disagreement. Council 16/09 r1: `authenticated` joined the tuple (Go/Java/JS
said true for a revoked signer) and the trust-store / sig_alg / foreign-classical-key / timestamp-sidecar cases were added."""
import base64, glob, json, os, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
from omega_evidence import pack as P, signing, trust  # noqa: E402
from omega_evidence import canonical  # noqa: E402
from omega_evidence.ledger import Ledger  # noqa: E402
try:
    from omega_evidence.pqbackends import mldsa
    HAVE_PQ = mldsa.available()
except Exception:  # noqa: BLE001
    HAVE_PQ = False

SCOPE = "Proves integrity; does NOT prove the claim."


def build_cases(d):
    """name -> (pack path, extra flags, declared {verifier: expected (verdict, pq)} or None)"""
    cases = {}
    def mk(name, body=None, scope=SCOPE):
        p = os.path.join(d, name + ".json")
        P.write_pack(p, P.build_pack("demo", body or {"claim": "x", "n": 1, "u": "ünï ✓ \U0001F600"}, scope))
        return p
    idt = signing.Identity("acme")
    cases["bare"] = (mk("bare"), [], None)
    a = mk("anchored"); P.anchor_pack(a, a[:-5] + ".ledger.jsonl"); cases["anchored"] = (a, [], None)
    s = mk("signed"); P.sign_pack(s, idt); cases["signed"] = (s, [], None)
    store = os.path.join(d, "trust.jsonl"); tr = trust.TrustRegistry(store); tr.trust("acme", idt.public_key_b64)
    cases["signed-trusted"] = (s, ["--trust-store", store], None)
    other = signing.Identity("mallory"); s2 = mk("signed-other"); P.sign_pack(s2, other)
    cases["signed-untrusted"] = (s2, ["--trust-store", store], None)
    t = mk("tampered"); P.sign_pack(t, idt); dd = json.load(open(t)); dd["claim"] = "y"; json.dump(dd, open(t, "w"))
    cases["tampered"] = (t, [], None)
    # sidecar hostile shapes
    for nm, mut in (("sig-space", lambda sd: dict(sd, signature_b64=sd["signature_b64"][:8] + " " + sd["signature_b64"][8:])),
                    ("sig-digest-upper", lambda sd: dict(sd, signed_pack_sha3=sd["signed_pack_sha3"].upper())),
                    ("sig-alg-unknown", lambda sd: dict(sd, sig_alg="rsa-pss")),
                    ("pq-alg-int", lambda sd: dict(sd, pq_sig_alg=123)),
                    ("pq-alg-classical", lambda sd: dict(sd, pq_sig_alg="ed25519", pq_public_key_b64=sd["public_key_b64"], pq_signature_b64=sd["signature_b64"]))):
        p = mk(nm); P.sign_pack(p, idt); sp = p[:-5] + ".sig.json"; json.dump(mut(json.load(open(sp))), open(sp, "w"))
        cases[nm] = (p, [], None)
    cases["pq-alg-classical-required"] = (cases["pq-alg-classical"][0], ["--require-pq"], None)
    # council 16/09 r1: sig_alg shapes and a classical-layer sidecar that declares a PQ alg only
    for nm, mut in (("sig-alg-number", lambda sd: dict(sd, sig_alg=5)),
                    ("sig-alg-list", lambda sd: dict(sd, sig_alg=["x"])),
                    ("sig-alg-pq-only", lambda sd: {"signer_id": "acme", "sig_alg": "ml-dsa-65", "signed_pack_sha3": sd["signed_pack_sha3"],
                                                    "public_key_b64": "A" * 2604, "signature_b64": "A" * 4412})):
        p = mk(nm); P.sign_pack(p, idt); sp = p[:-5] + ".sig.json"; json.dump(mut(json.load(open(sp))), open(sp, "w"))
        cases[nm] = (p, [], None)
    un = mk("sig-alg-unknown-sha3-number"); P.sign_pack(un, idt); sp = un[:-5] + ".sig.json"; sd = json.load(open(sp)); sd["sig_alg"] = "rsa-pss"; json.dump(sd, open(sp, "w"))
    dd = json.load(open(un)); dd["pack_sha3"] = 5; json.dump(dd, open(un, "w")); cases["sig-alg-unknown-sha3-number"] = (un, [], None)
    # timestamp sidecar shapes (the token itself is verified by the reference only; shape and binding by all)
    tl = mk("tsr-list"); P.sign_pack(tl, idt); open(tl[:-5] + ".tsr.json", "w").write("[1]"); cases["tsr-list"] = (tl, [], None)
    tm = mk("tsr-mismatch"); P.sign_pack(tm, idt); json.dump({"digest_sha256": "0" * 64, "tsa": "x", "tsr_b64": "AA=="}, open(tm[:-5] + ".tsr.json", "w")); cases["tsr-digest-mismatch"] = (tm, [], None)
    # trust store shapes: a broken chain and a line with a duplicated key (strict profile: refused, never a pin)
    bs = mk("trust-broken"); P.sign_pack(bs, idt); store_b = os.path.join(d, "trust_broken.jsonl"); trust.TrustRegistry(store_b).trust("acme", idt.public_key_b64)
    ln = json.loads(open(store_b).read().splitlines()[0]); ln["ts"] = "1999-01-01T00:00:00Z"; open(store_b, "w").write(json.dumps(ln, separators=(",", ":")) + "\n")
    cases["trust-broken-chain"] = (bs, ["--trust-store", store_b], None)
    dk = mk("trust-dup"); P.sign_pack(dk, other); store_d = os.path.join(d, "trust_dup.jsonl"); trust.TrustRegistry(store_d).trust("acme", idt.public_key_b64)
    txt = open(store_d).read(); txt = txt.replace('"pubkey":"' + idt.public_key_b64 + '"', '"pubkey":"' + idt.public_key_b64 + '","pubkey":"' + other.public_key_b64 + '"', 1)
    e = json.loads(txt); e2 = {k: v for k, v in e.items() if k != "self_hash"}; import hashlib as _h; e["self_hash"] = _h.sha256(json.dumps(e2, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    txt = txt.replace(json.loads(open(store_d).read())["self_hash"], e["self_hash"]); open(store_d, "w").write(txt.rstrip("\n") + "\n")
    cases["trust-dup-key-line"] = (dk, ["--trust-store", store_d], None)
    # council r2: signer_id shapes, duplicated sidecar key, malformed trust records, body tampered after signing
    from omega_evidence.ledger import _hash_entry
    for nm, mut in (("sig-signer-id-list", lambda sd: dict(sd, signer_id=["acme"])),
                    ("sig-signer-id-missing", lambda sd: {k: v for k, v in sd.items() if k != "signer_id"})):
        p = mk(nm); P.sign_pack(p, idt); sp = p[:-5] + ".sig.json"; json.dump(mut(json.load(open(sp))), open(sp, "w"))
        cases[nm] = (p, ["--trust-store", store], None)
    sdk = mk("sig-dup-key"); P.sign_pack(sdk, idt); sp = sdk[:-5] + ".sig.json"; txt = open(sp).read().rstrip().rstrip("}")
    open(sp, "w").write(txt + ', "public_key_b64": "' + other.public_key_b64 + '"}'); cases["sig-dup-key"] = (sdk, [], None)
    def _store_with(name, edit):
        pth = mk(name); P.sign_pack(pth, idt); st_ = os.path.join(d, name + "_trust.jsonl"); trust.TrustRegistry(st_).trust("acme", idt.public_key_b64)
        e = json.loads(open(st_).read().splitlines()[0]); edit(e); e["self_hash"] = _hash_entry(e); open(st_, "w").write(json.dumps(e, separators=(",", ":")) + "\n")
        return pth, st_
    p1, s1 = _store_with("trust-data-list", lambda e: e.__setitem__("data", [1])); cases["trust-data-not-object"] = (p1, ["--trust-store", s1], None)
    p2, s2 = _store_with("trust-sid-list", lambda e: e["data"].__setitem__("signer_id", ["acme"])); cases["trust-signer-id-list"] = (p2, ["--trust-store", s2], None)
    bt = mk("body-tampered"); P.sign_pack(bt, idt); dd = json.load(open(bt)); dd["claim"] = "y"; json.dump(dd, open(bt, "w"))
    cases["body-tampered-trusted"] = (bt, ["--trust-store", store], None)
    # council r3: a REALLY signed uppercase digest + PQ fields of the right length (Python refused the sidecar before
    # the PQ layer -> false; Go/Java/JS reached it -> null); and an unsigned pack with the PQ layer required
    up = mk("upper-signed"); dd = json.load(open(up)); dd["pack_sha3"] = dd["pack_sha3"].upper(); json.dump(dd, open(up, "w")); P.sign_pack(up, idt)
    P.add_pq_signature(up, "ml-dsa-65", base64.b64encode(b"\x01" * 1952).decode(), base64.b64encode(b"\x02" * 3309).decode())
    cases["sig-digest-upper-signed-with-pq"] = (up, [], None)
    cases["unsigned-required-pq"] = (cases["bare"][0], ["--require-pq"], None)
    # honest scope variants and pack shapes — every one ANCHORED with the hash a lenient verifier would accept (review r2,
    # Opus: a bare pack is FAIL whatever the verifier does with floats / duplicate keys / depth / scope, so the case could
    # not fail); hashes computed with json.dumps directly where the toolkit itself refuses the content
    import hashlib as _hs
    def _lax_sha3(dd):
        return _hs.sha3_256(json.dumps({k: v for k, v in dd.items() if k != "pack_sha3"}, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
    def anchor_hash(p, h):
        Ledger(p[:-5] + ".ledger.jsonl").append({"anchored_pack_sha3": h})
    def mk_scope(name, scope):   # build_pack refuses a bad scope: forge it after, with a consistent pack_sha3, anchored
        p = mk(name); dd = json.load(open(p)); dd["honest_scope"] = scope
        dd["pack_sha3"] = canonical.sha3({k: v for k, v in dd.items() if k != "pack_sha3"}); json.dump(dd, open(p, "w")); anchor_hash(p, dd["pack_sha3"]); return p
    cases["scope-note-only"] = (mk_scope("scope-note", "NOTE: this proves everything, cannot fail"), [], None)
    cases["scope-not-accredited"] = (mk_scope("scope-notacc", "NOT accredited; proves integrity only"), [], None)
    cases["scope-certified-overclaim"] = (mk_scope("scope-cert", "fully certified evidence; does NOT prove x"), [], None)
    def mk_hostile(name, mutate, text=None):
        p = mk(name); dd = json.load(open(p)); mutate(dd); h = _lax_sha3(dd); dd["pack_sha3"] = h
        open(p, "w").write(text(dd) if text else json.dumps(dd)); anchor_hash(p, h.lower()); return p
    # duplicate key: the same value twice — a last-wins parser hashes the same content and says PASS
    cases["dup-key"] = (mk_hostile("dupkey", lambda dd: None, text=lambda dd: json.dumps(dd).rstrip().rstrip("}") + ',"n":1}'), [], None)
    cases["float"] = (mk_hostile("float", lambda dd: dd.__setitem__("n", 1.5)), [], None)
    cases["sha3-upper"] = (mk_hostile("upper", lambda dd: None, text=lambda dd: json.dumps(dict(dd, pack_sha3=dd["pack_sha3"].upper()))), [], None)
    deep_v = json.loads("[" * 600 + "]" * 600)
    cases["deep-600"] = (mk_hostile("deep", lambda dd: dd.__setitem__("deep", deep_v)), [], None)
    cases["lone-surrogate"] = (mk_hostile("lone", lambda dd: None, text=lambda dd: json.dumps(dd).rstrip().rstrip("}") + ',"s":"\\ud800"}'), [], None)
    # (lone-surrogate: the hash is over the content WITHOUT "s" — a verifier that keeps the escape hashes differently and
    # says FAIL for the wrong reason; so the anchored hash is computed WITH it, below)
    lone_p = cases["lone-surrogate"][0]; ld = json.load(open(lone_p)); ld["s"] = "\ud800"
    h = _hs.sha3_256(json.dumps({k: v for k, v in ld.items() if k != "pack_sha3"}, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
    ld["pack_sha3"] = h; open(lone_p, "w").write(json.dumps(ld)); open(lone_p[:-5] + ".ledger.jsonl", "w").close(); anchor_hash(lone_p, h)
    # review r3 (Opus): a float LEXEME with an integer value — JSON.parse("1.0") is 1 and Node's canon() could not see it (PASS
    # in Node alone, hashed as "n":1); the honest_scope regexes with Unicode \b / i≡ı folding in Python vs ASCII in the three
    # ("does NOTé" and "certıfied": FAIL in Python, PASS in the three); typed LTV material (an int was a Python traceback)
    def mk_text(name, dd, text):
        p = os.path.join(d, name + ".json"); h = canonical.sha3({k: v for k, v in dd.items() if k != "pack_sha3"})
        open(p, "w", encoding="utf-8").write(text.replace("%H", h)); anchor_hash(p, h); return p
    cases["pack-float-1.0-hashed-as-1"] = (mk_text("f10", {"kind": "d", "honest_scope": "does NOT x", "n": 1}, '{"kind":"d","honest_scope":"does NOT x","n":1.0,"pack_sha3":"%H"}'), [], None)
    cases["pack-exp-1E2-hashed-as-100"] = (mk_text("e12", {"kind": "d", "honest_scope": "does NOT x", "n": 100}, '{"kind":"d","honest_scope":"does NOT x","n":1E2,"pack_sha3":"%H"}'), [], None)
    for nm, scope in (("scope-NOT-before-accented-letter", "does NOT\u00e9 prove x"), ("scope-dotless-i-overclaim", "fully cert\u0131fied; does NOT prove x")):
        dd = {"kind": "d", "honest_scope": scope, "n": 1}
        cases[nm] = (mk_text(nm, dd, json.dumps(dict(dd, pack_sha3="%H"), ensure_ascii=False)), [], None)
    for nm, vm in (("tsr-vm-crls-int", '{"available": true, "crls_b64": 1}'), ("tsr-vm-crls-list-of-int", '{"available": true, "crls_b64": [1]}')):
        tp = mk(nm); P.anchor_pack(tp, tp[:-5] + ".ledger.jsonl"); dg = _hs.sha256(open(tp, "rb").read()).hexdigest()
        open(tp[:-5] + ".tsr.json", "w").write('{"digest_sha256": "%s", "tsa": "x", "tsr_b64": "AA==", "validation_material": %s}' % (dg, vm)); cases[nm] = (tp, [], None)
    # review r4 (Opus): the anchoring rule reads the ENTRY in the three and read `data` in Python (a top-level
    # anchored_pack_sha3: PASS in the three, FAIL in Python; data.data.anchored_pack_sha3: the reverse); a trust-store entry
    # without "data" was skipped by Python and a broken store for the three; Node's `[^.]{0,40}` counted UTF-16 units
    from omega_evidence.ledger import GENESIS as _G, _hash_entry as _he4
    def _entry(idx, prev, extra):
        e = {"idx": idx, "ts": "2026-09-21T00:00:00+00:00", "prev_hash": prev}; e.update(extra); e["self_hash"] = _he4(e); return e
    for nm, mk_extra in (("ledger-anchor-top-level", lambda H: {"data": {}, "anchored_pack_sha3": H}),
                         ("ledger-anchor-under-data-data", lambda H: {"data": {"data": {"anchored_pack_sha3": H}}})):
        ap = mk(nm); H = json.load(open(ap))["pack_sha3"]
        open(ap[:-5] + ".ledger.jsonl", "w").write(json.dumps(_entry(0, _G, mk_extra(H)), separators=(",", ":")) + "\n"); cases[nm] = (ap, [], None)
    tw = mk("trust-no-data"); P.sign_pack(tw, idt); st_w = os.path.join(d, "trust_no_data.jsonl"); trust.TrustRegistry(st_w).trust("acme", idt.public_key_b64)
    e0 = json.loads(open(st_w).read().splitlines()[0]); open(st_w, "a").write(json.dumps(_entry(1, e0["self_hash"], {}), separators=(",", ":")) + "\n")
    cases["trust-entry-without-data"] = (tw, ["--trust-store", st_w], None)
    dd = {"kind": "d", "honest_scope": "guaranteed; does NOT " + "\U0001F600" * 21 + " guarantee x", "n": 1}
    cases["scope-astral-21-between-NOT-and-guarant"] = (mk_text("astral", dd, json.dumps(dict(dd, pack_sha3="%H"), ensure_ascii=False)), [], None)
    bad8 = os.path.join(d, "bad8.json"); open(bad8, "wb").write(b'{"kind":"d","honest_scope":"does NOT x","s":"\xff","pack_sha3":"' + b"0" * 64 + b'"}'); cases["non-utf8"] = (bad8, [], None)   # not JSON anywhere: FAIL at pack-json
    # ledgers
    e = mk("empty-ledger"); open(e[:-5] + ".ledger.jsonl", "w").close(); cases["ledger-empty"] = (e, [], None)
    u = mk("unrelated-ledger"); L = Ledger(u[:-5] + ".ledger.jsonl"); L.append({"anchored_pack_sha3": "0" * 64}); cases["ledger-unrelated"] = (u, [], None)
    tl = mk("tampered-ledger"); P.anchor_pack(tl, tl[:-5] + ".ledger.jsonl"); lines = open(tl[:-5] + ".ledger.jsonl").read().splitlines(); ee = json.loads(lines[0]); ee["ts"] = "1999-01-01T00:00:00Z"; open(tl[:-5] + ".ledger.jsonl", "w").write(json.dumps(ee, separators=(",", ":")) + "\n"); cases["ledger-tampered"] = (tl, [], None)
    fl = mk("float-ledger"); P.anchor_pack(fl, fl[:-5] + ".ledger.jsonl"); ln = json.loads(open(fl[:-5] + ".ledger.jsonl").read().splitlines()[0]); ln["data"]["x"] = 1.5; open(fl[:-5] + ".ledger.jsonl", "w").write(json.dumps(ln, separators=(",", ":")) + "\n"); cases["ledger-float"] = (fl, [], None)
    # 21/09/2026, propagated from the cra-evidence review: an own "__proto__" key added without rehashing (JS dropped it while
    # copying and said PASS alone), a raw non-UTF-8 byte where U+FFFD was hashed (a lossy decoder reads exactly the hashed text:
    # JS and Java said PASS), a raw byte in a key (Python raised UnicodeDecodeError instead of a verdict), a ledger line that is not
    # an object. Every one is FAIL in the four verifiers.
    from omega_evidence.ledger import _hash_entry as _he
    pp = mk("proto-pack"); P.anchor_pack(pp, pp[:-5] + ".ledger.jsonl")   # anchored FIRST: a bare pack is FAIL whatever its hash (review r1, Opus)
    txt = open(pp).read(); open(pp, "w").write('{"__proto__": {"evil": 1}, ' + txt[1:]); cases["pack-proto-key-hash-untouched"] = (pp, [], None)
    pl = mk("proto-ledger"); P.anchor_pack(pl, pl[:-5] + ".ledger.jsonl"); lpp = pl[:-5] + ".ledger.jsonl"; txt = open(lpp).read()
    open(lpp, "w").write('{"__proto__": {"evil": 1}, ' + txt[1:]); cases["ledger-proto-key-hash-untouched"] = (pl, [], None)
    ff = mk("fffd-ledger"); P.anchor_pack(ff, ff[:-5] + ".ledger.jsonl"); lpf = ff[:-5] + ".ledger.jsonl"
    ent = json.loads(open(lpf).read().splitlines()[0]); ent["data"]["note"] = "\ufffd"; ent.pop("self_hash"); ent["self_hash"] = _he(ent)
    open(lpf, "wb").write(json.dumps(ent, ensure_ascii=False, separators=(",", ":")).encode("utf-8").replace("\ufffd".encode("utf-8"), b"\xff", 1) + b"\n")
    cases["ledger-raw-byte-hashed-as-fffd"] = (ff, [], None)
    fp = mk("fffd-pack"); dd = json.load(open(fp)); dd["note"] = "\ufffd"; dd.pop("pack_sha3"); dd["pack_sha3"] = canonical.sha3(dd)
    open(fp, "wb").write(json.dumps(dd, ensure_ascii=False).encode("utf-8").replace("\ufffd".encode("utf-8"), b"\xff", 1))
    Ledger(fp[:-5] + ".ledger.jsonl").append({"anchored_pack_sha3": dd["pack_sha3"]})   # anchored by the hash over U+FFFD: a lossy reader says PASS
    cases["pack-raw-byte-hashed-as-fffd"] = (fp, [], None)
    ls_ = mk("lone-ledger"); P.anchor_pack(ls_, ls_[:-5] + ".ledger.jsonl"); lpl = ls_[:-5] + ".ledger.jsonl"
    ent = json.loads(open(lpl).read().splitlines()[0]); ent["data"]["note"] = "\ud800"; ent.pop("self_hash"); ent["self_hash"] = _he(ent)
    open(lpl, "w").write(json.dumps(ent, separators=(",", ":")) + "\n"); cases["ledger-lone-surrogate-entry"] = (ls_, [], None)   # r2: Python 0.8.2 wrote and accepted it
    rb = mk("raw-ledger"); P.anchor_pack(rb, rb[:-5] + ".ledger.jsonl"); lpr = rb[:-5] + ".ledger.jsonl"; bb = open(lpr, "rb").read()
    open(lpr, "wb").write(bb.replace(b'"ts"', b'"t\xffs"', 1)); cases["ledger-raw-byte-in-key"] = (rb, [], None)
    ll = mk("list-ledger"); P.anchor_pack(ll, ll[:-5] + ".ledger.jsonl"); open(ll[:-5] + ".ledger.jsonl", "w").write("[1]\n"); cases["ledger-line-not-object"] = (ll, [], None)
    # review r1 (Opus, 21/09): a missing --ledger path was an uncaught ENOENT in Node; the .tsr.json sidecar was read with the
    # LOOSE json.loads in Python (a float / duplicate key beside a matching digest: PASS in Python, FAIL in the other three;
    # 100000 "[" a RecursionError traceback); a trust-store line that is not an object raised AttributeError in Python
    import hashlib as _hl
    cases["ledger-path-missing"] = (cases["anchored"][0], ["--ledger", os.path.join(d, "no-such.ledger.jsonl")], None)
    for nm, body in (("tsr-float-beside-good-digest", '{"digest_sha256": "%s", "tsa": "x", "tsr_b64": "AA==", "x": 1.5}'),
                     ("tsr-dup-key-beside-good-digest", '{"digest_sha256": "%s", "digest_sha256": "%s", "tsa": "x", "tsr_b64": "AA=="}'),
                     ("tsr-deep", "[" * 100000)):
        tp = mk(nm); P.anchor_pack(tp, tp[:-5] + ".ledger.jsonl"); dg = _hl.sha256(open(tp, "rb").read()).hexdigest()
        open(tp[:-5] + ".tsr.json", "w").write(body.replace("%s", dg)); cases[nm] = (tp, [], None)
    tn = mk("trust-line-list"); P.sign_pack(tn, idt); st_n = os.path.join(d, "trust_line_list.jsonl"); open(st_n, "w").write(open(store).read() + "[1]\n")
    cases["trust-line-not-object"] = (tn, ["--trust-store", st_n], None)
    cases["cli-eq-form-verdict"] = (cases["anchored"][0], ["--ledger=" + cases["anchored"][0][:-5] + ".ledger.jsonl"], None)   # --flag=value is accepted by all four (argparse and Go flag do natively)
    rot = mk("rotated"); P.sign_pack(rot, idt); store_r = os.path.join(d, "trust_rot.jsonl"); tr2 = trust.TrustRegistry(store_r); tr2.trust("acme", other.public_key_b64); tr2.rotate("acme", idt.public_key_b64)
    cases["trust-rotated"] = (rot, ["--trust-store", store_r], None)
    rev = mk("revoked"); P.sign_pack(rev, idt); store_v = os.path.join(d, "trust_rev.jsonl"); tr3 = trust.TrustRegistry(store_v); tr3.trust("acme", idt.public_key_b64); tr3.revoke("acme", "x")
    cases["trust-revoked"] = (rev, ["--trust-store", store_v], None)
    if HAVE_PQ:
        kf = os.path.join(d, "acme.pq"); mldsa.MlDsaFileSigner.keygen(kf); ps = mldsa.MlDsaFileSigner(kf); K = ps.public_key_b64
        store_h = os.path.join(d, "trust_h.jsonl"); trust.TrustRegistry(store_h).trust("acme", idt.public_key_b64, pq_pubkey=K)
        h = mk("hybrid"); P.sign_pack(h, idt); P.pq_cosign(h, ps)
        JS_NO_PQ = {"js": ("FAIL", False, True)}
        cases["hybrid-unpinned"] = (h, [], None)
        cases["hybrid-registry-required"] = (h, ["--trust-store", store_h, "--require-pq"], JS_NO_PQ)
        cases["hybrid-expected-key"] = (h, ["--expect-pq-key", K], JS_NO_PQ)
        cases["hybrid-edonly-registry-required"] = (h, ["--trust-store", store, "--require-pq"], None)
        st = mk("stripped"); P.sign_pack(st, idt); P.pq_cosign(st, ps); sp = st[:-5] + ".sig.json"; sd = json.load(open(sp)); [sd.pop(k) for k in ("pq_sig_alg", "pq_public_key_b64", "pq_signature_b64")]; json.dump(sd, open(sp, "w"))
        cases["hybrid-stripped-required"] = (st, ["--expect-pq-key", K], None)
        kf2 = os.path.join(d, "other.pq"); mldsa.MlDsaFileSigner.keygen(kf2); fo = mk("foreign"); P.sign_pack(fo, idt); P.pq_cosign(fo, mldsa.MlDsaFileSigner(kf2))
        cases["hybrid-foreign-key"] = (fo, ["--expect-pq-key", K], None)
        bp = mk("badpq"); P.sign_pack(bp, idt); P.pq_cosign(bp, ps); sp = bp[:-5] + ".sig.json"; sd = json.load(open(sp)); raw = bytearray(base64.b64decode(sd["pq_signature_b64"])); raw[5] ^= 1; sd["pq_signature_b64"] = base64.b64encode(bytes(raw)).decode(); json.dump(sd, open(sp, "w"))
        cases["hybrid-bad-pq"] = (bp, [], {"js": ("PASS", None, True)})
        # council 16/09 r1: a FOREIGN Ed25519 key under a trusted signer_id must not borrow that signer's PQ pin
        fe = mk("foreign-ed"); P.sign_pack(fe, signing.Identity("acme")); P.pq_cosign(fe, ps)
        cases["hybrid-foreign-classical-key"] = (fe, ["--trust-store", store_h], None)
        cases["hybrid-foreign-classical-key-required"] = (fe, ["--trust-store", store_h, "--require-pq"], None)
        # a revoked hybrid signer: never authenticated, never pq-protected through the registry
        store_hr = os.path.join(d, "trust_hr.jsonl"); thr = trust.TrustRegistry(store_hr); thr.trust("acme", idt.public_key_b64, pq_pubkey=K); thr.revoke("acme", "x")
        cases["hybrid-revoked-required"] = (h, ["--trust-store", store_hr, "--require-pq"], None)
        # rotation of the classical key KEEPS the PQ pin (recorded in the ledger, so every replay agrees) unless dropped
        store_rk = os.path.join(d, "trust_rk.jsonl"); trk = trust.TrustRegistry(store_rk); trk.trust("acme", other.public_key_b64, pq_pubkey=K); trk.rotate("acme", idt.public_key_b64)
        cases["hybrid-rotated-keeps-pq-required"] = (h, ["--trust-store", store_rk, "--require-pq"], JS_NO_PQ)
        store_rd = os.path.join(d, "trust_rd.jsonl"); trd = trust.TrustRegistry(store_rd); trd.trust("acme", other.public_key_b64, pq_pubkey=K); trd.rotate("acme", idt.public_key_b64, drop_pq=True)
        cases["hybrid-rotated-dropped-pq-required"] = (h, ["--trust-store", store_rd, "--require-pq"], None)
        cases["hybrid-bad-pq-required"] = (bp, ["--expect-pq-key", K], None)
        sw = mk("pq-space"); P.sign_pack(sw, idt); P.pq_cosign(sw, ps); sp = sw[:-5] + ".sig.json"; sd = json.load(open(sp)); sd["pq_signature_b64"] = sd["pq_signature_b64"][:6] + " " + sd["pq_signature_b64"][6:]; json.dump(sd, open(sp, "w"))
        cases["hybrid-pq-lenient-base64"] = (sw, [], None)
    else:
        print("  hybrid (ML-DSA-65) cases NOT measured: cryptography >= 48 absent")
    return cases


def run(cmd, path, flags, go_style):
    args = list(cmd) + ([f.replace("--", "-", 1) for f in flags] + [path] if go_style else [path] + flags)
    try:
        out = subprocess.run(args, capture_output=True, text=True, timeout=60)
        r = json.loads(out.stdout)
        return (r["verdict"], r.get("pq_protected"), r.get("authenticated"))
    except Exception:  # noqa: BLE001
        return ("NONJSON/CRASH", None, None)


def main():
    avail = {"python": [sys.executable, "-m", "omega_evidence"], "js": ["node", os.path.join(HERE, "js", "oeverify.mjs")]}
    tmp = tempfile.mkdtemp()
    go = os.environ.get("OEVERIFY_GO")
    if not go and shutil.which("go"):
        b = os.path.join(tmp, "oeverify")
        if subprocess.run(["go", "build", "-o", b, "./cmd/oeverify"], cwd=os.path.join(HERE, "go"), capture_output=True).returncode == 0:
            go = b
    if go:
        avail["go"] = [go]
    else:
        print("  go verifier NOT measured (no OEVERIFY_GO and no Go toolchain)")
    java = os.environ.get("OEVERIFY_JAVA")
    if not java:
        for bdir in [os.path.join(os.environ.get("JAVA_HOME", ""), "bin")] + sorted(glob.glob(os.path.expanduser("~/.local/jdk/jdk-*/bin")), reverse=True) + [os.path.dirname(shutil.which("javac") or "/x/javac")]:
            javac = os.path.join(bdir, "javac")
            if os.path.exists(javac):
                ver = subprocess.run([os.path.join(bdir, "java"), "-version"], capture_output=True, text=True).stderr
                try:
                    major = int(ver.split('"')[1].split(".")[0])
                except Exception:  # noqa: BLE001
                    continue
                if major < 24:
                    continue
                out = os.path.join(tmp, "oej")
                if subprocess.run([javac, "-d", out, os.path.join(HERE, "java", "OeVerify.java")], capture_output=True).returncode == 0:
                    java = f"{os.path.join(bdir, 'java')} -cp {out} OeVerify"
                    break
    if java:
        avail["java"] = java.split()
    else:
        print("  java verifier NOT measured (no OEVERIFY_JAVA and no JDK >= 24)")
    if not shutil.which("node"):
        del avail["js"]
        print("  js verifier NOT measured (no node)")
    print(f"differential oracle over {len(avail)} pack verifiers: {sorted(avail)}")
    cases = build_cases(tmp)
    diffs = declared = 0
    for name, (path, flags, decl) in cases.items():
        res = {k: run(cmd, path, flags, k in ("go", "java")) for k, cmd in avail.items()}
        ref = res.get("python")
        bad = {k: v for k, v in res.items() if v != ref}
        if bad and decl and all(k in decl and decl[k] == v for k, v in bad.items()):
            declared += 1
            print(f"  [DECL] {name:34} {res}  <- declared: this Node has no ML-DSA (OpenSSL < 3.5)")
            continue
        if bad:
            diffs += 1
        print(f"  [{'OK ' if not bad else 'DIFF'}] {name:34} {res}")
    # CLI grammar (21/09/2026, found on cra-evidence): an unknown flag, a value flag without a value / with "" / with a flag as
    # value, an abbreviation, a second positional = usage error (exit 2, no verdict) in EVERY CLI — never a verdict with the
    # constraint silently dropped (Node gave a verdict on all of them)
    valid = cases["bare"][0]
    cli = {"cli-unknown-flag": ["--no-such-flag"], "cli-ledger-empty": ["--ledger", ""], "cli-ledger-missing-value": ["--ledger"],
           "cli-ledger-flag-as-value": ["--ledger", "--require-pq"], "cli-abbreviation": ["--ledg", valid], "cli-two-positionals": [valid],
           # review r1 (Opus): the pack path itself "" or "-" (an unset $PACK), the "--" terminator, a value on the boolean flag
           "cli-empty-pack": ["--pack", ""], "cli-dash-pack": ["--pack", "-"], "cli-double-dash": ["--"], "cli-bool-eq-false": ["--require-pq=false"],
           "cli-help": ["--help"], "cli-h": ["-h"]}   # r3 (Sonnet): argparse answered --help with exit 0 while the three said usage
    cli["cli-other-dash-spelling-verdict"] = ["--other-dash"]   # r4 (Sonnet): -ledger in Python/Node, --ledger in Go/Java → a verdict, the same flag
    for name, extra in cli.items():
        row = {}
        for k, cmd in avail.items():
            gs = k in ("go", "java")
            ex = [(a.replace("--", "-", 1) if gs and a.startswith("--") and a != "--" else a) for a in extra]   # the exact "--" is sent as is (r2: Sonnet/Opus)
            # Go/Java take flags before the positional: a bare value flag is run LAST with nothing after it (otherwise the
            # pack path would be eaten as its value and the usage error would come from the missing positional — review
            # 21/09, Sonnet); there the missing-value path is the flag library's own ("flag needs an argument") and Java's
            # bounds guard, while the "" and flag-as-value cases are the ones that exercise flag.Visit / val()
            if gs and name == "cli-ledger-missing-value":
                args = list(cmd) + ex
            elif extra[0] == "--pack":   # the positional itself is the hostile value ("--pack" is a marker of this table, not a flag)
                args = list(cmd) + [extra[1]]
            elif extra[0] == "--other-dash":
                lp_ = cases["anchored"][0][:-5] + ".ledger.jsonl"; ap_ = cases["anchored"][0]
                args = list(cmd) + (["--ledger", lp_, ap_] if gs else [ap_, "-ledger", lp_])
            else:
                args = list(cmd) + (ex + [valid] if gs else [valid] + ex)
            try:
                out = subprocess.run(args, capture_output=True, text=True, timeout=60)
                try:
                    row[k] = "verdict:" + str(json.loads(out.stdout).get("verdict"))
                except Exception:  # noqa: BLE001
                    row[k] = "usage" if out.returncode == 2 else f"exit{out.returncode}"
            except Exception:  # noqa: BLE001
                row[k] = "CRASH"
        want = "verdict:PASS" if name.endswith("-verdict") else "usage"
        ok = all(v == want for v in row.values())
        if not ok:
            diffs += 1
        print(f"  [{'OK ' if ok else 'DIFF'}] {name:34} expect {want if want != 'usage' else 'usage(exit 2)'}: {row}")
    print(f"disagreements: {diffs}/{len(cases) + len(cli)} (declared Node divergences: {declared})")
    shutil.rmtree(tmp, ignore_errors=True)
    return 1 if diffs else 0


if __name__ == "__main__":
    sys.exit(main())
