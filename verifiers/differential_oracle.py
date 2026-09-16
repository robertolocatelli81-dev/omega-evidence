#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Differential oracle over the omega-evidence PACK verifiers: the Python reference (python -m omega_evidence), Go
(OEVERIFY_GO or built from verifiers/go), Java (OEVERIFY_JAVA or compiled from verifiers/java with a JDK >= 24) and
Node (verifiers/js/oeverify.mjs) must give the same (verdict, pq_protected, authenticated) on every case — except the declared
Node divergences (Node has no ML-DSA: a REQUIRED post-quantum layer is FAIL there, an INVALID ML-DSA co-signature is
not detectable there). Cases are generated with the toolkit itself; ML-DSA cases need cryptography >= 48 (skipped
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
    # honest scope variants
    def mk_scope(name, scope):   # build_pack refuses a bad scope: forge it after, with a consistent pack_sha3
        p = mk(name); dd = json.load(open(p)); dd["honest_scope"] = scope
        dd["pack_sha3"] = canonical.sha3({k: v for k, v in dd.items() if k != "pack_sha3"}); json.dump(dd, open(p, "w")); return p
    cases["scope-note-only"] = (mk_scope("scope-note", "NOTE: this proves everything, cannot fail"), [], None)
    cases["scope-not-accredited"] = (mk_scope("scope-notacc", "NOT accredited; proves integrity only"), [], None)
    cases["scope-certified-overclaim"] = (mk_scope("scope-cert", "fully certified evidence; does NOT prove x"), [], None)
    # pack shapes
    dup = os.path.join(d, "dupkey.json"); open(dup, "w").write(open(cases["bare"][0]).read().rstrip().rstrip("}") + ',"n":1}'); cases["dup-key"] = (dup, [], None)
    flt = os.path.join(d, "float.json"); dd = json.load(open(cases["bare"][0])); dd["n"] = 1.5; json.dump(dd, open(flt, "w")); cases["float"] = (flt, [], None)
    up = os.path.join(d, "upper.json"); dd = json.load(open(cases["bare"][0])); dd["pack_sha3"] = dd["pack_sha3"].upper(); json.dump(dd, open(up, "w")); cases["sha3-upper"] = (up, [], None)
    deep = os.path.join(d, "deep.json"); open(deep, "w").write('{"kind":"d","honest_scope":"does NOT x","deep":' + "[" * 600 + "]" * 600 + ',"pack_sha3":"' + "0" * 64 + '"}'); cases["deep-600"] = (deep, [], None)
    lone = os.path.join(d, "lone.json"); open(lone, "w").write('{"kind":"d","honest_scope":"does NOT x","s":"\\ud800","pack_sha3":"' + "0" * 64 + '"}'); cases["lone-surrogate"] = (lone, [], None)
    bad8 = os.path.join(d, "bad8.json"); open(bad8, "wb").write(b'{"kind":"d","honest_scope":"does NOT x","s":"\xff","pack_sha3":"' + b"0" * 64 + b'"}'); cases["non-utf8"] = (bad8, [], None)
    # ledgers
    e = mk("empty-ledger"); open(e[:-5] + ".ledger.jsonl", "w").close(); cases["ledger-empty"] = (e, [], None)
    u = mk("unrelated-ledger"); L = Ledger(u[:-5] + ".ledger.jsonl"); L.append({"anchored_pack_sha3": "0" * 64}); cases["ledger-unrelated"] = (u, [], None)
    tl = mk("tampered-ledger"); P.anchor_pack(tl, tl[:-5] + ".ledger.jsonl"); lines = open(tl[:-5] + ".ledger.jsonl").read().splitlines(); ee = json.loads(lines[0]); ee["ts"] = "1999-01-01T00:00:00Z"; open(tl[:-5] + ".ledger.jsonl", "w").write(json.dumps(ee, separators=(",", ":")) + "\n"); cases["ledger-tampered"] = (tl, [], None)
    fl = mk("float-ledger"); P.anchor_pack(fl, fl[:-5] + ".ledger.jsonl"); ln = json.loads(open(fl[:-5] + ".ledger.jsonl").read().splitlines()[0]); ln["data"]["x"] = 1.5; open(fl[:-5] + ".ledger.jsonl", "w").write(json.dumps(ln, separators=(",", ":")) + "\n"); cases["ledger-float"] = (fl, [], None)
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
            print(f"  [DECL] {name:34} {res}  <- declared: Node has no ML-DSA")
            continue
        if bad:
            diffs += 1
        print(f"  [{'OK ' if not bad else 'DIFF'}] {name:34} {res}")
    print(f"disagreements: {diffs}/{len(cases)} (declared Node divergences: {declared})")
    shutil.rmtree(tmp, ignore_errors=True)
    return 1 if diffs else 0


if __name__ == "__main__":
    sys.exit(main())
