#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""Generative, DIFFERENTIAL bench for the closed schemas of 2026-10-10 (README «closed sidecars and ledger entries») across
the four pack verifiers: Python reference (python -m omega_evidence), Go, Java and Node.

Method: the expected class of every mutation comes from the README's rule, never from a verifier; each mutation is fed to
every verifier that builds here, and three things must hold — (1) every verifier gives the class the rule prescribes,
(2) all verifiers AGREE on (verdict, authenticated), (3) a key nobody defined is NAMED in the detail of the layer that
reads the object (producer-signature, timestamp — `rfc3161` in Python —, ledger-chain), and a body key of the pack is
LISTED in the pack-fields layer by all four.

Mutation classes and the rule behind each expected class:
  sig_unknown / sig_unknown_multi      .sig.json key nobody defined → FAIL, named (SIG_SIDECAR_KEYS)
  sig_legacy_absent                    fingerprint / signed_utc removed (legacy sidecar) → PASS (the rule must not reject too much)
  sig_dup_key                          duplicate key in the sidecar text → FAIL (strict acceptance profile)
  tsr_unknown                          .tsr.json key nobody defined, digest bound → FAIL, named (TSR_SIDECAR_KEYS)
  tsr_known_all                        every key of the closed list → the source's verdict (PASS)
  tsr_digest_mismatch                  → FAIL (pack changed after stamping)
  ledger_unknown / ledger_unknown_all  entry top-level key nobody defined, self_hash recomputed → FAIL, named (LEDGER_ENTRY_KEYS)
  ledger_unknown_in_data               the same key inside data → PASS
  ledger_unknown_no_rehash             → FAIL (broken chain; naming not required)
  ledger_anchor_fields_top_level       anchored_pack_sha3 + anchored_utc at the top level → PASS (in the closed list)
  pack_body_unknown                    a producer-written body key → PASS, LISTED in pack-fields by all four

Usage: python3 closed_schema_mutants.py [--quick | --n N] [--seed S] [--tree DIR] [--only python,js,go,java] [--js PATH] [--out F]
  --tree points the bench at ANOTHER copy of the repository (positive control: the tree before the alignment must go red);
  --js overrides the Node verifier path (the CI test points it at a lax copy: the bench must go red).
Exit 0 = every mutation in class, every verifier agreeing, every foreign key named; 1 otherwise."""
import argparse
import glob
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_TREE = os.path.dirname(HERE)
sys.path.insert(0, DEFAULT_TREE)
from omega_evidence import pack as P, signing  # noqa: E402
from omega_evidence.ledger import _hash_entry  # noqa: E402

# the closed lists, copied from the README (not read from a verifier)
SIG_KEYS = ("signer_id", "sig_alg", "public_key_b64", "fingerprint", "signed_pack_sha3", "signature_b64", "signed_utc", "pq_sig_alg", "pq_public_key_b64", "pq_signature_b64")
TSR_KEYS = ("digest_sha256", "tsa", "tsr_b64", "stamped_utc", "validation_material")
ENTRY_KEYS = ("idx", "ts", "data", "prev_hash", "self_hash", "anchored_pack_sha3", "anchored_utc")
FORMAT_KEYS = ("kind", "generated_utc", "honest_scope", "pack_sha3")
SCOPE = "Proves integrity; does NOT prove the claim."
KNOWN = set(SIG_KEYS) | set(TSR_KEYS) | set(ENTRY_KEYS) | set(FORMAT_KEYS)

KNOWN_VARIANTS = ["Signer_id", "SIG_ALG", "signature_b64 ", " signer_id", "digest_SHA256", "Idx", "anchored_pack_sha3_", "pq_signature", "signatures", "tsa_url"]
JS_SPECIAL = ["__proto__", "constructor", "prototype", "toString", "hasOwnProperty", "valueOf"]
UNICODE_KEYS = ["clé", "ключ", "鍵", "\U0001F511", "ﬁeld", " "]
ODD_KEYS = ["", "0", "-1", "a b", "data.x", "a\"b", "a\\b", "a\nb", "\u0000", "x" * 40, "layer", "verdict"]


def rand_key(rng):
    pool = rng.choice([KNOWN_VARIANTS, JS_SPECIAL, UNICODE_KEYS, ODD_KEYS, None, None])
    k = rng.choice(pool) if pool else "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789_") for _ in range(rng.randint(1, 12)))
    return k if k not in KNOWN else k + "_x"


def rand_value(rng, depth=0):
    c = rng.randint(0, 7 if depth < 2 else 4)
    if c == 0:
        return None
    if c == 1:
        return rng.choice([True, False])
    if c == 2:
        return rng.choice([0, -1, 1, 2 ** 53 - 1, rng.randint(-10 ** 6, 10 ** 6)])
    if c in (3, 4):
        return rng.choice(["", "x", "é", "a\"b", "日本", "\U0001F600", "0" * 64])
    if c == 5:
        return [rand_value(rng, depth + 1) for _ in range(rng.randint(0, 3))]
    return {rand_key(rng): rand_value(rng, depth + 1) for _ in range(rng.randint(0, 3))}


# ---------------------------------------------------------------- sources: directories with pack + sidecars + ledger
def make_sources(root):
    """name -> directory holding pack.json (+ .sig.json / .tsr.json / .ledger.jsonl). All PASS as produced."""
    idt = signing.Identity("acme")
    out = {}
    def mk(name, body, sign=True, tsr=False):
        d = os.path.join(root, name); os.makedirs(d)
        p = os.path.join(d, "pack.json")
        P.write_pack(p, P.build_pack("demo", body, SCOPE)); P.anchor_pack(p, p[:-5] + ".ledger.jsonl")
        if sign:
            P.sign_pack(p, idt)
        if tsr:
            dg = hashlib.sha256(open(p, "rb").read()).hexdigest()
            with open(p[:-5] + ".tsr.json", "w", encoding="utf-8") as f:
                json.dump({"digest_sha256": dg, "tsa": "x", "tsr_b64": "AA==", "stamped_utc": "2026-10-11T00:00:00+00:00"}, f)
        out[name] = d
    mk("signed-anchored", {"claim": "x", "n": 1})
    mk("signed-anchored-tsr", {"claim": "y", "u": "ünï ✓"}, tsr=True)
    mk("anchored-only", {"claim": "z", "records": [{"a": 1}]}, sign=False)
    mk("signed-anchored-nested", {"claim": {"deep": {"k": [1, None, True]}}}, tsr=True)
    return out


def copy_source(src, dst):
    shutil.copytree(src, dst)
    return os.path.join(dst, "pack.json")


def edit_json(path, fn):
    with open(path, encoding="utf-8") as f:
        o = json.load(f)
    fn(o)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(o, f, ensure_ascii=False)


def rechain(lp, fn):
    with open(lp, encoding="utf-8") as f:
        es = [json.loads(ln) for ln in f if ln.strip()]
    fn(es)
    prev = None
    for e in es:
        e.pop("self_hash", None)
        if prev is not None:
            e["prev_hash"] = prev
        e["self_hash"] = _hash_entry(e); prev = e["self_hash"]
    with open(lp, "w", encoding="utf-8") as f:
        f.write("".join(json.dumps(e, ensure_ascii=False, separators=(",", ":")) + "\n" for e in es))


# ---------------------------------------------------------------- mutations: (class_name, expected, named_layer, named_text)
def m_sig_unknown(rng, p, has_sig, has_tsr):
    if not has_sig:
        return None
    k = rand_key(rng); edit_json(p[:-5] + ".sig.json", lambda sd: sd.__setitem__(k, rand_value(rng)))
    return "sig_unknown", "FAIL", "producer-signature", "outside the closed schema: " + k


def m_sig_unknown_multi(rng, p, has_sig, has_tsr):
    if not has_sig:
        return None
    ks = []
    while len(ks) < rng.randint(2, 3):
        k = rand_key(rng)
        if k not in ks:
            ks.append(k)
    if sum(len(k) + 2 for k in ks) > 118:
        return None
    edit_json(p[:-5] + ".sig.json", lambda sd: [sd.__setitem__(k, rand_value(rng)) for k in ks])
    return "sig_unknown_multi", "FAIL", "producer-signature", "outside the closed schema: " + ", ".join(sorted(ks))


def m_sig_legacy_absent(rng, p, has_sig, has_tsr):
    if not has_sig:
        return None
    drop = rng.choice([["fingerprint"], ["signed_utc"], ["fingerprint", "signed_utc"]])
    edit_json(p[:-5] + ".sig.json", lambda sd: [sd.pop(k, None) for k in drop])
    return "sig_legacy_absent", "PASS", None, None


def m_sig_dup_key(rng, p, has_sig, has_tsr):
    if not has_sig:
        return None
    sp = p[:-5] + ".sig.json"
    with open(sp, encoding="utf-8") as f:
        txt = f.read().rstrip().rstrip("}")
    k = rng.choice(["signer_id", "sig_alg", "signed_utc"])
    with open(sp, "w", encoding="utf-8") as f:
        f.write(txt + ', "%s": "dup"}' % k)
    return "sig_dup_key", "FAIL", None, None


def _tsr_write(p, extra, bad_digest=False):
    dg = hashlib.sha256(open(p, "rb").read()).hexdigest()
    side = {"digest_sha256": ("0" * 64 if bad_digest else dg), "tsa": "x", "tsr_b64": "AA==", "stamped_utc": "2026-10-11T00:00:00+00:00"}
    side.update(extra)
    with open(p[:-5] + ".tsr.json", "w", encoding="utf-8") as f:
        json.dump(side, f, ensure_ascii=False)


def m_tsr_unknown(rng, p, has_sig, has_tsr):
    k = rand_key(rng); _tsr_write(p, {k: rand_value(rng)})
    return "tsr_unknown", "FAIL", "timestamp", "outside the closed schema: " + k


def m_tsr_known_all(rng, p, has_sig, has_tsr):
    _tsr_write(p, {"validation_material": {"available": False}})
    return "tsr_known_all", "PASS", None, None


def m_tsr_digest_mismatch(rng, p, has_sig, has_tsr):
    _tsr_write(p, {}, bad_digest=True)
    return "tsr_digest_mismatch", "FAIL", None, None


def m_ledger_unknown(rng, p, has_sig, has_tsr):
    k = rand_key(rng); lp = p[:-5] + ".ledger.jsonl"
    rechain(lp, lambda es: es[rng.randrange(len(es))].__setitem__(k, rand_value(rng)))
    return "ledger_unknown", "FAIL", "ledger-chain", "outside the closed schema, first at idx 0: " + k


def m_ledger_unknown_all(rng, p, has_sig, has_tsr):
    ks = sorted({rand_key(rng), rand_key(rng)}); lp = p[:-5] + ".ledger.jsonl"
    rechain(lp, lambda es: [e.__setitem__(k, 1) for e in es for k in ks])
    return "ledger_unknown_all", "FAIL", "ledger-chain", "outside the closed schema, first at idx 0: " + ", ".join(ks)


def m_ledger_unknown_in_data(rng, p, has_sig, has_tsr):
    k = rand_key(rng); lp = p[:-5] + ".ledger.jsonl"
    rechain(lp, lambda es: es[0].setdefault("data", {}).__setitem__(k, rand_value(rng)) if isinstance(es[0].get("data"), dict) else None)
    return "ledger_unknown_in_data", "PASS", None, None


def m_ledger_unknown_no_rehash(rng, p, has_sig, has_tsr):
    k = rand_key(rng); lp = p[:-5] + ".ledger.jsonl"
    with open(lp, encoding="utf-8") as f:
        es = [json.loads(ln) for ln in f if ln.strip()]
    es[0][k] = "x"
    with open(lp, "w", encoding="utf-8") as f:
        f.write("".join(json.dumps(e, ensure_ascii=False, separators=(",", ":")) + "\n" for e in es))
    return "ledger_unknown_no_rehash", "FAIL", None, None


def m_ledger_anchor_fields_top_level(rng, p, has_sig, has_tsr):
    with open(p, encoding="utf-8") as f:
        H = json.load(f)["pack_sha3"]
    e0 = {"idx": 0, "ts": "2026-10-11T00:00:00+00:00", "data": {}, "prev_hash": "0" * 64, "anchored_pack_sha3": H, "anchored_utc": "2026-10-11T00:00:00+00:00"}
    e0["self_hash"] = _hash_entry(e0)
    with open(p[:-5] + ".ledger.jsonl", "w", encoding="utf-8") as f:
        f.write(json.dumps(e0, separators=(",", ":")) + "\n")
    return "ledger_anchor_fields_top_level", "PASS", None, None


def m_ledger_dup_key(rng, p, has_sig, has_tsr):
    lp = p[:-5] + ".ledger.jsonl"
    with open(lp, encoding="utf-8") as f:
        lines = f.read().splitlines()
    lines[0] = lines[0].rstrip().rstrip("}") + ',"ts":"dup"}'
    with open(lp, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return "ledger_dup_key", "FAIL", None, None


def m_pack_body_unknown(rng, p, has_sig, has_tsr):
    """A producer-written body key: rebuilt from scratch (anchored, signed like the source) — reported, never refused."""
    k = rand_key(rng)
    d = os.path.dirname(p)
    for f_ in os.listdir(d):
        os.remove(os.path.join(d, f_))
    P.write_pack(p, P.build_pack("demo", {"claim": "x", k: rand_value(rng)}, SCOPE)); P.anchor_pack(p, p[:-5] + ".ledger.jsonl")
    if has_sig:
        P.sign_pack(p, signing.Identity("acme"))
    return "pack_body_unknown", "PASS", "pack-fields", k


MAKERS = [m_sig_unknown, m_sig_unknown_multi, m_sig_legacy_absent, m_sig_dup_key, m_tsr_unknown, m_tsr_known_all, m_tsr_digest_mismatch,
          m_ledger_unknown, m_ledger_unknown_all, m_ledger_unknown_in_data, m_ledger_unknown_no_rehash, m_ledger_anchor_fields_top_level,
          m_ledger_dup_key, m_pack_body_unknown]


# ---------------------------------------------------------------- the verifiers of a tree
def find_java():
    cands = []
    if os.environ.get("JAVA_HOME"):
        cands.append(os.path.join(os.environ["JAVA_HOME"], "bin"))
    if shutil.which("javac"):
        cands.append(os.path.dirname(shutil.which("javac")))
    cands += sorted(glob.glob(os.path.expanduser("~/.local/jdk/jdk-*/bin")), reverse=True)
    best = None
    for b in cands:
        javac, java = os.path.join(b, "javac"), os.path.join(b, "java")
        if not (os.path.exists(javac) and os.path.exists(java)):
            continue
        try:
            ver = subprocess.run([java, "-version"], capture_output=True, text=True, timeout=30).stderr
            major = int(ver.split('"')[1].split(".")[0]) if '"' in ver else 0
        except Exception:  # noqa: BLE001
            continue
        if best is None or major > best[0]:
            best = (major, javac, java)
    return best


def discover(tree, tmp, only=None, js_override=None):
    """name -> (cmd, cwd). Python runs `-m omega_evidence` from the tree (so THAT tree's package is the one measured)."""
    v = {"python": ([sys.executable, "-m", "omega_evidence"], tree),
         "js": (["node", js_override or os.path.join(tree, "verifiers", "js", "oeverify.mjs")], None)}
    if shutil.which("go"):
        out = os.path.join(tmp, "oeverify-go")
        r = subprocess.run(["go", "build", "-o", out, "./cmd/oeverify"], cwd=os.path.join(tree, "verifiers", "go"), capture_output=True, text=True)
        if r.returncode != 0:
            raise SystemExit("go build failed: " + r.stderr[:400])
        v["go"] = ([out], None)
    jdk = find_java()
    if jdk:
        out = os.path.join(tmp, "oej")
        r = subprocess.run([jdk[1], "-d", out, os.path.join(tree, "verifiers", "java", "OeVerify.java")], capture_output=True, text=True, timeout=180)
        if r.returncode != 0:
            raise SystemExit("javac failed: " + r.stderr[:400])
        v["java"] = ([jdk[2], "-cp", out, "OeVerify"], None)
    if only:
        v = {k: x for k, x in v.items() if k in only}
    return v


def run_one(cmd, cwd, path):
    try:
        out = subprocess.run(cmd + [path], capture_output=True, text=True, timeout=120, cwd=cwd)
        r = json.loads(out.stdout)
    except Exception:  # noqa: BLE001
        return ("NONJSON/CRASH", None), None
    return (r.get("verdict", "NOVERDICT"), r.get("authenticated")), r


def layer_detail(receipt, layer):
    for ly in receipt.get("layers", []):
        name = ly.get("layer")
        if name == layer or (layer == "timestamp" and name == "rfc3161"):   # Python's name for the RFC 3161 layer
            return ly.get("detail") or ""
    return ""


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--n", type=int, default=None, help="number of mutations (default 800; --quick = 100)")
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--seed", type=int, default=20261011)
    ap.add_argument("--tree", default=DEFAULT_TREE)
    ap.add_argument("--only", default=None)
    ap.add_argument("--js", default=None)
    ap.add_argument("--out", default=None)
    ap.add_argument("--keep", action="store_true")
    a = ap.parse_args(argv)
    n = a.n or (100 if a.quick else 800)
    rng = random.Random(a.seed)
    tmp = tempfile.mkdtemp(prefix="oe-closed-mutants-")
    try:
        srcs = make_sources(os.path.join(tmp, "src"))
        verifiers = discover(os.path.abspath(a.tree), tmp, set(a.only.split(",")) if a.only else None, a.js)
        print(f"closed-schema bench (omega-evidence): {n} mutations from {len(srcs)} sources, seed {a.seed}, tree {a.tree}")
        print(f"verifiers: {sorted(verifiers)}")
        out_of_class = {k: 0 for k in verifiers}; silent = {k: 0 for k in verifiers}; unnamed = {k: 0 for k in verifiers}
        disagree = 0; per_class = {}; failures = []
        made, i = 0, 0
        while made < n:
            maker = MAKERS[i % len(MAKERS)]; i += 1
            src_name, src_dir = rng.choice(list(srcs.items()))
            case_dir = os.path.join(tmp, "m%d" % made)
            p = copy_source(src_dir, case_dir)
            has_sig = os.path.exists(p[:-5] + ".sig.json"); has_tsr = os.path.exists(p[:-5] + ".tsr.json")
            r = maker(rng, p, has_sig, has_tsr)
            if r is None:
                shutil.rmtree(case_dir, ignore_errors=True)
                continue
            cls, expected, layer, text = r
            name = f"{cls}@{src_name}#{made}"
            made += 1
            res = {k: run_one(cmd, cwd, p) for k, (cmd, cwd) in verifiers.items()}
            tuples = {k: t for k, (t, _) in res.items()}
            pc = per_class.setdefault(cls, {"n": 0, "bad": 0}); pc["n"] += 1
            bad = False
            if len(set(tuples.values())) != 1:
                disagree += 1; bad = True
            for k, (t, rec) in res.items():
                if t[0] != expected:
                    out_of_class[k] += 1; bad = True
                    if expected == "FAIL" and t[0] == "PASS":
                        silent[k] += 1
                if layer and (rec is None or text not in layer_detail(rec, layer)):
                    unnamed[k] += 1; bad = True
            if bad:
                pc["bad"] += 1
                if len(failures) < 40:
                    failures.append({"mutation": name, "expected": expected, "results": {k: list(t) for k, t in tuples.items()}, "named": [layer, text],
                                     "details": {k: layer_detail(rec, layer) for k, (_, rec) in res.items() if rec and layer}})
            if not a.keep:
                shutil.rmtree(case_dir, ignore_errors=True)
        summary = {"mutations": n, "sources": len(srcs), "seed": a.seed, "tree": os.path.abspath(a.tree), "verifiers": sorted(verifiers),
                   "disagreements": disagree, "out_of_class": out_of_class, "silent_pass_on_expected_fail": silent, "unnamed_foreign_key": unnamed,
                   "per_class": per_class, "first_failures": failures}
        print(json.dumps({k: v for k, v in summary.items() if k != "first_failures"}, indent=1, ensure_ascii=False))
        for f_ in failures[:12]:
            print("  [BAD]", f_["mutation"], "expected", f_["expected"], f_["results"], "named", f_["named"])
        if a.out:
            with open(a.out, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=1, ensure_ascii=False)
        ok = disagree == 0 and not any(out_of_class.values()) and not any(unnamed.values())
        print("RESULT:", "GREEN" if ok else "RED")
        if a.keep:
            print("corpus kept in", tmp)
        return 0 if ok else 1
    finally:
        if not a.keep:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
