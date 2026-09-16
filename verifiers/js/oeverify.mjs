// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Roberto Locatelli
//
// oeverify.mjs — independent Node (stdlib) verifier of omega-evidence packs (0.7.0): the same layers as the
// Python reference and the Go/Java verifiers — strict JSON acceptance profile, honest-scope, pack-sha3 (canonical
// JSON without pack_sha3, SHA3-256), ledger-chain with the dedicated anchored_pack_sha3 entry, Ed25519 producer
// signature over the pack_sha3 hex bytes, trust registry replay, authenticity. The ML-DSA-65 co-signature is NOT
// verified here (Node/OpenSSL 3.5 has no ML-DSA): a present layer is reported null (unverified), never true.
// Usage: node oeverify.mjs <pack.json> [--ledger L] [--trust-store T] [--expect-pq-key B64] [--require-pq]
import { createHash, createPublicKey, verify as edVerify } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";



function pyEscape(s) {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i), ch = s[i];
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch === "\t") out += "\\t";
    else if (ch === "\b") out += "\\b";
    else if (ch === "\f") out += "\\f";
    else if (c < 0x20 || c > 0x7e) out += "\\u" + c.toString(16).padStart(4, "0");
    else out += ch;
  }
  return out + '"';
}
const cmp = (a, b) => { const A = [...a], B = [...b]; for (let i = 0; i < Math.min(A.length, B.length); i++) { const d = A[i].codePointAt(0) - B[i].codePointAt(0); if (d) return d; } return A.length - B.length; };
function canon(v) {
  if (v === null) return "null";
  if (v === true) return "true";
  if (v === false) return "false";
  if (typeof v === "number") { if (!Number.isInteger(v) || !Number.isSafeInteger(v)) throw new Error("non-portable number (float or |int|>2^53-1)"); return String(v); }
  if (typeof v === "string") return pyEscape(v);
  if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
  if (typeof v === "object") return "{" + Object.keys(v).sort(cmp).map((k) => pyEscape(k) + ":" + canon(v[k])).join(",") + "}";
  throw new Error("unserialisable " + typeof v);
}

function hasDuplicateKeys(text) {
  const seen = []; let inStr = false, esc = false, expectKey = false, i = 0, curKey = null, readingKey = false;
  while (i < text.length) {
    const c = text[i++];
    if (inStr) {
      if (esc) {
        esc = false;
        if (readingKey) {
          if (c === "u") { const hex = text.substr(i, 4); i += 4; curKey += String.fromCharCode(parseInt(hex, 16)); }
          else curKey += ({ n: "\n", t: "\t", r: "\r", b: "\b", f: "\f", "/": "/", '"': '"' }[c] ?? c);
        }
      }
      else if (c === String.fromCharCode(92)) { esc = true; }
      else if (c === '"') { inStr = false; readingKey = false; }
      else if (readingKey) curKey += c;
      continue;
    }
    if (c === '"') { inStr = true; if (expectKey) { readingKey = true; curKey = ''; } continue; }
    if (c === '{') { seen.push(new Set()); expectKey = true; }
    else if (c === '}') { seen.pop(); expectKey = false; }
    else if (c === '[') { seen.push(null); expectKey = false; }
    else if (c === ']') { seen.pop(); expectKey = false; }
    else if (c === ':') {
      const set = seen.length ? seen[seen.length - 1] : null;
      if (curKey !== null && set) { if (set.has(curKey)) return true; set.add(curKey); }
      curKey = null; expectKey = false;
    } else if (c === ',') { expectKey = seen.length > 0 && seen[seen.length - 1] instanceof Set; }
  }
  return false;
}

// --- acceptance-profile pre-scans (linear, no parsing), same rules as verifier.py (14/09/2026):
//     nesting > MAX_JSON_DEPTH → json_too_deep; unpaired \uD800-\uDFFF escape → lone_surrogate.
export const MAX_JSON_DEPTH = 512;
export function jsonNestingDepth(text) {
  let depth = 0, max = 0, inStr = false, esc = false;
  for (const ch of text) {
    if (inStr) { if (esc) esc = false; else if (ch === "\\") esc = true; else if (ch === '"') inStr = false; }
    else if (ch === '"') inStr = true;
    else if (ch === "[" || ch === "{") { depth++; if (depth > max) max = depth; }
    else if (ch === "]" || ch === "}") depth--;
  }
  return max;
}
export function hasLoneSurrogate(text) {
  let i = 0; const n = text.length, hex = (s) => (/^[0-9a-fA-F]{4}$/.test(s) ? parseInt(s, 16) : NaN);
  while (i < n) {
    if (text[i] !== "\\") { i++; continue; }
    if (text[i + 1] === "u" && i + 5 < n) {
      const cp = hex(text.slice(i + 2, i + 6));
      if (Number.isNaN(cp)) { i += 2; continue; }   // malformed escape: the parser refuses it, not this rule
      if (cp >= 0xd800 && cp <= 0xdbff) {
        if (text.slice(i + 6, i + 8) !== "\\u") return true;
        const lo = hex(text.slice(i + 8, i + 12));
        if (!(lo >= 0xdc00 && lo <= 0xdfff)) return true;
        i += 12; continue;
      }
      if (cp >= 0xdc00 && cp <= 0xdfff) return true;
      i += 6; continue;
    }
    i += 2;
  }
  return false;
}

// Signed chain tip (15/09/2026, cryptovalid_tip.py / tip.go): same signed bytes in every language —
// {"entries":N,"kind":"cryptovalid_tip/1","ledger_id":"…","tip_sha256":"…","ts":"…"} (ledger_id = self_hash of entry 0,
// the chain's identity). With the tip and the TRUSTED log key,
// tail truncation / suffix rewrite / an unsealed append become named failures (a bare chain cannot see them).
export const TIP_KIND = "cryptovalid_tip/1";

const SPKI = Buffer.from("302a300506032b6570032100", "hex");
const MAX_INPUT_BYTES = 256 * 1024 * 1024;
const SCOPE_LIMIT = /\bNOT\b/, SCOPE_OVERCLAIM = /\b(accredited|certified|qualified|guaranteed)\b/i, SCOPE_NEGATED = /\bNOT\b[^.]{0,40}(accredit|certif|qualif|guarant)/i;
const honestScope = (s) => typeof s === "string" && SCOPE_LIMIT.test(s) && !(SCOPE_OVERCLAIM.test(s) && !SCOPE_NEGATED.test(s));
const b64Strict = (s, n) => { if (typeof s !== "string" || s.length !== Math.ceil(n / 3) * 4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) return null; const raw = Buffer.from(s, "base64"); return raw.length === n && raw.toString("base64") === s ? raw : null; };
const sidecar = (p, suf) => (p.endsWith(".json") ? p.slice(0, -5) + suf : p + suf);

function parseStrict(text) {
  const t = text.replace(/^[ \t\r\n]+|[ \t\r\n]+$/g, "");
  const d = jsonNestingDepth(t); if (d > MAX_JSON_DEPTH) throw new Error("json_too_deep");
  if (hasLoneSurrogate(t)) throw new Error("lone_surrogate");
  if (hasDuplicateKeys(t)) throw new Error("duplicate_key");
  const v = JSON.parse(t); canon(v);   // canon throws on floats / non-portable integers
  return v;
}
function readObject(path) {
  if (statSync(path).size > MAX_INPUT_BYTES) throw new Error("input_too_large");
  const v = parseStrict(readFileSync(path, "utf-8"));
  if (!v || typeof v !== "object" || Array.isArray(v)) throw new Error("not a JSON object");
  return v;
}
const sha3Hex = (b) => createHash("sha3-256").update(b).digest("hex");
const sha256Hex = (b) => createHash("sha256").update(b).digest("hex");
const withoutKey = (o, k) => { const c = {}; for (const key of Object.keys(o)) if (key !== k) c[key] = o[key]; return c; };

function ledgerEntries(path) {
  if (statSync(path).size > MAX_INPUT_BYTES) return { ok: false, entries: [] };
  const out = []; let ok = true, prev = "0".repeat(64), n = 0;
  for (const ln of readFileSync(path, "utf-8").split("\n")) {
    if (!ln.replace(/[ \t\r]/g, "")) continue;
    let e; try { e = parseStrict(ln); if (!e || typeof e !== "object" || Array.isArray(e)) throw new Error("x"); } catch { ok = false; n++; continue; }
    const sh = e.self_hash, ph = e.prev_hash;
    let sum = null; try { sum = sha256Hex(Buffer.from(canon(withoutKey(e, "self_hash")), "utf-8")); } catch { sum = null; }
    if (typeof e.idx === "boolean" || e.idx !== n || ph !== prev || typeof sh !== "string" || sh !== sum) ok = false;
    if (typeof sh === "string") prev = sh;
    out.push(e); n++;
  }
  return { ok, entries: out };
}
const anchors = (e, digest) => e.anchored_pack_sha3 === digest || (e.data && typeof e.data === "object" && e.data.anchored_pack_sha3 === digest);

function trustState(path) {
  const { ok, entries } = ledgerEntries(path); const st = {};
  if (!ok) return { ok, st };
  for (const e of entries) {
    const d = e.data; if (!d || typeof d !== "object") continue;
    const sid = d.signer_id; if (typeof sid !== "string" || !sid) continue;
    if (d.action === "trust") { if (st[sid] && st[sid].revoked) continue; st[sid] = { pubkey: d.pubkey, pq: d.pq_pubkey, revoked: false }; }
    else if (d.action === "rotate") st[sid] = { pubkey: d.pubkey, pq: d.pq_pubkey, revoked: false };
    else if (d.action === "revoke" && st[sid]) st[sid].revoked = true;
  }
  return { ok, st };
}

export function verifyPack(packPath, { ledger = "", trustStore = "", expectPQ = "", requirePQ = false } = {}) {
  const layers = []; const add = (layer, status, detail = "") => layers.push({ layer, status, detail });
  const required = requirePQ || Boolean(expectPQ);
  let pack;
  try { pack = readObject(packPath); } catch (e) { add("pack-json", "FAIL", e.message); return finish(layers, false, false, required); }
  add("pack-json", "PASS");
  add("honest-scope", honestScope(pack.honest_scope) ? "PASS" : "FAIL", honestScope(pack.honest_scope) ? "limit declared" : "no explicit honest_scope (or overclaim without a real NOT-limit)");
  const declared = typeof pack.pack_sha3 === "string" ? pack.pack_sha3 : "";
  let computed = ""; try { computed = sha3Hex(Buffer.from(canon(withoutKey(pack, "pack_sha3")), "utf-8")); } catch { computed = null; }
  add("pack-sha3", computed !== null && declared && declared === computed ? "PASS" : "FAIL");
  let lp = ledger; if (!lp && existsSync(sidecar(packPath, ".ledger.jsonl"))) lp = sidecar(packPath, ".ledger.jsonl");
  let ledgerOK = false;
  if (!lp) add("ledger-chain", "SKIP", "no ledger beside pack");
  else { const { ok, entries } = ledgerEntries(lp);
    if (!ok) add("ledger-chain", "FAIL", lp + ": broken chain");
    else if (!entries.length) add("ledger-chain", "FAIL", lp + ": ledger empty — nothing anchored");
    else if (declared && entries.some((e) => anchors(e, declared))) { add("ledger-chain", "PASS", lp + ": pack_sha3 recorded"); ledgerOK = true; }
    else add("ledger-chain", "FAIL", "valid chain but this pack is not anchored (no anchored_pack_sha3 entry)"); }
  if (existsSync(sidecar(packPath, ".tsr.json"))) {   // shape + content-binding checked like the reference; the token itself is not
    let ts = null; try { ts = readObject(sidecar(packPath, ".tsr.json")); } catch { ts = null; }
    if (!ts) add("timestamp", "FAIL", "malformed sidecar");
    else if (ts.digest_sha256 !== sha256Hex(readFileSync(packPath))) add("timestamp", "FAIL", "pack changed after stamping");
    else add("timestamp", "SKIP", "RFC 3161 token present: not verified by this verifier (use the Python reference)");
  } else add("timestamp", "SKIP", "no timestamp sidecar");
  let sigStatus = "SKIP", trusted = false, trustFailed = false;
  const sp = sidecar(packPath, ".sig.json");
  if (!existsSync(sp)) add("producer-signature", "SKIP", "pack not signed");
  else {
    let side = null; try { side = readObject(sp); } catch (e) { add("producer-signature", "FAIL", "malformed sidecar: " + e.message); sigStatus = "FAIL"; }
    if (side) {
      const alg = "sig_alg" in side ? side.sig_alg : "ed25519";
      if ("sig_alg" in side && typeof alg !== "string") { add("producer-signature", "FAIL", "malformed sidecar fields: sig_alg is not a string"); sigStatus = "FAIL"; }  // council 16/09 r1
      else if (alg !== "ed25519") add("producer-signature", "SKIP", "unsupported sig_alg: " + alg);
      else {
        const pk = b64Strict(side.public_key_b64, 32), sig = b64Strict(side.signature_b64, 64);
        let okSig = false;
        try { okSig = Boolean(pk && sig && declared && edVerify(null, Buffer.from(declared, "utf-8"), createPublicKey({ key: Buffer.concat([SPKI, pk]), format: "der", type: "spki" }), sig)); } catch { okSig = false; }
        if (!okSig || side.signed_pack_sha3 !== declared) { add("producer-signature", "FAIL", "signature invalid or pack changed"); sigStatus = "FAIL"; }
        else {
          const sid = side.signer_id; add("producer-signature", "PASS", `signed by ${sid} (ed25519)`); sigStatus = "PASS";
          let st = null, stOK = true; if (trustStore) { const r = trustState(trustStore); st = r.st; stOK = r.ok; }
          // the registry's PQ pin is borrowed only when the classical key that signed is the registered one (council 16/09 r1)
          let pinned = expectPQ; if (!pinned && st && stOK && st[sid] && !st[sid].revoked && st[sid].pq && st[sid].pubkey === side.public_key_b64) pinned = st[sid].pq;
          checkPQ(layers, side, pinned, requirePQ);
          if (trustStore) {
            const te = st[sid];
            if (stOK && te && !te.revoked && te.pubkey === side.public_key_b64) { add("trusted-signer", "PASS", sid + " in trust registry"); trusted = true; }
            else { add("trusted-signer", "FAIL", !stOK ? "trust store unreadable or broken" : te && te.revoked ? sid + ": key revoked" : te ? sid + ": key differs" : sid + ": not in trust registry"); trustFailed = true; }
          }
        }
      }
    }
  }
  if (required && sigStatus !== "PASS") add("pq-signature", "FAIL", "post-quantum layer required but the pack carries no valid classical signature (hybrid = both)");
  if (sigStatus === "FAIL") add("authenticity", "FAIL", "producer signature present but invalid");
  else if (trustFailed) add("authenticity", "FAIL", "valid signature but signer not trusted/revoked");
  else if (trusted) add("authenticity", "PASS", "trusted-signed");
  else if (sigStatus === "PASS") add("authenticity", "PASS", "signed (identity not checked against a registry)");
  else if (ledgerOK) add("authenticity", "PASS", "anchored (integrity/time, not identity)");
  else add("authenticity", "FAIL", "no anchor and no signature: cannot authenticate");
  return finish(layers, trusted, sigStatus === "PASS" && !trustFailed, required);   // council 16/09 r1: never authenticated for a revoked/untrusted signer
}

// No ML-DSA in Node: the layer is reported as Python does without a backend (SKIP unverified; FAIL when required),
// plus the pinned-key and shape checks this verifier CAN do — never true.
function checkPQ(layers, side, expectPQ, requirePQ) {
  const add = (s, d) => layers.push({ layer: "pq-signature", status: s, detail: d });
  const required = requirePQ || Boolean(expectPQ);
  if ("pq_sig_alg" in side && typeof side.pq_sig_alg !== "string") { add("FAIL", "pq_sig_alg is not a string"); return; }
  const palg = side.pq_sig_alg;
  if (!palg) { if (required) add("FAIL", "post-quantum layer required but absent (stripped or never signed)"); return; }
  if (expectPQ && side.pq_public_key_b64 !== expectPQ) { add("FAIL", palg + " co-signature by a key other than the pinned one"); return; }
  if (palg === "ml-dsa-65" && (!b64Strict(side.pq_public_key_b64, 1952) || !b64Strict(side.pq_signature_b64, 3309))) { add("FAIL", "ml-dsa-65 co-signature invalid"); return; }
  add(required ? "FAIL" : "SKIP", palg + " present but NOT verified by this verifier (no ML-DSA in Node): use the Python, Go or Java verifier" + (required ? " — a required layer that cannot be checked is not a pass" : ""));
}

function finish(layers, trusted, signed, pqRequired) {
  const checked = layers.filter((l) => l.status === "PASS" || l.status === "FAIL");
  const valid = checked.length > 0 && checked.every((l) => l.status === "PASS");
  const pqL = layers.find((l) => l.layer === "pq-signature");
  const pq = !pqL ? false : pqL.status === "PASS" ? true : pqL.status === "SKIP" ? null : false;
  return { valid, layers, authenticated: trusted || signed, pq_protected: pq, verdict: valid && (!pqRequired || pq === true) ? "PASS" : "FAIL", verifier: "oeverify.mjs (Node stdlib; ML-DSA not verified)" };
}

function main(argv) {
  const opt = (f) => (argv.includes(f) ? argv[argv.indexOf(f) + 1] : "");
  const pack = argv.find((a, i) => !a.startsWith("--") && (i === 0 || !["--ledger", "--trust-store", "--expect-pq-key"].includes(argv[i - 1])));
  if (!pack) { console.error("usage: node oeverify.mjs <pack.json> [--ledger L] [--trust-store T] [--expect-pq-key B64] [--require-pq]"); process.exit(2); }
  const r = verifyPack(pack, { ledger: opt("--ledger"), trustStore: opt("--trust-store"), expectPQ: opt("--expect-pq-key"), requirePQ: argv.includes("--require-pq") });
  console.log(JSON.stringify(r, null, 1));
  process.exit(r.verdict === "PASS" ? 0 : 1);
}
if (process.argv[1] && process.argv[1].endsWith("oeverify.mjs")) main(process.argv.slice(2));
