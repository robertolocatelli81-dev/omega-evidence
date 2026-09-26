// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Roberto Locatelli
//
// oeverify.mjs — independent Node (stdlib) verifier of omega-evidence packs (0.7.0): the same layers as the
// Python reference and the Go/Java verifiers — strict JSON acceptance profile, honest-scope, pack-sha3 (canonical
// JSON without pack_sha3, SHA3-256), ledger-chain with the dedicated anchored_pack_sha3 entry, Ed25519 producer
// signature over the pack_sha3 hex bytes, trust registry replay, authenticity. The ML-DSA-65 co-signature IS
// verified when the Node build's OpenSSL is >= 3.5 (Node >= 24.6 documents ML-DSA keys; the raw key is wrapped in a
// SubjectPublicKeyInfo with OID 2.16.840.1.101.3.4.3.18 and checked with crypto.verify, empty context — measured
// 2026-09-19 on Node 24.21.0/OpenSSL 3.5.8 and 22.23.2/OpenSSL 3.5.7 against cryptography-produced signatures);
// on an older OpenSSL the layer is reported as before: present-but-unverified (null), never true.
// Usage: node oeverify.mjs <pack.json> [--ledger L] [--trust-store T] [--expect-pq-key B64] [--require-pq]
import { createHash, createPublicKey, verify as edVerify } from "node:crypto";
import { closeSync, constants as FS, existsSync, fstatSync, openSync, readSync } from "node:fs";



// Python json.dumps(ensure_ascii=True) string form, one UTF-16 unit at a time. One regex pass (25/09/2026): the former
// char-by-char `out += ch` built a rope of one node per character, and a 70 MB string exhausted the V8 heap (NEMESIS).
const PY_SHORT = { '"': '\\"', "\\": "\\\\", "\n": "\\n", "\r": "\\r", "\t": "\\t", "\b": "\\b", "\f": "\\f" };
const escUnits = (s) => s.replace(/["\\]|[^ -~]/g, (ch) => PY_SHORT[ch] ?? "\\u" + ch.charCodeAt(0).toString(16).padStart(4, "0"));
const ESC_CHUNK = 1 << 16;   // a replace() over millions of matches keeps one part per match alive: bounded chunks keep the peak low
function pyEscapeInto(s, out) {
  out.push('"');
  if (s.length <= ESC_CHUNK) out.push(escUnits(s)); else for (let i = 0; i < s.length; i += ESC_CHUNK) out.push(escUnits(s.slice(i, i + ESC_CHUNK)));
  out.push('"');
}
const cmp = (a, b) => { const A = [...a], B = [...b]; for (let i = 0; i < Math.min(A.length, B.length); i++) { const d = A[i].codePointAt(0) - B[i].codePointAt(0); if (d) return d; } return A.length - B.length; };
// canonical JSON as a list of parts (25/09/2026): hashed part by part, never joined into one string — at the input bound a
// joined canonical form plus its Buffer copy took most of the V8 heap on non-ASCII text
function canonInto(v, out) {
  if (v === null) out.push("null");
  else if (v === true) out.push("true");
  else if (v === false) out.push("false");
  else if (typeof v === "number") { if (!Number.isInteger(v) || !Number.isSafeInteger(v)) throw new Error("non-portable number (float or |int|>2^53-1)"); out.push(String(v)); }
  else if (typeof v === "string") pyEscapeInto(v, out);
  else if (Array.isArray(v)) { out.push("["); v.forEach((x, i) => { if (i) out.push(","); canonInto(x, out); }); out.push("]"); }
  else if (typeof v === "object") { out.push("{"); Object.keys(v).sort(cmp).forEach((k, i) => { if (i) out.push(","); pyEscapeInto(k, out); out.push(":"); canonInto(v[k], out); }); out.push("}"); }
  else throw new Error("unserialisable " + typeof v);
}
function canonHash(algo, v) { const o = []; canonInto(v, o); const h = createHash(algo); for (const part of o) h.update(part, "utf8"); return h.digest("hex"); }
// the number rule of canon() without building the string (parseStrict only needs the throw)
function checkPortable(v) {
  if (typeof v === "number") { if (!Number.isInteger(v) || !Number.isSafeInteger(v)) throw new Error("non-portable number (float or |int|>2^53-1)"); }
  else if (Array.isArray(v)) v.forEach(checkPortable);
  else if (v !== null && typeof v === "object") for (const k of Object.keys(v)) checkPortable(v[k]);
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
// a number token with '.', 'e' or 'E' outside a string: JSON.parse("1.0") is the integer 1 and canon() cannot see the lexeme
// (a pack with "n":1.0 hashed as "n":1 verified PASS here alone — 0.8.3 review r3, Opus); Python's parse_float, Go and Java
// refuse it on the text, so does this
export function hasFloatLexeme(text) {
  let inStr = false, esc = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inStr) { if (esc) esc = false; else if (ch === "\\") esc = true; else if (ch === '"') inStr = false; continue; }
    if (ch === '"') { inStr = true; continue; }
    if (ch === "-" || (ch >= "0" && ch <= "9")) {
      let j = i + 1;
      while (j < text.length && /[0-9.eE+\-]/.test(text[j])) j++;
      if (/[.eE]/.test(text.slice(i, j))) return true;
      i = j - 1;
    }
  }
  return false;
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
// One bound for every file read (pack, sidecars, ledger, trust store — and so for any ledger line), the same number in
// the four verifiers (25/09/2026; it was 256 MiB here and in Java, a 64 MiB line in Go, none in Python). Above it the file
// is refused as an unreadable one is.
export const MAX_INPUT_BYTES = 64 * 1024 * 1024;
const SCOPE_LIMIT = /\bNOT\b/, SCOPE_OVERCLAIM = /\b(accredited|certified|qualified|guaranteed)\b/i, SCOPE_NEGATED = /\bNOT\b[^.]{0,40}(accredit|certif|qualif|guarant)/i;
// r4 (Opus): without the u flag `[^.]{0,40}` counts UTF-16 code units — 21 astral characters between NOT and "guarant" are 42
// units here and 21 code points in Python/Go/Java; each astral character is folded to one BMP placeholder before the tests
// (the u flag is not used: with /iu the \b and \w semantics would diverge from the ASCII ones of the other three)
const oneUnitPerCodePoint = (s) => s.replace(/[\u{10000}-\u{10FFFF}]/gu, "\ufffd");   // one pass, no array of code points (25/09/2026)
const honestScope = (s0) => { if (typeof s0 !== "string") return false; const s = oneUnitPerCodePoint(s0); return SCOPE_LIMIT.test(s) && !(SCOPE_OVERCLAIM.test(s) && !SCOPE_NEGATED.test(s)); };
const b64Strict = (s, n) => { if (typeof s !== "string" || s.length !== Math.ceil(n / 3) * 4 || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) return null; const raw = Buffer.from(s, "base64"); return raw.length === n && raw.toString("base64") === s ? raw : null; };
// signing.Identity.fingerprint: "ed25519:" + first 8 + U+2026 + last 8 hex digits of SHA-256(raw public key)
const fingerprintOf = (pkRaw) => { const h = createHash("sha256").update(pkRaw).digest("hex"); return "ed25519:" + h.slice(0, 8) + "\u2026" + h.slice(-8); };
// the instant sign_pack writes (isoformat, seconds, +00:00), ASCII digits, a real calendar date, year >= 1, second <= 59
function signedUtcOK(v) {
  if (typeof v !== "string" || !/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\+00:00$/.test(v)) return false;
  const n = (a, b) => Number(v.slice(a, b)); const y = n(0, 4), mo = n(5, 7), d = n(8, 10), h = n(11, 13), mi = n(14, 16), se = n(17, 19);
  const leap = (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
  const dim = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return y >= 1 && mo >= 1 && mo <= 12 && d >= 1 && d <= dim[mo - 1] && h <= 23 && mi <= 59 && se <= 59;
}
const sidecar = (p, suf) => (p.endsWith(".json") ? p.slice(0, -5) + suf : p + suf);

// trim ASCII space/tab/CR/LF by index: the former /^[ \t\r\n]+|[ \t\r\n]+$/g is quadratic on long inner whitespace runs
function trimJsonWs(text) {
  const ws = (c) => c === 32 || c === 9 || c === 13 || c === 10;
  let a = 0, z = text.length;
  while (a < z && ws(text.charCodeAt(a))) a++;
  while (z > a && ws(text.charCodeAt(z - 1))) z--;
  return a === 0 && z === text.length ? text : text.slice(a, z);
}
function parseStrict(text) {
  const t = trimJsonWs(text);
  const d = jsonNestingDepth(t); if (d > MAX_JSON_DEPTH) throw new Error("json_too_deep");
  if (hasLoneSurrogate(t)) throw new Error("lone_surrogate");
  if (hasFloatLexeme(t)) throw new Error("float_lexeme");
  if (hasDuplicateKeys(t)) throw new Error("duplicate_key");
  const v = JSON.parse(t); checkPortable(v);   // floats / non-portable integers throw (canon()'s rule, without the string)
  return v;
}
// One verifier input (25/09/2026, NEMESIS: a FIFO in place of a sidecar blocked all four verifiers, a symlink to /dev/zero
// exhausted memory): opened O_NONBLOCK so a FIFO does not block the open, accepted only if fstat says the OPENED file is
// regular, read to at most MAX_INPUT_BYTES + 1 bytes. Every refusal throws, and each caller reports it as it reports an
// unreadable file.
export function readInput(path, limit = MAX_INPUT_BYTES) {
  const fd = openSync(path, FS.O_RDONLY | (FS.O_NONBLOCK ?? 0));
  try {
    if (!fstatSync(fd).isFile()) throw new Error("not a regular file");
    const chunks = []; let total = 0;
    while (total <= limit) {
      const buf = Buffer.allocUnsafe(Math.min(1 << 20, limit + 1 - total));
      const n = readSync(fd, buf, 0, buf.length, null);
      if (n === 0) break;
      chunks.push(n === buf.length ? buf : buf.subarray(0, n)); total += n;
    }
    if (total > limit) throw new Error("input exceeds " + limit + " bytes");
    return Buffer.concat(chunks, total);
  } finally { closeSync(fd); }
}
function objectOf(text) {
  const v = parseStrict(text);
  if (!v || typeof v !== "object" || Array.isArray(v)) throw new Error("not a JSON object");
  return v;
}
const readObject = (path) => objectOf(readText(path));
const sha256Hex = (b) => createHash("sha256").update(b).digest("hex");
const withoutKey = (o, k) => Object.fromEntries(Object.entries(o).filter(([key]) => key !== k));   // keeps an own "__proto__" key (c[key] = … would invoke the setter and DROP it: a ledger entry with that key added and self_hash untouched verified PASS here alone — 21/09/2026)
const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });   // strict: one invalid byte is unreadable, never U+FFFD
const readText = (path) => UTF8.decode(readInput(path));

function ledgerEntries(path) {
  const out = []; let ok = true, prev = "0".repeat(64), n = 0;
  let ledgerText;   // a missing / unreadable / oversized / non-UTF-8 file is a broken ledger, never an uncaught ENOENT (0.8.3 review)
  try { ledgerText = readText(path); } catch { return { ok: false, entries: [] }; }   // bounded, non-blocking, regular file only (readInput)
  // one line at a time: split("\n") built every line first (64 MiB of empty lines → ~1 GB, measured 26/09/2026)
  for (let start = 0, more = true; more;) {
    const end = ledgerText.indexOf("\n", start);
    const ln = end < 0 ? ledgerText.slice(start) : ledgerText.slice(start, end);
    if (end < 0) more = false; else start = end + 1;
    if (!ok) break;   // the chain is already broken and no caller reads the entries of a broken chain: stop accumulating
                      // (26/09/2026: 22 M lines "{}" kept 22 M objects, 1.95 GB)
    if (!ln.replace(/[ \t\r]/g, "")) continue;
    let e; try { e = parseStrict(ln); if (!e || typeof e !== "object" || Array.isArray(e)) throw new Error("x"); } catch { ok = false; n++; continue; }
    const sh = e.self_hash, ph = e.prev_hash;
    let sum = null; try { sum = canonHash("sha256", withoutKey(e, "self_hash")); } catch { sum = null; }
    if (typeof e.idx === "boolean" || e.idx !== n || ph !== prev || typeof sh !== "string" || sh !== sum) ok = false;
    if (typeof sh === "string") prev = sh;
    out.push(e); n++;
  }
  return { ok, entries: ok ? out : [] };
}
const anchors = (e, digest) => e.anchored_pack_sha3 === digest || (e.data && typeof e.data === "object" && e.data.anchored_pack_sha3 === digest);

function trustState(path) {
  const { ok, entries } = ledgerEntries(path); const st = Object.create(null);   // r5 (Opus): with {} a signer_id "toString" or "__proto__" read through Object.prototype (a revoke of "__proto__" then a trust of "toString" was FAIL here alone, and polluted the prototype)
  if (!ok) return { ok, st };
  for (const e of entries) {
    const d = e.data; if (!d || typeof d !== "object" || Array.isArray(d)) return { ok: false, st };   // council r2: malformed record = broken store
    if (!["trust", "rotate", "revoke"].includes(d.action)) continue;
    const sid = d.signer_id;
    const badKey = (v) => typeof v !== "string" || !v;
    if (badKey(sid) || (d.action !== "revoke" && badKey(d.pubkey)) || ("pq_pubkey" in d && badKey(d.pq_pubkey))) return { ok: false, st };
    if (d.action === "trust") { if (st[sid] && st[sid].revoked) continue; st[sid] = { pubkey: d.pubkey, pq: d.pq_pubkey, revoked: false }; }
    else if (d.action === "rotate") st[sid] = { pubkey: d.pubkey, pq: d.pq_pubkey, revoked: false };
    else if (d.action === "revoke" && st[sid]) st[sid].revoked = true;
  }
  return { ok, st };
}

export const INJECT_ENV = "OEVERIFY_INJECT_INTERNAL_ERROR";   // test hook, the same name in the four verifiers (README)
// A fault of the TOOL is not a finding about the pack (25/09/2026): the layer `internal` is FAIL with assessed=false, so the
// run is NOT_ASSESSED (exit 77) unless a layer judged before the fault is adverse; never authenticated, never pq-protected.
// Before, an uncaught exception here exited 1 — the code of FAIL. A V8 heap exhaustion is fatal, not catchable: the input
// bound, with the ledger read one line at a time, keeps it away on the shapes measured (README, 26/09/2026).
function internalError(layers, e) {
  const ls = layers.concat([{ layer: "internal", status: "FAIL", detail: "verifier error, not a finding about the pack: " + ((e && e.name) || typeof e), assessed: false }]);
  const r = finish(ls, false, false, false);
  return { ...r, authenticated: false, pq_protected: false };
}
export function verifyPack(packPath, opts = {}) {
  const layers = [];
  try { return verifyPackIn(layers, packPath, opts); } catch (e) { return internalError(layers, e); }
}
function verifyPackIn(layers, packPath, { ledger = "", trustStore = "", expectPQ = "", requirePQ = false } = {}) {
  const add = (layer, status, detail = "", assessed = true) => layers.push(assessed ? { layer, status, detail } : { layer, status, detail, assessed });
  const required = requirePQ || Boolean(expectPQ);
  let pack, packBytes;   // read ONCE; the timestamp binding hashes these bytes, not a second read
  try { packBytes = readInput(packPath); pack = objectOf(UTF8.decode(packBytes)); } catch (e) { add("pack-json", "FAIL", e.message); return finish(layers, false, false, required); }
  add("pack-json", "PASS");
  add("honest-scope", honestScope(pack.honest_scope) ? "PASS" : "FAIL", honestScope(pack.honest_scope) ? "limit declared" : "no explicit honest_scope (or overclaim without a real NOT-limit)");
  const declared = typeof pack.pack_sha3 === "string" ? pack.pack_sha3 : "";
  let computed = ""; try { computed = canonHash("sha3-256", withoutKey(pack, "pack_sha3")); } catch { computed = null; }
  add("pack-sha3", computed !== null && declared && declared === computed ? "PASS" : "FAIL");
  if (process.env[INJECT_ENV] === "1") throw new Error("internal error injected by " + INJECT_ENV);
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
    else if (ts.digest_sha256 !== sha256Hex(packBytes)) add("timestamp", "FAIL", "pack changed after stamping");
    else add("timestamp", "SKIP", "RFC 3161 token present and bound to the pack: not verified by any of the four verifiers (no trust anchor); the cryptographic check is timestamp.verify(..., ca_file=) for the operator");
  } else add("timestamp", "SKIP", "no timestamp sidecar");
  let sigStatus = "SKIP", trusted = false, trustFailed = false;
  const sp = sidecar(packPath, ".sig.json");
  if (!existsSync(sp)) add("producer-signature", "SKIP", "pack not signed");
  else {
    let side = null; try { side = readObject(sp); } catch (e) { add("producer-signature", "FAIL", "malformed sidecar: " + e.message); sigStatus = "FAIL"; }
    if (side) {
      const alg = "sig_alg" in side ? side.sig_alg : "ed25519";
      if ("sig_alg" in side && (typeof alg !== "string" || alg === "")) { add("producer-signature", "FAIL", "malformed sidecar fields: sig_alg is not a non-empty string"); sigStatus = "FAIL"; }  // council 16/09 r1; "" is present and malformed (25/09/2026)
      else if (alg !== "ed25519") add("producer-signature", "SKIP", "unsupported sig_alg: " + alg);
      else {
        const pk = b64Strict(side.public_key_b64, 32), sig = b64Strict(side.signature_b64, 64);
        let okSig = false;
        if (!pk || !sig || typeof declared !== "string" || !/^[0-9a-f]{64}$/.test(declared)) { add("producer-signature", "FAIL", "malformed sidecar fields (strict base64 32/64, lowercase hex digest)"); sigStatus = "FAIL"; }   // council r3
        // 25/09/2026 (NEMESIS): fingerprint / signed_utc were never read ("", 0, null, true, [], {}: PASS, authenticated).
        // Absent = legacy, fine; present = what sign_pack writes (the fingerprint derived from THIS key, the exact instant form)
        else if ("fingerprint" in side && side.fingerprint !== fingerprintOf(pk)) { add("producer-signature", "FAIL", "malformed sidecar field: fingerprint is not the one derived from public_key_b64"); sigStatus = "FAIL"; }
        else if ("signed_utc" in side && !signedUtcOK(side.signed_utc)) { add("producer-signature", "FAIL", "malformed sidecar field: signed_utc is not YYYY-MM-DDTHH:MM:SS+00:00"); sigStatus = "FAIL"; }
        else {
        try { okSig = !weakEd25519(pk) && Boolean(edVerify(null, Buffer.from(declared, "utf-8"), createPublicKey({ key: Buffer.concat([SPKI, pk]), format: "der", type: "spki" }), sig)); } catch { okSig = false; }
        if (!okSig || side.signed_pack_sha3 !== declared) { add("producer-signature", "FAIL", "signature invalid or pack changed"); sigStatus = "FAIL"; }
        else {
          const sid = side.signer_id;
          if (typeof sid !== "string" || !sid) { add("producer-signature", "FAIL", "malformed sidecar fields: signer_id must be a non-empty string"); sigStatus = "FAIL"; }   // council r2
          else {
          add("producer-signature", "PASS", `signed by ${sid} (ed25519)`); sigStatus = "PASS";
          let st = null, stOK = true; if (trustStore) { const r = trustState(trustStore); st = r.st; stOK = r.ok; }
          // the registry's PQ pin is borrowed only when the classical key that signed is the registered one (council 16/09 r1)
          let pinned = expectPQ; if (!pinned && st && stOK && st[sid] && !st[sid].revoked && st[sid].pq && st[sid].pubkey === side.public_key_b64) pinned = st[sid].pq;
          checkPQ(layers, side, pinned, requirePQ, declared);
          if (trustStore) {
            const te = st[sid];
            if (stOK && te && !te.revoked && te.pubkey === side.public_key_b64) { add("trusted-signer", "PASS", sid + " in trust registry"); trusted = true; }
            else { add("trusted-signer", "FAIL", !stOK ? "trust store unreadable or broken" : te && te.revoked ? sid + ": key revoked" : te ? sid + ": key differs" : sid + ": not in trust registry"); trustFailed = true; }
          }
          }
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

// ML-DSA-65 (FIPS 204) through OpenSSL >= 3.5 when the runtime has it; otherwise the layer is reported as Python does
// without a backend (SKIP unverified; FAIL when required) plus the pinned-key and shape checks — never true unverified.
// small-order / non-canonical Ed25519 keys (with the identity key R=identity, S=0 verifies on every message, other small-order points on a share of messages; OpenSSL accepts it, measured 25/09/2026 with the identity key) — same list as omega_evidence/signing.py WEAK_ED25519_KEYS
const WEAK_ED25519 = new Set(["0100000000000000000000000000000000000000000000000000000000000000", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000080", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", "0100000000000000000000000000000000000000000000000000000000000080", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"]);
function weakEd25519(pk) {
  if (pk.length !== 32 || WEAK_ED25519.has(pk.toString("hex"))) return true;
  if ((pk[31] & 0x7f) !== 0x7f || pk[0] < 0xed) return false;          // y >= p = 2^255-19 only when bytes 1..30 are 0xff too
  for (let i = 1; i < 31; i++) if (pk[i] !== 0xff) return false;
  return true;
}
const MLDSA65_SPKI_PREFIX = Buffer.from("308207b2300b0609608648016503040312038207a100", "hex");   // SEQ{ SEQ{OID 2.16.840.1.101.3.4.3.18}, BIT STRING(0x00||1952 bytes) }
function mldsa65Verify(pk, msg, sig) {
  // returns true/false, or null when this Node/OpenSSL cannot load ML-DSA keys (feature-detected, never guessed)
  let key;
  try { key = createPublicKey({ key: Buffer.concat([MLDSA65_SPKI_PREFIX, pk]), format: "der", type: "spki" }); } catch { return null; }
  try { return Boolean(edVerify(null, msg, key, sig)); } catch { return null; }
}
// PQ algorithms the project implements a backend for somewhere; membership does not mean THIS runtime has it.
const KNOWN_PQ_ALGS = new Set(["ml-dsa-65", "slh-dsa-sha2-128s"]);
export const MLDSA_SUPPORTED = (() => {
  try { createPublicKey({ key: Buffer.concat([MLDSA65_SPKI_PREFIX, Buffer.alloc(1952)]), format: "der", type: "spki" }); return true; } catch { return false; }
})();
function checkPQ(layers, side, expectPQ, requirePQ, digest) {
  // `assessed` defaults to true; a false here means THIS runtime could not run the check (see the two call sites).
  const add = (s, d, assessed = true) => layers.push(assessed ? { layer: "pq-signature", status: s, detail: d } : { layer: "pq-signature", status: s, detail: d, assessed });
  const required = requirePQ || Boolean(expectPQ);
  if ("pq_sig_alg" in side && (typeof side.pq_sig_alg !== "string" || side.pq_sig_alg === "")) { add("FAIL", "pq_sig_alg is not a non-empty string"); return; }   // "" is present and malformed, not absent (25/09/2026)
  const palg = side.pq_sig_alg;
  if (!palg) { if (required) add("FAIL", "post-quantum layer required but absent (stripped or never signed)"); return; }
  if (expectPQ && side.pq_public_key_b64 !== expectPQ) { add("FAIL", palg + " co-signature by a key other than the pinned one"); return; }
  if (palg !== "ml-dsa-65") {
    // Same split as the Python verifier: an algorithm the project knows but this runtime does not implement is an
    // absence; a name nobody knows stays a judgment (it can never be pq-protected).
    add(required ? "FAIL" : "SKIP", palg + " is not a registered PQ backend (pq-present-unverified" + (required ? ": a required layer that cannot be checked is not a pass)" : ")"), !KNOWN_PQ_ALGS.has(palg));
    return;
  }
  const pk = b64Strict(side.pq_public_key_b64, 1952), sig = b64Strict(side.pq_signature_b64, 3309);
  if (!pk || !sig) { add("FAIL", "ml-dsa-65 co-signature invalid"); return; }
  const ok = mldsa65Verify(pk, Buffer.from(digest, "utf-8"), sig);
  if (ok === null) {
    // This Node cannot run the check: FAIL when required (fail-closed), but marked so the roll-up does not report
    // OUR missing capability as a finding about the pack. An unknown algorithm name, above, stays a judgment.
    add(required ? "FAIL" : "SKIP", "ml-dsa-65 present but NOT verified by this Node (OpenSSL < 3.5): use the Python, Go or Java verifier" + (required ? " — a required layer that cannot be checked is not a pass" : ""), false);   // marked on SKIP too: an optional layer this Node cannot read still makes the run inconclusive
    return;
  }
  if (!ok) { add("FAIL", "ml-dsa-65 co-signature invalid"); return; }
  if (!expectPQ) { add(required ? "FAIL" : "SKIP", "ml-dsa-65 co-signature valid against the key INSIDE the sidecar only (pq-present-unpinned)" + (required ? "" : ": pin the signer's post-quantum key")); return; }
  add("PASS", "pq-protected (ml-dsa-65, pinned key)");
}

function finish(layers, trusted, signed, pqRequired) {
  const checked = layers.filter((l) => l.status === "PASS" || l.status === "FAIL");
  const valid = checked.length > 0 && checked.every((l) => l.status === "PASS");
  const pqL = layers.find((l) => l.layer === "pq-signature");
  const pq = !pqL ? false : pqL.status === "PASS" ? true : pqL.status === "SKIP" ? null : false;
  const integrity = layers.some((l) => l.layer === "pack-sha3" && l.status === "PASS");   // council r2
  const judged = layers.some((l) => l.status === "FAIL" && l.assessed !== false);
  const absent = layers.some((l) => l.assessed === false);
  const assessed = judged || !absent;                 // FAIL > NOT_ASSESSED > PASS, SKIP included
  const passed = valid && assessed && (!pqRequired || pq === true);
  return { valid, assessed, layers, authenticated: (trusted || signed) && integrity, pq_protected: pq, verdict: passed ? "PASS" : (assessed ? "FAIL" : "NOT_ASSESSED"), verifier: "oeverify.mjs (Node stdlib; ML-DSA-65 " + (MLDSA_SUPPORTED ? "verified through OpenSSL >= 3.5" : "not verifiable on this Node") + ")" };
}

function main(argv) {
  // one grammar in the four CLIs (21/09/2026): an unknown flag, a value flag without a value or with "", a second positional = usage
  const usage = () => { console.error("usage: node oeverify.mjs <pack.json> [--ledger L] [--trust-store T] [--expect-pq-key B64] [--require-pq]"); process.exit(2); };
  const VALUE = new Set(["--ledger", "--trust-store", "--expect-pq-key"]); const opts = {}; let pack = null;
  const norm = (a) => (/^-[a-z]/.test(a) ? "-" + a : a);   // r4: -ledger and --ledger are the same flag in the four CLIs
  const badValue = (v) => v === undefined || v === "" || v.startsWith("-");
  for (let i = 0; i < argv.length; i++) {
    const a = norm(argv[i]);
    if (a === "--require-pq") { opts[a] = true; continue; }
    if (VALUE.has(a)) { const v = argv[i + 1]; if (badValue(v)) usage(); opts[a] = v; i++; continue; }
    const eq = a.indexOf("=");   // --flag=value, the form Python's argparse and Go's flag accept (one grammar in the four)
    if (eq > 0 && VALUE.has(a.slice(0, eq))) { const v = a.slice(eq + 1); if (badValue(v)) usage(); opts[a.slice(0, eq)] = v; continue; }
    if (a.startsWith("-") || pack !== null) usage();
    pack = a;
  }
  if (!pack) usage();
  let r, out;
  try {
    r = verifyPack(pack, { ledger: opts["--ledger"] ?? "", trustStore: opts["--trust-store"] ?? "", expectPQ: opts["--expect-pq-key"] ?? "", requirePQ: Boolean(opts["--require-pq"]) });
    out = JSON.stringify(r, null, 1);
  } catch (e) { r = internalError([], e); out = JSON.stringify(r, null, 1); }   // a fault outside verifyPack's own guard: exit 77, never 1
  console.log(out);
  process.exit(r.verdict === "PASS" ? 0 : r.verdict === "FAIL" ? 1 : 77);   // 77 = nothing adverse found, the check did not run here
}
if (process.argv[1] && process.argv[1].endsWith("oeverify.mjs")) main(process.argv.slice(2));
