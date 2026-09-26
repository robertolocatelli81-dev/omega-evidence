// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Roberto Locatelli
//
// OeVerify — independent Java verifier of omega-evidence packs (0.7.0), JDK standard library only (JDK 24+ for
// ML-DSA-65; Ed25519 since JDK 15). The same layers and verdicts as omega_evidence/verifier.py and the Go
// verifier: pack-json (strict acceptance profile), honest-scope, pack-sha3 (canonical JSON without pack_sha3,
// SHA3-256), ledger-chain (strict chain + dedicated anchored_pack_sha3 entry), producer-signature (Ed25519 over the
// pack_sha3 hex bytes), pq-signature (ML-DSA-65, empty context, PINNED tri-state), trusted-signer (replay of the
// hash-chained trust registry), authenticity. RFC 3161 sidecars are NOT verified here (declared SKIP).
// Run:  java OeVerify.java <pack.json> [-ledger L] [-trust-store T] [-expect-pq-key B64] [-require-pq]
import java.io.*;
import java.nio.charset.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import java.util.regex.*;

public class OeVerify {
    static final int MAX_DEPTH = 512;
    static final long SAFE_INT = (1L << 53) - 1;
    // One bound for every file read (pack, sidecars, ledger, trust store — and so for any ledger line), the same number in
    // the four verifiers (25/09/2026; it was 256 MiB here and in Node, a 64 MiB line in Go, none in Python). Above it the
    // file is refused as an unreadable one is.
    static final int MAX_INPUT_BYTES = 64 * 1024 * 1024;
    static final String INJECT_ENV = "OEVERIFY_INJECT_INTERNAL_ERROR";   // test hook, the same name in the four verifiers (README)
    static final Set<String> ATTEST = Set.of("self_hash");   // omega-evidence ledgers: self_hash is the only attestation key
    static final String GENESIS = "0".repeat(64);
    static final byte[] ED_SPKI = hex("302a300506032b6570032100");
    static final byte[] MLDSA65_SPKI = hex("308207b2300b0609608648016503040312038207a100");
    // ASCII word boundaries spelled out (r5/r7): independent of the JDK's \\b semantics; the family profile is ASCII in the four
    static final String WB_L = "(?<![A-Za-z0-9_])", WB_R = "(?![A-Za-z0-9_])";
    static final Pattern SCOPE_LIMIT = Pattern.compile(WB_L + "NOT" + WB_R);
    static final Pattern SCOPE_OVERCLAIM = Pattern.compile(WB_L + "(accredited|certified|qualified|guaranteed)" + WB_R, Pattern.CASE_INSENSITIVE);
    static final Pattern SCOPE_NEGATED = Pattern.compile(WB_L + "NOT" + WB_R + "[^.]{0,40}(accredit|certif|qualif|guarant)", Pattern.CASE_INSENSITIVE);

    // ───────────────────────── strict JSON (acceptance profile) ─────────────────────────
    static final class Obj { final List<String> keys = new ArrayList<>(); final Map<String, Object> vals = new HashMap<>(); }
    static final class Num { final String lexeme; Num(String s) { lexeme = s; } }
    static final class Bad extends Exception { Bad(String m) { super(m); } }

    static int nestingDepth(byte[] t) {
        int depth = 0, max = 0; boolean inStr = false, esc = false;
        for (byte b : t) {
            char c = (char) (b & 0xff);
            if (inStr) { if (esc) esc = false; else if (c == '\\') esc = true; else if (c == '"') inStr = false; }
            else if (c == '"') inStr = true;
            else if (c == '[' || c == '{') { depth++; if (depth > max) max = depth; }
            else if (c == ']' || c == '}') depth--;
        }
        return max;
    }

    static boolean hasLoneSurrogate(byte[] t) {
        int i = 0, n = t.length;
        while (i < n) {
            if (t[i] != '\\') { i++; continue; }
            if (i + 1 < n && t[i + 1] == 'u' && i + 5 < n) {
                Integer cp = hex4(t, i + 2);
                if (cp == null) { i += 2; continue; }
                if (cp >= 0xD800 && cp <= 0xDBFF) {
                    if (i + 7 >= n || t[i + 6] != '\\' || t[i + 7] != 'u') return true;
                    Integer lo = hex4(t, i + 8);
                    if (lo == null || lo < 0xDC00 || lo > 0xDFFF) return true;
                    i += 12; continue;
                }
                if (cp >= 0xDC00 && cp <= 0xDFFF) return true;
                i += 6; continue;
            }
            i += 2;
        }
        return false;
    }
    static Integer hex4(byte[] t, int at) {   // 4 ASCII hex digits or null — never Integer.parseInt (it takes a sign and Unicode digits: r5)
        if (at + 4 > t.length) return null;
        int v = 0;
        for (int k = 0; k < 4; k++) { int d = hexDigit((char) (t[at + k] & 0xff)); if (d < 0) return null; v = (v << 4) | d; }
        return v;
    }
    static int hexDigit(char c) { return (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : (c >= 'A' && c <= 'F') ? c - 'A' + 10 : -1; }

    // strict UTF-8: one malformed byte is unreadable, never U+FFFD (a lossy read verified PASS on a ledger entry whose
    // self_hash was computed over U+FFFD while the file held the raw byte — found by the differential probe, 21/09/2026)
    // validated in a streaming pass with a small buffer, then decoded once (25/09/2026: decode() allocated a UTF-16
    // CharBuffer of the whole input, twice per file — most of the heap at the input bound); same acceptance as before
    static void requireUtf8(byte[] text) throws Bad {
        CharsetDecoder d = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT);
        java.nio.ByteBuffer in = java.nio.ByteBuffer.wrap(text); java.nio.CharBuffer out = java.nio.CharBuffer.allocate(8192);
        while (true) { CoderResult r = d.decode(in, out, true); if (r.isError()) throw new Bad("non-UTF-8 input"); if (r.isUnderflow()) break; out.clear(); }
        out.clear(); if (d.flush(out).isError()) throw new Bad("non-UTF-8 input");
    }
    static String strictUtf8(byte[] text) throws Bad { requireUtf8(text); return new String(text, StandardCharsets.UTF_8); }
    static Object parse(byte[] text) throws Bad {
        String s = strictUtf8(text);
        int d = nestingDepth(text);
        if (d > MAX_DEPTH) throw new Bad("json_too_deep: nesting " + d + " exceeds the acceptance-profile bound " + MAX_DEPTH);
        if (hasLoneSurrogate(text)) throw new Bad("lone_surrogate: unpaired UTF-16 surrogate escape is outside the acceptance profile");
        Parser p = new Parser(s);
        p.ws(); Object v = p.value(); p.ws();
        if (p.i != s.length()) throw new Bad("trailing data after JSON value");
        return v;
    }

    static final class Parser {
        final String s; int i = 0;
        Parser(String s) { this.s = s; }
        void ws() { while (i < s.length() && (s.charAt(i) == ' ' || s.charAt(i) == '\t' || s.charAt(i) == '\n' || s.charAt(i) == '\r')) i++; }
        char peek() throws Bad { if (i >= s.length()) throw new Bad("unexpected end of JSON"); return s.charAt(i); }
        Object value() throws Bad {
            char c = peek();
            switch (c) {
                case '{': return object();
                case '[': return array();
                case '"': return string();
                case 't': lit("true"); return Boolean.TRUE;
                case 'f': lit("false"); return Boolean.FALSE;
                case 'n': lit("null"); return null;
                default: return number();
            }
        }
        void lit(String w) throws Bad { if (!s.startsWith(w, i)) throw new Bad("invalid literal"); i += w.length(); }
        Obj object() throws Bad {
            Obj o = new Obj(); i++; ws();
            if (peek() == '}') { i++; return o; }
            while (true) {
                ws(); if (peek() != '"') throw new Bad("object key is not a string");
                String k = string(); ws();
                if (peek() != ':') throw new Bad("expected ':'"); i++; ws();
                Object v = value();
                if (o.vals.containsKey(k)) throw new Bad("duplicate key \"" + k + "\"");
                o.keys.add(k); o.vals.put(k, v); ws();
                char c = peek(); i++;
                if (c == '}') return o;
                if (c != ',') throw new Bad("expected ',' or '}'");
            }
        }
        List<Object> array() throws Bad {
            List<Object> a = new ArrayList<>(); i++; ws();
            if (peek() == ']') { i++; return a; }
            while (true) {
                ws(); a.add(value()); ws();
                char c = peek(); i++;
                if (c == ']') return a;
                if (c != ',') throw new Bad("expected ',' or ']'");
            }
        }
        String string() throws Bad {
            i++; int st = i;
            // fast path (25/09/2026): a string with no escape and no control character is one substring, not a StringBuilder
            while (i < s.length()) { char c = s.charAt(i); if (c == '"') { String r = s.substring(st, i); i++; return r; } if (c == '\\' || c < 0x20) break; i++; }
            StringBuilder b = new StringBuilder(); b.append(s, st, i);
            while (true) {
                char c = peek(); i++;
                if (c == '"') return b.toString();
                if (c < 0x20) throw new Bad("control character in string");
                if (c != '\\') { b.append(c); continue; }
                char e = peek(); i++;
                switch (e) {
                    case '"': b.append('"'); break; case '\\': b.append('\\'); break; case '/': b.append('/'); break;
                    case 'b': b.append('\b'); break; case 'f': b.append('\f'); break; case 'n': b.append('\n'); break;
                    case 'r': b.append('\r'); break; case 't': b.append('\t'); break;
                    case 'u': {
                        if (i + 4 > s.length()) throw new Bad("bad \\u escape");
                        int v = 0;
                        for (int k = 0; k < 4; k++) { int d = hexDigit(s.charAt(i + k)); if (d < 0) throw new Bad("bad \\u escape"); v = (v << 4) | d; }
                        b.append((char) v); i += 4; break;
                    }
                    default: throw new Bad("bad escape");
                }
            }
        }
        Num number() throws Bad {
            int st = i;
            if (i < s.length() && s.charAt(i) == '-') i++;
            if (i >= s.length() || !Character.isDigit(s.charAt(i)) || s.charAt(i) > '9') throw new Bad("invalid number");
            if (s.charAt(i) == '0') i++; else while (i < s.length() && s.charAt(i) >= '0' && s.charAt(i) <= '9') i++;
            String lex = s.substring(st, i);
            if (i < s.length() && (s.charAt(i) == '.' || s.charAt(i) == 'e' || s.charAt(i) == 'E')) {
                int j = i; while (j < s.length() && "0123456789.eE+-".indexOf(s.charAt(j)) >= 0) j++;
                throw new Bad("floating-point number \"" + s.substring(st, j) + "\" is forbidden by the profile");
            }
            if (lex.equals("-0")) lex = "0";
            try { long v = Long.parseLong(lex); if (v > SAFE_INT || v < -SAFE_INT) throw new Bad("integer " + lex + " outside the portable range +/-(2^53-1)"); }
            catch (NumberFormatException x) { throw new Bad("integer " + lex + " outside the portable range +/-(2^53-1)"); }
            return new Num(lex);
        }
    }

    // ───────────────────────── canonical JSON (Python ensure_ascii, sorted keys by code point) ─────────────────────────
    static final Comparator<String> BY_CODEPOINT = (a, b) -> {
        int[] x = a.codePoints().toArray(), y = b.codePoints().toArray();
        for (int k = 0; k < Math.min(x.length, y.length); k++) if (x[k] != y[k]) return Integer.compare(x[k], y[k]);
        return Integer.compare(x.length, y.length);
    };
    // The canonical form is pure ASCII (every other unit is escaped), so it can be hashed in 64 KiB spills instead of being
    // built whole (25/09/2026: at the input bound the whole string, its copy and its bytes were most of the heap).
    static void encode(StringBuilder b, Object v) { encode(b, v, null); }
    static void spill(StringBuilder b, MessageDigest md) { if (md != null && b.length() >= (1 << 16)) { md.update(b.toString().getBytes(StandardCharsets.ISO_8859_1)); b.setLength(0); } }
    static void encode(StringBuilder b, Object v, MessageDigest md) {
        if (v == null) b.append("null");
        else if (v instanceof Boolean) b.append(((Boolean) v) ? "true" : "false");
        else if (v instanceof Num) b.append(((Num) v).lexeme);
        else if (v instanceof String) writeString(b, (String) v, md);
        else if (v instanceof List) { b.append('['); List<?> l = (List<?>) v; for (int k = 0; k < l.size(); k++) { if (k > 0) b.append(','); encode(b, l.get(k), md); } b.append(']'); }
        else if (v instanceof Obj) {
            Obj o = (Obj) v; List<String> ks = new ArrayList<>(o.keys); ks.sort(BY_CODEPOINT); b.append('{');
            for (int k = 0; k < ks.size(); k++) { if (k > 0) b.append(','); writeString(b, ks.get(k), md); b.append(':'); encode(b, o.vals.get(ks.get(k)), md); }
            b.append('}');
        } else throw new IllegalStateException("unsupported value");
        spill(b, md);
    }
    static final char[] HEXL = "0123456789abcdef".toCharArray();
    static void writeString(StringBuilder b, String s) { writeString(b, s, null); }
    // Python json.dumps(ensure_ascii=True), one UTF-16 unit at a time: a surrogate pair gives the same two \\uXXXX escapes the
    // former per-code-point String.format computed (lowercase hex), without a format call per character
    static void writeString(StringBuilder b, String s, MessageDigest md) {
        b.append('"');
        for (int k = 0, n = s.length(); k < n; k++) {
            char r = s.charAt(k);
            switch (r) {
                case '"': b.append("\\\""); break; case '\\': b.append("\\\\"); break; case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break; case '\t': b.append("\\t"); break; case '\b': b.append("\\b"); break; case '\f': b.append("\\f"); break;
                default:
                    if (r >= 0x20 && r <= 0x7e) b.append(r);
                    else b.append('\\').append('u').append(HEXL[(r >> 12) & 15]).append(HEXL[(r >> 8) & 15]).append(HEXL[(r >> 4) & 15]).append(HEXL[r & 15]);
            }
            if ((k & 0xffff) == 0xffff) spill(b, md);
        }
        b.append('"');
    }
    static String canonHash(String algo, Obj o) throws Exception {
        MessageDigest md = MessageDigest.getInstance(algo); StringBuilder b = new StringBuilder(); encode(b, o, md);
        md.update(b.toString().getBytes(StandardCharsets.ISO_8859_1)); return toHex(md.digest());
    }
    static byte[] payload(Obj e) {
        Obj cp = new Obj();
        for (String k : e.keys) if (!ATTEST.contains(k)) { cp.keys.add(k); cp.vals.put(k, e.vals.get(k)); }
        StringBuilder b = new StringBuilder(); encode(b, cp); return b.toString().getBytes(StandardCharsets.UTF_8);
    }
    static String hash(String algo, byte[] p) throws Exception {
        return toHex(MessageDigest.getInstance(algo.equals("sha256") ? "SHA-256" : "SHA3-256").digest(p));
    }

    // ───────────────────────── helpers ─────────────────────────
    static byte[] hex(String s) { byte[] o = new byte[s.length() / 2]; for (int k = 0; k < o.length; k++) o[k] = (byte) Integer.parseInt(s.substring(2 * k, 2 * k + 2), 16); return o; }
    static String toHex(byte[] b) { StringBuilder sb = new StringBuilder(); for (byte x : b) sb.append(String.format("%02x", x)); return sb.toString(); }
    static boolean isHexN(String s, int n) { if (s == null || s.length() != n) return false; for (char c : s.toCharArray()) if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false; return true; }
    static byte[] b64Strict(String s, int n) {
        if (s == null || s.length() != ((n + 2) / 3) * 4 || !s.matches("[A-Za-z0-9+/]*={0,2}")) return null;
        try { byte[] raw = Base64.getDecoder().decode(s); return raw.length == n && Base64.getEncoder().encodeToString(raw).equals(s) ? raw : null; } catch (Exception e) { return null; }
    }
    static PublicKey key(String alg, byte[] hdr, byte[] raw) throws Exception {
        byte[] spki = new byte[hdr.length + raw.length]; System.arraycopy(hdr, 0, spki, 0, hdr.length); System.arraycopy(raw, 0, spki, hdr.length, raw.length);
        return KeyFactory.getInstance(alg).generatePublic(new X509EncodedKeySpec(spki));
    }
    // small-order / non-canonical Ed25519 keys (R=identity, S=0 verifies on every message; OpenSSL accepts it, measured 25/09/2026) — same list as omega_evidence/signing.py WEAK_ED25519_KEYS
    static final java.util.Set<String> WEAK_ED25519 = java.util.Set.of("0100000000000000000000000000000000000000000000000000000000000000", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000080", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", "0100000000000000000000000000000000000000000000000000000000000080", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    static boolean weakEd25519(byte[] pk) {
        if (pk.length != 32) return true;
        StringBuilder h = new StringBuilder(); for (byte b : pk) h.append(String.format("%02x", b & 0xff));
        if (WEAK_ED25519.contains(h.toString())) return true;
        if ((pk[31] & 0x7f) != 0x7f || (pk[0] & 0xff) < 0xed) return false;
        for (int i = 1; i < 31; i++) if ((pk[i] & 0xff) != 0xff) return false;
        return true;
    }
    static boolean edVerify(byte[] pk, byte[] msg, byte[] sig) { if (weakEd25519(pk)) return false; try { Signature v = Signature.getInstance("Ed25519"); v.initVerify(key("Ed25519", ED_SPKI, pk)); v.update(msg); return v.verify(sig); } catch (Exception e) { return false; } }
    static Boolean mldsaSupported() { try { Signature.getInstance("ML-DSA-65"); return true; } catch (Exception e) { return false; } }
    static boolean mldsaVerify(byte[] pk, byte[] msg, byte[] sig) { try { Signature v = Signature.getInstance("ML-DSA-65"); v.initVerify(key("ML-DSA", MLDSA65_SPKI, pk)); v.update(msg); return v.verify(sig); } catch (Exception e) { return false; } }

    // ───────────────────────── receipt (minimal JSON writer) ─────────────────────────
    static String j(Object v) {
        if (v == null) return "null";
        if (v instanceof Boolean || v instanceof Integer || v instanceof Long) return String.valueOf(v);
        if (v instanceof String) { StringBuilder b = new StringBuilder(); writeString(b, (String) v); return b.toString(); }
        if (v instanceof List) { StringBuilder b = new StringBuilder("["); List<?> l = (List<?>) v; for (int k = 0; k < l.size(); k++) { if (k > 0) b.append(","); b.append(j(l.get(k))); } return b.append("]").toString(); }
        if (v instanceof Map) { StringBuilder b = new StringBuilder("{"); boolean first = true; for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) { if (!first) b.append(","); first = false; b.append(j(e.getKey())).append(":").append(j(e.getValue())); } return b.append("}").toString(); }
        return "\"?\"";
    }


    // ───────────────────────── helpers ─────────────────────────
    static String sha(String algo, byte[] p) throws Exception { return toHex(MessageDigest.getInstance(algo).digest(p)); }
    static String str(Obj o, String k) { Object v = o.vals.get(k); return v instanceof String ? (String) v : null; }
    static Obj without(Obj o, String drop) { Obj cp = new Obj(); for (String k : o.keys) if (!k.equals(drop)) { cp.keys.add(k); cp.vals.put(k, o.vals.get(k)); } return cp; }
    static boolean honestScope(String s) {
        if (s == null || !SCOPE_LIMIT.matcher(s).find()) return false;
        if (SCOPE_OVERCLAIM.matcher(s).find() && !SCOPE_NEGATED.matcher(s).find()) return false;
        return true;
    }
    // One verifier input (25/09/2026, NEMESIS: a FIFO in place of a sidecar blocked the four verifiers, a symlink to
    // /dev/zero exhausted memory): accepted only when the path resolves to a regular file, read to at most
    // MAX_INPUT_BYTES + 1 bytes. The JDK has no O_NONBLOCK, so the type is checked on the path right BEFORE the open —
    // a FIFO in place is never opened; one swapped in between the check and the open can still block (a race the other
    // three close by checking the opened descriptor; declared in the README).
    static byte[] readInput(String path) throws Bad, IOException {
        Path p = Path.of(path);
        if (!Files.readAttributes(p, java.nio.file.attribute.BasicFileAttributes.class).isRegularFile()) throw new Bad(path + ": not a regular file");
        try (java.nio.channels.FileChannel ch = java.nio.channels.FileChannel.open(p, StandardOpenOption.READ)) {
            // sized from the channel (no doubling copies), grown only if the file grows, never past MAX_INPUT_BYTES + 1
            byte[] b = new byte[(int) Math.min(Math.max(ch.size(), 0L), (long) MAX_INPUT_BYTES) + 1]; int total = 0;
            while (true) {
                if (total == b.length) { if (b.length > MAX_INPUT_BYTES) break; b = Arrays.copyOf(b, (int) Math.min(2L * b.length, MAX_INPUT_BYTES + 1L)); }
                int n = ch.read(java.nio.ByteBuffer.wrap(b, total, b.length - total));
                if (n < 0) break;
                total += n;
            }
            if (total > MAX_INPUT_BYTES) throw new Bad(path + ": input exceeds " + MAX_INPUT_BYTES + " bytes");
            return total == b.length ? b : Arrays.copyOf(b, total);
        }
    }
    static Obj readObject(String path) throws Bad, IOException { return objectOf(readInput(path)); }
    static boolean jsonWs(byte c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }
    static Obj objectOf(byte[] raw) throws Bad {
        // trimmed of ASCII space/tab/CR/LF on the bytes (single-byte characters, so the same cut as on the decoded text),
        // then decoded ONCE by parse(); a non-UTF-8 byte is refused there, as before
        int a = 0, z = raw.length; while (a < z && jsonWs(raw[a])) a++; while (z > a && jsonWs(raw[z - 1])) z--;
        Object v = parse(a == 0 && z == raw.length ? raw : Arrays.copyOfRange(raw, a, z));
        if (!(v instanceof Obj)) throw new Bad("not a JSON object");
        return (Obj) v;
    }
    static String sidecar(String pack, String suffix) { return pack.endsWith(".json") ? pack.substring(0, pack.length() - 5) + suffix : pack + suffix; }

    // ───────────────────────── strict ledger chain (the cryptovalid profile; self_hash is the only attestation key here) ─────────────────────────
    static List<Obj> ledgerEntries(String path, boolean[] ok) throws Exception {
        List<Obj> out = new ArrayList<>(); ok[0] = true;
        String prev = GENESIS; int n = 0;
        byte[] all; try { all = readInput(path); requireUtf8(all); } catch (Bad | IOException e) { ok[0] = false; return out; }   // bounded, regular file only; one bad byte anywhere = unreadable, as before
        {
            // LF lines cut on the BYTES (25/09/2026: decode, cut, re-encode and decode again held four copies of a long line);
            // for valid UTF-8 the bytes of a line are exactly the re-encoding of its decoded text
            // one line at a time: a List<int[]> of every line first ran out of memory on 64 MiB of empty lines (26/09/2026)
            for (int start = 0; start <= all.length; ) {
                int end = start; while (end < all.length && all[end] != '\n') end++;
                int[] ln = {start, end}; start = end + 1;
                if (!ok[0]) break;   // chain already broken, no caller reads its entries: stop accumulating (26/09: 22 M "{}" lines → OOM)
                if (ln[0] == ln[1] && ln[1] == all.length && all.length > 0 && all[all.length - 1] == '\n') break;   // after a final LF: nothing
                boolean blank = true; for (int k = ln[0]; k < ln[1]; k++) if (all[k] != ' ' && all[k] != '\t' && all[k] != '\r') { blank = false; break; }
                if (blank) continue;
                Object v; try { v = parse(ln[0] == 0 && ln[1] == all.length ? all : Arrays.copyOfRange(all, ln[0], ln[1])); } catch (Bad e) { ok[0] = false; n++; continue; }
                if (!(v instanceof Obj)) { ok[0] = false; n++; continue; }
                Obj e = (Obj) v;
                Object idx = e.vals.get("idx"); String sh = str(e, "self_hash"), ph = str(e, "prev_hash");
                String sum = canonHash("SHA-256", without(e, "self_hash"));
                if (!(idx instanceof Num) || !((Num) idx).lexeme.equals(String.valueOf(n)) || ph == null || !ph.equals(prev) || sh == null || !sh.equals(sum)) ok[0] = false;
                if (sh != null) prev = sh;
                out.add(e); n++;
            }
        }
        return ok[0] ? out : new ArrayList<>();
    }
    static boolean anchors(Obj e, String digest) {
        if (digest.equals(str(e, "anchored_pack_sha3"))) return true;
        Object d = e.vals.get("data");
        return d instanceof Obj && digest.equals(str((Obj) d, "anchored_pack_sha3"));
    }
    static final class TrustEntry { String pubkey, pq; boolean revoked; }
    static Map<String, TrustEntry> trustState(String path, boolean[] ok) throws Exception {
        Map<String, TrustEntry> st = new HashMap<>();
        for (Obj e : ledgerEntries(path, ok)) {
            Object d = e.vals.get("data"); if (!(d instanceof Obj)) { ok[0] = false; return st; } Obj dd = (Obj) d;   // council r2: malformed record = broken store
            String act = str(dd, "action"); if (!"trust".equals(act) && !"rotate".equals(act) && !"revoke".equals(act)) continue;
            String sid = str(dd, "signer_id"), pk = str(dd, "pubkey"), pq = str(dd, "pq_pubkey");
            if (sid == null || sid.isEmpty() || (!"revoke".equals(act) && (pk == null || pk.isEmpty())) || (dd.vals.containsKey("pq_pubkey") && (pq == null || pq.isEmpty()))) { ok[0] = false; return st; }
            if ("trust".equals(act)) { TrustEntry cur = st.get(sid); if (cur != null && cur.revoked) continue; TrustEntry t = new TrustEntry(); t.pubkey = pk; t.pq = pq; st.put(sid, t); }
            else if ("rotate".equals(act)) { TrustEntry t = new TrustEntry(); t.pubkey = pk; t.pq = pq; st.put(sid, t); }
            else if ("revoke".equals(act)) { TrustEntry cur = st.get(sid); if (cur != null) cur.revoked = true; }
        }
        return st;
    }

    // ───────────────────────── the verdict ─────────────────────────
    public static void main(String[] args) {
        try { run(args); }
        // a fault outside verifyPack's own guard: still not a finding — NOT_ASSESSED, exit 77 (25/09/2026: this printed
        // verdict FAIL and exited 1 on ANY Throwable, an OutOfMemoryError included)
        catch (Throwable t) { System.out.println(j(internalError(new ArrayList<>(), t))); System.exit(77); }
    }
    // A fault of the TOOL is not a finding about the pack: the layer "internal" is FAIL with assessed=false, so the run is
    // NOT_ASSESSED unless a layer judged before the fault is adverse (FAIL > NOT_ASSESSED > PASS); never authenticated,
    // never pq-protected.
    static Map<String, Object> internalError(List<Map<String, Object>> layers, Throwable t) {
        List<Map<String, Object>> ls = new ArrayList<>(layers);
        Map<String, Object> m = new LinkedHashMap<>(); m.put("layer", "internal"); m.put("status", "FAIL");
        m.put("detail", "verifier error, not a finding about the pack: " + t.getClass().getSimpleName()); m.put("assessed", Boolean.FALSE); ls.add(m);
        Map<String, Object> r = finish(ls, false, false, false);
        r.put("authenticated", false); r.put("pq_protected", false);
        return r;
    }
    static String val(String[] args, int k) { if (k >= args.length || args[k].isEmpty() || args[k].startsWith("-")) usage(); return args[k]; }   // "" or a flag as a value: usage (21/09/2026)
    static void usage() { System.err.println("usage: java OeVerify.java <pack.json> [-ledger L] [-trust-store T] [-expect-pq-key B64] [-require-pq]"); System.exit(2); }
    static void run(String[] args) throws Exception {
        String pack = null, ledger = "", trust = "", epq = ""; boolean reqPQ = false;
        for (int k = 0; k < args.length; k++) {
            String a = args[k]; String v = null; if (a.startsWith("--") && a.length() > 2) a = a.substring(1);   // r4: -flag and --flag alike
            int eq = a.indexOf('=');
            if (eq > 0 && a.startsWith("-")) { v = a.substring(eq + 1); a = a.substring(0, eq); }   // -flag=value (one grammar in the four)
            try {
                switch (a) {
                    case "-ledger": ledger = v != null ? val(new String[]{v}, 0) : val(args, ++k); break;
                    case "-trust-store": trust = v != null ? val(new String[]{v}, 0) : val(args, ++k); break;
                    case "-expect-pq-key": epq = v != null ? val(new String[]{v}, 0) : val(args, ++k); break;
                    case "-require-pq": if (v != null) { usage(); return; } reqPQ = true; break;
                    default: if (a.startsWith("-") || a.isEmpty() || pack != null || v != null) { usage(); return; } pack = a;
                }
            } catch (ArrayIndexOutOfBoundsException e) { usage(); return; }
        }
        if (pack == null) { usage(); return; }
        Map<String, Object> r = verifyPack(pack, ledger, trust, epq, reqPQ);
        System.out.println(j(r));
        String v = (String) r.get("verdict");
        System.exit("PASS".equals(v) ? 0 : "FAIL".equals(v) ? 1 : 77);   // 77 = the check did not run on this JDK
    }

    static Map<String, Object> verifyPack(String packPath, String ledgerPath, String trustStore, String expectedPQ, boolean requirePQ) {
        List<Map<String, Object>> layers = new ArrayList<>();
        try { return verifyPackIn(layers, packPath, ledgerPath, trustStore, expectedPQ, requirePQ); }
        catch (Throwable t) { return internalError(layers, t); }
    }
    static Map<String, Object> verifyPackIn(List<Map<String, Object>> layers, String packPath, String ledgerPath, String trustStore, String expectedPQ, boolean requirePQ) throws Exception {
        java.util.function.BiConsumer<String[], String> add = (ls, d) -> { Map<String, Object> m = new LinkedHashMap<>(); m.put("layer", ls[0]); m.put("status", ls[1]); m.put("detail", d); layers.add(m); };
        boolean required = requirePQ || !expectedPQ.isEmpty();
        Obj pack; byte[] packBytes;   // read ONCE: the timestamp binding hashes these bytes, not a second read
        try { packBytes = readInput(packPath); pack = objectOf(packBytes); } catch (Exception e) { add.accept(new String[]{"pack-json", "FAIL"}, e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()); return finish(layers, false, false, required); }
        add.accept(new String[]{"pack-json", "PASS"}, "");
        String scope = str(pack, "honest_scope");
        if (honestScope(scope)) add.accept(new String[]{"honest-scope", "PASS"}, "limit declared"); else add.accept(new String[]{"honest-scope", "FAIL"}, "no explicit honest_scope (or overclaim without a real NOT-limit)");
        String declared = str(pack, "pack_sha3"); if (declared == null) declared = "";
        String computed = canonHash("SHA3-256", without(pack, "pack_sha3"));
        add.accept(new String[]{"pack-sha3", !declared.isEmpty() && declared.equals(computed) ? "PASS" : "FAIL"}, "");
        if ("1".equals(System.getenv(INJECT_ENV))) throw new IllegalStateException("internal error injected by " + INJECT_ENV);
        // ledger anchor
        String lp = ledgerPath;
        if (lp.isEmpty() && Files.exists(Path.of(sidecar(packPath, ".ledger.jsonl")))) lp = sidecar(packPath, ".ledger.jsonl");
        boolean ledgerOK = false;
        if (lp.isEmpty()) add.accept(new String[]{"ledger-chain", "SKIP"}, "no ledger beside pack");
        else {
            boolean[] ok = new boolean[1]; List<Obj> entries;
            try { entries = ledgerEntries(lp, ok); } catch (Exception e) { entries = new ArrayList<>(); ok[0] = false; }
            if (!ok[0]) add.accept(new String[]{"ledger-chain", "FAIL"}, lp + ": broken chain");
            else if (entries.isEmpty()) add.accept(new String[]{"ledger-chain", "FAIL"}, lp + ": ledger empty — nothing anchored");
            else { boolean anch = false; for (Obj e : entries) if (!declared.isEmpty() && anchors(e, declared)) { anch = true; break; }
                if (anch) { add.accept(new String[]{"ledger-chain", "PASS"}, lp + ": pack_sha3 recorded"); ledgerOK = true; }
                else add.accept(new String[]{"ledger-chain", "FAIL"}, "valid chain but this pack is not anchored (no anchored_pack_sha3 entry)"); }
        }
        if (Files.exists(Path.of(sidecar(packPath, ".tsr.json")))) {   // shape + content-binding checked like the reference; the token itself is not
            Obj ts = null; try { ts = readObject(sidecar(packPath, ".tsr.json")); } catch (Exception e) { ts = null; }
            if (ts == null) add.accept(new String[]{"timestamp", "FAIL"}, "malformed sidecar");
            else if (!sha("SHA-256", packBytes).equals(str(ts, "digest_sha256"))) add.accept(new String[]{"timestamp", "FAIL"}, "pack changed after stamping");
            else add.accept(new String[]{"timestamp", "SKIP"}, "RFC 3161 token present and bound to the pack: not verified by any of the four verifiers (no trust anchor); the cryptographic check is timestamp.verify(..., ca_file=) for the operator");
        }
        else add.accept(new String[]{"timestamp", "SKIP"}, "no timestamp sidecar");
        // producer signature
        String sigStatus = "SKIP"; boolean trusted = false, trustFailed = false;
        String sp = sidecar(packPath, ".sig.json");
        if (!Files.exists(Path.of(sp))) add.accept(new String[]{"producer-signature", "SKIP"}, "pack not signed");
        else {
            Obj side = null;
            try { side = readObject(sp); } catch (Exception e) { add.accept(new String[]{"producer-signature", "FAIL"}, "malformed sidecar: " + e.getMessage()); sigStatus = "FAIL"; }
            if (side != null) {
                boolean algPresent = side.vals.containsKey("sig_alg");
                String alg = algPresent ? str(side, "sig_alg") : "ed25519";
                String signedDigest = str(side, "signed_pack_sha3"), pkB64 = str(side, "public_key_b64"), sigB64 = str(side, "signature_b64");
                if (algPresent && (alg == null || alg.isEmpty())) { add.accept(new String[]{"producer-signature", "FAIL"}, "malformed sidecar fields: sig_alg is not a non-empty string"); sigStatus = "FAIL"; }  // council 16/09 r1; "" is present and malformed (25/09/2026)
                else if (!"ed25519".equals(alg)) add.accept(new String[]{"producer-signature", "SKIP"}, "unsupported sig_alg: " + alg);
                else {
                    byte[] pk = b64Strict(pkB64, 32), sig = b64Strict(sigB64, 64);
                    if (pk == null || sig == null || !declared.matches("[0-9a-f]{64}")) { add.accept(new String[]{"producer-signature", "FAIL"}, "malformed sidecar fields (strict base64 32/64, lowercase hex digest)"); sigStatus = "FAIL"; }   // council r3
                    // 25/09/2026 (NEMESIS): fingerprint / signed_utc were never read ("", 0, null, true, [], {}: PASS, authenticated).
                    // Absent = legacy, fine; present = what sign_pack writes (derived from THIS key; the exact instant form)
                    else if (side.vals.containsKey("fingerprint") && !fingerprintOf(pk).equals(side.vals.get("fingerprint"))) { add.accept(new String[]{"producer-signature", "FAIL"}, "malformed sidecar field: fingerprint is not the one derived from public_key_b64"); sigStatus = "FAIL"; }
                    else if (side.vals.containsKey("signed_utc") && !signedUtcOK(side.vals.get("signed_utc"))) { add.accept(new String[]{"producer-signature", "FAIL"}, "malformed sidecar field: signed_utc is not YYYY-MM-DDTHH:MM:SS+00:00"); sigStatus = "FAIL"; }
                    else {
                    boolean okSig = edVerify(pk, declared.getBytes(StandardCharsets.UTF_8), sig);
                    if (!okSig || !declared.equals(signedDigest)) { add.accept(new String[]{"producer-signature", "FAIL"}, "signature invalid or pack changed"); sigStatus = "FAIL"; }
                    else {
                        String sid = str(side, "signer_id");
                        if (sid == null || sid.isEmpty()) { add.accept(new String[]{"producer-signature", "FAIL"}, "malformed sidecar fields: signer_id must be a non-empty string"); sigStatus = "FAIL"; }   // council r2
                        else {
                        add.accept(new String[]{"producer-signature", "PASS"}, "signed by " + sid + " (ed25519)"); sigStatus = "PASS";
                        Map<String, TrustEntry> st = null; boolean[] stOK = new boolean[]{true};
                        if (!trustStore.isEmpty()) { try { st = trustState(trustStore, stOK); } catch (Exception e) { st = new HashMap<>(); stOK[0] = false; } }
                        String pinned = expectedPQ;
                        // the registry's PQ pin is borrowed only when the classical key that signed is the registered one (council 16/09 r1)
                        if (pinned.isEmpty() && st != null && stOK[0]) { TrustEntry te = st.get(sid); if (te != null && !te.revoked && te.pq != null && te.pubkey != null && te.pubkey.equals(pkB64)) pinned = te.pq; }
                        checkPQ(layers, side, declared, pinned, requirePQ);
                        if (!trustStore.isEmpty()) {
                            TrustEntry te = st.get(sid);
                            if (stOK[0] && te != null && !te.revoked && te.pubkey != null && te.pubkey.equals(pkB64)) { add.accept(new String[]{"trusted-signer", "PASS"}, sid + " in trust registry"); trusted = true; }
                            else { String d = !stOK[0] ? "trust store unreadable or broken" : te != null && te.revoked ? sid + ": key revoked" : te != null ? sid + ": key differs" : sid + ": not in trust registry"; add.accept(new String[]{"trusted-signer", "FAIL"}, d); trustFailed = true; }
                        }
                        }
                    }
                    }
                }
            }
        }
        if (required && !"PASS".equals(sigStatus)) add.accept(new String[]{"pq-signature", "FAIL"}, "post-quantum layer required but the pack carries no valid classical signature (hybrid = both)");
        if ("FAIL".equals(sigStatus)) add.accept(new String[]{"authenticity", "FAIL"}, "producer signature present but invalid");
        else if (trustFailed) add.accept(new String[]{"authenticity", "FAIL"}, "valid signature but signer not trusted/revoked");
        else if (trusted) add.accept(new String[]{"authenticity", "PASS"}, "trusted-signed");
        else if ("PASS".equals(sigStatus)) add.accept(new String[]{"authenticity", "PASS"}, "signed (identity not checked against a registry)");
        else if (ledgerOK) add.accept(new String[]{"authenticity", "PASS"}, "anchored (integrity/time, not identity)");
        else add.accept(new String[]{"authenticity", "FAIL"}, "no anchor and no signature: cannot authenticate");
        return finish(layers, trusted, "PASS".equals(sigStatus) && !trustFailed, required);   // council 16/09 r1: never authenticated for a revoked/untrusted signer
    }

    // signing.Identity.fingerprint: "ed25519:" + first 8 + U+2026 + last 8 hex digits of SHA-256(raw public key)
    static String fingerprintOf(byte[] pk) throws Exception { String h = sha("SHA-256", pk); return "ed25519:" + h.substring(0, 8) + "\u2026" + h.substring(56); }
    static final Pattern SIGNED_UTC = Pattern.compile("[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\+00:00");
    // the instant sign_pack writes (isoformat, seconds, +00:00), ASCII digits, a real calendar date, year >= 1, second <= 59
    static boolean signedUtcOK(Object v) {
        if (!(v instanceof String) || !SIGNED_UTC.matcher((String) v).matches()) return false;
        String s = (String) v;
        int y = Integer.parseInt(s.substring(0, 4)), mo = Integer.parseInt(s.substring(5, 7)), d = Integer.parseInt(s.substring(8, 10));
        int h = Integer.parseInt(s.substring(11, 13)), mi = Integer.parseInt(s.substring(14, 16)), se = Integer.parseInt(s.substring(17, 19));
        boolean leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        int[] dim = {31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
        return y >= 1 && mo >= 1 && mo <= 12 && d >= 1 && d <= dim[mo - 1] && h <= 23 && mi <= 59 && se <= 59;
    }

    // PQ algorithms the project implements a backend for somewhere; membership does not mean THIS JDK has it.
    static final java.util.Set<String> KNOWN_PQ_ALGS = java.util.Set.of("ml-dsa-65", "slh-dsa-sha2-128s");

    static void checkPQ(List<Map<String, Object>> layers, Obj side, String digest, String expectedPQ, boolean requirePQ) {
        java.util.function.BiConsumer<String, String> add = (s, d) -> { Map<String, Object> m = new LinkedHashMap<>(); m.put("layer", "pq-signature"); m.put("status", s); m.put("detail", d); layers.add(m); };
        boolean required = requirePQ || !expectedPQ.isEmpty();
        Object palgRaw = side.vals.get("pq_sig_alg");
        if (side.vals.containsKey("pq_sig_alg") && (!(palgRaw instanceof String) || ((String) palgRaw).isEmpty())) { add.accept("FAIL", "pq_sig_alg is not a non-empty string"); return; }   // "" is present and malformed, not absent (25/09/2026)
        String palg = (String) palgRaw;
        if (palg == null || palg.isEmpty()) { if (required) add.accept("FAIL", "post-quantum layer required but absent (stripped or never signed)"); return; }
        String pkB64 = str(side, "pq_public_key_b64"), sigB64 = str(side, "pq_signature_b64");
        if (!expectedPQ.isEmpty() && !expectedPQ.equals(pkB64)) { add.accept("FAIL", palg + " co-signature by a key other than the pinned one"); return; }
        if (!"ml-dsa-65".equals(palg)) {
            // Same split as the Python verifier: a PQ algorithm the project knows but this runtime does not implement
            // is an absence; a name nobody knows stays a judgment (it can never be pq-protected).
            add.accept(required ? "FAIL" : "SKIP", palg + " is not a registered PQ backend (pq-present-unverified" + (required ? ": a required layer that cannot be checked is not a pass)" : ")"));
            if (KNOWN_PQ_ALGS.contains(palg)) layers.get(layers.size() - 1).put("assessed", Boolean.FALSE);
            return;
        }
        // FORM BEFORE CAPABILITY (24/09/2026): well-formedness needs no backend, so it is judged first. Probing the
        // backend first handed a real defect of the artifact to the absence side on a JDK without ML-DSA.
        byte[] pk = b64Strict(pkB64, 1952), sig = b64Strict(sigB64, 3309);
        if (pk == null || sig == null) { add.accept("FAIL", "ml-dsa-65 co-signature is not strict base64 of the expected length (checked without a backend)"); return; }
        if (!mldsaSupported()) {
            // This JDK cannot run the check: FAIL when required (fail-closed), but marked so the roll-up does not
            // report OUR missing capability as a finding about the pack. An unknown algorithm name stays a judgment.
            add.accept(required ? "FAIL" : "SKIP", "ml-dsa-65 present but this JDK has no ML-DSA (pq-present-unverified" + (required ? ": not a pass)" : ")"));
            // marked on SKIP too: an optional layer this JDK cannot read still makes the run inconclusive
            layers.get(layers.size() - 1).put("assessed", Boolean.FALSE);
            return;
        }
        if (!mldsaVerify(pk, digest.getBytes(StandardCharsets.UTF_8), sig)) { add.accept("FAIL", "ml-dsa-65 co-signature invalid"); return; }
        if (expectedPQ.isEmpty()) { add.accept(required ? "FAIL" : "SKIP", "ml-dsa-65 co-signature valid against the key INSIDE the sidecar only (pq-present-unpinned)"); return; }
        add.accept("PASS", "pq-protected (ml-dsa-65, pinned key)");
    }

    static Map<String, Object> finish(List<Map<String, Object>> layers, boolean trusted, boolean signed, boolean pqRequired) {
        boolean valid = true, checked = false; Boolean pq = null; boolean hasPQ = false;
        for (Map<String, Object> l : layers) {
            String s = (String) l.get("status");
            if (s.equals("PASS") || s.equals("FAIL")) { checked = true; if (s.equals("FAIL")) valid = false; }
            if ("pq-signature".equals(l.get("layer"))) { hasPQ = true; pq = s.equals("PASS") ? Boolean.TRUE : s.equals("SKIP") ? null : Boolean.FALSE; }
        }
        if (!hasPQ) pq = Boolean.FALSE;
        boolean integrity = false; for (Map<String, Object> l : layers) if ("pack-sha3".equals(l.get("layer")) && "PASS".equals(l.get("status"))) integrity = true;   // council r2
        signed = signed && integrity; trusted = trusted && integrity;
        boolean anyAbsent = false, anyJudged = false;
        for (Map<String, Object> l : layers) {
            if (Boolean.FALSE.equals(l.get("assessed"))) anyAbsent = true;
            if ("FAIL".equals(l.get("status")) && !Boolean.FALSE.equals(l.get("assessed"))) anyJudged = true;
        }
        boolean assessed = anyJudged || !anyAbsent;    // FAIL > NOT_ASSESSED > PASS, SKIP included
        boolean passed = checked && valid && assessed && (!pqRequired || Boolean.TRUE.equals(pq));
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("valid", checked && valid); r.put("assessed", assessed); r.put("layers", layers);
        r.put("authenticated", trusted || signed); r.put("pq_protected", pq);
        r.put("verdict", passed ? "PASS" : (assessed ? "FAIL" : "NOT_ASSESSED"));
        r.put("verifier", "OeVerify (Java, JDK stdlib)");
        return r;
    }
}
