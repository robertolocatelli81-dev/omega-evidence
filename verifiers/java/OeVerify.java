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
    static final long MAX_INPUT_BYTES = 256L * 1024 * 1024;
    static final Set<String> ATTEST = Set.of("self_hash");   // omega-evidence ledgers: self_hash is the only attestation key
    static final String GENESIS = "0".repeat(64);
    static final byte[] ED_SPKI = hex("302a300506032b6570032100");
    static final byte[] MLDSA65_SPKI = hex("308207b2300b0609608648016503040312038207a100");
    static final Pattern SCOPE_LIMIT = Pattern.compile("\\bNOT\\b");
    static final Pattern SCOPE_OVERCLAIM = Pattern.compile("\\b(accredited|certified|qualified|guaranteed)\\b", Pattern.CASE_INSENSITIVE);
    static final Pattern SCOPE_NEGATED = Pattern.compile("\\bNOT\\b[^.]{0,40}(accredit|certif|qualif|guarant)", Pattern.CASE_INSENSITIVE);

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

    static Object parse(byte[] text) throws Bad {
        String s;
        try { s = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(java.nio.ByteBuffer.wrap(text)).toString(); }
        catch (CharacterCodingException e) { throw new Bad("non-UTF-8 input"); }
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
            StringBuilder b = new StringBuilder(); i++;
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
    static void encode(StringBuilder b, Object v) {
        if (v == null) b.append("null");
        else if (v instanceof Boolean) b.append(((Boolean) v) ? "true" : "false");
        else if (v instanceof Num) b.append(((Num) v).lexeme);
        else if (v instanceof String) writeString(b, (String) v);
        else if (v instanceof List) { b.append('['); List<?> l = (List<?>) v; for (int k = 0; k < l.size(); k++) { if (k > 0) b.append(','); encode(b, l.get(k)); } b.append(']'); }
        else if (v instanceof Obj) {
            Obj o = (Obj) v; List<String> ks = new ArrayList<>(o.keys); ks.sort(BY_CODEPOINT); b.append('{');
            for (int k = 0; k < ks.size(); k++) { if (k > 0) b.append(','); writeString(b, ks.get(k)); b.append(':'); encode(b, o.vals.get(ks.get(k))); }
            b.append('}');
        } else throw new IllegalStateException("unsupported value");
    }
    static void writeString(StringBuilder b, String s) {
        b.append('"');
        s.codePoints().forEach(r -> {
            switch (r) {
                case '"': b.append("\\\""); break; case '\\': b.append("\\\\"); break; case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break; case '\t': b.append("\\t"); break; case '\b': b.append("\\b"); break; case '\f': b.append("\\f"); break;
                default:
                    if (r >= 0x20 && r <= 0x7e) b.append((char) r);
                    else if (r > 0xFFFF) { int q = r - 0x10000; b.append(String.format("\\u%04x\\u%04x", 0xD800 + (q >> 10), 0xDC00 + (q & 0x3FF))); }
                    else b.append(String.format("\\u%04x", r));
            }
        });
        b.append('"');
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
    static boolean edVerify(byte[] pk, byte[] msg, byte[] sig) { try { Signature v = Signature.getInstance("Ed25519"); v.initVerify(key("Ed25519", ED_SPKI, pk)); v.update(msg); return v.verify(sig); } catch (Exception e) { return false; } }
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
    static byte[] canonBytes(Obj o) { StringBuilder b = new StringBuilder(); encode(b, o); return b.toString().getBytes(StandardCharsets.UTF_8); }
    static boolean honestScope(String s) {
        if (s == null || !SCOPE_LIMIT.matcher(s).find()) return false;
        if (SCOPE_OVERCLAIM.matcher(s).find() && !SCOPE_NEGATED.matcher(s).find()) return false;
        return true;
    }
    static Obj readObject(String path) throws Bad, IOException {
        byte[] raw = Files.readAllBytes(Path.of(path));
        String t = new String(raw, StandardCharsets.UTF_8);   // trimmed of ASCII space/tab/CR/LF only
        int a = 0, z = t.length(); while (a < z && " \t\r\n".indexOf(t.charAt(a)) >= 0) a++; while (z > a && " \t\r\n".indexOf(t.charAt(z - 1)) >= 0) z--;
        Object v = parse(t.substring(a, z).getBytes(StandardCharsets.UTF_8));
        if (!(v instanceof Obj)) throw new Bad("not a JSON object");
        return (Obj) v;
    }
    static String sidecar(String pack, String suffix) { return pack.endsWith(".json") ? pack.substring(0, pack.length() - 5) + suffix : pack + suffix; }

    // ───────────────────────── strict ledger chain (the cryptovalid profile; self_hash is the only attestation key here) ─────────────────────────
    static List<Obj> ledgerEntries(String path, boolean[] ok) throws Exception {
        List<Obj> out = new ArrayList<>(); ok[0] = true;
        if (Files.size(Path.of(path)) > MAX_INPUT_BYTES) { ok[0] = false; return out; }
        String prev = GENESIS; int n = 0;
        try (BufferedReader br = new BufferedReader(new InputStreamReader(new FileInputStream(path), StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder(); int c;
            List<String> lines = new ArrayList<>();
            while ((c = br.read()) >= 0) { if (c == '\n') { lines.add(sb.toString()); sb.setLength(0); } else sb.append((char) c); }
            if (sb.length() > 0) lines.add(sb.toString());
            for (String ln : lines) {
                boolean blank = true; for (char ch : ln.toCharArray()) if (ch != ' ' && ch != '\t' && ch != '\r') { blank = false; break; }
                if (blank) continue;
                Object v; try { v = parse(ln.getBytes(StandardCharsets.UTF_8)); } catch (Bad e) { ok[0] = false; n++; continue; }
                if (!(v instanceof Obj)) { ok[0] = false; n++; continue; }
                Obj e = (Obj) v;
                Object idx = e.vals.get("idx"); String sh = str(e, "self_hash"), ph = str(e, "prev_hash");
                String sum = sha("SHA-256", canonBytes(without(e, "self_hash")));
                if (!(idx instanceof Num) || !((Num) idx).lexeme.equals(String.valueOf(n)) || ph == null || !ph.equals(prev) || sh == null || !sh.equals(sum)) ok[0] = false;
                if (sh != null) prev = sh;
                out.add(e); n++;
            }
        }
        return out;
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
        catch (Throwable t) { System.out.println("{\"valid\":false,\"verdict\":\"FAIL\",\"layers\":[{\"layer\":\"internal\",\"status\":\"FAIL\",\"detail\":\"" + t.getClass().getSimpleName() + "\"}]}"); System.exit(1); }
    }
    static void usage() { System.err.println("usage: java OeVerify.java <pack.json> [-ledger L] [-trust-store T] [-expect-pq-key B64] [-require-pq]"); System.exit(2); }
    static void run(String[] args) throws Exception {
        String pack = null, ledger = "", trust = "", epq = ""; boolean reqPQ = false;
        for (int k = 0; k < args.length; k++) {
            String a = args[k];
            try {
                switch (a) {
                    case "-ledger": ledger = args[++k]; break; case "-trust-store": trust = args[++k]; break;
                    case "-expect-pq-key": epq = args[++k]; break; case "-require-pq": reqPQ = true; break;
                    default: if (a.startsWith("-") || pack != null) { usage(); return; } pack = a;
                }
            } catch (ArrayIndexOutOfBoundsException e) { usage(); return; }
        }
        if (pack == null) { usage(); return; }
        Map<String, Object> r = verifyPack(pack, ledger, trust, epq, reqPQ);
        System.out.println(j(r));
        System.exit("PASS".equals(r.get("verdict")) ? 0 : 1);
    }

    static Map<String, Object> verifyPack(String packPath, String ledgerPath, String trustStore, String expectedPQ, boolean requirePQ) throws Exception {
        List<Map<String, Object>> layers = new ArrayList<>();
        java.util.function.BiConsumer<String[], String> add = (ls, d) -> { Map<String, Object> m = new LinkedHashMap<>(); m.put("layer", ls[0]); m.put("status", ls[1]); m.put("detail", d); layers.add(m); };
        boolean required = requirePQ || !expectedPQ.isEmpty();
        Obj pack;
        try { pack = readObject(packPath); } catch (Exception e) { add.accept(new String[]{"pack-json", "FAIL"}, e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()); return finish(layers, false, false, required); }
        add.accept(new String[]{"pack-json", "PASS"}, "");
        String scope = str(pack, "honest_scope");
        if (honestScope(scope)) add.accept(new String[]{"honest-scope", "PASS"}, "limit declared"); else add.accept(new String[]{"honest-scope", "FAIL"}, "no explicit honest_scope (or overclaim without a real NOT-limit)");
        String declared = str(pack, "pack_sha3"); if (declared == null) declared = "";
        String computed = sha("SHA3-256", canonBytes(without(pack, "pack_sha3")));
        add.accept(new String[]{"pack-sha3", !declared.isEmpty() && declared.equals(computed) ? "PASS" : "FAIL"}, "");
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
            else if (!sha("SHA-256", Files.readAllBytes(Path.of(packPath))).equals(str(ts, "digest_sha256"))) add.accept(new String[]{"timestamp", "FAIL"}, "pack changed after stamping");
            else add.accept(new String[]{"timestamp", "SKIP"}, "RFC 3161 token present: not verified by this verifier (use the Python reference)");
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
                if (algPresent && alg == null) { add.accept(new String[]{"producer-signature", "FAIL"}, "malformed sidecar fields: sig_alg is not a string"); sigStatus = "FAIL"; }  // council 16/09 r1
                else if (!"ed25519".equals(alg)) add.accept(new String[]{"producer-signature", "SKIP"}, "unsupported sig_alg: " + alg);
                else {
                    byte[] pk = b64Strict(pkB64, 32), sig = b64Strict(sigB64, 64);
                    boolean okSig = pk != null && sig != null && !declared.isEmpty() && edVerify(pk, declared.getBytes(StandardCharsets.UTF_8), sig);
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
        if (required && !"PASS".equals(sigStatus)) add.accept(new String[]{"pq-signature", "FAIL"}, "post-quantum layer required but the pack carries no valid classical signature (hybrid = both)");
        if ("FAIL".equals(sigStatus)) add.accept(new String[]{"authenticity", "FAIL"}, "producer signature present but invalid");
        else if (trustFailed) add.accept(new String[]{"authenticity", "FAIL"}, "valid signature but signer not trusted/revoked");
        else if (trusted) add.accept(new String[]{"authenticity", "PASS"}, "trusted-signed");
        else if ("PASS".equals(sigStatus)) add.accept(new String[]{"authenticity", "PASS"}, "signed (identity not checked against a registry)");
        else if (ledgerOK) add.accept(new String[]{"authenticity", "PASS"}, "anchored (integrity/time, not identity)");
        else add.accept(new String[]{"authenticity", "FAIL"}, "no anchor and no signature: cannot authenticate");
        return finish(layers, trusted, "PASS".equals(sigStatus) && !trustFailed, required);   // council 16/09 r1: never authenticated for a revoked/untrusted signer
    }

    static void checkPQ(List<Map<String, Object>> layers, Obj side, String digest, String expectedPQ, boolean requirePQ) {
        java.util.function.BiConsumer<String, String> add = (s, d) -> { Map<String, Object> m = new LinkedHashMap<>(); m.put("layer", "pq-signature"); m.put("status", s); m.put("detail", d); layers.add(m); };
        boolean required = requirePQ || !expectedPQ.isEmpty();
        Object palgRaw = side.vals.get("pq_sig_alg");
        if (side.vals.containsKey("pq_sig_alg") && !(palgRaw instanceof String)) { add.accept("FAIL", "pq_sig_alg is not a string"); return; }
        String palg = (String) palgRaw;
        if (palg == null || palg.isEmpty()) { if (required) add.accept("FAIL", "post-quantum layer required but absent (stripped or never signed)"); return; }
        String pkB64 = str(side, "pq_public_key_b64"), sigB64 = str(side, "pq_signature_b64");
        if (!expectedPQ.isEmpty() && !expectedPQ.equals(pkB64)) { add.accept("FAIL", palg + " co-signature by a key other than the pinned one"); return; }
        if (!"ml-dsa-65".equals(palg)) { add.accept(required ? "FAIL" : "SKIP", palg + " is not a registered PQ backend (pq-present-unverified" + (required ? ": a required layer that cannot be checked is not a pass)" : ")")); return; }
        if (!mldsaSupported()) { add.accept(required ? "FAIL" : "SKIP", "ml-dsa-65 present but this JDK has no ML-DSA (pq-present-unverified" + (required ? ": not a pass)" : ")")); return; }
        byte[] pk = b64Strict(pkB64, 1952), sig = b64Strict(sigB64, 3309);
        if (pk == null || sig == null || !mldsaVerify(pk, digest.getBytes(StandardCharsets.UTF_8), sig)) { add.accept("FAIL", "ml-dsa-65 co-signature invalid"); return; }
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
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("valid", checked && valid); r.put("layers", layers); r.put("authenticated", trusted || signed); r.put("pq_protected", pq);
        r.put("verdict", (checked && valid && (!pqRequired || Boolean.TRUE.equals(pq))) ? "PASS" : "FAIL");
        r.put("verifier", "OeVerify (Java, JDK stdlib)");
        return r;
    }
}
