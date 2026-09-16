// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Roberto Locatelli
//
// pack.go — independent Go verifier of omega-evidence packs (0.7.0), the same layers and verdicts as
// omega_evidence/verifier.py: pack-json (strict acceptance profile), honest-scope, pack-sha3 (canonical JSON of the
// pack without pack_sha3, SHA3-256), ledger-chain (strict chain + the pack anchored by a dedicated
// anchored_pack_sha3 entry), producer-signature (Ed25519 sidecar over the pack_sha3 hex bytes), pq-signature
// (ML-DSA-65, empty context, PINNED tri-state), trusted-signer (the hash-chained trust registry), authenticity.
// RFC 3161 timestamp sidecars are NOT verified here (declared: SKIP "not verified by this verifier").
package oeverify

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha3"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

const Genesis = "0000000000000000000000000000000000000000000000000000000000000000"

type Layer struct {
	Layer  string `json:"layer"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type Receipt struct {
	Valid         bool    `json:"valid"`
	Layers        []Layer `json:"layers"`
	Authenticated bool    `json:"authenticated"`
	PQProtected   *bool   `json:"pq_protected"`
	Verdict       string  `json:"verdict"`
	Verifier      string  `json:"verifier"`
}

var (
	scopeLimit     = regexp.MustCompile(`\bNOT\b`)
	scopeOverclaim = regexp.MustCompile(`(?i)\b(accredited|certified|qualified|guaranteed)\b`)
	scopeNegated   = regexp.MustCompile(`(?i)\bNOT\b[^.]{0,40}(accredit|certif|qualif|guarant)`)
	hex64          = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func honestScope(s string) bool {
	if !scopeLimit.MatchString(s) {
		return false
	}
	if scopeOverclaim.MatchString(s) && !scopeNegated.MatchString(s) {
		return false
	}
	return true
}

func b64Strict(s string, n int) []byte {
	if len(s) != ((n+2)/3)*4 {
		return nil
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || len(raw) != n || base64.StdEncoding.EncodeToString(raw) != s {
		return nil
	}
	return raw
}

// payloadOE: the pack/entry without ONE key (pack_sha3 for packs, self_hash for ledger entries).
func without(o *Object, drop string) *Object {
	cp := &Object{Vals: map[string]any{}}
	for _, k := range o.Keys {
		if k == drop {
			continue
		}
		cp.Keys = append(cp.Keys, k)
		cp.Vals[k] = o.Vals[k]
	}
	return cp
}

func str(o *Object, k string) (string, bool) {
	v, ok := o.Vals[k].(string)
	return v, ok
}

func readObject(path string) (*Object, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	v, err := Parse([]byte(strings.Trim(string(raw), " \t\r\n")))
	if err != nil {
		return nil, err
	}
	o, ok := v.(*Object)
	if !ok {
		return nil, fmt.Errorf("not a JSON object")
	}
	return o, nil
}

// ledgerEntries verifies the strict chain (LF lines, blank = space/tab/CR, strict JSON, sequential idx,
// content → self_hash → prev link) and returns the parsed entries when the chain holds.
func ledgerEntries(path string) ([]*Object, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 64<<20)
	prev, n, ok := Genesis, 0, true
	var out []*Object
	for sc.Scan() {
		raw := sc.Bytes()
		blank := true
		for _, c := range raw {
			if c != ' ' && c != '\t' && c != '\r' {
				blank = false
				break
			}
		}
		if blank {
			continue
		}
		v, err := Parse(raw)
		e, isObj := v.(*Object)
		if err != nil || !isObj {
			ok = false
			n++
			continue
		}
		idx, _ := e.Vals["idx"].(json.Number)
		sh, _ := str(e, "self_hash")
		ph, _ := str(e, "prev_hash")
		p, perr := Canonical(without(e, "self_hash"))
		sum := sha256Hex(p)
		if perr != nil || idx.String() != fmt.Sprint(n) || ph != prev || sh != sum {
			ok = false
		}
		if sh != "" {
			prev = sh
		}
		out = append(out, e)
		n++
	}
	if sc.Err() != nil {
		ok = false
	}
	return out, ok
}

func anchors(e *Object, digest string) bool {
	if v, _ := str(e, "anchored_pack_sha3"); v == digest {
		return true
	}
	if d, ok := e.Vals["data"].(*Object); ok {
		if v, _ := str(d, "anchored_pack_sha3"); v == digest {
			return true
		}
	}
	return false
}

// trustState replays the hash-chained trust registry exactly like TrustRegistry._apply.
type trustEntry struct {
	pubkey, pqPubkey string
	revoked          bool
}

func trustState(path string) (map[string]*trustEntry, bool) {
	entries, ok := ledgerEntries(path)
	st := map[string]*trustEntry{}
	if !ok {
		return st, false
	}
	for _, e := range entries {
		d, isObj := e.Vals["data"].(*Object)
		if !isObj {
			continue
		}
		act, _ := str(d, "action")
		sid, _ := str(d, "signer_id")
		if sid == "" {
			continue
		}
		pk, _ := str(d, "pubkey")
		pq, _ := str(d, "pq_pubkey")
		switch act {
		case "trust":
			if cur := st[sid]; cur != nil && cur.revoked {
				continue
			}
			st[sid] = &trustEntry{pubkey: pk, pqPubkey: pq}
		case "rotate":
			st[sid] = &trustEntry{pubkey: pk, pqPubkey: pq}
		case "revoke":
			if cur := st[sid]; cur != nil {
				cur.revoked = true
			}
		}
	}
	return st, true
}

func sidecarPath(pack, suffix string) string {
	if strings.HasSuffix(pack, ".json") {
		return pack[:len(pack)-5] + suffix
	}
	return pack + suffix
}

// VerifyPack mirrors omega_evidence.verifier.verify_pack. expectedPQ pins the ML-DSA-65 key (and requires the
// layer); requirePQ requires a pinned, valid layer (through the trust registry).
func VerifyPack(packPath, ledgerPath, trustStore, expectedPQ string, requirePQ bool) Receipt {
	r := Receipt{Layers: []Layer{}, Verifier: "oeverify (Go, stdlib)"}
	add := func(l, s, d string) { r.Layers = append(r.Layers, Layer{l, s, d}) }
	pack, err := readObject(packPath)
	if err != nil {
		add("pack-json", "FAIL", err.Error())
		return finish(r, "", false, false, "FAIL", false)
	}
	add("pack-json", "PASS", "")
	scope, _ := str(pack, "honest_scope")
	if honestScope(scope) {
		add("honest-scope", "PASS", "limit declared")
	} else {
		add("honest-scope", "FAIL", "no explicit honest_scope (or overclaim without a real NOT-limit)")
	}
	declared, _ := str(pack, "pack_sha3")
	canon, cerr := Canonical(without(pack, "pack_sha3"))
	computed := ""
	if cerr != nil {
		add("pack-sha3", "FAIL", "not canonicalisable")
	} else {
		s := sha3.Sum256(canon)
		computed = hex.EncodeToString(s[:])
		if declared != "" && declared == computed {
			add("pack-sha3", "PASS", "")
		} else {
			add("pack-sha3", "FAIL", "")
		}
	}
	// ledger anchor
	lp := ledgerPath
	if lp == "" {
		if _, e := os.Stat(sidecarPath(packPath, ".ledger.jsonl")); e == nil {
			lp = sidecarPath(packPath, ".ledger.jsonl")
		}
	}
	ledgerOK := false
	if lp == "" {
		add("ledger-chain", "SKIP", "no ledger beside pack")
	} else if entries, ok := ledgerEntries(lp); !ok {
		add("ledger-chain", "FAIL", lp+": broken chain")
	} else if len(entries) == 0 {
		add("ledger-chain", "FAIL", lp+": ledger empty — nothing anchored")
	} else {
		anch := false
		for _, e := range entries {
			if declared != "" && anchors(e, declared) {
				anch = true
				break
			}
		}
		if anch {
			add("ledger-chain", "PASS", lp+": pack_sha3 recorded")
			ledgerOK = true
		} else {
			add("ledger-chain", "FAIL", "valid chain but this pack is not anchored (no anchored_pack_sha3 entry)")
		}
	}
	// timestamp sidecar: declared, not verified here
	tsStatus := "SKIP"
	if _, e := os.Stat(sidecarPath(packPath, ".tsr.json")); e == nil {
		add("timestamp", "SKIP", "RFC 3161 token present: not verified by this verifier (use the Python reference)")
	} else {
		add("timestamp", "SKIP", "no timestamp sidecar")
	}
	// producer signature
	sigStatus, trusted, trustFailed := "SKIP", false, false
	sp := sidecarPath(packPath, ".sig.json")
	var side *Object
	if _, e := os.Stat(sp); e != nil {
		add("producer-signature", "SKIP", "pack not signed")
	} else if side, err = readObject(sp); err != nil {
		add("producer-signature", "FAIL", "malformed sidecar: "+err.Error())
		sigStatus = "FAIL"
	} else {
		alg, hasAlg := str(side, "sig_alg")
		if !hasAlg {
			alg = "ed25519"
		}
		signedDigest, _ := str(side, "signed_pack_sha3")
		pkB64, _ := str(side, "public_key_b64")
		sigB64, _ := str(side, "signature_b64")
		if alg != "ed25519" {
			add("producer-signature", "SKIP", "unsupported sig_alg: "+alg)
		} else {
			pk, sig := b64Strict(pkB64, 32), b64Strict(sigB64, 64)
			okSig := pk != nil && sig != nil && declared != "" && ed25519.Verify(ed25519.PublicKey(pk), []byte(declared), sig)
			if !okSig || signedDigest != declared {
				add("producer-signature", "FAIL", "signature invalid or pack changed")
				sigStatus = "FAIL"
			} else {
				sid, _ := str(side, "signer_id")
				add("producer-signature", "PASS", "signed by "+sid+" (ed25519)")
				sigStatus = "PASS"
				var st map[string]*trustEntry
				stOK := true
				if trustStore != "" {
					st, stOK = trustState(trustStore)
				}
				pinned := expectedPQ
				if pinned == "" && trustStore != "" && stOK {
					if te := st[sid]; te != nil && !te.revoked {
						pinned = te.pqPubkey
					}
				}
				checkPQ(&r, side, declared, pinned, requirePQ)
				if trustStore != "" {
					te := st[sid]
					if stOK && te != nil && !te.revoked && te.pubkey == pkB64 {
						add("trusted-signer", "PASS", sid+" in trust registry")
						trusted = true
					} else {
						d := sid + ": not in trust registry"
						if te != nil && te.revoked {
							d = sid + ": key revoked"
						} else if te != nil {
							d = sid + ": key differs"
						}
						add("trusted-signer", "FAIL", d)
						trustFailed = true
					}
				}
			}
		}
	}
	if (requirePQ || expectedPQ != "") && sigStatus != "PASS" {
		add("pq-signature", "FAIL", "post-quantum layer required but the pack carries no valid classical signature (hybrid = both)")
	}
	// authenticity
	switch {
	case sigStatus == "FAIL":
		add("authenticity", "FAIL", "producer signature present but invalid")
	case trustFailed:
		add("authenticity", "FAIL", "valid signature but signer not trusted/revoked")
	case trusted:
		add("authenticity", "PASS", "trusted-signed")
	case sigStatus == "PASS":
		add("authenticity", "PASS", "signed (identity not checked against a registry)")
	case ledgerOK || tsStatus == "PASS":
		add("authenticity", "PASS", "anchored (integrity/time, not identity)")
	default:
		add("authenticity", "FAIL", "no anchor and no signature: cannot authenticate")
	}
	return finish(r, declared, trusted, sigStatus == "PASS", "", requirePQ || expectedPQ != "")
}

// checkPQ: the pinned tri-state (cryptovalid 0.13.0 / omega-evidence 0.7.0 rules).
func checkPQ(r *Receipt, side *Object, digest, expectedPQ string, requirePQ bool) {
	add := func(s, d string) { r.Layers = append(r.Layers, Layer{"pq-signature", s, d}) }
	required := requirePQ || expectedPQ != ""
	palg, has := str(side, "pq_sig_alg")
	if !has || palg == "" {
		if _, present := side.Vals["pq_sig_alg"]; present && !has { // non-string alg: present and malformed
			add("FAIL", "pq_sig_alg is not a string")
			return
		}
		if required {
			add("FAIL", "post-quantum layer required but absent (stripped or never signed)")
		}
		return
	}
	pkB64, _ := str(side, "pq_public_key_b64")
	sigB64, _ := str(side, "pq_signature_b64")
	if expectedPQ != "" && pkB64 != expectedPQ {
		add("FAIL", palg+" co-signature by a key other than the pinned one")
		return
	}
	if palg != "ml-dsa-65" {
		if required {
			add("FAIL", palg+" is not a registered PQ backend (pq-present-unverified: a required layer that cannot be checked is not a pass)")
		} else {
			add("SKIP", palg+" is not a registered PQ backend (pq-present-unverified)")
		}
		return
	}
	if !PQSupported {
		if required {
			add("FAIL", "ml-dsa-65 present but this verifier was built with Go < 1.27 (pq-present-unverified: not a pass)")
		} else {
			add("SKIP", "ml-dsa-65 present but this verifier was built with Go < 1.27 (pq-present-unverified)")
		}
		return
	}
	pk, sig := b64Strict(pkB64, 1952), b64Strict(sigB64, 3309)
	if pk == nil || sig == nil || !mldsaVerify(pk, []byte(digest), sig) {
		add("FAIL", "ml-dsa-65 co-signature invalid")
		return
	}
	if expectedPQ == "" {
		if required {
			add("FAIL", "ml-dsa-65 co-signature valid against the key INSIDE the sidecar only (pq-present-unpinned)")
		} else {
			add("SKIP", "ml-dsa-65 co-signature valid against the key INSIDE the sidecar only (pq-present-unpinned): pin the signer's post-quantum key")
		}
		return
	}
	add("PASS", "pq-protected (ml-dsa-65, pinned key)")
}

func finish(r Receipt, digest string, trusted, signed bool, force string, pqRequired bool) Receipt {
	valid, checked := true, false
	for _, l := range r.Layers {
		if l.Status == "PASS" || l.Status == "FAIL" {
			checked = true
			if l.Status == "FAIL" {
				valid = false
			}
		}
	}
	r.Valid = checked && valid
	r.Authenticated = trusted || signed
	var pq *bool
	for _, l := range r.Layers {
		if l.Layer == "pq-signature" {
			t, f := true, false
			switch l.Status {
			case "PASS":
				pq = &t
			case "SKIP":
				pq = nil
			default:
				pq = &f
			}
		}
	}
	if pq == nil {
		hasPQ := false
		for _, l := range r.Layers {
			if l.Layer == "pq-signature" {
				hasPQ = true
			}
		}
		if !hasPQ {
			f := false
			pq = &f
		}
	}
	r.PQProtected = pq
	r.Verdict = "FAIL"
	if r.Valid && (!pqRequired || (pq != nil && *pq)) {
		r.Verdict = "PASS"
	}
	if force != "" {
		r.Verdict = force
	}
	_ = sort.Strings
	return r
}

func sha256Hex(b []byte) string {
	h, _ := Hash("sha256", b)
	return h
}
