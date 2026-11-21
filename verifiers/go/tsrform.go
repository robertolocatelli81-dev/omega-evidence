// Copyright 2026 Roberto Locatelli
// SPDX-License-Identifier: Apache-2.0

package oeverify

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// The timestamp sidecar's form, judged without a trust anchor (0.14.0, the four verifiers): tsr_b64 is canonical
// base64 of ONE DER SEQUENCE, and validation_material has the closed shape every release wrote. The same rules and the
// same texts as omega_evidence/verifier.py (_b64_canon, _der_one_sequence, _vm_problem).

const tsrFormMsg = "malformed sidecar: tsr_b64 is not canonical base64 of one DER SEQUENCE (checked without a trust anchor)"

var b64Alphabet = regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)

// b64Canon: the bytes of a non-empty string in canonical standard base64, else nil.
func b64Canon(v any) []byte {
	s, ok := v.(string)
	if !ok || s == "" || len(s)%4 != 0 || !b64Alphabet.MatchString(s) {
		return nil
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != s {
		return nil
	}
	return raw
}

// derOneSequence: exactly one DER SEQUENCE (tag 0x30, shortest definite length of at most four octets, nothing after).
func derOneSequence(b []byte) bool {
	if len(b) < 2 || b[0] != 0x30 {
		return false
	}
	first := int(b[1])
	n, head := 0, 0
	if first < 0x80 {
		n, head = first, 2
	} else {
		k := first & 0x7f
		if k == 0 || k > 4 || len(b) < 2+k || b[2] == 0 {
			return false
		}
		for _, c := range b[2 : 2+k] {
			n = n<<8 | int(c)
		}
		if n < 0x80 {
			return false
		}
		head = 2 + k
	}
	return head+n == len(b)
}

var vmKeys = map[string]bool{"available": true, "note": true, "tsa_transport": true, "certs_der_b64": true, "cert_count": true,
	"subjects": true, "crl_distribution_points": true, "crls_b64": true, "crl_fetch": true, "token_verified": true}
var vmUnavailableKeys = map[string]bool{"available": true, "note": true, "tsa_transport": true}
var crlFetchKeys = map[string]bool{"fetched": true, "reason": true, "chain_certificates": true}

func intOf(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := strconv.ParseInt(n.String(), 10, 64)
	return i, err == nil
}

func strList(v any) bool {
	a, ok := v.([]any)
	if !ok {
		return false
	}
	for _, x := range a {
		if _, isStr := x.(string); !isStr {
			return false
		}
	}
	return true
}

func keySet(o *Object) string {
	k := append([]string(nil), o.Keys...)
	sort.Strings(k)
	return strings.Join(k, ",")
}

// vmProblem: "" when validation_material has the closed shape, else the first reason.
func vmProblem(v any) string {
	vm, ok := v.(*Object)
	if !ok {
		return "not a JSON object"
	}
	if unk := unknownKeys(vm, vmKeys); len(unk) != 0 {
		return "field(s) outside the closed schema: " + cutRunes(strings.Join(unk, ", "), 120)
	}
	avail, ok := vm.Vals["available"].(bool)
	if !ok {
		return "available is not a boolean"
	}
	if nv, present := vm.Vals["note"]; present {
		if _, isStr := nv.(string); !isStr {
			return "note is not a string"
		}
	}
	if tv, present := vm.Vals["tsa_transport"]; present {
		if t, isStr := tv.(string); !isStr || (t != "http" && t != "https") {
			return "tsa_transport is not http or https"
		}
	}
	if !avail {
		if unk := unknownKeys(vm, vmUnavailableKeys); len(unk) != 0 {
			return "material not available, yet it carries: " + cutRunes(strings.Join(unk, ", "), 120)
		}
		return ""
	}
	for _, k := range []string{"certs_der_b64", "cert_count", "subjects", "crl_distribution_points"} {
		if _, present := vm.Vals[k]; !present {
			return k + " missing"
		}
	}
	certs, ok := vm.Vals["certs_der_b64"].([]any)
	if ok {
		for _, c := range certs {
			if !derOneSequence(b64Canon(c)) {
				ok = false
				break
			}
		}
	}
	if !ok {
		return "certs_der_b64 is not an array of canonical base64 DER certificates"
	}
	if n, isInt := intOf(vm.Vals["cert_count"]); !isInt || n != int64(len(certs)) {
		return "cert_count is not the number of certs_der_b64"
	}
	if !strList(vm.Vals["subjects"]) || !strList(vm.Vals["crl_distribution_points"]) {
		return "subjects and crl_distribution_points must be arrays of strings"
	}
	if cv, present := vm.Vals["crls_b64"]; present {
		crls, isArr := cv.([]any)
		if !isArr {
			return "crls_b64 is not an array"
		}
		for _, x := range crls {
			c, isObj := x.(*Object)
			if !isObj {
				return "a crls_b64 entry is not an object with a url string"
			}
			if _, isStr := c.Vals["url"].(string); !isStr {
				return "a crls_b64 entry is not an object with a url string"
			}
			switch keySet(c) {
			case "error,url":
				if _, isStr := c.Vals["error"].(string); !isStr {
					return "a crls_b64 error is not a string"
				}
			case "bytes,crl_b64,url":
				raw := b64Canon(c.Vals["crl_b64"])
				if n, isInt := intOf(c.Vals["bytes"]); raw == nil || !isInt || n != int64(len(raw)) {
					return "a crls_b64 entry is not canonical base64 with its byte count"
				}
			default:
				return "a crls_b64 entry has neither {url, crl_b64, bytes} nor {url, error}"
			}
		}
	}
	if fv, present := vm.Vals["crl_fetch"]; present {
		cf, isObj := fv.(*Object)
		if !isObj || len(unknownKeys(cf, crlFetchKeys)) != 0 {
			return "crl_fetch is not an object {fetched, reason?, chain_certificates?}"
		}
		if _, isBool := cf.Vals["fetched"].(bool); !isBool {
			return "crl_fetch is not an object {fetched, reason?, chain_certificates?}"
		}
		if rv, present := cf.Vals["reason"]; present {
			if _, isStr := rv.(string); !isStr {
				return "crl_fetch.reason is not a string"
			}
		}
		if cc, present := cf.Vals["chain_certificates"]; present {
			if n, isInt := intOf(cc); !isInt || n < 0 {
				return "crl_fetch.chain_certificates is not a non-negative integer"
			}
		}
	}
	if tv, present := vm.Vals["token_verified"]; present && tv != nil {
		if _, isBool := tv.(bool); !isBool {
			return "token_verified is not true, false or null"
		}
	}
	return ""
}

func vmProblemIfPresent(side *Object) string {
	if v, present := side.Vals["validation_material"]; present {
		return vmProblem(v)
	}
	return ""
}
