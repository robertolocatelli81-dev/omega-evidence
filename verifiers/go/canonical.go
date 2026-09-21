// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Roberto Locatelli
//
// Package oeverify — Go verifier of omega-evidence packs and ledgers (the cryptovalid acceptance profile:
// (SPEC_EVIDENCE_FORMAT.md §3): canonical JSON identical, byte for byte, to Python
// json.dumps(obj, sort_keys=True, separators=(",", ":")) with ensure_ascii=True, plus the
// SHA-256 / SHA3-256 hash chain. Stdlib only. The constrained profile refuses floats and
// duplicate keys (both forbidden by the spec) instead of guessing.
package oeverify

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Object keeps insertion order for parsing but is serialised with sorted keys.
type Object struct {
	Keys []string
	Vals map[string]any
}

// Parse decodes ONE JSON text strictly: duplicate keys → error, floats → error,
// invalid UTF-8 → error, trailing garbage → error. Numbers stay json.Number.
func Parse(text []byte) (any, error) {
	if !utf8.Valid(text) {
		return nil, errors.New("non-UTF-8 input")
	}
	if err := prescan(text); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(text))
	dec.UseNumber()
	v, err := parseValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data after JSON value")
	}
	return v, nil
}

func parseValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			obj := &Object{Vals: map[string]any{}}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				k, ok := kt.(string)
				if !ok {
					return nil, errors.New("object key is not a string")
				}
				if _, dup := obj.Vals[k]; dup {
					return nil, fmt.Errorf("duplicate key %q", k)
				}
				v, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				obj.Keys = append(obj.Keys, k)
				obj.Vals[k] = v
			}
			if _, err := dec.Token(); err != nil { // '}'
				return nil, err
			}
			return obj, nil
		case '[':
			arr := []any{}
			for dec.More() {
				v, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				arr = append(arr, v)
			}
			if _, err := dec.Token(); err != nil { // ']'
				return nil, err
			}
			return arr, nil
		}
		return nil, fmt.Errorf("unexpected delimiter %v", t)
	case json.Number:
		s := t.String()
		if strings.ContainsAny(s, ".eE") {
			return nil, fmt.Errorf("floating-point number %q is forbidden by the profile", s)
		}
		if s == "-0" {
			s = "0" // Python: json.loads("-0") == 0 → dumps "0"
		}
		// portable range: same bound as verifier.py (_SAFE_INT) and cvverify.mjs — an int64 above
		// 2^53-1 is exact in Python and Go but not in JS, so the profile refuses it (send it as a string).
		i, err := strconv.ParseInt(s, 10, 64)
		if err != nil || i > safeInt || i < -safeInt {
			return nil, fmt.Errorf("integer %s outside the portable range +/-(2^53-1)", s)
		}
		return json.Number(s), nil
	default:
		return tok, nil // string, bool, nil
	}
}

// Canonical serialises a parsed value with the normative rules of §3.
func Canonical(v any) ([]byte, error) {
	var b bytes.Buffer
	if err := encode(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func encode(b *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if t {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case json.Number:
		b.WriteString(t.String())
	case string:
		writeString(b, t)
	case []any:
		b.WriteByte('[')
		for i, x := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := encode(b, x); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case *Object:
		keys := append([]string(nil), t.Keys...)
		sort.Strings(keys) // byte order of UTF-8 == code-point order == Python str ordering
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, k)
			b.WriteByte(':')
			if err := encode(b, t.Vals[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("unsupported value type %T", v)
	}
	return nil
}

// writeString reproduces Python's ensure_ascii escaping: only 0x20..0x7e printed raw
// (except " and \), short escapes for \b \f \n \r \t, everything else \uXXXX lowercase,
// astral code points as UTF-16 surrogate pairs.
func writeString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if r >= 0x20 && r <= 0x7e {
				b.WriteRune(r)
			} else if r > 0xFFFF {
				r -= 0x10000
				fmt.Fprintf(b, `\u%04x\u%04x`, 0xD800+(r>>10), 0xDC00+(r&0x3FF))
			} else {
				fmt.Fprintf(b, `\u%04x`, r)
			}
		}
	}
	b.WriteByte('"')
}

// Payload is the canonical form of an entry without self_hash / signature / signer — the CRYPTOVALID attestation set, kept
// from the shared code. NOT the omega-evidence profile (which drops self_hash only; pack.go uses without(e, "self_hash")):
// do not use it for an omega-evidence ledger (0.8.3 r11).
func Payload(entry *Object) ([]byte, error) {
	cp := &Object{Vals: map[string]any{}}
	for _, k := range entry.Keys {
		if k == "self_hash" || k == "signature" || k == "signer" || k == "signature_pq" || k == "signer_pq" {
			continue
		}
		cp.Keys = append(cp.Keys, k)
		cp.Vals[k] = entry.Vals[k]
	}
	return Canonical(cp)
}

// Hash applies the profile's digest to the payload.
func Hash(algo string, payload []byte) (string, error) {
	switch algo {
	case "sha256":
		s := sha256.Sum256(payload)
		return hex.EncodeToString(s[:]), nil
	case "sha3_256":
		s := sha3.Sum256(payload)
		return hex.EncodeToString(s[:]), nil
	}
	return "", fmt.Errorf("unknown algo %q", algo)
}

var Algos = []string{"sha256", "sha3_256"}

const safeInt = 1<<53 - 1
