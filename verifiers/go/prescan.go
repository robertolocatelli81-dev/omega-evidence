// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Roberto Locatelli
package oeverify

import (
	"errors"
	"fmt"
	"strconv"
)

// MaxJSONDepth is the acceptance-profile bound (spec/CONFORMANCE.md), identical in verifier.py and cvverify.mjs.
const MaxJSONDepth = 512

// NestingDepth is the linear pre-scan of verifier.json_nesting_depth: brackets inside strings ignored,
// escapes honoured, no parsing and no recursion.
func NestingDepth(text []byte) int {
	depth, max := 0, 0
	inStr, esc := false, false
	for _, c := range text {
		switch {
		case inStr:
			if esc {
				esc = false
			} else if c == '\\' {
				esc = true
			} else if c == '"' {
				inStr = false
			}
		case c == '"':
			inStr = true
		case c == '[' || c == '{':
			depth++
			if depth > max {
				max = depth
			}
		case c == ']' || c == '}':
			depth--
		}
	}
	return max
}

// HasLoneSurrogate reports an unpaired \uD800-\uDFFF escape (same scan as verifier.has_lone_surrogate).
// Go's json decoder would silently replace it with U+FFFD, Python/JS keep it: the profile refuses it.
func HasLoneSurrogate(text []byte) bool {
	hex4 := func(b []byte) (int64, bool) { // exactly four hex digits (r9: ParseInt would take a sign)
		if len(b) < 4 {
			return 0, false
		}
		for _, c := range b[:4] {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return 0, false
			}
		}
		v, err := strconv.ParseInt(string(b[:4]), 16, 32)
		return v, err == nil
	}
	i, n := 0, len(text)
	for i < n {
		if text[i] != '\\' {
			i++
			continue
		}
		if i+1 < n && text[i+1] == 'u' && i+5 < n {
			cp, ok := hex4(text[i+2:])
			if !ok { // malformed escape: the decoder refuses it, not this rule
				i += 2
				continue
			}
			if cp >= 0xD800 && cp <= 0xDBFF {
				if i+7 >= n || text[i+6] != '\\' || text[i+7] != 'u' {
					return true
				}
				lo, ok := hex4(text[i+8:])
				if !ok || lo < 0xDC00 || lo > 0xDFFF {
					return true
				}
				i += 12
				continue
			}
			if cp >= 0xDC00 && cp <= 0xDFFF {
				return true
			}
			i += 6
			continue
		}
		i += 2
	}
	return false
}

// prescan applies the profile bounds BEFORE the decoder sees the text.
func prescan(text []byte) error {
	if d := NestingDepth(text); d > MaxJSONDepth {
		return fmt.Errorf("json_too_deep: nesting %d exceeds the acceptance-profile bound %d", d, MaxJSONDepth)
	}
	if HasLoneSurrogate(text) {
		return errors.New("lone_surrogate: unpaired UTF-16 surrogate escape is outside the acceptance profile")
	}
	return nil
}
