// oeverify — Go verifier of omega-evidence packs. Exit 0 = PASS, 1 = FAIL, 77 = NOT_ASSESSED, 2 = usage.
// Flags: -ledger L, -trust-store T, -expect-pq-key B64, -require-pq, -require-signed (0.10.0: fail-closed on the classical layer).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	oe "github.com/robertolocatelli81-dev/omega-evidence/verifiers/go"
)

func main() {
	ledger := flag.String("ledger", "", "ledger the pack must be anchored in (default: <pack>.ledger.jsonl if present)")
	trust := flag.String("trust-store", "", "hash-chained trust registry (JSONL) binding signer ids to keys")
	pq := flag.String("expect-pq-key", "", "pinned ML-DSA-65 public key (base64): requires the hybrid layer")
	req := flag.Bool("require-pq", false, "require a pinned, valid post-quantum layer (trust registry)")
	reqSigned := flag.Bool("require-signed", false, "fail-closed: a missing or unverifiable producer signature is FAIL, never 'anchored'")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: oeverify [-ledger L] [-trust-store T] [-expect-pq-key B64] [-require-pq] [-require-signed] <pack.json>")
		os.Exit(2)
	}
	args := os.Args[1:]
	for i := 0; i < len(args); i++ { // no "--" terminator, no value on a boolean flag: the other three CLIs refuse them (one grammar in the four)
		a := args[i]
		if a == "--" || strings.HasPrefix(a, "-require-pq=") || strings.HasPrefix(a, "--require-pq=") ||
			strings.HasPrefix(a, "-require-signed=") || strings.HasPrefix(a, "--require-signed=") {
			flag.Usage()
		}
		name := strings.TrimLeft(a, "-")
		if strings.Count(a, "-")-strings.Count(name, "-") > 2 || name == a {
			continue
		}
		if eq := strings.IndexByte(name, '='); eq >= 0 { // -flag=value: the value must be non-empty and not flag-like
			if k, v := name[:eq], name[eq+1:]; (k == "ledger" || k == "trust-store" || k == "expect-pq-key") && (v == "" || strings.HasPrefix(v, "-")) {
				fmt.Fprintf(os.Stderr, "usage: -%s needs a value (got %q)\n", k, v)
				os.Exit(2)
			}
			continue
		}
		if name == "ledger" || name == "trust-store" || name == "expect-pq-key" { // r13: EVERY occurrence — flag.Visit sees the final value only,
			if i+1 >= len(args) || args[i+1] == "" || strings.HasPrefix(args[i+1], "-") { // so `-ledger -require-pq -ledger L` ate the boolean flag
				fmt.Fprintf(os.Stderr, "usage: -%s needs a value (got %q)\n", name, func() string {
					if i+1 < len(args) {
						return args[i+1]
					}
					return ""
				}())
				os.Exit(2)
			}
			i++
		}
	}
	flag.Parse()
	flag.Visit(func(f *flag.Flag) { // a value flag given with "" (or a flag as its value): usage (one grammar in the four, 21/09/2026)
		if v := f.Value.String(); v == "" || strings.HasPrefix(v, "-") {
			fmt.Fprintf(os.Stderr, "usage: -%s needs a value (got %q)\n", f.Name, v)
			os.Exit(2)
		}
	})
	if flag.NArg() != 1 || flag.Arg(0) == "" || strings.HasPrefix(flag.Arg(0), "-") { // an unset $PACK is not a path
		flag.Usage()
	}
	defer func() { // a fault outside VerifyPack's own recover: still not a finding (exit 77, never 1 or 2) — 25/09/2026
		if p := recover(); p != nil {
			out, _ := json.MarshalIndent(oe.InternalError(nil, fmt.Sprintf("%T", p)), "", " ")
			fmt.Println(string(out))
			os.Exit(77)
		}
	}()
	r := oe.VerifyPackRequireSigned(flag.Arg(0), *ledger, *trust, *pq, *req, *reqSigned)
	out, _ := json.MarshalIndent(r, "", " ")
	fmt.Println(string(out))
	if r.Verdict == "PASS" {
		os.Exit(0)
	}
	if r.Verdict == "NOT_ASSESSED" {
		os.Exit(77) // nothing adverse was found, and a required check could not run on this runtime
	}
	os.Exit(1)
}
