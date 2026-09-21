// oeverify — Go verifier of omega-evidence packs. Exit 0 = PASS, 1 = FAIL, 2 = usage.
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
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: oeverify [-ledger L] [-trust-store T] [-expect-pq-key B64] [-require-pq] <pack.json>")
		os.Exit(2)
	}
	for _, a := range os.Args[1:] { // no "--" terminator, no value on the boolean flag: the other three CLIs refuse them (one grammar in the four)
		if a == "--" || strings.HasPrefix(a, "-require-pq=") || strings.HasPrefix(a, "--require-pq=") {
			flag.Usage()
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
	r := oe.VerifyPack(flag.Arg(0), *ledger, *trust, *pq, *req)
	out, _ := json.MarshalIndent(r, "", " ")
	fmt.Println(string(out))
	if r.Verdict == "PASS" {
		os.Exit(0)
	}
	os.Exit(1)
}
