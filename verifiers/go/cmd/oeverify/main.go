// oeverify — Go verifier of omega-evidence packs. Exit 0 = PASS, 1 = FAIL, 2 = usage.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

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
	flag.Parse()
	if flag.NArg() != 1 {
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
