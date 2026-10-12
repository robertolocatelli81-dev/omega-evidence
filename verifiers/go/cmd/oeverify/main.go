// oeverify — Go verifier of omega-evidence packs. Exit 0 = PASS, 1 = FAIL, 77 = NOT_ASSESSED, 2 = usage,
// 74 = the receipt could not be written whole (stdout full or its reader gone), whatever the verdict (0.11.3). With stdout
// closed at start the Go runtime reopens fd 1 on /dev/null, so that case cannot be seen here (declared in the README).
// Flags: -ledger L, -trust-store T, -expect-pq-key B64, -require-pq, -require-signed (0.10.0: fail-closed on the classical layer).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	oe "github.com/robertolocatelli81-dev/omega-evidence/verifiers/go"
)

// exIOErr is sysexits.h EX_IOERR: the verdict was computed but the receipt was not written whole.
const exIOErr = 74

// emit writes the receipt and exits with code only when the whole receipt reached stdout; otherwise one line
// "receipt not written: <reason>" goes to stderr (best effort) and the exit is 74. 0.11.2 discarded fmt.Println's
// error: exit 0 / 1 with stdout on /dev/full, and death by SIGPIPE (141) on a pipe whose reader had gone (12/10/2026).
func emit(receipt []byte, code int) {
	if _, err := os.Stdout.Write(append(receipt, '\n')); err != nil { // os.Stdout is unbuffered: Write is the flush
		fmt.Fprintf(os.Stderr, "receipt not written: %v\n", err)
		os.Exit(exIOErr)
	}
	os.Exit(code)
}

func main() {
	// With SIGPIPE delivered to a channel, a write on a pipe whose reader has gone returns EPIPE instead of killing the
	// process (os/signal: "If the program has called Notify to receive SIGPIPE signals ... the write will fail with a
	// [syscall.EPIPE] error"), so the broken pipe becomes exit 74 like every other lost receipt.
	signal.Notify(make(chan os.Signal, 1), syscall.SIGPIPE)
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
			emit(out, 77)
		}
	}()
	r := oe.VerifyPackRequireSigned(flag.Arg(0), *ledger, *trust, *pq, *req, *reqSigned)
	out, _ := json.MarshalIndent(r, "", " ")
	if r.Verdict == "PASS" {
		emit(out, 0)
	}
	if r.Verdict == "NOT_ASSESSED" {
		emit(out, 77) // nothing adverse was found, and a required check could not run on this runtime
	}
	emit(out, 1)
}
