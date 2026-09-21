#!/bin/bash
# Positive control of the oracle's Python column: a deliberately LENIENT copy of the reference (json.loads instead of
# loads_strict, no honest_scope check, no reserved-tag / surrogate / float refusal in canonical_json) must turn the
# hostile pack/ledger/sidecar cases red. Prints the oracle summary; the number is the one quoted in README.
# usage: OEVERIFY_GO=… OEVERIFY_JAVA="…" verifiers/lax_python_ablation.sh
set -e
ROOT=$(cd "$(dirname "$0")/.." && pwd); T=$(mktemp -d)
cp -r "$ROOT/omega_evidence" "$T/"
python3 - "$T" <<'PY'
import sys, os
t = sys.argv[1]
def sub(rel, old, new):
    p = os.path.join(t, rel); s = open(p).read(); assert old in s, (rel, old); open(p, "w").write(s.replace(old, new, 1))
sub("omega_evidence/ledger.py", "def loads_strict(text: str):", "def loads_strict(text: str):\n    return json.loads(text)   # ABLATION: lax\ndef _unused_loads_strict(text):")
sub("omega_evidence/verifier.py", "_hs_ok = _honest_scope_declares_limit(scope)", "_hs_ok = True   # ABLATION")
sub("omega_evidence/canonical.py", "def _reject_reserved(obj: Any, allow_tag: bool = False) -> None:", "def _reject_reserved(obj: Any, allow_tag: bool = False) -> None:\n    return   # ABLATION\ndef _unused_reject(obj, allow_tag=False):")
PY
OEVERIFY_PYTHONPATH="$T" python3 "$ROOT/verifiers/differential_oracle.py" | grep -E "^\s+\[DIFF\]|^disagreements" || true
rm -rf "$T"
