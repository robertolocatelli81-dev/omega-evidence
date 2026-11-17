#!/usr/bin/env python3
# Copyright 2026 Roberto Locatelli — Apache-2.0
"""Build omega_evidence/pqbackends/vectors/nist_acvp_mldsa65.jsonl from the NIST ACVP-Server JSON files (0.12.0).

Source: https://github.com/usnistgov/ACVP-Server, commit COMMIT below, files
gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json and
gen-val/json-files/ML-DSA-sigGen-FIPS204/internalProjection.json, checked against the SHA-256 pinned here before
anything is read. The values are NIST's (software developed by NIST employees is not subject to copyright protection
within the United States); the selection rule and the file format are this repository's:

  * every test case of the sigVer test group with parameterSet ML-DSA-65, signatureInterface external, preHash pure,
    externalMu false (NIST's testPassed true and false alike, NIST's reason kept);
  * every test case with an EMPTY context of the sigGen test groups with the same four values (deterministic and
    hedged): the path this profile signs and verifies on (pure ML-DSA-65, empty context), as known answers.

Output: JSON Lines, closed. Line 1: {"kind": "provenance", ...}. Each other line: {"kind": "case", "file": "sigVer" |
"sigGen", "tgId", "tcId", "testPassed", "reason", "pk", "message", "context", "signature"} (hex, lowercase; the secret
key `sk` and the hedged `rnd` are not copied). Usage, from the repository root:

    python3 tools/build_nist_acvp_mldsa65.py <sigVer internalProjection.json> <sigGen internalProjection.json>
"""
import hashlib
import json
import os
import sys

COMMIT = "975de31eb83d87039ec88934fdc47d8c312b892d"   # usnistgov/ACVP-Server master on 2026-11-17 (committed 2026-08-12)
SHA256 = {"sigVer": "47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437",
          "sigGen": "72dcaf5f69853ca267ccd16af9cb40949786aca0fcfbf05d1ebeba132b93af22"}
GROUP = {"parameterSet": "ML-DSA-65", "signatureInterface": "external", "preHash": "pure", "externalMu": False}
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "omega_evidence", "pqbackends", "vectors", "nist_acvp_mldsa65.jsonl")


def _load(path: str, which: str) -> dict:
    with open(path, "rb") as f:
        raw = f.read()
    got = hashlib.sha256(raw).hexdigest()
    if got != SHA256[which]:
        raise SystemExit(f"{which}: SHA-256 {got}, pinned {SHA256[which]}: not the pinned NIST file")
    return json.loads(raw)


def _groups(doc: dict) -> list:
    return [g for g in doc["testGroups"] if all(g.get(k) == v for k, v in GROUP.items())]


def build(sigver_path: str, siggen_path: str) -> list:
    rows = []
    for which, path in (("sigVer", sigver_path), ("sigGen", siggen_path)):
        groups = _groups(_load(path, which))
        if which == "sigVer" and len(groups) != 1:
            raise SystemExit(f"sigVer: {len(groups)} groups match {GROUP}, expected 1")
        for g in groups:
            for t in g["tests"]:
                if which == "sigGen" and t["context"] != "":
                    continue
                rows.append({"kind": "case", "file": which, "tgId": g["tgId"], "tcId": t["tcId"],
                             "testPassed": t["testPassed"] if which == "sigVer" else True,
                             "reason": t.get("reason", "") if which == "sigVer" else "known-answer signature",
                             "pk": t["pk"].lower(), "message": t["message"].lower(), "context": t["context"].lower(),
                             "signature": t["signature"].lower()})
    return rows


def main(argv):
    if len(argv) != 3:
        raise SystemExit(__doc__)
    rows = build(argv[1], argv[2])
    head = {"kind": "provenance", "source": "NIST ACVP-Server (https://github.com/usnistgov/ACVP-Server)",
            "commit": COMMIT, "sha256": SHA256, "group": GROUP,
            "rule": "sigVer: every case of the group; sigGen: every case of the matching groups with an empty context",
            "built_by": "tools/build_nist_acvp_mldsa65.py"}
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        for obj in [head] + rows:
            f.write(json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n")
    print(f"{OUT}: {len(rows)} cases")


if __name__ == "__main__":
    main(sys.argv)
