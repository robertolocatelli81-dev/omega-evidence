# Signing and release verification

This file says which keys sign omega-evidence releases and how anyone can check them. Only **public** keys and
fingerprints are listed here; private keys are never published.

## 1. Release evidence pack (Ed25519)

Each GitHub release from 0.7.0 on carries an evidence pack made with omega-cra-evol (`omega-evidence-<version>-cra_pack.json`, its
ledger `-cra.ledger.jsonl`, its signature `-cra_pack.json.sig.json`) and a trust file `-trust.json`. The signature is
Ed25519; the signer id is `roberto-locatelli-aws-kms`, a key the maintainer holds in AWS KMS.

- Public key (raw Ed25519, hex): `86db2b7231930b37debf3c9bcd5baedcc12c430f8d7785a93212a6f83706440b`
- SHA-256 of the public key: `7a72250f64773c0577a38b2dc0d790246d134af5f73176d7811cacab72007092`
- The `.sig.json` of every release from 0.7.0 to 0.11.4 names this signer and this key (read on 2026-11-17).
- The same key is in the release's `-trust.json` asset. Compare it with this file: a copy that differs means
  something was altered.
- Check (omega-cra-evol installed): `python -c "import json; from omega_cra_evol import signing as s;
  print(s.verify_pack_signature('omega-evidence-<version>-cra_pack.json', json.load(open('omega-evidence-<version>-trust.json'))))"`
  prints `status: PASS`, `detail: trusted-signed`. Measured on the 0.11.4 assets on 2026-11-17.

## 2. Commits and tags (SSH signatures)

Commits after `6d69983` (main, 2026-11-03) are signed with an SSH Ed25519 key, fingerprint
`SHA256:YTnE9PgWCm9XNiECrqk1Q645tWJUaRFO1WabYSJSfTo`. Check one locally with `git verify-commit <commit>` and an
allowed-signers file containing that key. The tags `v0.1.0` … `v0.11.4`, their commits and the two commits on main
after `v0.11.4` (`f722486`, `6d69983`) carry no signature (17 tags, counted on 2026-11-17).

## 3. Checksums and PyPI

Every release from 0.7.0 on has a `SHA256SUMS` asset. The workflow `.github/workflows/pypi.yml` (added to the main
branch on 2026-11-03, after the tag v0.11.4) uploads to PyPI the wheel and the sdist of the GitHub release after
checking them against `SHA256SUMS`, through Trusted Publishing, which adds PEP 740 attestations. For 0.11.4 the two
files on PyPI have the SHA-256 listed in `SHA256SUMS` and PyPI serves a provenance for each of them (checked on
2026-11-17). The release build (`release-build.yml`) makes no GitHub artifact attestation.

## 4. Key changes

- A planned key change is announced in advance in the release notes, signed by both the old and the new key. The list
  of every key ever used is kept in this file and never deleted.
- If a key is suspected compromised, it stops being used immediately, and an advisory is published as soon as
  possible, giving the cut-off date and the SHA-256 of the releases that remain trustworthy.
- Apart from withdrawing a suspected key, no SLA or fixed deadline is promised for these steps.

## 5. Post-quantum transition

The keys of §1 and §2 are Ed25519 (EdDSA). NIST IR 8547, *Transition to Post-Quantum Cryptography Standards* (final,
October 2026, https://doi.org/10.6028/NIST.IR.8547, §4.1.1 Table 2; read on 2026-11-17): ECDSA, EdDSA and RSA
signatures are "Deprecated after 2030" and "Disallowed after 2035" under NIST standards and guidelines. This
repository's verifiers do not date-limit these signatures; the dates concern making new ones.
