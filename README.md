# OMEGA Open Evidence

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.22539633.svg)](https://doi.org/10.5281/zenodo.22539633)

An open, standard toolkit for **verifiable, long-term compliance evidence** —
so anyone can prove that a record was not altered, and anyone can verify it
**offline, without trusting the producer**.

**Licence: Apache-2.0.** Self-contained: Python standard library +
[`cryptography`](https://cryptography.io) (for Ed25519). Optional `openssl` for
RFC 3161 timestamping.

This is the open reference layer of the OMEGA project. It does **not** include
OMEGA's proprietary sector engines; those remain private and interoperate with,
but do not derive from, this toolkit.

## Install

```bash
# from the static PEP 503 index (artifacts on GitHub Releases, sha256-pinned)
pip install --extra-index-url https://robertolocatelli81-dev.github.io/pypi/ omega-evidence

# or straight from the tagged source
pip install git+https://github.com/robertolocatelli81-dev/omega-evidence@v0.5.0
```

Release artifacts (`.whl` / `.tar.gz`) are attached to each
[GitHub Release](https://github.com/robertolocatelli81-dev/omega-evidence/releases);
the index links carry `#sha256=` fragments, so pip verifies every download.

## Building blocks

| Module | What it does |
|---|---|
| `canonical` | Deterministic canonical SHA3 hashing (injective type-tagging) |
| `ledger` | Append-only, hash-chained, **fail-closed** ledger (a tampered file raises on load); two durability modes — `sync` (fsync per entry, the safe default) and `batch` (fsync every `batch_size`, ~40–100× faster, small crash-window, declared) |
| `pack` | Self-describing evidence pack — a **mandatory `honest_scope`** stating what it does *not* prove; a recomputable `pack_sha3` |
| `signing` | Ed25519 producer identity and signatures (bound to the payload) |
| `trust` | TOFU trust registry with explicit rotation and revocation |
| `timestamp` | RFC 3161 trusted timestamping (a qualified TSA adds legal presumption of time) |
| `attestation` | PII-free attestation primitive — salted per-record digests, **no linkability** |
| `verifier` | One offline verifier with **graduated authenticity** |
| `interop.aat` | Export/verify **Agent Audit Trail** chains (draft-sharif-agent-audit-trail-00): JCS hash chain, vocabularies, optional ECDSA P-256 signatures |

## Graduated authenticity

A pack's trust level is *stated, not implied*:

```
trusted-signed  producer signature valid AND key trusted in the registry
signed          producer signature valid (identity not checked)
anchored        valid ledger chain OR valid TSA timestamp (integrity/time)
none            internal consistency only  →  rejected, cannot authenticate
```

A bare fabricated pack (no ledger, no timestamp, no signature) **cannot pass**.

## Quick start

```python
from omega_evidence import pack, signing, trust, verify_pack
from omega_evidence.ledger import Ledger

# 1. record events in a hash-chained ledger next to the pack
Ledger("pack.ledger.jsonl").append({"event": "something auditable"})

# 2. build a self-describing pack (honest_scope is mandatory)
p = pack.build_pack("my_evidence", {"payload": "..."},
                    "reference evidence; NOT a conformity assessment")
pack.write_pack("pack.json", p)

# 3. sign it and (optionally) timestamp it with a real TSA
ident = signing.Identity("acme-compliance")
pack.sign_pack("pack.json", ident)
pack.stamp_pack("pack.json", "http://tsa.izenpe.com")

# 4. trust the producer's key, then verify — reaches trusted-signed
trust.TrustRegistry("trust.jsonl").trust("acme-compliance", ident.public_key_b64)
result = verify_pack("pack.json", trust_store="trust.jsonl")
assert result["valid"]
```

## Honest scope

This toolkit produces **firm-side, verifiable evidence** and open standards. It
is **not** a conformity-assessment body, not a notified body, not a QTSP, not a
CA/PKI, not the official CSIRT/ENISA or TRACES channel, and not legal advice.
The trust registry is TOFU: it proves a key was decided to be trusted and
prevents silent key-swap, not the legal identity of the holder.

## Agent Audit Trail interop (2026-09-14)

Compared with the 2026 field (audit-trail products, OWASP agentic logging, EU AI Act Art. 12 — scheduled for
2 August 2026, deferral pending in the Digital Omnibus):
the requirement has converged, the record has not. The first Internet-Draft proposing one is
`draft-sharif-agent-audit-trail-00` (R. Sharif, 29 March 2026 — an individual draft, not an IETF standard,
expires 29 September 2026). `omega_evidence.interop.aat` exports an `AgentEvidenceLog` ledger as AAT chains — one chain per
session, each opened by a synthesised (and so labelled) `lifecycle` / `session_start` genesis record, as the
draft requires — with mandatory fields, controlled vocabularies and `prev_hash` = SHA-256 over the JCS of the
previous record; and verifies any AAT chain offline, fail-closed (chain, vocabularies, lifecycle, UTC and
monotonic timestamps, canonical UUID v4 identifiers), including the optional ECDSA P-256 signatures (IEEE P1363
r||s). The draft's author has an IPR disclosure on the datatracker: reading and verifying the format is what
this module does.
Declared: the mapping is lossy (omega's policy rule, decision and attestation travel inside `action_detail`)
but never fabricates (unknown action/outcome, missing agent id or unparsable timestamp raise); identifiers are
UUID-v4-format values derived deterministically from the omega digests, so the same ledger exports to the same
chain; signing happens inside the export (the draft hashes all fields of the previous record, signature
included); `trust_level` is what the caller declares; JCS follows RFC 8785 with ES6 number serialisation, so foreign
chains with non-integer numbers verify too (integers beyond 2^53 are refused on export); the draft may change —
its version is pinned in `AAT_DRAFT`.

```python
from omega_evidence.interop import aat
chains = aat.from_omega(list(log._ledger.entries()), agent_version="1.2.3", trust_level="L1")
for session_id, chain in chains.items():
    aat.verify_chain(chain)                 # {"ok": True, ...}; add pubkey_pem=... to check signatures
```

## Standards

RFC 3161 (timestamping, optional `openssl`); RFC 4998 / eIDAS LTA renewal *semantics*
(`preservation`: long-term evidence records renewed across hash and timestamp aging, verifiable
offline, tested — not the RFC 4998 ASN.1 wire format); Ed25519 with an optional post-quantum
co-signature (SLH-DSA / FIPS 205 through an external liboqs backend; any PQ scheme is admitted only
by a known-answer-test gate — no home-grown PQ crypto; a hybrid pack is reported `pq-protected` only
when a verifying backend is present); SD-JWT (RFC 9901) issue/verify for the eIDAS 2.0 / EUDI wallet
lane; PII-free by design (salted per-record digests, no linkability).

## Tests

```bash
python3 tests/test_toolkit.py
```

## Releasing (maintainers)

Releases publish to PyPI via **Trusted Publishing (OIDC)** — no API token is
stored anywhere. Two halves:

1. **One-time PyPI registration** (owner). Because the project does not exist on
   PyPI yet, register a **pending publisher** first: pypi.org → *Your account* →
   *Publishing* → *Add a pending publisher* → GitHub, with:
   - PyPI Project Name: `omega-evidence`
   - Owner: `robertolocatelli81-dev`
   - Repository: `omega-evidence`
   - Workflow: `publish.yml`
   - Environment: `pypi`

   (After the first successful publish the project exists, and the same entry
   appears under the project's own *Publishing* settings.)
2. **Cut a release**: create a GitHub Release (tag e.g. `v0.1.0`). The
   `publish.yml` workflow builds, `twine check`s, runs the tests, and publishes
   to PyPI using short-lived OIDC credentials.

CI (`ci.yml`) runs the test suite on every push and pull request across
Python 3.9 / 3.11 / 3.13.
