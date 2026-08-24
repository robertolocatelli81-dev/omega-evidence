# OMEGA Open Evidence

An open, standard toolkit for **verifiable, long-term compliance evidence** —
so anyone can prove that a record was not altered, and anyone can verify it
**offline, without trusting the producer**.

**Licence: Apache-2.0.** Self-contained: Python standard library +
[`cryptography`](https://cryptography.io) (for Ed25519). Optional `openssl` for
RFC 3161 timestamping.

This is the open reference layer of the OMEGA project. It does **not** include
OMEGA's proprietary sector engines; those remain private and interoperate with,
but do not derive from, this toolkit.

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

## Standards

RFC 3161 (timestamping), RFC 4998 (long-term evidence, on the roadmap),
Ed25519 / ML-DSA (FIPS 204, hybrid on the roadmap), aligned with eIDAS 2.0 /
EUDI and the Digital Public Goods Standard (PII-free by design).

## Tests

```bash
python3 tests/test_toolkit.py
```
