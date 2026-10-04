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
pip install git+https://github.com/robertolocatelli81-dev/omega-evidence@v0.8.3
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
| `interop.aat` | Export/verify **Agent Audit Trail** chains (draft-sharif-agent-audit-trail-**04**): JCS hash chain, record phases, §7 detail fields, ES256 / ML-DSA-65 / hybrid signatures resolved by RFC 7638 thumbprint, Merkle epochs (RFC 6962), tombstones, session close, JSONL/CSV |

## Graduated authenticity

A pack's trust level is *stated, not implied*:

```
trusted-signed  producer signature valid AND key trusted in the registry
signed          producer signature valid (identity not checked)
anchored        valid ledger chain (integrity/time) — an RFC 3161 token is recorded and bound to the pack, not a tier
none            internal consistency only  →  rejected, cannot authenticate
```

A bare fabricated pack (no ledger, no signature) **cannot pass**. A signed pack whose signature this verifier cannot check
does not fall silently to `anchored`: a `sig_alg` that is a non-canonical spelling of a supported name (`"eD25519"`,
`"ed2 5519"`) is a **FAIL**; a genuinely unknown algorithm is a SKIP that says "signature present, algorithm unsupported,
not verified", in the signature layer and in the authenticity layer, and `--require-signed` (`require_signed=True`)
turns it, and a missing signature, into a FAIL (0.10.0, below).

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

## Agent Audit Trail interop (draft -04, 2026-09-19)

Compared with the 2026 field (observability schemas, security-event schemas, EU AI Act Art. 12): the requirement has
converged, the record has not. The Internet-Draft that proposes one is `draft-sharif-agent-audit-trail` (R. Sharif; an
individual draft, not an IETF standard; -00 of 29 March 2026, **-04 of 15 September 2026, expires 19 March 2027**;
the author has an IPR disclosure on the datatracker: reading, writing and verifying the format is what this module does).
`omega_evidence.interop.aat` implements **-04**: it exports an `AgentEvidenceLog` ledger as AAT chains — one chain per
session, opened by a synthesised (and so labelled) genesis record and, on request, closed by a `session_end` record with
the draft's `session_hash` — and verifies any AAT chain offline, fail-closed: chain (`prev_hash` = SHA-256 over the JCS
of the previous record), vocabularies, UUID v4 identifiers, UTC monotonic timestamps, **`record_phase`** and the §4.2
pre-execution rules, the §7 REQUIRED `action_detail` fields per action type, recording independence (§5), the §5.3
fail-safe trust level, nonces, tombstones (§9.3), size bounds, the §13 rule that a decision may be called `reproducible`
only with a closed attestation, and every signature present: **ES256** (P-256, IEEE P1363), **ML-DSA-65** (FIPS 204,
empty context, through `cryptography` ≥ 48) and the **hybrid** mode, each key resolved by its `signer_kid` — the RFC 7638
JWK thumbprint for P-256 (checked against jwcrypto 1.6.1) and the AKP thumbprint of draft-ietf-cose-dilithium-11 for
ML-DSA-65 (reproduces the draft's own example `kid`). Optional §6.4 **Merkle batch anchoring** builds RFC 6962 epochs with
audit paths (roots and paths identical to cryptovalid's implementation for 1…20 leaves) and anchors the root with an
RFC 3161 token (verified only against a trust anchor, never green without one). Exports: JSONL (§10.1, the JCS form, so
the file re-reads to the same hashes) and CSV (§10.3, lossy, declared).

Six independent review rounds (19 September 2026; the dossier lists every finding;
every guard is asserted by its own message in the tests and ablated) found and we fixed, each re-measured — round 1: a **forged tombstone** (`tombstone_hash` := the next record's public `prev_hash`, stale signature kept)
made any signed record disappear with `ok: true` — the draft's §9.3 "retains the signature field" is exactly that hole,
so this module DEVIATES: a tombstone is signed anew by the deleting authority (`tombstone(..., key=)`) and verified like
any record, an unsigned tombstone passes only in an unsigned chain and is reported; hostile inputs crashed the verifier
(invalid calendar dates that match the RFC 3339 regex, lone surrogates and NaN in signed records, 600-deep nesting,
list-valued `action_type`) — all problems now, never exceptions; independent recording was not required to be signed
(§5.2 MUST) and was keyed on the genesis SHOULD field rather than on `recording_component` itself; a signed record without
`signer_kid` (§3.3 MUST) was accepted through the -03 fallback — now `allow_legacy_03=True` is explicit; `verify_epochs`
claimed a `leaf_count` check it did not do (now: index bound, index proven by the audit path, incomplete epochs
reported, complete epochs rebuilt); non-UTC offsets (a SHOULD) were refused; booleans passed as numbers in the §13.8
margin rule; truncation of a signed chain to a valid prefix was silent (now a warning, and stated as undetectable
without the close or an anchor). Round 2 added: with `keys` given, an unsigned record is a problem (a signed prefix
with an unsigned continuation is a rewrite — round 1 had left that open for the `keys` path); the -03 fallback never
applies to an independent recorder; `recording_component` equal to the agent is not independence; `verify_epochs`
survives hostile anchors and records (non-objects, unhashable ids, NaN, deep nesting), refuses conflicting anchors for
one epoch and reports anchors no record accounts for; integers beyond the double range are "not canonicalizable"
instead of an `OverflowError`; the export refuses a missing session, an outcome the runtime never writes, a duplicate
record identity, a backdated close and a `recording_component` equal to the agent; leap seconds and 7-9 digit fractions
parse. Round 3 added: one agent per chain (`agent_id` is checked against the genesis, the export refuses two agents in
one session); with `agent_kid`, a self-recorded record signed by another key in the key set is a problem (§6.3 step 3a
— a key rotation mid-session needs a new session); `leaf_count` is mandatory in an epoch anchor (an anchor without it
would hide a dropped record); every format check uses fullmatch (a trailing newline is not a digest); fractional seconds
of any length parse on Python 3.9-3.13; the synthesised close never claims `task_complete` (`trigger: "export"`,
`close_basis`); §13 fields on a non-decision record are a problem; an L2+ session recorded by the agent itself is a
warning (§5.2 SHOULD). Also declared: an agent whose key is compromised can tombstone its own self-recorded records with a
valid signature — only an independent recorder or an anchored epoch reveals it. Round 4 added: independence is decided
for the whole session (genesis `recording_mode`, or any record naming a recording component other than the agent) and
required of every record, tombstones and appended tails included — a record cannot opt out by omitting the field; one
recorder per session; a whole epoch missing from the chain is a problem under `require_complete` (an attacker cuts on
an epoch boundary); a record's `external_timestamp` is verified over the record's own digest only — a token over some
Merkle root never counts for a record (adding the token changes the record's leaf hash, so no inclusion proof can bind
the two: epoch-root tokens live in the epoch anchor); audit paths are built bottom-up (O(n log n), 4 000 records in
well under a second instead of quadratic); `anchor_epoch` refuses integers outside ±(2^53−1) like every export (until
0.9.1 the AAT export alone let exactly ±2^53 through: see the 0.10.0 notes); uppercase or
braced session ids are the same session; `keys={}` still means every record must be signed; a tombstone's `deleted_at`
before the record's own timestamp is a problem. Not checked and stated: §4.3 (a pre-execution record before every
state-changing action of a high-risk system) — which actions change state is not in the record; `time_verified` in
`verify_epochs` is the only green about time, `ok` is about structure. Round 5 added: a key-set entry whose `kid` is not
the RFC 7638 / AKP thumbprint of its key is rejected (a mislabelled or poisoned map cannot pass a key off as the agent's
or the recorder's); ES256 signatures are emitted in low-S form and a high-S signature is reported as malleable — the
`(r, n−s)` twin verifies, so an outsider can change a signed record's HASH (never its content; the draft mandates no
low-S, reported to the author); §13 field names inside the `action_detail` of a non-decision record are preserved as
unknown fields with a warning (the draft reserves only `aat_`), at the record's top level they are a problem;
`environment_attestation` must be base64 or a URI; `inclusion_proof` is OPTIONAL — a complete epoch rebuilds without them;
a CSV cell that would start a spreadsheet formula is prefixed with `'` (the CSV is never the record); a leap second, an
empty `agent_version` and a negative `margin_epsilon` are refused. Round 6 added: epoch membership is decided by the leaf
hash, not by `record_id` (a copied record with altered content is not a member); an RFC 3161 anchoring that fails raises
instead of returning an unanchored anchor, and an anchor declaring a TSA without a token is malformed; the exported
`record_phase_basis` says what is true — the phase is DERIVED from the omega outcome, the omega library gates nothing — and an
omega entry whose decision and outcome contradict each other (`consistent: false`) is refused; a tombstone of a tombstone
keeps the original record's hash; **who may delete is pinned**: in a self-recorded session a tombstone must be signed by
the agent (`agent_kid`) or by one of `tombstone_kids`, any other key in the key set is a problem, and without either the
signer is named in a warning; the synthesised close states `session_outcome: "unknown"` (its `outcome` is that of the
close action, declared — the draft's synthetic close for orphaned sessions describes a crash a monitor detected, which an
export cannot claim either); `1e999` in a JSONL is refused as non-finite, the `--epochs` file cannot crash the CLI, an
unparsable `pubkey_pem` or a non-dict `keys` is reported in `keys_rejected`; every guard of rounds 1-6 is now asserted by
its own message in the tests, on chains re-linked and re-signed so that neither `prev_hash` nor the signature masks it.

**0.8.1 (20 September 2026) — round 7**, run after 0.8.0 shipped and applied the same day: the **recorder of an
independent session is pinned** (`recorder_kid`, or the first signing key of the session), so a deleting-only key or any
other non-agent key in the key set can no longer rewrite the tail of an independent session with `ok: true` (0.8.0's "who
may delete is pinned" held only for self-recorded sessions — corrected, measured); the -03 fallback key is judged by its
thumbprint like any other, so `agent_kid` and the deleting authorities also bind legacy records; a tombstone whose
`signer_kid_classical` is not a string is a verdict, not a `TypeError`; `tombstone_kids` is type-checked; a tombstoned session
close is refused like a tombstoned genesis (a deleted close would reopen the chain to appends); `tool_response.parent_call_id`
must name an earlier `tool_call` of the session; the RFC 6962 comparison with cryptovalid is vendored as 20 root/path
vectors in `tests/fixtures/`, so it reproduces in any clone. **Round 8** (the last, its findings applied and re-measured
without a further round): a tombstoned close followed by appends was refused only while the tombstone was still the last
record — and 0.8.1's `original_event` guard could be written by the deleter ("pause" on a deleted close reopened the
chain: found by the same round, measured against the shipped 0.8.1). **0.8.2** closes it the only way that does not trust
the deleter: **no lifecycle record is ever tombstoned** (`tombstone()` raises; a chain carrying one is refused anywhere;
lifecycle records carry no erasable content, §9.3 exists for content), and a tombstone as the LAST record is a problem
(its `tombstone_hash` is bound to nothing). Also from round 8: a self-recorded session without `agent_kid` pins the genesis
signer as the agent (warning), so a second key in the key set cannot rewrite the tail without a problem; the PRIMARY
signer (`signer_kid`) is what every pin is compared with — a hybrid record whose classical half is the agent's key while
the primary is foreign is not the agent's; re-tombstoning keeps the ORIGINAL record's signature as evidence and lists the
deleters' signatures; the export verifies its own chains with the keys it just used before returning them, and refuses an
omega `agent_id` that cannot become a URI or a non-string `human_approver`; `inference_config` and `environment` values
are typed for the §13.6 closure.

Corrections to 0.7.0 (measured, not softened): 0.7.0 implemented -00 and its exports **violated the draft's REQUIRED
per-action `action_detail` fields** (`tool_name`, `parameters_hash`, `decision_type` were not emitted; the verifier did
not check them) — fixed and enforced; -00 chains have no `record_phase` and are refused with an explicit reason
(re-export them). Declared choices where the draft is silent (also reported to the author): §13 fields accepted at the
record top level or in `action_detail`; a record's `external_timestamp` token is checked over
SHA-256(JCS(record without external_timestamp, signature-value fields and batch)); epoch tokens live in a separate
epoch anchor (a token computed after the epoch is built cannot sit inside an already-chained record — only `batch` is
detached); a hybrid record whose classical signature fails is a problem. Declared limits: the mapping from omega
records is lossy and derives only what the record carries (`tool_call` and `decision`; other action types raise);
identifiers are UUID v4-format values derived deterministically from the omega digests (RFC 9562 reserves v4 for random
generation); `trust_level` is what the caller declares; AAT chains are verified by the Python module only (the Go/Java/JS
verifiers cover packs); the draft may change again.

```python
from omega_evidence.interop import aat
chains = aat.from_omega(list(log._ledger.entries()), agent_version="1.2.3", trust_level="L1",
                        private_key_pem=p256_priv, pq_signer=mldsa_signer, close=True)     # hybrid-signed, closed
for session_id, chain in chains.items():
    kid = aat.p256_thumbprint(p256_pub); pkid = aat.mldsa65_thumbprint(pq_pub_raw)
    aat.verify_chain(chain, keys={kid: p256_pub, pkid: pq_pub_raw})          # {"ok": True, "hybrid_verified": N, ...}
    anchor = aat.anchor_epoch(chain, tsa_url="https://freetsa.org/tsr")        # RFC 6962 epoch + RFC 3161 over the root
    aat.verify_epochs(chain, [anchor], tsa_ca_file="freetsa-cacert.pem")
```

```
python -m omega_evidence.interop.aat verify chain.jsonl --key <kid>=agent.pem --key <pkid>=agent.pq.pub --epochs epochs.json --require-signatures
```

The competitor table with the primary sources of 19 September 2026 (OpenTelemetry GenAI semantic conventions, OCSF
1.9.0, RFC 5848) is in the 0.8.0 release dossier: none of them carries a hash chain, a signature or a pre-execution
phase for agent records — they are observability and security-event schemas, not evidence formats.

## Independent verifiers (Go, Java, Node) and the differential oracle

### The absence side of the verdict

A check that could not run is not a finding about the pack. The **CLI** reports three verdicts, with a total order
`FAIL > NOT_ASSESSED > PASS` (the library returns `valid` and `assessed`; `verdict` is the CLI's rendering of the pair):

| `verdict` | exit | meaning |
|---|---|---|
| `PASS` | 0 | every layer that ran passed |
| `FAIL` | 1 | at least one layer was checked and is adverse |
| `NOT_ASSESSED` | 77 | nothing adverse was found, and a required check could not run on this host — or the verifier itself failed (layer `internal`, see *0.9.1* below) |

This holds whether the check was **required or optional**. Measured 24/09/2026: with the PQ layer optional and a
co-signature present but unverifiable here, a runtime without the backend used to answer `PASS` / exit 0 on the very
pack a capable runtime rejects with `FAIL` / exit 1 — an absence turning into a pass, which is the fail-open half of
the same defect. A present layer this runtime cannot read now marks the run `NOT_ASSESSED` even when it is optional,
so exit 0 means "checked, and nothing adverse", never "did not look". A layer that is genuinely absent from the pack
changes nothing: there was nothing to read.

Whether the artifact is well-formed is judged before the backend is probed, because that needs no backend: a
required co-signature of a known algorithm that is not strict base64 is a `FAIL` on every runtime, capable or not.

`valid` stays false under `NOT_ASSESSED` (fail-closed: a check that did not run is never a pass), and a layer carries
`assessed: false` when it failed only because this runtime lacks the capability — today, a known PQ algorithm with no
backend registered here. An **unknown** algorithm name stays a judgment: it can never be pq-protected. An absence
never hides a finding: one adverse layer beside a missing backend still gives `FAIL`.

Measured 24/09/2026, the same `OeVerify.java` on the same signed pack with `-require-pq`: on JDK 17, which has no
ML-DSA, `NOT_ASSESSED` / exit 77; on JDK 27, which has it, `FAIL` / exit 1 — because there the co-signature really is
invalid. Before this change both answered `FAIL`, and the first of the two was declaring a defect it had not checked.

All four verifiers carry the same split, and agree on it (measured on one signed pack with `--require-pq`):

| `pq_sig_alg` | Python | Node | Java 27 | Go 1.27 |
|---|---|---|---|---|
| `slh-dsa-sha2-128s` — known to the project, no backend in any of these runtimes | `NOT_ASSESSED` / 77 | `NOT_ASSESSED` / 77 | `NOT_ASSESSED` / 77 | `NOT_ASSESSED` / 77 |
| an unknown name — never pq-protected, so a judgment | `FAIL` / 1 | `FAIL` / 1 | `FAIL` / 1 | `FAIL` / 1 |
| `ml-dsa-65` with a backend present — the co-signature is really invalid | `FAIL` / 1 | `FAIL` / 1 | `FAIL` / 1 | `FAIL` / 1 |



`verifiers/` holds three stdlib-only re-implementations of the pack verifier — Go (`verifiers/go`, `crypto/mldsa`
for ML-DSA-65 with Go ≥ 1.27), Java (`verifiers/java/OeVerify.java`, JDK 24+ for ML-DSA-65, single file) and Node
(`verifiers/js/oeverify.mjs`: Ed25519, SHA3 and — since 0.8.0 — **ML-DSA-65 through the Node build's OpenSSL ≥ 3.5**,
feature-detected: the raw key is wrapped in a SubjectPublicKeyInfo and checked with `crypto.verify`, measured on Node
24.21.0 and 22.23.2; on an older OpenSSL the layer is reported present-but-unverified, never true) — plus
`verifiers/differential_oracle.py`, which builds packs, sidecars, ledgers and trust registries with the toolkit and
demands the same `(verdict, pq_protected, authenticated)` from Python, Go, Java and Node on every case — except from
a verifier that answers `NOT_ASSESSED`, which is neither agreement nor disagreement and is reported with its own
denominator (24/09/2026: counting it as agreement is how a shared incapacity used to read as consensus) — (tampered
packs, lenient base64, uppercase digests, unknown or non-string algorithms, classical algorithm declared as PQ,
overclaimed or missing `honest_scope`, duplicate keys, floats, nesting beyond 512, lone surrogates, non-UTF-8,
empty / unrelated / tampered / float ledgers, rotated and revoked signers, stripped / foreign / invalid post-quantum
layers, and — since 0.8.3 — an own `__proto__` key added without rehashing, a raw non-UTF-8 byte where U+FFFD was hashed,
a raw byte in a ledger key, a ledger line that is not an object): 0 disagreements on 86 pack cases plus 17 CLI-grammar cases
with 4 verifiers (21 September 2026); the hostile pack cases are anchored with the hash a lenient verifier would accept,
so the named layer decides (except `non-utf8` and `ledger-raw-byte-in-key`, which only detect a crash — a lossy decoder fails them on the hash anyway; the lossy-decoder cases are the two `…-hashed-as-fffd`); the signed-sidecar shape cases are anchored too, so a layer SKIP and a layer FAIL give different verdicts; on a Node without ML-DSA the two Node divergences are declared, not hidden. None of the four verifies the RFC 3161 token inside the
pack verdict: `verify_pack` checks the sidecar's shape and its digest→pack binding and reports the layer as SKIP with the
reason (round 6: the earlier sentence "verified by the Python reference only" was not true of the code — no trust
anchor reaches `verify_pack`); the cryptographic check exists as `timestamp.verify(tsr_b64, digest, ca_file=<TSA roots>)`
for the operator. The ledger profile is the cryptovalid one, so cryptovalid's five verifiers also
accept omega-evidence ledgers unchanged (measured 16/09/2026).

```
go run ./verifiers/go/cmd/oeverify -trust-store trust.jsonl -require-pq pack.json
java verifiers/java/OeVerify.java pack.json -expect-pq-key <b64>
node verifiers/js/oeverify.mjs pack.json --ledger pack.ledger.jsonl
python -m omega_evidence pack.json --trust-store trust.jsonl --require-pq
python -m omega_evidence pack.json --require-signed     # 0.10.0: a missing or unverifiable producer signature is FAIL (the four CLIs)
```

## Standards

RFC 3161 (timestamping, optional `openssl`); RFC 4998 / eIDAS LTA renewal *semantics*
(`preservation`: long-term evidence records renewed across hash and timestamp aging, verifiable
offline, tested — not the RFC 4998 ASN.1 wire format); Ed25519 with an optional post-quantum
co-signature — since 0.7.0 **ML-DSA-65 (FIPS 204)** built in through `cryptography` ≥ 48, SLH-DSA (FIPS 205)
through an external liboqs backend; any PQ scheme is admitted only by a known-answer-test gate (the built-in
ML-DSA backend must pass the NIST ACVP sigVer vectors shipped in `pqbackends/vectors/` before it is registered) —
no home-grown PQ crypto; SD-JWT (RFC 9901) issue/verify for the eIDAS 2.0 / EUDI wallet lane; PII-free by design
(salted per-record digests, no linkability).

## Hybrid post-quantum packs (0.7.0)

The same profile as cryptovalid 0.13.0, so the same rules and verifiers apply: the ML-DSA-65 co-signature is pure
ML-DSA with the **empty context string** over the UTF-8 bytes of the pack's `pack_sha3` hex string (the very bytes
the Ed25519 sidecar signs), 3309-byte signature and 1952-byte key in strict base64. The empty context is a measured
choice (16/09/2026): the JDK 24-27 built-in ML-DSA provider has no context API (JDK 27 GA 2026-09-15) and an AWS
KMS `ML_DSA_SHAKE_256` / `MessageType RAW` signature verifies with the empty context (measured against a real
KMS key; the Sign API has no context parameter) — a context would have locked Java verifiers and HSM signing
out; the PQ key MUST therefore be dedicated to this profile.

```python
from omega_evidence import pack, signing, trust, verify_pack
from omega_evidence.pqbackends import mldsa
idt = signing.Identity("acme")
pack.sign_pack("p.json", idt)                                # classical sidecar first (hybrid = both)
pq = mldsa.MlDsaFileSigner.keygen("acme.pq")                 # or mldsa.AwsKmsMlDsaSigner("<key id>", region=...)
pack.pq_cosign("p.json", mldsa.MlDsaFileSigner("acme.pq"))   # self-verified against the declared key
trust.TrustRegistry("trust.jsonl").trust("acme", idt.public_key_b64, pq_pubkey=pq["public_key_b64"])  # pin BOTH
verify_pack("p.json", trust_store="trust.jsonl", require_pq=True)["pq_protected"]     # True
```

`pq_protected` is a tri-state: **true** only when a registered backend verifies the co-signature AND the key is
the one the relying party pinned (`expected_pq_public_key_b64`, or the signer's `pq_pubkey` in the trust
registry, and only when the classical key that signed is the registered one) and the classical signature holds;
**null** when a layer is present but unpinned or not verifiable on this host and nothing required it; **false**
when absent, foreign, malformed or invalid — and also when the layer was required (`require_pq`, or a pinned key)
and could not be confirmed: a required layer that is stripped, foreign or unverifiable is a FAIL, never null. A
downgrade to Ed25519-only is refused by the relying party's requirement, not by the file. `authenticated` is
never true for a revoked or untrusted signer, nor when the body no longer matches `pack_sha3` (a signed identity over
content that was changed afterwards is not authenticated content). Re-establishing a revoked signer with `rotate` must
decide its post-quantum key explicitly (`pq_pubkey=<new>` or `drop_pq=True`). The PQ private key lives on disk (PKCS#8, 0600) or in **AWS KMS**
(`KeySpec ML_DSA_65`, `ML_DSA_SHAKE_256`, `MessageType RAW`; the Sign response's KeyId must match the key whose
public key was read). Rotating the classical key (`rotate`) keeps the pinned PQ key unless a new one is given or
`drop_pq=True`. Without `cryptography` ≥ 48 (ML-DSA on the OpenSSL 3.5 wheels since 48.0.0; the backend is
registered only after the NIST ACVP known-answer gate, which includes two empty-context signatures through the
very function registered) the layer is reported present-but-unverifiable (never a pass).

### 0.11.0 — malformed inputs rejected as the specs say, and an RFC 3161 mark only for a token for this digest (4 October 2026)

An audit of the verifiers (30 September 2026) and its review rounds. Each change of behaviour in the Python package has a
test that fails on the code before it; the new note of the Go, Java and Node verifiers was measured on a bench, not by a test.
**What changes for a user of 0.10.0** is listed at the end of the entry.

- **DSSE (`interop/dsse.py`)**: base64 as DSSE v1.0.0 asks verifiers to accept it — standard or URL-safe, one alphabet per
  string, padding only at the end, length a multiple of 4, no whitespace — with the same verdict on Python 3.9, 3.11 and
  3.13. `payload`, `payloadType` and `signatures` are required; a `payloadType` other than `application/vnd.in-toto+json`
  is rejected; a body that cannot be parsed as UTF-8 JSON is rejected even under a valid signature; NaN and Infinity are
  not JSON. A malformed envelope is `verified: false`, never a traceback.
- **SD-JWT (`interop/sdjwt.py`)**: `verify()` applies RFC 9901 §7.1 and rejects the whole token when a step fails (an alg
  other than EdDSA, an `_sd_alg` other than `sha-256`, a Disclosure of the wrong shape or not referenced, a repeated
  digest, a claim name that is not a string, is `_sd` or `...`, or is already present, an `exp` or `nbf` that is not a
  finite number or not satisfied), and the format rules of §4.2.1 and §4.2.4.1; BASE64URL is read strictly (RFC 7515).
  `issue()` refuses what `verify()` would reject: keys that are not strings or are `_sd`, `...` or `_sd_alg` anywhere, a
  disclosed name already in clear, NaN or Infinity.
- **Preservation records (`preservation.py`)**: an RFC 3161 token is checked as `timestamp.verify` reports it — PASS or
  FAIL against `tsa_ca_file` (new, optional), SKIP when it is recorded but not verified. Up to 0.10.0 the layer read a
  key that `verify()` never returns, so a record with an RFC 3161 token was always FAIL. **Verdict change:** an archive
  timestamp that declares `time_source: rfc3161` with `tsr_b64` missing, empty or not a string is a FAIL, not a SKIP: the
  token is what makes the claim of trusted time verifiable (RFC 4998 §4.1 makes `timeStamp` the one field of an
  ArchiveTimeStamp that is not OPTIONAL). A malformed record is `valid: false`, never an exception.
- **`timestamp.stamp` records `anchored: true` only for a reply carrying a token whose imprint is the requested digest.**
  Any HTTP body — an error page, a rejection, a genuine token for another digest — was recorded as anchored with its bytes
  as `tsr_b64`. The reply is read with `openssl ts -reply -text` (one parser, shared with `verify`). A token whose CMS
  signature is broken is still anchored at stamp time and refused by `verify` with the TSA roots: proving the signature
  needs the trust anchor, which is the verifier's job. `tests/test_stamp_granted.py` (a local TSA built with openssl behind
  a local HTTP server) now runs in CI.
- **`timestamp.verify` notes say what happened**: «no token recorded» when `tsr_b64` is missing, empty or not a string;
  «token recorded, not decoded or verified» without a trust anchor (it said «token decoded» before any decoding). The Go,
  Java and Node verifiers said «RFC 3161 token present and bound to the pack» for a sidecar with no token; they now say
  «no RFC 3161 token recorded», as Python does (status SKIP in the four, unchanged).
- **`ots.py`**: a sidecar that cannot be read or parsed is status `malformed`; the docstring no longer says the
  opentimestamps package verifies on Bitcoin when installed, which the code does not do.
- `timestamp`, `chip_registry` and `interop.aat` close every file and HTTP response they open.

**What changes for a user of 0.10.0.** An archive timestamp declaring `rfc3161` without a token now fails
`verify_evidence_record`; a preservation record with a genuine token is no longer always FAIL; DSSE envelopes and SD-JWTs
that 0.10.0 accepted against the specifications are rejected; a digest spelled with colons (`aa:bb:…`) is no longer
anchored by `stamp()` (`verify` already treated it as another digest).

Measured before the tag: `tests/test_toolkit.py` 159 tests and `tests/test_stamp_granted.py` 6 on Python 3.9.25, 3.11.2
and 3.13.15, each with and without `cryptography`; `tests/fuzz_toolkit.py` 3000 iterations, 0 violations;
`verifiers/differential_oracle.py` 0 disagreements of 193 here (Node 22, Go 1.24, Java 17: 9 cases not assessable on
this host); the CI run on the tagged commit measures Node 24, Go 1.27 and Java 27.

### 0.10.0 — two limits that were not declared, and a silent downgrade (28–29 September 2026)

(a) and (b) were found on 28/09/2026 by an independent review of 0.9.1 and confirmed by measurement before any code was
written; neither was stated anywhere in the 0.9.1 documentation. (c) was found the same day by the fuzzer added in this
release. The fixes are in this release; the description of what was wrong is this entry. **What changes for a user of
0.9.1** is listed at the end of the entry.

- **(a) Several processes appending to the same ledger corrupted it.** Up to 0.9.1 `Ledger.append` was guarded by a
  `threading.Lock` only, so two *processes* (not threads) writing the same file interleaved their lines: measured on
  commit `6728ced`, 4 processes × 200 appends left 601 lines of 801, `verify()` FAIL, 399 duplicate `idx`; another run
  gave 401 lines and 200 duplicates. 0.10.0 holds an exclusive advisory `fcntl.flock` on the open ledger file for each
  append (shared for a load); under it the instance first replays what other writers appended since its last write, so
  every entry links to the last hash on disk and carries the next `idx`. POSIX only: on Windows there is no `fcntl` and
  the ledger has one writer process, advisory only, not reliable on NFS — all stated in `ledger.py` and below. The test
  suite now has N threads and N processes appending to one ledger, plus a positive control that disables the lock and
  must break the chain. Cost and the full measurement: "Performance and robustness" below.
- **(b) The AAT export (`aat.jcs`, strict mode) accepted exactly ±2^53.** `omega_evidence/interop/aat.py` refused
  `abs(x) > 2**53`, so 9007199254740992 and −9007199254740992 went through the export while `canonical.py`, `ledger.py`
  and the Go, Java and Node verifiers refuse anything outside ±(2^53−1) — the I-JSON bound (RFC 7493 §2.2; RFC 8785
  Appendix B note 1). The exported text was still correct (2^53 is exact as a double, ES6 prints it as
  `9007199254740992`), so no hash changed; what was wrong is that one bound in the package was one integer wider than the
  other, and the docstrings said "beyond 2^53" where the rest says "outside ±(2^53−1)". 0.10.0 imports the package
  constant (`canonical._SAFE_INT`) into `aat.py` instead of a second hand-written number; strict export now refuses
  ±2^53, accepts ±(2^53−1); the verify path (`strict=False`) is unchanged (an out-of-range integer is serialised as ES6
  would serialise the double). Test `test_jcs_strict_integer_bound_20260928` covers 2^53−1 / 2^53 / −2^53 / 2^53+1 and
  contains its own positive control (with the 0.9.1 bound put back, the test sees 2^53 accepted). The text of the AAT
  Internet-Draft -04 (IETF archive, 115 736 bytes, SHA-256 `c75a8fdf…`, read on 28/09/2026) contains no integer of 16
  digits or more and no test vector, so no published AAT vector sits on this boundary; no fixture in this repository
  uses 2^53 exactly. Nothing that verified before verifies differently now: only an export of a record carrying exactly
  ±2^53 changes, from accepted to refused. `ledger.py` had its own copy of the same number; it now imports the one
  constant too (no behaviour changes; the test asserts the three names are one object).
- **(c) A one-bit change of `sig_alg` downgraded a signed pack silently.** Since 0.7.0 the producer-signature layer
  accepted `sig_alg: "ed25519"` only and reported any other string as an "unsupported algorithm" SKIP — in the four
  verifiers alike. Measured on 28/09/2026 by the seeded fuzzer (seeds 1 and 2: `"eD25519"`, `"ed2 5519"`): on a pack that
  was signed AND anchored, that SKIP left the verdict `PASS` / exit 0, with `authenticated: false` — the pack fell from
  `signed` to `anchored` and nothing but the `authenticated` field said so. No forgery, but a silent downgrade of the
  tier that a relying party reading the exit code would not see. 0.10.0, the same in Python, Go, Java and Node:
  - a `sig_alg` that is a **non-canonical spelling of a supported name** — the name folded to ASCII lowercase letters and
    digits, everything else dropped, equals `ed25519`: `"eD25519"`, `"ED25519"`, `"ed2 5519"`, `"ed-25519"`,
    `"ed25519\n"`, `" ed25519"`, a zero-width space appended — is a **FAIL** of the producer-signature layer ("sig_alg is
    not the canonical name of a supported algorithm"): no producer writes such a name, so it is a judgment about the
    sidecar, not an absence;
  - a **genuinely unknown** name (`"rsa-pss"`, a post-quantum name in the classical field, a name with a non-ASCII
    look-alike letter — declared limit: such a letter makes the name unknown, not a variant) stays a SKIP, the pack
    earns the tier its other layers give it, and the SKIP is never silent: the layer reads "signature present, algorithm
    unsupported, not verified: <name>" and the authenticity layer carries "— a signature is present but its algorithm is
    unsupported and was not verified" (also when the pack then fails for want of an anchor);
  - **`--require-signed`** in the four CLIs (`verify_pack(..., require_signed=True)` in the library; one dash or two, no
    value on the flag, as the other boolean) is fail-closed on the classical layer: a pack with no signature sidecar
    ("signature required but the pack is not signed") or with a signature that could not be verified is `FAIL`, never
    `anchored`; a verified signature (canonical name, or the legacy sidecar without `sig_alg`) satisfies it.

  Measured on 29/09/2026 on this tree, the four verifiers on 32 sidecar / flag shapes: the same verdict, exit code,
  `authenticated` and the same two layer texts in all four. The differential oracle gained 32 `sig_alg` cases with an
  expected verdict each — for every `sig-alg-` case the oracle also compares the (status, detail) of the producer-signature
  and authenticity layers, so the reason is one reason in the four — and one CLI-grammar case: 0 disagreements over 193
  cases with the four verifiers on 29/09/2026; 37 of the `sig-alg-` cases run against the four 0.9.1 verifiers
  (Python, Go, Java and Node built from commit `6728ced`) are red on 32 of them and green only on the 5 whose behaviour
  did not change (positive control). The fuzzer gained the property "no silent downgrade" (a mutator that produces
  spellings and unknown names, and a second `require_signed` call on every mutant) and two positive controls that
  disable the canonical-name rule and the requirement (26 and 160 violations seen on the smoke seed); the unit tests a
  class that is red on 0.9.1 (11 spellings verify `valid` there) and carries its own positive control.

  **What changes for a user of 0.9.1.** (1) Any sidecar whose `sig_alg` folds to `ed25519` without being exactly
  `ed25519` now verifies `FAIL` where it verified SKIP + the tier of its other layers. The producer of this toolkit has
  only ever written `"ed25519"`; only hand-written or altered sidecars are affected. (2) The text of the SKIP for an
  unknown algorithm changed from "unsupported sig_alg: X" to "signature present, algorithm unsupported, not verified: X",
  the authenticity texts changed as described above, and Python's "anchored … — ledger" is now the wording of the other
  three (layer `detail` strings are declared non-normative; the verdict tuple is unchanged for these). (3) A new flag
  and a new keyword argument, both opt-in; nothing changes for a caller who does not pass them. (4) `verify_pack`'s
  `authenticated` is computed from the same three booleans as in Go, Java and Node (signature PASS, registry not
  refusing, integrity PASS) instead of being read off the wording of the authenticity layer — the same value in every
  case the oracle and the tests exercise. (5) **A ledger truncated or replaced under an open `Ledger` instance is refused**:
  the next `append()` raises `RuntimeError("ledger truncated by another writer …")`, and so does every later one from that
  instance — recreate the `Ledger` after a log rotation (`os.rename` + a new file) or any external truncation. 0.9.1 went
  on writing a fresh file starting at the next `idx` with a broken chain, silently (measured on `6728ced` by the 29/09
  review). In batch mode both versions keep writing to the old inode through their open handle. A filesystem that
  refuses `flock` makes `append()` raise `OSError` (not wrapped). (6) Go: the exported `VerifyPack` keeps its 0.7.0
  signature; the requirement is `VerifyPackRequireSigned(…, requirePQ, requireSigned)`. Java keeps the 5-argument
  `verifyPack` and adds a 6-argument one; Node takes `requireSigned` in its options object. (7) The private Python helper
  `verifier._check_signature_and_trust` returns a 4-tuple (a fourth element saying why the layer is not PASS) instead of
  a 3-tuple. (8) `Ledger.entries()` and `raw_entries()` read the file as one snapshot under the shared file lock, like
  `verify()` (0.9.1 read line by line with no lock, so a concurrent writer's half-written line could in principle be
  seen); the lock is released before the first entry is yielded, so appending while iterating cannot deadlock, and the
  text is held in memory while iterating. (9) The Node verifier writes its receipt and exits only once the write is
  drained: with a receipt longer than a pipe buffer (64 KiB, e.g. a layer detail quoting a 70 000-byte `sig_alg`) a piped
  reader got 65 536 bytes of unparsable JSON in 0.9.1; the oracle now carries that case (the four write it whole).

### Corrections (2026-09-26)

- Small-order keys allow a forgery on any message, not on "a share of messages" (correction to the 0.9.1 notes). The
  0.9.1 note said that, for the small-order points other than the identity, a forgery holds only "on a share of
  messages". By the verification equation, that is true of one fixed construction (R = identity, S = 0), but it
  understated the risk: with any small-order public key A, of order n = 2, 4 or 8, anyone can produce a signature on any
  message. Pick S and a guess g for k mod n, set R = [S]B − [g]A, compute k = H(R ‖ A ‖ M) mod L as the verifier does,
  and retry until k ≡ g (mod n); each try succeeds with probability about 1/n. Measured on 2026-09-26 with curve
  arithmetic written for the measurement, not this repository's code: for each of the 8 small-order public keys, a
  signature on one message chosen in advance verified under OpenSSL, through Python `cryptography` (1 to 16 tries) and
  through Node 22 `crypto` (1 to 17 tries) — the same backend, so one measurement, not two independent ones. In the
  Python probe, the same construction against an ordinary key verified 0 times in 2000 (null control). The refusal of
  these keys added in 0.9.1 is unchanged; this corrects only the description of what it prevents. The source comments
  that repeated the wording are corrected too.
- The SBOM license of 0.7.0 to 0.9.1 was wrong. The CycloneDX SBOM attached to the 0.7.0, 0.8.0, 0.8.1, 0.8.2, 0.8.3,
  0.9.0 and 0.9.1 releases declares `AGPL-3.0-or-later`; the package is `Apache-2.0` (LICENSE and `pyproject.toml` at
  each of those tags). The release script had the license hard-coded; it now reads it from `pyproject.toml` and fails if
  none is declared. The earlier assets are left as published, since a replaced asset would no longer match the published
  SHA256SUMS nor the copies already downloaded; this entry is the correction.

### 0.9.1 — inputs, sidecar fields, verifier faults and memory (25–26 September 2026)

Found by an adversarial review (NEMESIS) of 0.9.0 on 25/09 and by an independent review of the ledger reading on 26/09.
The verdicts below are the same in the Python reference, Node, Go and Java; where the four differ in how they get there,
it is said. Numbers dated 25/09 come from the author's measurement records, which are not part of this repository, and
were not re-measured for 0.9.1; the oracle cases and tests that exercise each rule are in the repository and run with it.

- **Small-order Ed25519 keys refused (25/09).** With the identity key as public key, R=identity, S=0 is a valid
  signature on every message; the other small-order points admit such forgeries on a share of messages (the hash depends
  on R, so not on every one; not measured here); a non-canonical encoding (y >= p) is refused because the key has no
  unique encoding. Measured with the identity key through Python `cryptography` and Node: a forged pack signed that way,
  with that key pinned by the relying party, verified as valid and authenticated; the Go and Java verifiers received the
  same guard without a measurement of their behaviour without it. The four now refuse those keys with the same list (8
  small-order encodings, 2 with the sign bit on x = 0, every y >= p). The list was checked against curve arithmetic in
  Python (0 disagreements on 48 special and 200 000 random keys); that the four verifiers apply it alike rests on 6 oracle
  cases, all FAIL in the four.
- **Only regular files are read, without blocking, and read once (25/09).** A FIFO in place of the pack, a sidecar, the
  ledger or the trust store blocked all four verifiers; a symlink to `/dev/zero` exhausted memory in at least one verifier (Java reported the
  `OutOfMemoryError` as a `FAIL` of the pack). Each file is now opened with `O_NONBLOCK` (Python, Node, Go) and accepted
  only if the opened descriptor is a regular file; anything else fails its layer exactly as an unreadable file does
  (`pack-json`, `producer-signature`, `ledger-chain`, `rfc3161`/`timestamp`, `trusted-signer` FAIL — the outcome a
  directory in that position already had). The JDK has no `O_NONBLOCK`: Java checks the type on the path right before
  opening, so a FIFO in place is never opened, but one swapped in between that check and the open can still block it (a
  race the other three close by checking the descriptor).
- **One input bound, the same number in the four: 64 MiB (67 108 864 bytes) per file (25/09)** — and therefore per
  ledger line. Before: 256 MiB in Node and Java, a 64 MiB line buffer in Go that no document mentioned (its pack and
  sidecar reads were unbounded), no bound in Python. A file of 64 MiB + 1 byte now fails its layer in all four; files
  between 64 and 256 MiB that the previous limit of Node and Java admitted are refused. On the input shapes of the 25/09
  record (one ledger line of 64 MiB, a ledger of 161 200 lines, a pack field and a sidecar field of 64 MiB, in ASCII,
  with `é` escapes and with raw 3-byte UTF-8), measured on 25/09 before the line reader of 26/09, peak RSS: Python 3.11
  397 MiB, Go 1.27.1 517 MiB, Node 22.23.2 501 MiB, Java 27 1325 MiB — the JVM grows its heap lazily up to its default
  maximum (1618 MiB on that 6.3 GiB host), so what Java needs is the smallest heap that still verifies every shape: 389
  MiB (`-Xmx`); for Node, 304 MiB (`--max-old-space-size`). Below that heap Java answers `NOT_ASSESSED` (see "A fault of the verifier" below); a
  V8 heap exhaustion or a Go runtime out-of-memory is fatal in the runtime itself and cannot be turned into a receipt.
  To stay within the bound, three copies were removed: Node hashes the canonical form part by part instead of joining it
  (and escapes strings in bounded chunks), Java validates UTF-8 in a streaming pass, decodes each file once and hashes in
  64 KiB spills; the bytes produced are the same as before (checked on 25/09, record not published).
- **The ledger is read one line at a time (26/09).** The bound alone did not keep memory in check: a ledger of 64 MiB
  made of many short lines was split into all its lines at once. Measured on the code of this release before the line
  reader (`474122b`, which already has the bound and the fault guard), under `prlimit --data` 2.5 GB, peak RSS:
  67 108 864 empty lines — Python, Node and Go answered FAIL at 611, 1018 and 1701 MiB, Java answered `NOT_ASSESSED` (out
  of memory, 1761 MiB); 22 M lines `{}` — Go crashed with no verdict (2307 MiB), Python and Java answered `NOT_ASSESSED`
  (2365 and 1786 MiB), Node answered FAIL at 2170 MiB. Node, Go and Java now stop at the first break of the chain (no
  caller reads the entries of a broken chain), Python after 1 000 bad lines, which it reports (`agent.verify()` adds
  `bad_entries_truncated`). After (`8956528`), same cap, both shapes: every verifier answers FAIL at 157–254 MiB; Python
  on the `{}` shape takes 0.3–0.5 s, where before it ran 84 s and then answered `NOT_ASSESSED` for want of memory. Python's line reader is ~3× slower than `split` on the empty-line
  shape (12.9 s against 4.7 s in-process). **Still open:** a VALID document of 64 MiB holding one container with tens of
  millions of elements (measured: one ledger line with 33.5 M zeros; a pack field of that kind behaves the same in Go and
  Java) under a 2.5 GB cap — Python PASS at 544 MiB, Node PASS at 1813 MiB, Go crashes with no verdict at 2396 MiB, Java
  answers `NOT_ASSESSED` at 1765 MiB; Go and Java measured identical before this change (Python and Node: no before). A bound on the number of JSON values is the candidate
  fix, not made.
- **The sidecar fields the producer writes are read (25/09).** `fingerprint` and `signed_utc` were never looked at, so
  `""`, `0`, `null`, `true`, `[]` or `{}` left a signed pack PASS and `authenticated`. Absent, they are still accepted
  (legacy sidecars); present, they must be what `pack.sign_pack` writes — `fingerprint` equal to the one derived from
  `public_key_b64` (`"ed25519:"` + the first 8 and last 8 hex digits of SHA-256 of the raw key, joined by U+2026), and
  `signed_utc` of the form `YYYY-MM-DDTHH:MM:SS+00:00` in ASCII digits naming a real calendar instant (year ≥ 1, second ≤
  59) — else `producer-signature` is FAIL ("malformed sidecar field").
- **`""` is a present, malformed algorithm name (25/09).** `pq_sig_alg: ""` read as absent while `null` was a FAIL, and
  `sig_alg: ""` was an "unsupported algorithm" SKIP while `null` was a FAIL: both are now FAIL of their layer.
- **A fault of the verifier is not a finding about the pack (25/09).** Java turned any `Throwable` into `verdict: FAIL` /
  exit 1; the Python CLI and Node exited 1 on an uncaught exception (the code of FAIL) and Go 2 on a panic (the code of a
  usage error). Each verifier now catches its own faults and adds a layer `internal`, status FAIL with `assessed: false`:
  the run is `NOT_ASSESSED` / exit 77, unless a layer judged before the fault is adverse (then `FAIL`, as ever: an absence
  never hides a finding); `authenticated` and `pq_protected` are false. The library `verify_pack` returns that receipt
  instead of raising. Test hook, the same in the four: `OEVERIFY_INJECT_INTERNAL_ERROR=1` raises an internal error right
  after the `pack-sha3` layer (it can only lower a verdict to `NOT_ASSESSED` or keep a `FAIL`, never produce a `PASS`).

**Oracle and tests.** The differential oracle compares the four verifiers and, for the new cases, a DECLARED expected
verdict, so four verifiers wrong the same way are red. Recorded on 25/09: 48 new cases for the 25/09 rules other than the key list; 0.9.0 was red on
43 of them against the expected verdicts; 135 pack cases plus 17 CLI cases at 0 disagreements after the change; each check of that set (not the key list)
removed in turn, in each verifier, turned red its own cases. A verdict that is not one (crash, timeout, missing
JSON, an exit code other than 0/1/77) counts as a disagreement even when all four share it. The cases that used to
block or exhaust memory ran on 25/09 under a `systemd-run` MemoryMax cap that turned out not to limit on this host (500
MB allocated under MemoryMax=100M, measured 26/09); since 26/09 they run under `prlimit --data` 1.5 GB, which does limit
(at that cap the old Node ledger reader crashes on the `{}` case and the row turns red). Totals on 26/09 on the commit tagged v0.9.1: 160
oracle cases with 0 disagreements over Python, Node, Go and Java (the 6 small-order-key cases and 2 many-line ledgers
added after the 152 above), 124 tests (1 skipped).

### 0.8.3 — verifier hygiene from the cra-evidence review (21 September 2026)

Twelve review rounds on cra-evidence 0.3.0, whose verifiers are re-implementations of these, found defect classes in
shared code; a review round on this release (three independent reviewers; a fourth was unavailable) found more of the same
class here. Measured on 21/09/2026 with a four-verifier probe before each fix and with the differential oracle after
(103 cases, 0 disagreements); the same oracle run against the four 0.8.2 verifiers (Python, Go, Java, Node from tag
v0.8.2) is red on 46 cases, and against a deliberately lenient Python (loose parser, no scope check, no reserved-tag /
surrogate / float refusal — `verifiers/lax_python_ablation.sh`, re-measured 21/09/2026) on 13:

- **Node dropped an own `__proto__` key while copying** (`c[k] = …` invokes the prototype setter): a pack or ledger
  entry with such a key added and its hash untouched verified PASS in Node alone. `Object.fromEntries` keeps the key.
- **Node and Java decoded a non-UTF-8 file lossily**: a pack or ledger entry whose hash was computed over U+FFFD while
  the file held the raw byte verified PASS in both (a lossy decoder reads exactly the hashed text). Strict UTF-8
  decoding in both; a malformed byte is a `FAIL` verdict.
- **The Python reference raised instead of answering** (a traceback, no verdict): `UnicodeDecodeError` on a raw byte in
  the ledger, `AttributeError` on a ledger or trust-store line that is not an object, `JSONDecodeError` on a ledger
  that is not JSON, `RecursionError` on a 100000-deep `.tsr.json`. `Ledger` now loads with the strict parser and
  raises one `RuntimeError`; the verifier reports the layer as `FAIL`.
- **The Python reference had no lone-surrogate rule** (round 2): an anchored pack holding `"\ud800"` with a correct
  hash — and a ledger entry the 0.8.2 producer itself wrote — verified PASS in Python and FAIL in Go, Java and Node. The
  linear pre-scan of the three (`HasLoneSurrogate`) is now in `loads_strict`, and the producer refuses such strings.
- **Node accepted a float lexeme with an integer value** (round 3): `JSON.parse("1.0")` is the integer 1 and the
  canonical form could not see the lexeme, so a pack with `"n":1.0` hashed as `"n":1` verified PASS in Node alone
  (Python's `parse_float`, Go and Java refuse it on the text). A linear scan of the raw text now refuses `.`/`e`/`E` in
  a number outside a string.
- **The `honest_scope` gate had two regex semantics**: Python's Unicode `\b` and its `i ≡ ı` (U+0131) case folding made
  `"does NOTé prove x"` and `"fully certıfied; does NOT prove x"` FAIL in Python and PASS in Go (RE2), Node (no `u`
  flag) and Java (no `UNICODE_CASE`). Python now uses `re.ASCII`, the semantics of the three.
- **The Python reference crashed on typed-wrong LTV material**: `validation_material.crls_b64` as an int or a list of
  ints beside a correct digest was a `TypeError` traceback while the three gave a verdict. Typed now.
- **The anchoring rule was read at two levels** (round 4): Go, Java and Node look for `anchored_pack_sha3` in the
  ledger ENTRY (top-level or under `data`); the Python reference looked inside `data` (so `data.anchored_pack_sha3` or
  `data.data.anchored_pack_sha3`). A chain-valid entry with a top-level anchor was PASS in the three and FAIL in Python;
  one under `data.data` the reverse. Python now reads the entry. A trust-store entry without `data` was skipped by
  Python and a broken store for the three: broken everywhere now.
- **Node's `[^.]{0,40}` counted UTF-16 code units** (no `u` flag): 21 astral characters between `NOT` and `guarant`
  were 42 units in Node and 21 code points elsewhere, so the negation was seen by three verifiers and not by Node.
  Astral characters are folded to one placeholder unit before the three scope tests.
- **The reserved type-tag key was a verifier rule in Python only** (round 5): a pack carrying
  `__omega_reserved_type__` (top-level or nested) was `pack-sha3 FAIL` in Python and PASS in the three, which hash the
  text as it is. The key is a producer rule (an object must not forge the tag the encoder emits for `Decimal`); the
  verifier now hashes what it read (`sha3(obj, from_text=True)`), the producer still refuses it.
- **Node's trust state was a plain `{}`**: a signer id such as `toString` or `__proto__` read through `Object.prototype`
  (a chain-valid store with a revoke of `__proto__` then a trust of `toString`: FAIL in Node alone, and the process
  prototype polluted). `Object.create(null)` now.
- **Python resolved `-l` / `-ledg` by prefix** once `-ledger` was registered as an option string in round 4
  (`allow_abbrev=False` guards the `--` branch only): a verdict in Python alone. Only the `--` forms are registered and
  the exact one-dash spellings are mapped before parsing.
- **The Python reference read the RFC 3161 sidecar with the loose `json.loads`**: a `.tsr.json` with a float or a
  duplicate key beside a correct digest was PASS in Python and FAIL in Go, Java and Node. Strict parser there too.
- **Node crashed with an uncaught `ENOENT`** on a `--ledger` path that does not exist (the other three: FAIL).
- **One CLI grammar in the four.** Usage error (exit 2, no verdict) everywhere for: an unknown flag; a value flag with
  `""`, without a value, or with a flag as its value; an abbreviated flag; a second positional; a pack path `""` or
  `-`; the `--` terminator; `--require-pq=false`; `-h`/`--help` (round 3: argparse answered it with exit 0); a value flag
  repeated with a bad value first (round 13: Go's `flag.Visit` and argparse checked the final value only — `-ledger
  -require-pq -ledger L` ran in Go with the post-quantum requirement silently eaten as a value). `--flag=value` is accepted by all four (argparse and Go's `flag` did
  natively; Java and Node now do), and so is one dash or two (`-ledger` / `--ledger`: Go's `flag` took both, Java one,
  Python and Node two — round 4). Before: `python -m omega_evidence anchored.json --ledger ""` was **PASS** with the
  operator's ledger silently replaced by the sidecar (measured on v0.8.2), Node gave a verdict on an unknown flag,
  Go and Java took `""` as "not given" and a flag as a path, Python accepted `--ledg` and crashed on it.

Declared, not aligned: Go's `flag` stops at the first positional, so `oeverify pack.json -ledger L` is a usage error
in Go and a verdict in Python, Java and Node (put flags first); in 0.8.3–0.9.0 Node and Java refused an input over 256 MiB, Go
bounded only a ledger line (64 MiB; its pack and sidecar reads were unbounded) and Python had no bound — a valid file beyond
those sizes verified in some of the four only (one bound in the four since 0.9.1, below). Not measured:
Ed25519 decoding of non-canonical or small-order points in a sidecar (the four backends — pure Python, OpenSSL, Go's
`edwards25519`, SunEC — have their own rules; no such vectors are in the oracle yet). Go's `(?i)` in the scope regexes is Unicode simple folding (the other three fold
ASCII only): harmless while no keyword contains `k` or `s` (KELVIN SIGN, LONG S fold to them) — a caveat for whoever adds a word.

Verdicts that changed, counted by script from the positive-control table (criterion: well-formed JSON input; a
crash→verdict is listed apart). **Python, twelve**: `scope-NOT-before-accented-letter`, `scope-dotless-i-overclaim`,
`ledger-anchor-top-level`, `pack-reserved-tag-key-top-level`, `pack-reserved-tag-key-nested` FAIL→PASS;
`lone-surrogate`, `ledger-lone-surrogate-entry`, `ledger-anchor-under-data-data`, `trust-entry-without-data`,
`tsr-float-beside-good-digest`, `tsr-dup-key-beside-good-digest`, `scope-overclaim-glued-to-accented-letter` PASS→FAIL — each toward the verdict of the other three; and
seven inputs that were a traceback now get a verdict (two of them non-UTF-8 files). **Node, seven**: `scope-astral-21-…`,
`trust-revoke-proto-then-trust-toString`, `pack-proto-key-hashed-by-producer` (a pack the producer API makes, with a
top-level `__proto__` key) FAIL→PASS; `pack-float-1.0-hashed-as-1`, `pack-exp-1E2-hashed-as-100`,
`pack-proto-key-hash-untouched`, `ledger-proto-key-hash-untouched` PASS→FAIL; plus one crash→verdict (`ledger-path-missing`).
**Go and Java: none** on well-formed JSON (Java: one usage→verdict, `cli-eq-form-verdict`, counted under the CLI
paragraph). On the two non-UTF-8 files hashed over U+FFFD, Node and Java PASS→FAIL.

Three classes of input that the **0.8.2 producer API** wrote change verdict: (1) a pack whose body has a top-level
`__proto__` key — Node FAIL→PASS; (2) a ledger entry holding a lone surrogate (`Ledger.append` accepted it, `json.dumps`
wrote `"\ud800"`) — Python PASS→FAIL, the three already failed it; (3) an `honest_scope` with an overclaim keyword glued
to a non-ASCII letter, e.g. `"écertified. Does NOT prove y"` — Python PASS→FAIL (Unicode `\b` saw no word boundary before
`certified`; ASCII does), the three already failed it, and the 0.8.3 producer refuses it (measured on v0.8.2, 21/09/2026).
The 0.8.3 producer additionally accepts scopes such as `"does NOTé prove x"` that the 0.8.2 Python verifier refused.

Two Go files carried an `AGPL-3.0-or-later` SPDX header in this Apache-2.0 repository (the author's own code): corrected to
`Apache-2.0`.

### Breaking changes in 0.8.0 / 0.8.1 / 0.8.2

- `interop.aat` now implements draft **-04**: `record_phase` is mandatory, the §7 per-action `action_detail` fields
  are required, `signer_kid`/`sig_alg` accompany every signature, and `verify_chain` takes `keys={kid: key}`
  (`pubkey_pem` resolves signed records without `signer_kid` only with `allow_legacy_03=True`). Chains exported by 0.7.0 (-00) do
  not verify any more (no `record_phase`, missing §7 fields): re-export them from the ledger — the export is
  deterministic, so the new chain is the same evidence in the new format. `sign_record(rec, key)` accepts a P-256
  private PEM (ES256) or an ML-DSA-65 signer; `sign_record_hybrid` produces the hybrid record.

### Breaking changes in 0.7.0

- **Strict acceptance profile** (shared with the Go/Java/JS verifiers and cryptovalid 0.13.0): packs, ledgers,
  sidecars and trust stores with **floats**, duplicate keys, integers beyond ±(2^53−1), nesting deeper than 512,
  NaN/Infinity, CR line endings or non-sequential `idx` are refused. A 0.6.x ledger or pack holding a float
  (e.g. `{"amount": 10.5}`) no longer verifies: store such values as strings (`"10.5"`) or `Decimal`.
- The producer-signature layer accepts **`sig_alg: "ed25519"` only** (missing = ed25519); a non-string is a malformed
  sidecar (since 0.9.1 the empty string is a malformed sidecar too, no longer a SKIP). Any other string was an
  "unsupported algorithm" SKIP up to 0.9.1; since 0.10.0 a non-canonical spelling of `ed25519` is a FAIL and a genuinely
  unknown name is a SKIP that names the unverified signature (see the 0.10.0 notes). A post-quantum backend is never a
  classical producer signature.
- A trust store that fails the strict chain verification raises `ValueError` on load and is a `trusted-signer`
  FAIL in the verifier (it used to crash, or trust the last of two duplicated keys).
- `TrustRegistry.rotate()` keeps the pinned post-quantum key unless `drop_pq=True` (it used to drop it silently).

The normative output of every verifier is the tuple `(verdict, pq_protected, authenticated)` plus each layer's
status; layer `detail` strings are human-readable and non-normative (their wording and the order in which two
malformations are reported may differ between implementations).

## Performance and robustness (measured)

Every number below was produced on **28 September 2026** by the command next to it, on one host: **Intel Core i3-N305, 8
CPU, 6 471 MiB RAM, Linux 6.6 x86_64, CPython 3.11.2, `cryptography` 50.0.1 as the Ed25519 backend**, ext4 on flash.
They describe that host and nothing else; a shared CI runner gives other numbers, which is why the CI bench job has no
threshold. Reproduce: `python3 tests/bench_toolkit.py --json bench.json` (about 3 minutes; the JSON carries the host,
the parameters and every figure, including the ones not shown here).

| Operation | Throughput | Latency p50 / p95 / p99 |
|---|---|---|
| canonical SHA3-256 of a small object | 86 096 ops/s | — |
| `Ledger.append`, sync (fsync per entry) | 487 ops/s | 1 994 / 2 581 / 3 587 µs (n = 1 000) |
| `Ledger.append`, batch (fsync every 256) | 30 542 ops/s | 24 / 33 / 55 µs (n = 20 000) |
| `verify_text` of a 20 100-entry ledger (read + verify) | 34 040 entries/s | 591 / 598 / 598 ms per run (n = 5); peak Python allocations 8.4 MiB |
| `Ledger(path)` open, strict replay of 20 100 entries | 34 215 entries/s | 586 / 599 / 599 ms per run (n = 5) |
| Ed25519 sign | 14 541 ops/s | 67 / 75 / 85 µs (n = 20 000) |
| Ed25519 verify | 9 299 ops/s | 105 / 116 / 136 µs (n = 20 000) |
| `verify_pack` end to end (pack + ledger + signature + trust store, files re-read each call) | 2 106 ops/s | 467 / 518 / 591 µs (n = 250) |

The tail percentiles (p95 / p99) are from ONE run. Measured on 28/09/2026 on this host with a second, independent full run of
the same bench 36 minutes later (71 numeric figures compared): throughput, totals, medians and memory agreed within 8 %;
of the 14 p95 / p99 figures, 8 differed by more than 10 % and 5 by more than 20 %, the largest by 34 % (`verify_pack`
p95: 518 → 694 µs); the per-run maxima by up to 71 %. Read the p95 / p99 column as an order of magnitude, not a bound.

- **Scale, batch mode, 1 000 000 entries** (`{"e": i, "p": "payload-i"}`, file 230 MiB): append 35.6 s (28 127
  entries/s), open with strict replay 31.8 s, `verify()` 32.4 s (30 869 entries/s), chain OK; peak Python allocations of
  `verify_text` (read + verify) 461 MiB, process `ru_maxrss` 812 MiB after the run (55 MiB before). The library's
  `Ledger.verify()` has no size bound: the 64 MiB bound belongs to the verifiers, which refuse such a file.
- **Tamper detection at scale**: one byte changed in the middle entry of the 20 100-entry ledger is reported as a broken
  chain (1 bad line) in 585 ms.
- **Concurrent appends (`tests/test_toolkit.py`, `TestConcurrentAppend20260928`)**: 4 threads sharing one instance, 4
  threads with an instance each, and 4 processes with an instance each, in sync and in batch mode, all appending to one
  ledger: at the end `verify()` is OK, the count is the sum of the appends, every `idx` present exactly once. Before the
  file lock of 28/09/2026 (commit `6728ced`, `threading.Lock` only), 4 processes × 200 appends left 601 lines of 801,
  `verify()` FAIL, 399 duplicate `idx`, and one process refused to open the file mid-write ("catena rotta"); another run
  of the same probe gave 401 lines and 200 duplicates (the outcome depends on the interleaving). The positive control in the
  test suite disables the lock in every worker and must be able to break the ledger: measured on the final code, 4 × 60
  appends, lock disabled, sync and batch, every worker exited on a broken chain and the file held 5 and 16 lines of 241.
  The lock costs a band of 12–28 % of batch-mode throughput on this host (median 17 %: 6 alternated pairs of 20 000
  appends, HEAD ledger against this one, each run in its own process; two further 3-pair runs gave 13 % and 20 %, a
  re-run of the 6-pair script 15.6–20.8 %, median 17.3 %) — a band because run-to-run noise on this host is of the same
  order as the effect; the sync mode is bound by fsync and unaffected within noise.
- **Fuzz (`tests/fuzz_toolkit.py`, stdlib, seeded)**: byte, JSON-structure, ledger-line and `sig_alg` mutations of four
  valid cases (anchored, signed, full, stamped) against `verify_pack` (plain and with `require_signed=True`) and the
  library API. Measured on 29/09/2026 (the figures of 28/09 changed with the `sig_alg` mutator: the mutation sequence of a
  seed is a function of the mutator list). Seed 20260928, 3 000 iterations: 0 violations, 545 PASS / 2 455 FAIL, twice
  with an identical verdict sequence (SHA-256 `2698f366…`), and the same sequence on CPython 3.9.25, 3.11.2 and 3.13.15
  — this is the CI smoke job. Seed 1, 30 000 iterations: 0 violations (5 598 PASS). Seed 2, 90 s: 53 899 iterations, 0
  violations (10 200 PASS; a time-bound count, 52–54 000 across three runs of the day). Positive controls on seed 20260928, 3 000 iterations, one check of the verifier disabled at a
  time: producer signature 2 violations, pack-sha3 recomputation 181, ledger chain 312, strict JSON profile 60, the
  canonical-name rule of `sig_alg` 26, the `require_signed` requirement 160 — the fuzzer sees each. Two properties of
  the family the fuzz confirmed and encodes: a ledger cut at its tail to a valid prefix that still holds the anchor is a
  valid chain (undetectable without a close record or an external anchor); a signature sidecar whose `sig_alg` became a
  genuinely unknown string is a SKIP that names the unverified signature, so a pack that is also anchored still verifies
  `valid` with `authenticated: false` — read `authenticated`, or pass `--require-signed`; a non-canonical spelling of
  `ed25519` is a FAIL (0.10.0; on 28/09 both were a silent SKIP). Found and fixed in the fuzzer itself on 29/09: its
  lenient re-read of a mutant used `json.loads`, whose recursion limit is the interpreter's (3.11 refused a 5 000-deep
  mutant, 3.13 parsed it), so one seed gave two verdict sequences on two interpreters from iteration 796 — the re-read is
  now bounded at a fixed depth, and `--trace` writes one line per iteration to compare two runs.
  A weekly job (`fuzz-weekly.yml`) runs 20 minutes per Python version on a new seed each week.

The figures above are from CPython 3.11.2 only. The test suite (137 tests) was run on 29/09/2026 on CPython 3.9.25,
3.11.2 and 3.13.15, each with `cryptography` 50.0.1, all green; the differential oracle over the four pack verifiers
(Python 3.11.2, Go 1.27.1, JDK 27, Node 22.23) was run the same day on this tree: 0 disagreements over 193 cases, every
runtime ML-DSA capable. The oracle exercises the pack verifiers, not the AAT module. Not measured here: Windows (no `fcntl`: the ledger has no cross-process
lock there), NFS, other hardware.

## Tests

```bash
python3 tests/test_toolkit.py                       # unit + end-to-end, incl. N threads / N processes appending to one ledger
python3 tests/fuzz_toolkit.py --iterations 3000     # seeded mutation fuzz of the verifier and the ledger (exit 1 on a violation)
python3 tests/fuzz_toolkit.py --ablate signature    # positive control: the sabotaged verifier must make the fuzzer red (6 ablations)
python3 tests/bench_toolkit.py --json bench.json    # latencies, throughput, memory, the 1 000 000-entry run (see below)
```

## Releasing (maintainers)

Distribution is the **GitHub Release** and the author's PEP 503 index (`https://robertolocatelli81-dev.github.io/pypi/`,
sha256-pinned to the release assets); publication on PyPI was dropped by decision of the author on 15 September 2026.
A release ships the wheel and sdist, a CycloneDX SBOM, a CRA evidence pack (ledger, pack, AWS KMS Ed25519 signature,
trust store) and `SHA256SUMS`; `release-build.yml` rebuilds the distributions, checks their metadata and runs the tests
on every published release. Install:

```bash
pip install --extra-index-url https://robertolocatelli81-dev.github.io/pypi/ omega-evidence
```

CI (`ci.yml`) runs the test suite on every push and pull request across Python 3.9 / 3.11 / 3.13, with and without
`cryptography`, and the differential oracle with Go 1.27, JDK 27 and Node 24.

## Contact, pilots, citation

- **Questions, interoperability reports, divergences found by your own verifier**: open a thread in this repository's
  [Discussions](https://github.com/robertolocatelli81-dev/omega-evidence/discussions) or an issue; e-mail: roberto.locatelli.81@gmail.com.
- **Pilots**: the author runs short evaluation pilots (four to six weeks, scoped and priced up front) with teams building agents or AI systems under the AI Act that need an interoperable, offline-verifiable audit trail. Write with the use case; the answer says what is measured and what is not.
- **Licence**: Apache-2.0: use it freely, also in closed products. If you build on it, a note in Discussions helps the roadmap (and tells the author the work is used).
- **Citation**: DOI [10.5281/zenodo.22539633](https://doi.org/10.5281/zenodo.22539633) (Zenodo, concept DOI: always the latest version).
- Author: Roberto Locatelli, 2026. Noûs, AI agent operating under a revocable mandate from Roberto Locatelli, who reviews and is accountable.
