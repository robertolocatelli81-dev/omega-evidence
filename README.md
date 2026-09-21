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

A bare fabricated pack (no ledger, no signature) **cannot pass**.

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

Six review rounds (Gemini 3.1 Pro, Claude Opus 5, Sonnet 5, Haiku 4.5, 19 September 2026; the dossier lists every finding;
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
well under a second instead of quadratic); `anchor_epoch` refuses integers beyond 2^53 like every export; uppercase or
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

`verifiers/` holds three stdlib-only re-implementations of the pack verifier — Go (`verifiers/go`, `crypto/mldsa`
for ML-DSA-65 with Go ≥ 1.27), Java (`verifiers/java/OeVerify.java`, JDK 24+ for ML-DSA-65, single file) and Node
(`verifiers/js/oeverify.mjs`: Ed25519, SHA3 and — since 0.8.0 — **ML-DSA-65 through the Node build's OpenSSL ≥ 3.5**,
feature-detected: the raw key is wrapped in a SubjectPublicKeyInfo and checked with `crypto.verify`, measured on Node
24.21.0 and 22.23.2; on an older OpenSSL the layer is reported present-but-unverified, never true) — plus
`verifiers/differential_oracle.py`, which builds packs, sidecars, ledgers and trust registries with the toolkit and
demands the same `(verdict, pq_protected, authenticated)` from Python, Go, Java and Node on every case (tampered
packs, lenient base64, uppercase digests, unknown or non-string algorithms, classical algorithm declared as PQ,
overclaimed or missing `honest_scope`, duplicate keys, floats, nesting beyond 512, lone surrogates, non-UTF-8,
empty / unrelated / tampered / float ledgers, rotated and revoked signers, stripped / foreign / invalid post-quantum
layers, and — since 0.8.3 — an own `__proto__` key added without rehashing, a raw non-UTF-8 byte where U+FFFD was hashed,
a raw byte in a ledger key, a ledger line that is not an object): 0 disagreements on 84 pack cases plus 15 CLI-grammar cases
with 4 verifiers (21 September 2026); the hostile pack cases are anchored with the hash a lenient verifier would accept,
so the named layer decides (except `non-utf8`, hash of zeros: it only detects a crash; the lossy-decoder case is `pack-raw-byte-hashed-as-fffd`); on a Node without ML-DSA the two Node divergences are declared, not hidden. None of the four verifies the RFC 3161 token inside the
pack verdict: `verify_pack` checks the sidecar's shape and its digest→pack binding and reports the layer as SKIP with the
reason (round 6, Opus: the earlier sentence "verified by the Python reference only" was not true of the code — no trust
anchor reaches `verify_pack`); the cryptographic check exists as `timestamp.verify(tsr_b64, digest, ca_file=<TSA roots>)`
for the operator. The ledger profile is the cryptovalid one, so cryptovalid's five verifiers also
accept omega-evidence ledgers unchanged (measured 16/09/2026).

```
go run ./verifiers/go/cmd/oeverify -trust-store trust.jsonl -require-pq pack.json
java verifiers/java/OeVerify.java pack.json -expect-pq-key <b64>
node verifiers/js/oeverify.mjs pack.json --ledger pack.ledger.jsonl
python -m omega_evidence pack.json --trust-store trust.jsonl --require-pq
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

### 0.8.3 — verifier hygiene from the cra-evidence review (21 September 2026)

Twelve review rounds on cra-evidence 0.3.0, whose verifiers are re-implementations of these, found defect classes in
shared code; a review round on this release (Opus, Sonnet, Haiku — Gemini Pro out of credits) found more of the same
class here. Measured on 21/09/2026 with a four-verifier probe before each fix and with the differential oracle after
(99 cases, 0 disagreements); the same oracle run against the four 0.8.2 verifiers (Python, Go, Java, Node from tag
v0.8.2) is red on 43 cases, and against a deliberately lenient Python (loose parser, no scope check, no reserved-tag /
surrogate / float refusal — `verifiers/lax_python_ablation.sh`, re-measured 21/09/2026) on 12:

- **Node dropped an own `__proto__` key while copying** (`c[k] = …` invokes the prototype setter): a pack or ledger
  entry with such a key added and its hash untouched verified PASS in Node alone. `Object.fromEntries` keeps the key.
- **Node and Java decoded a non-UTF-8 file lossily**: a pack or ledger entry whose hash was computed over U+FFFD while
  the file held the raw byte verified PASS in both (a lossy decoder reads exactly the hashed text). Strict UTF-8
  decoding in both; a malformed byte is a `FAIL` verdict.
- **The Python reference raised instead of answering** (a traceback, no verdict): `UnicodeDecodeError` on a raw byte in
  the ledger, `AttributeError` on a ledger or trust-store line that is not an object, `JSONDecodeError` on a ledger
  that is not JSON, `RecursionError` on a 100000-deep `.tsr.json`. `Ledger` now loads with the strict parser and
  raises one `RuntimeError`; the verifier reports the layer as `FAIL`.
- **The Python reference had no lone-surrogate rule** (round 2, Opus): an anchored pack holding `"\ud800"` with a correct
  hash — and a ledger entry the 0.8.2 producer itself wrote — verified PASS in Python and FAIL in Go, Java and Node. The
  linear pre-scan of the three (`HasLoneSurrogate`) is now in `loads_strict`, and the producer refuses such strings.
- **Node accepted a float lexeme with an integer value** (round 3, Opus): `JSON.parse("1.0")` is the integer 1 and the
  canonical form could not see the lexeme, so a pack with `"n":1.0` hashed as `"n":1` verified PASS in Node alone
  (Python's `parse_float`, Go and Java refuse it on the text). A linear scan of the raw text now refuses `.`/`e`/`E` in
  a number outside a string.
- **The `honest_scope` gate had two regex semantics**: Python's Unicode `\b` and its `i ≡ ı` (U+0131) case folding made
  `"does NOTé prove x"` and `"fully certıfied; does NOT prove x"` FAIL in Python and PASS in Go (RE2), Node (no `u`
  flag) and Java (no `UNICODE_CASE`). Python now uses `re.ASCII`, the semantics of the three.
- **The Python reference crashed on typed-wrong LTV material**: `validation_material.crls_b64` as an int or a list of
  ints beside a correct digest was a `TypeError` traceback while the three gave a verdict. Typed now.
- **The anchoring rule was read at two levels** (round 4, Opus): Go, Java and Node look for `anchored_pack_sha3` in the
  ledger ENTRY (top-level or under `data`); the Python reference looked inside `data` (so `data.anchored_pack_sha3` or
  `data.data.anchored_pack_sha3`). A chain-valid entry with a top-level anchor was PASS in the three and FAIL in Python;
  one under `data.data` the reverse. Python now reads the entry. A trust-store entry without `data` was skipped by
  Python and a broken store for the three: broken everywhere now.
- **Node's `[^.]{0,40}` counted UTF-16 code units** (no `u` flag): 21 astral characters between `NOT` and `guarant`
  were 42 units in Node and 21 code points elsewhere, so the negation was seen by three verifiers and not by Node.
  Astral characters are folded to one placeholder unit before the three scope tests.
- **The reserved type-tag key was a verifier rule in Python only** (round 5, Opus): a pack carrying
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
  `-`; the `--` terminator; `--require-pq=false`; `-h`/`--help` (round 3: argparse answered it with exit 0). `--flag=value` is accepted by all four (argparse and Go's `flag` did
  natively; Java and Node now do), and so is one dash or two (`-ledger` / `--ledger`: Go's `flag` took both, Java one,
  Python and Node two — round 4, Sonnet). Before: `python -m omega_evidence anchored.json --ledger ""` was **PASS** with the
  operator's ledger silently replaced by the sidecar (measured on v0.8.2), Node gave a verdict on an unknown flag,
  Go and Java took `""` as "not given" and a flag as a path, Python accepted `--ledg` and crashed on it.

Declared, not aligned: Go's `flag` stops at the first positional, so `oeverify pack.json -ledger L` is a usage error
in Go and a verdict in Python, Java and Node (put flags first); Node and Java refuse an input over 256 MiB and Go a ledger line
over 64 MiB while Python has no bound — a valid file beyond those sizes verifies in some of the four only. Not measured:
Ed25519 decoding of non-canonical or small-order points in a sidecar (the four backends — pure Python, OpenSSL, Go's
`edwards25519`, SunEC — have their own rules; no such vectors are in the oracle yet).

Verdicts that changed, counted by script from the positive-control table (criterion: well-formed JSON input; a
crash→verdict is listed apart). **Python, eleven**: `scope-NOT-before-accented-letter`, `scope-dotless-i-overclaim`,
`ledger-anchor-top-level`, `pack-reserved-tag-key-top-level`, `pack-reserved-tag-key-nested` FAIL→PASS;
`lone-surrogate`, `ledger-lone-surrogate-entry`, `ledger-anchor-under-data-data`, `trust-entry-without-data`,
`tsr-float-beside-good-digest`, `tsr-dup-key-beside-good-digest` PASS→FAIL — each toward the verdict of the other three; and
seven inputs that were a traceback now get a verdict. **Node, seven**: `scope-astral-21-…`,
`trust-revoke-proto-then-trust-toString`, `pack-proto-key-hashed-by-producer` (a pack the producer API makes, with a
top-level `__proto__` key) FAIL→PASS; `pack-float-1.0-hashed-as-1`, `pack-exp-1E2-hashed-as-100`,
`pack-proto-key-hash-untouched`, `ledger-proto-key-hash-untouched` PASS→FAIL; plus one crash→verdict (`ledger-path-missing`).
**Go and Java: none** on well-formed JSON. On the two non-UTF-8 files hashed over U+FFFD, Node and Java PASS→FAIL. So one
producer-made input changes verdict: a pack whose body has a top-level `__proto__` key was FAIL in 0.8.2 Node alone and
is PASS everywhere now; the 0.8.3 producer additionally accepts an `honest_scope` such as `"does NOTé prove x"` (ASCII
word rule), which the 0.8.2 Python verifier refused.

Declared, not aligned: Go's `flag` stops at the first positional, so `oeverify pack.json -ledger L` is a usage error
in Go and a verdict in Python, Java and Node (put flags first); Node and Java refuse an input over 256 MiB and Go a ledger line
over 64 MiB while Python has no bound — a valid file beyond those sizes verifies in some of the four only. Not measured:
Ed25519 decoding of non-canonical or small-order points in a sidecar (the four backends — pure Python, OpenSSL, Go's
`edwards25519`, SunEC — have their own rules; no such vectors are in the oracle yet).

Verdicts that changed on in-profile input (measured, the positive-control table): the Python reference on eight —
`scope-NOT-before-accented-letter`, `scope-dotless-i-overclaim`, `ledger-anchor-top-level`, `pack-reserved-tag-key-*` (×2)
FAIL→PASS; `ledger-anchor-under-data-data`, `trust-entry-without-data`, `ledger-lone-surrogate-entry` PASS→FAIL — each
toward the verdict of the other three; a 0.8.2-written ledger entry holding a lone surrogate now FAILs everywhere. Node
on four: `scope-astral-21-…` and `trust-revoke-proto-then-trust-toString` FAIL→PASS, `pack-proto-key-hash-untouched`
and `ledger-proto-key-hash-untouched` PASS→FAIL (well-formed JSON with a hash that does not cover the added key). On the
two non-UTF-8 files hashed over U+FFFD, Node and Java PASS→FAIL (criterion for the lists above: well-formed JSON input;
the count is read off the positive-control table). Nothing that both the 0.8.2 and the 0.8.3 producer API accept changes
verdict; the 0.8.3 producer additionally accepts an `honest_scope` such as `"does NOTé prove x"` (ASCII word rule), which
the 0.8.2 Python verifier would refuse. Two Go files carried an `AGPL-3.0-or-later`
SPDX header in this Apache-2.0 repository (the author's own code): corrected to `Apache-2.0`.

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
- The producer-signature layer accepts **`sig_alg: "ed25519"` only** (missing = ed25519); any other string is an
  honest SKIP, a non-string is a malformed sidecar. A post-quantum backend is never a classical producer signature.
- A trust store that fails the strict chain verification raises `ValueError` on load and is a `trusted-signer`
  FAIL in the verifier (it used to crash, or trust the last of two duplicated keys).
- `TrustRegistry.rotate()` keeps the pinned post-quantum key unless `drop_pq=True` (it used to drop it silently).

The normative output of every verifier is the tuple `(verdict, pq_protected, authenticated)` plus each layer's
status; layer `detail` strings are human-readable and non-normative (their wording and the order in which two
malformations are reported may differ between implementations).

## Tests

```bash
python3 tests/test_toolkit.py
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
- Author: Roberto Locatelli, 2026. Public interventions by his AI agent (Noûs) are signed as such.
