# Milestone 2 — identity and compatibility decision

Status: **approved; implemented in [CRYPTOGRAPHIC_AUTHENTICITY.md](CRYPTOGRAPHIC_AUTHENTICITY.md)**.
The remainder records the original pre-implementation investigation and proposal.
At that investigation checkpoint, no application source, encryption format,
existing key, conversation, database, or Milestone 1 authorization rule was
changed during this investigation. The previous milestone's uncommitted changes
remain intact. This document records the architectural decision needed before
changing message identity and legacy write behaviour.

## Confirmed behaviour

The review's S2 and S5 findings were checked against the current implementation,
including Milestone 1's changes:

- `frontend/src/lib/crypto.ts:207` accepts the public key supplied with each
  message. `useReporterCase.ts` calls this function without an independent
  investigator key comparison.
- `crypto.ts:319`, `:360`, and `:401` use the same `crypto_box` key agreement in
  both directions. Its symmetric authentication tag establishes possession of
  the shared secret, not which participant authored the message.
- `frontend/src/components/Conversation.tsx:25` renders authorship using the
  server-provided `senderType`/`sender` label.
- Case IDs, message IDs, direction and participant identities are not covered by
  an application signature or authenticated protocol context. The submission
  handler even generates the case ID after encrypting its report.
- `Case` stores one outer reporter encryption public key. `CaseMessage` stores
  ciphertext, nonce, a public key, and an unsigned role. Neither stores a protocol
  version, signing identity, signature or authenticated message context.
- `seed.py` supplies a fixed encryption identity. Its private key can still be
  recovered using the demonstration password present in `poc.ts`, even though
  Milestone 1 removed password prefilling and restricted the encrypted account
  endpoint. Re-encrypting that same private key under a new password would not
  make it private again.
- Milestone 1 now rejects anonymous investigator writes and mismatched reply
  keys. The former arbitrary-key POST exploit is therefore blocked on that route.
  This does not repair the client's cryptographic acceptance rules, establish
  authorship against the other participant, or authenticate stored data supplied
  by a compromised API/database.

A memory-only diagnostic invoked the actual frontend module with fresh synthetic
participant keys. It reproduced:

| Probe | Current result |
| --- | --- |
| Outsider encrypts to reporter and supplies outsider public key | Accepted by reporter decryption |
| Reporter ciphertext relabelled as investigator | Accepted by reporter decryption |
| Investigator ciphertext relabelled as reporter | Accepted by investigator decryption |
| Case ID and message ID replaced | Accepted by decryption |
| Same message delivered again | Accepted again |
| Ciphertext bit flipped | Rejected |
| Different valid recovery phrase | Rejected by decryption |
| Public demo key unlocked from shipped fixture material | Recovered public key matches seed |

This diagnostic did not bypass Milestone 1 HTTP authorization or write to a
database. It separates protocol acceptance from API access. Diagnostic source is
in ignored `scratch/probe_message_authenticity.ts`; it does not print private
keys, passwords, or recovery phrases.

## Why a key/compatibility decision is required

Pinning the current X25519 key and adding a role inside the existing encrypted
plaintext would be insufficient. Both participants can create valid shared-key
MACs, and the current investigator secret is publicly recoverable. Deriving a
signing identity from that disclosed secret would also be forgeable. The
Milestone 1 access key is known by the backend and must not become the root of a
supposed browser-only signing identity.

There is no existing browser-side investigator identity provisioning flow or key
history. There is also no cryptographic evidence in old messages from which to
retroactively establish their sender. A safe implementation must introduce a
fresh private signing identity and explicitly choose how legacy conversations
remain usable. That changes key provisioning and the permitted legacy workflow,
not just the encryption function's argument list.

## Recommended minimal v2

**Fresh identity, explicit public-key pin, new v2 cases; legacy records remain
readable but unverified and read-only. No data is deleted or silently upgraded.**

1. Generate independent random investigator X25519 encryption and Ed25519 signing
   keypairs in the browser, with a fresh user-chosen master password. Protect
   their private material using the existing Argon2id and secretbox stack with
   fresh salts/nonces and a versioned encrypted key bundle. Export/import only
   that encrypted record and public material through an explicit local setup
   operation. Never send a private key or the password to the server. Preserve
   the old encrypted encryption-key record for reading legacy reports.
2. Install the investigator's new public identity as an explicit local client
   pin, separate from per-message fields and API-provided key suggestions. The
   pinned identity authenticates the signing key and associated encryption key.
   No silent replacement, automatic trust reset or fallback to the demo key.
3. Derive the reporter's **separate Ed25519 signing seed** from mnemonic root
   material with a new purpose/version domain. Keep the existing recovery phrase,
   X25519 derivation and access-credential derivation stable. Do not reinterpret
   an X25519 private-key byte array as an Ed25519 signing key.
4. A v2 initial report binds its case UUID, protocol/domain, both participants'
   signing/encryption public keys, recipient identity and encrypted report into a
   reporter-signed manifest. The investigator verifies this manifest before
   accepting its reporter identity or composing a reply. On recovery, the
   reporter checks the manifest against their locally rederived identity and the
   investigator pin. A new anonymous reporter self-enrols a pseudonymous identity;
   this does not prove a real-world identity or the truth of a report.
5. Retain existing sealed-box, box and attachment encryption primitives for
   confidentiality. Add standard **Ed25519 detached signatures** over an exactly
   specified, versioned encoding of message context and encrypted content: case
   UUID, client-generated message UUID, sender role, both participant identities,
   initial-manifest identity/hash, nonce and ciphertext. Define exact signing
   bytes and test vectors, rather than signing arbitrary object serialization.
   Verify using the case's established identities and investigator pin, never a
   key chosen by the message. Verify before decrypting or displaying authorship.
6. The backend independently verifies the same signature/context before any
   message/status mutation. Keep the Milestone 1 session and CSRF requirements
   on investigator endpoints; a signature does not replace API authorization.
   Use a maintained Python Ed25519 implementation, not handwritten arithmetic
   or a Node subprocess per request. The current requirements declare no such
   backend dependency; the globally installed `cryptography` 3.4.8 must not be
   mistaken for a reproducible, current project dependency.
7. Persist version, immutable case identity/manifest and signed message IDs via
   explicit schema migration. Atomically reject duplicate message IDs before
   status changes. Clients reject duplicate IDs within a thread and reject
   changed case, role, participant, nonce, ciphertext or ID contexts. Refreshing
   the same history must not create new messages or be mistaken for an attack.
8. Legacy messages receive an explicit **unverified legacy sender** presentation,
   without a verified investigator/reporter badge inferred from their role label.
   Unknown versions and malformed v2 signatures fail closed, without a legacy
   fallback. Existing styles/components are reused; no visual redesign.

Signing the encrypted content and context is distinct from encrypting it:
`crypto_box` keeps message contents confidential and checks its shared-key MAC;
Ed25519 establishes authorship relative to the separately trusted signing key.
The proposed protocol uses existing reviewed primitives, not a new signature or
key-exchange algorithm. See libsodium's
[authenticated-encryption semantics](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption),
[Ed25519 signatures](https://doc.libsodium.org/public-key_cryptography/public-key_signatures),
and [guidance on separate signing/encryption keys](https://doc.libsodium.org/advanced/ed25519-curve25519).

## Alternatives requiring a different scope/trust decision

| Choice | Consequences |
| --- | --- |
| **Explicit pin + new v2 cases (recommended)** | Smallest clear model for this local project. One-time local browser key provisioning and pin installation. Old data stays readable/unverified; old cases stop accepting new replies. |
| **TOFU + new v2 cases** | Trust the first investigator identity received in each browser and persist it; reject subsequent changes. Easier initial setup, but first contact and lost/cleared local trust depend on the server. Still requires genuinely fresh private keys; does not authenticate old messages. |
| **Explicit enrolment/upgrade of existing conversations** | Keep old cases writable only after a defined fresh-key enrolment process for both participants, with an explicit trust anchor and downgrade/rollback rules. More protocol, schema and recovery work; old messages still cannot be retrospectively authenticated. No automatic inference of authorship from old ciphertext. |

There is no safe option that gives old unsigned messages verified authorship
merely by changing their database version field, copying a key into a new column,
or having the backend sign them.

## Required implementation verification

After the identity/compatibility choice is approved, regression tests must use the
actual frontend module and isolated backend storage to cover genuine replies in
both directions; outsider and other-participant impersonation; substituted keys;
both reflection directions; cross-case and message-ID replacement; modified
ciphertext/signatures/nonces/roles; duplicate POSTs and duplicate history entries;
wrong recovery phrases; unknown/downgraded protocol versions; and explicit legacy
handling. Server rejection tests must assert no message, status or audit mutation.
Add signature test vectors shared by browser and backend implementations.

Re-run all existing Investigator authentication/authorization tests and public
submission/tracking tests, frontend lint/typecheck/build, and actual browser
conversation flows. Do not substitute passing legacy decryption for signature
verification.

Executed during this investigation:

- Actual frontend memory-only diagnostic: all eight observations above confirmed.
- `python -m unittest test_investigator_auth -v`: **18 passed** on disposable
  database/file storage; Milestone 1 remains intact.
- No dependency installation, database migration, application source change,
  deployment, commit or push. Frontend checks were not rerun because no frontend
  source was changed. The requested v2 regressions have not been implemented yet.

## Limits of either trust choice

Neither model authenticates JavaScript delivered by a fully malicious application
server. Pinning only helps an honest, independently trusted client enforce its
configured identity against substituted API/message data. TOFU additionally
trusts the first key response. A compromised endpoint, stolen signing secret,
weak wrapping password or compromised pin distribution defeats those boundaries.

Message signatures and duplicate-ID checks do not establish complete history,
timestamp truth, absence of withheld messages, ordering, or rollback resistance
after lost client state/server rewrite. Those require the separate audit/history
milestone. Existing reporter stored-verifier replay and metadata/anonymity limits
are separate issues. This proposal claims neither non-repudiation nor protection
from a wholly malicious server/runtime.
