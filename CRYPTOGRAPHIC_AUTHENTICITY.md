# Cryptographic message authenticity — implemented v2

**M4 update:** the v2 encryption/signature protocol below is unchanged. Reporter
API access additionally requires versioned proof-of-possession challenges, and
server history checks explicitly do not prove completeness. V1 is readable only
through the authenticated Investigator archive; legacy Reporter recovery returns
410 rather than accepting a static verifier. Existing databases also require the
separate additive M4 migration. See [M4 audit](MILESTONE_4_SECURITY_AUDIT.md) and
[DEMO.md](DEMO.md) for the current access and migration contract.

Milestone 2 implements the approved decision in
`CRYPTOGRAPHIC_AUTHENTICITY_PLAN.md`. Milestone 1 sessions and CSRF protection
remain mandatory for investigator operations. New submissions and replies use
protocol **2**. Existing protocol **1** data remains readable, explicitly
**UNVERIFIED**, and **READ-ONLY**. No conversation was silently upgraded and no
existing private key was repurposed as a signing key.

## Local activation — 21 October 2026 (verification in progress)

The developer's local SQLite database has now been migrated additively, after a
protected online backup of the DB, encrypted attachments and existing key records.
All four original cases and five original messages were preserved as v1. A second
protected backup was taken before importing the user-generated encrypted v2
identity and existing M1 access configuration. Backups are under ignored
`storage/backups/`; no reset, deletion or ciphertext rewrite was performed.

The user's downloaded encrypted identity was validated and imported unchanged as
the single active v2 identity. Its public signing pin was installed in ignored
`frontend/.env.local` from that trusted local export, independently of the API.
The original export is retained. The master password was not requested in chat,
and no private key, recovery phrase, access key or password was printed.

Verified against the running local application:

- Public v2 identity matches the independent pin; anonymous investigator reads
  and replies return 401, incorrect login returns 401, authenticated legacy writes
  return 409. Rejected requests leave stored data/status unchanged.
- Real browser v2 report submission, 12-word credential presentation, fresh
  recovery including whitespace/case normalization, wrong-phrase rejection, and
  a signed reporter follow-up. One clearly synthetic verification case is retained.
- Actual frontend verification of the live signed manifest/message, plus rejection
  of role reflection, changed keys, case/ID substitution, nonce/ciphertext/signature
  changes, protocol downgrade and duplicate-message replay. Live API replay and
  reflection/tampering attempts were also rejected without persistent mutations.
- 29 isolated authentication/protocol tests, frontend lint/typecheck and the
  production build with the configured pin pass. Compiled public assets contain
  the expected public pin and do not contain the workspace access key.

At the end of that activation session, agent verification of the real
Investigator's private-key operations was pending. Milestone 3 subsequently
exercised the complete v2 workflow and both legacy read-only views with synthetic
identities in disposable environments, without requiring the user's password.
See [MILESTONE_3_REPORT.md](MILESTONE_3_REPORT.md) for current reliability behavior
and verification. The v2 signature domains, keys and ciphertext formats are unchanged.
No identity was regenerated; no application code, crypto protocol, commit or push
was introduced during this local activation.

## Threat model and original defects

Previously, Track decrypted using `investigatorPublicKey` attached to each message
and displayed the server's sender label. An outsider-selected key could therefore
produce readable content labelled Investigator. Both parties also share the
`crypto_box` authentication secret, so either direction's ciphertext could be
reflected into the other direction. Case, message ID and role were not bound to
the MAC. Milestone 1 blocked anonymous investigator POSTs, but did not turn these
MACs into sender signatures or authenticate data delivered by an altered API/DB.

V2 uses **Ed25519 detached signatures**, separate from encryption keys, to verify
authorship relative to established pseudonymous signing identities. A signature
does not prove a real person's identity or that a report is true. `crypto_box`
still supplies confidentiality and a shared-key MAC; a shared-key MAC alone
cannot establish which participant authored a message. See the primary
[libsodium signature documentation](https://doc.libsodium.org/public-key_cryptography/public-key_signatures)
and [authenticated-encryption semantics](https://doc.libsodium.org/public-key_cryptography/authenticated_encryption).

The attacker tests include outsider forgery and attempts by either legitimate
participant to impersonate the other, even though that participant can calculate
valid box ciphertexts/MACs. Signatures cover the complete message context and are
checked independently by the server and receiving browser.

## Initialize and pin an investigator identity locally

Use the installed requirements (`cryptography>=46.0.0` is now declared for backend
Ed25519 verification). Do not reset an existing database or rerun a destructive
test harness. Back up an existing local DB and encrypted attachment storage before
the explicit schema migration:

```powershell
python migrate_v2.py
# If initializing a new local database/account:
python seed.py
python configure_investigator_access.py --username "compliance.lead@integrity-trust.corp"
```

`migrate_v2.py` adds nullable manifest/signature fields, explicit version columns
defaulted to **1**, and the investigator identity table. It is idempotent and
does not rewrite ciphertext or manufacture signatures for old rows. Startup
detects an old schema and asks for this explicit migration. Migration was tested
on disposable SQLite during implementation; the later local activation is recorded
above.

Start the local API/frontend, then visit `/investigator/setup` from a trusted
local checkout/browser. This page performs **no registration/import API call**.
It generates independent fresh random X25519 and Ed25519 keypairs using libsodium.
Choose a fresh private master password, at least 16 characters; do not use the
public PoC password. Download `sealed-identity-v2.json`, which contains public
keys, a public identity certificate and password-encrypted private material only.
The page clears password fields after generation and wipes temporary key buffers.

Copy the public pin **directly from this trusted setup session**, not from
`/investigators/public-key`, a conversation, or a message. Install it in local
`frontend/.env.local`:

```text
NEXT_PUBLIC_INVESTIGATOR_SIGNING_KEYS=<base64 Ed25519 public key from trusted setup>
```

This is a public trust anchor, not a secret. Import the encrypted export using
the explicit local administration command, then restart/rebuild the frontend so
its compiled pin is current:

```powershell
python import_investigator_identity.py --username "compliance.lead@integrity-trust.corp" --file "C:/path/to/sealed-identity-v2.json"
```

The importer validates the bundle format, fixed KDF parameters and identity
certificate; it refuses the old demonstration encryption public key and duplicate
signing-key imports. It never decrypts the bundle. Only the local administrator
can import identities; the API has no endpoint for changing a case's signing
identities or replacing the pin. Importing keys into the DB alone does **not**
establish browser trust. An empty/mismatched pin fails closed for v2 submission,
identity unlocking, report validation and thread verification.

Keep encrypted exports/backups outside version control (or in ignored storage)
and keep their passwords separately. The generated export filename is gitignored
and excluded from Docker build context. Losing a password/private bundle makes
its encrypted reports unreadable; rotating the access key cannot recover it.
The existing local Docker example does not provision a v2 identity or install a
build-time pin automatically. No container deployment was performed.

## Private key persistence, sessions and rotation

Private keys persist only as an encrypted **128-byte binary bundle**, protected
by the existing Argon2id parameters (ops 2, memory 64 MiB, Argon2id algorithm 2)
and XSalsa20-Poly1305 `crypto_secretbox_easy`, using fresh salt/nonce:

| Plain bundle bytes | Content |
| --- | --- |
| 0–31 | UTF-8 `sealed:identity-private:v2`, followed by zero bytes |
| 32–63 | Fresh X25519 encryption private key |
| 64–127 | Independent Ed25519 secret key in libsodium's 64-byte format |

The resulting ciphertext is 144 bytes including the MAC. On unlock the browser
checks the tag, exact bundle length, both derived public keys, and the Ed25519
seed/public-half consistency. An identity certificate signs the association of
the encryption and signing public keys; the signing key is checked against the
independently configured pin. No X25519-to-signing conversion is performed.

After Milestone 1 API authentication, `/investigators/identities` returns only
the authenticated account's encrypted bundles. They are unlocked in tab memory
using the master password. Pins and password determine which current/archived
identities can unlock. Multiple retained identities may use different passwords;
sign in with the password for the desired archive. Lock, expiry, unauthorized
responses and unmount clear/wipe local key buffers. No signing private key is
stored in localStorage/sessionStorage. The reporter's existing tab mnemonic
storage is unchanged; signing keys are rederived from it.

To **rotate**, generate/export another fresh identity in the browser, retain the
old encrypted bundles/backups, and add the newly trusted signing public key to the
comma-separated pin allowlist through the same trusted local process. Import
the new export. The importer atomically archives prior identities; only the new
identity receives new submissions. Prior v2 cases remain signature-verifiable
and decryptable with their original keys/passwords and retained pins, but become
read-only. The original legacy account record and access configuration are not
overwritten. Restart/rebuild the frontend after updating pins.

If a signing identity is compromised, remove its pin to quarantine its data in
the honest client and import a fresh identity. Keeping a compromised key pinned
does not restore trustworthy historical signatures. There is no automatic
historical re-certification, participant re-enrolment, TOFU, cross-signing trust
expansion or silent pin replacement.

The API still uses Milestone 1's opaque HttpOnly cookie and exact-Origin/custom
header checks. Signing does not replace backend authorization. Conversely,
knowledge of an API access key does not reveal a browser-only signing secret.
Password protection is only as strong as the chosen password; encrypted bundle
theft permits offline password guessing. Wiping is best effort: JS strings,
garbage collection, browser extensions and endpoint compromise remain relevant.

## Reporter identity and initial case binding

The existing mnemonic, encryption-key and access-token derivations are retained.
A new domain tag, `sealed:reporter_signing:v2`, derives a separate 32-byte signing
seed via the existing keyed BLAKE2b root derivation. `crypto_sign_seed_keypair`
then creates the Ed25519 pair. It is not the encryption private key used as a
signing seed. Recovery normalizes case and whitespace consistently.

The browser assigns the case UUID before signing. Its signed report manifest
binds the reporter's encryption/signing identities, the pinned investigator's
encryption/signing identities, recipient certificate, encrypted initial report,
and a credential commitment. The commitment is base64 SHA-256 of the **ASCII
presented access-token-hash string**. It binds the existing bearer credential
without returning that credential in the manifest. This is an identity binding,
not a fix for the separate stored-verifier replay finding.

On recovery, the reporter verifies the manifest with locally rederived signing
and encryption public keys and the credential commitment, plus the investigator
pin. The investigator verifies the reporter's initial signature before accepting
that case's reporter key or composing replies. The reporter initially
self-enrols a pseudonym; this is not a third-party certificate of their identity.

## Exact signed bytes and protocol fields

All signatures use single-part **Ed25519**, not Ed25519ph or handwritten curve
arithmetic. Backend verification uses the maintained `cryptography` Ed25519 API.
Both implementations are checked against each other's exact signing bytes.

Encoding is UTF-8 of a JSON **array** in the exact order below, with no whitespace.
Numbers are the literal integer `2`. Domains/roles are fixed ASCII strings;
UUIDs use canonical lowercase hyphenated form; binary values use canonical padded
standard base64. Variable fields are ASCII, so Python `json.dumps` with
`separators=(',', ':')` and JS `JSON.stringify` have identical signing bytes.

```text
Identity certificate:
["sealed:identity",2,investigatorEncryptionPublicKey,investigatorSigningPublicKey]

Initial report signature (the case UUID identifies the initial report):
["sealed:report",2,caseId,"REPORTER",
 reporterEncryptionPublicKey,reporterSigningPublicKey,
 investigatorEncryptionPublicKey,investigatorSigningPublicKey,
 identitySignature,credentialCommitment,encryptedReport]

Conversation message signature:
["sealed:message",2,caseId,messageId,senderRole,
 reporterEncryptionPublicKey,reporterSigningPublicKey,
 investigatorEncryptionPublicKey,investigatorSigningPublicKey,
 reportSignature,nonce,ciphertext]
```

The sealed-box initial ciphertext carries its own ephemeral encryption material;
it has no separate application nonce field. Follow-ups retain their existing
24-byte random nonces, 4 KiB block padding and `crypto_box_easy` ciphertexts.
Attachments retain their existing secretbox encryption, with attachment metadata
inside the signed-and-encrypted payload. No private key, password, plaintext
report or attachment key is sent to the server by these operations.

The initial report signature binds the full initial context; subsequent message
signatures bind that signature too, distinguishing initial transcripts even if
participants reuse a conversation key. A per-message public key is never a new
trust anchor. Role comes from the signed transcript, is verified against the
expected route on the server, and must match both DTO role fields in the client.

The server validates the manifest and signature before persisting a message or
updating status. It uses a client-generated signed message UUID as the primary
key: duplicates return `409`, and unique-constraint races roll back their whole
transaction. A changed message ID, case, role, participant, nonce or ciphertext
invalidates the signature. Clients reject duplicate IDs within a received thread;
rejected messages display an unverified placeholder without plaintext/attachments
or a trusted author badge. Revalidating the same history during normal refresh
works. None of this prevents a legitimate signer from intentionally sending the
same text again under a fresh signed ID.

## Compatibility and scope

- Existing data defaults to version 1 with no generated manifest/signature.
  Legacy decryption functions are used only by the explicit legacy read path;
  their results are labelled `UNVERIFIED legacy sender` and never verified v2.
- Investigators select **Open legacy archive** and use the original decryption
  password to read old reports. The old demo secret is not used for any v2 key.
- New legacy submissions and legacy/archived replies are rejected server-side.
  Case-linked uploads are also read-only for these cases. Public staged uploads,
  public key retrieval and legitimate v2 reporter tracking remain available.
- Unknown versions, failed v2 signatures and incomplete manifests fail closed.
  There is no failed-v2-to-v1 decryption fallback. A record explicitly delivered
  as legacy can never receive a verified sender label.
- This is an application crypto version; the existing HTTP `/api/v1` prefix is
  retained. Use the updated client; old clients do not implement v2 verification.

## Verification performed

- `python -m unittest test_investigator_auth test_message_protocol -v`: 29 tests
  cover preserved investigator authentication/CSRF plus v2 positive/negative
  flows, wire interoperability, mutation-free denials, replay, reflection,
  substitution, legacy read-only policy, migration and local identity rotation.
- `tests/frontend_crypto.ts` runs the actual frontend crypto/protocol modules.
  Its security operation checks genuine messages; outsider/other-participant
  signatures; replaced keys; case/ID/role substitutions; both reflection
  directions; ciphertext/nonce/signature changes; duplicate IDs; wrong recovery;
  unknown/downgraded versions; no-pin rejection; corrupted/wrong-password bundles;
  encrypted identity reload; and deterministic signing-key recovery.
- `python test_api.py`: existing API regressions retained and adapted to signed
  v2 fixtures, including public tracking, attachments and rate limits. Passing
  old audit assertions does not establish the broader audit claims.
- `e2e.ts` now uses the actual frontend protocol, requires a separately supplied
  trusted `SEALED_E2E_PIN`, and checks live v2 submission, unlock, both signed reply
  directions, recovery, replay denial and anonymous access denial. Executed only
  against a disposable loopback API with browser-generated identity/pin.
- Root `npm test`: retained legacy primitive demonstration passed.
- Frontend lint, TypeScript and production build; targeted standalone caller and
  crypto-bridge typechecks. The existing multiple-lockfile build warning remains.
- Real browser: generated/exported an identity, imported it into a disposable
  database, configured the independently obtained pin, submitted a report,
  authenticated/unlocked/decrypted, sent and recovered both signed reply
  directions, relogged into the persisted identity, rejected an injected forged
  DB message, and read legacy reports/replies with disabled reply/upload controls.

The initial implementation verification did not migrate developer data. The later
local activation and its remaining checks are recorded above. No deployment,
commit or push was performed.

## Remaining threat-model limitations

The pin comes from a trusted local setup/configuration channel, **not the API**.
It helps an honest trusted client reject substituted API/message keys. A fully
malicious application server can still deliver hostile JavaScript that steals
entered credentials or changes verification. Pinning is not a solution to the
browser-delivery/endpoint trust problem. Neither a compromise of that runtime nor
compromise of the configured pin source is covered.

The API initially accepts anonymous reporter self-enrolment. A malicious server
can invent a different self-signed anonymous case or suppress/replace the entire
initial case for an investigator who has no prior receipt. It cannot forge the
original reporter's Ed25519 signature, and a recovering honest reporter checks
their own locally derived identity. No claim of real-world sender identity or
complete protection from a malicious server is made.

Signatures do not prove complete history, trusted timestamps, ordering,
non-repudiation, or absence of truncation/rollback after client state loss. Audit
integrity, the existing server-reported audit badge, reporter stored-verifier
replay, public-key metadata, padding/file-size limits, staged-file cleanup and
submission reconciliation remain separate findings. The signature verifier can
reject a forged message even while the old audit badge still reports a valid
chain; those are independent checks. Encryption is not complete anonymity.

Schema/migration verification was on SQLite. PostgreSQL was not exercised.
Single-workspace/session limitations from Milestone 1 remain unchanged.


## Main files changed

| Area | Files |
| --- | --- |
| Protocol and persistence | `message_protocol.py`, `models.py`, `schemas.py`, `migrate_v2.py`, `requirements.txt` |
| Identity lifecycle and server enforcement | `import_investigator_identity.py`, `routers/investigators.py`, `routers/cases.py`, `main.py` |
| Browser crypto, pins and key generation | `frontend/src/lib/protocol.ts`, `frontend/src/lib/crypto.ts`, `frontend/src/lib/types.ts`, `frontend/src/app/investigator/setup/page.tsx` |
| Existing workflows and sender presentation | `frontend/src/lib/api.ts`, both session hooks, Submit/Investigator pages, `TrackReport.tsx`, `Conversation.tsx` |
| Regression tools | `test_message_protocol.py`, `test_investigator_auth.py`, `test_api.py`, `test_support.py`, `tests/frontend_crypto.ts`, `e2e.ts` |
| Setup and threat-model documentation | this document, approved plan status, `README.md`, `INVESTIGATOR_ACCESS.md`, `.gitignore`, `.dockerignore` |

The original technical review remains unchanged. Milestone 1 source files remain
present and its authorization tests pass; the existing uncommitted work was not
committed, pushed, discarded or reset.
