# Milestone 4 security and integrity audit

Assessment and final verification: 24–25 October 2026. Scope: the local, single-workspace Sealed implementation after Milestones 1–3, including the uncommitted working tree. This is an engineering assessment, not an independent cryptographic audit or production certification.

## Trust boundaries

The reporter's 12 words derive separate encryption and signing identities in the browser. The investigator's independent encryption and Ed25519 signing keys are generated in the browser and unlocked locally from an encrypted identity packet. Backend Investigator access uses the separate M1 access key, challenge authentication and HttpOnly session cookie. Unlocking a private key is not API authentication.

The investigator signing pin is installed from a trusted local identity export. It is not learned from the API response being verified, and there is no TOFU or participant re-enrolment. The server distributes signed identity packets and ciphertext; the browser independently verifies v2 manifests and messages against the established participants. M4 does not change the v2 ciphertext format, key derivation or message-signature construction.

Trusted components include the local configuration/pin, browser-delivered application code, endpoint and cryptographic libraries. The backend remains trusted for availability, initial case lookup, status and server consistency results. A malicious delivered frontend can steal entered secrets; a malicious backend can omit or roll back history. Encryption does not provide network anonymity.

## Findings and disposition

No CRITICAL or HIGH finding was established in this bounded review. Severity reflects this local portfolio threat model, not an internet deployment.

| Finding | Severity / evidence | Before | M4 disposition |
|---|---|---|---|
| Stored reporter verifier was a reusable bearer credential | MEDIUM; reproduced in an isolated pre-change fixture | Copying `case_access_token_hash` permitted case lookup without the words/private key. V2 message signatures still prevented fabrication of a valid authored message; this was not proof of plaintext decryption. | Static credentials alone now fail. Reads, replies and uploads require a fresh, request-bound Ed25519 proof. |
| Audit badge overstated integrity | MEDIUM; reproduced | Changing report ciphertext and case status could leave the old audit verification green. The chain did not bind the current business data. | New consistency history binds signed report/message records, attachment bytes and case status. UI says **Server consistency check passed; Completeness not proven**. |
| Incomplete lifecycle enforcement | MEDIUM; code-confirmed | No complete authorized close/reopen workflow; reporter replies could implicitly change status. | Investigator-only transitions, revision checks, idempotent transition IDs and transaction serialization. Closed cases reject both roles' replies and new uploads. |
| Public attachment/audit reads exposed ciphertext and metadata | LOW; code-confirmed | Knowing object IDs permitted unauthenticated reads. This did not expose decrypted filenames or attachment keys. | Reads require an Investigator session or a case-bound Reporter proof; staged files are not downloadable. |
| Legacy audit digest/schema mismatch | LOW; code-confirmed | 512-bit hexadecimal digests could exceed a 64-character column declaration. SQLite did not enforce the width. | New history uses explicit 32-byte BLAKE2b / 64 hex characters and separate additive tables. Existing legacy audit rows are preserved. |
| Forwarded headers could spoof rate-limit identity | LOW; code-confirmed | Client-supplied forwarding headers influenced rate-limit keys. | Use the ASGI peer address; spoofing regression included. Local Next proxy clients share the proxy peer bucket. |
| Validation responses could echo submitted values | LOW; code-confirmed | Default validation details could repeat invalid request input. | Generic API validation errors; no submitted value echo. API responses use `Cache-Control: no-store`. |

Evidence: `routers/cases.py`, `routers/investigators.py`, `reporter_auth.py`, `routers/reporter_authentication.py`, `history_service.py`, `models.py`, `main.py`, `rate_limiter.py`; actual client implementations in `frontend/src/lib/{api,reporterAuth,protocol}.ts` and the two session hooks. Before/after reproduction and negative cases are represented by `test_milestone4.py`, the existing auth/protocol/reliability suites and `tests/reporter_auth.ts`.

## Reporter authentication v1

This is an explicitly versioned **request-authentication protocol**, separate from encrypted message protocol **v2**. The historical `caseAccessTokenHash` field remains an opaque locator and signed-manifest credential commitment; it is no longer sufficient authorization. Existing v2 words and signing identities remain usable without re-enrolment.

For each protected operation, the browser requests a challenge from `POST /api/v1/reporter-auth/challenge`. Existing-case challenges use the manifest's enrolled reporter signing key, not a supplied replacement. The browser checks all expected context before signing. The exact UTF-8 JSON array signed with Ed25519 is:

```text
["sealed:reporter-auth",1,2,challengeId,nonce,caseId,locator,
 signingPublicKey,operation,requestDigest,expiresAt]
```

`operation` is the method plus API path. JSON requests bind SHA-256 of the exact UTF-8 body; bodyless reads bind the empty body. Uploads bind an unambiguous versioned array containing attachment ID, case ID, actual ciphertext digest, staging token and credential. Multipart boundaries do not affect this semantic digest. The server compares streamed ciphertext bytes to the authenticated digest before publication.

The browser sends `X-Sealed-Challenge` and `X-Sealed-Proof`. Challenges expire after 60 seconds, are bounded in memory and consumed atomically under a lock before validation; invalid attempts consume them too. Replays, changed body/path/case, expired challenges and wrong signing identities fail. Process restart invalidates challenges. There is no database-stored Reporter bearer session, private signing key or recovery phrase. Public pre-case upload enrolment only authorizes staging owned by that reporter identity and locator; claiming requires the matching signed case.

This uses standard Ed25519 detached signatures and SHA-256 request digests, not password hashing as authentication or a new encryption primitive. See the [libsodium signature documentation](https://doc.libsodium.org/public-key_cryptography/public-key_signatures). M1's independent access-key authentication and HttpOnly/SameSite cookie/CSRF protections remain in place.

### Compatibility

- Existing v2 records retain their manifest, ciphertext, participant keys and 12-word recovery behavior.
- V1 has no enrolled Ed25519 identity. Reporter tracking returns an explicit **410** rather than silently restoring insecure bearer authentication. V1 remains available through the authenticated Investigator legacy archive, visibly **UNVERIFIED and READ-ONLY**, with the original decryption key. There is no unsafe re-enrolment or automatic v1-to-v2 conversion.
- Uncommitted pre-M4 staging leases use an older owner binding and must be prepared again; finalized attachments and existing cases are preserved. Old frontend clients must be updated together with the backend.

## History: what is and is not verified

`CaseHistoryEvent` and `CaseHistoryHead` record a sequence, previous/current hash, event identity, case, actor, timestamp, operation identity and canonical payload. Each payload snapshots the signed manifest, signed messages, attachment IDs/sizes/content hashes and status. Event insertion, head update and business mutation share a SQL transaction. Case updates serialize concurrent writes; reads acquire the same case lock for a stable database view.

The verifier validates report/message signatures, recomputes stored hashes and file digests, checks sequence/head consistency and compares the final snapshot with current business data. Regression tests detect changed report/message/status, a removed message, deleted event/tail, reordered events, modified payload and corrupted attachment bytes. Mutations refuse an inconsistent existing history. Existing v2 data begins with an explicit baseline on its first successful mutation; older activity is not retroactively certified. Missing history is **unavailable**, never a green result. Legacy history is **unverified**.

The browser independently verifies v2 content signatures. It does **not** independently authenticate status, timestamps or the server's history-check response. A hash chain in the same database is not an independent trust anchor. Coherent rollback of events, head and business rows can still pass: a regression explicitly demonstrates this limitation. A malicious backend can rewrite its own consistency history or conceal a valid message. `completenessVerified` is always false. Detecting those actions needs an independently retained trusted checkpoint/receipt; this milestone does not implement one.

## Reviewed protections retained

- M1 session expiration/logout, missing/incorrect credentials, CSRF origin/header requirements and negative Investigator route tests remain covered.
- V2 uses independent signing keys, context-bound signatures and established pinning. Role reflection, cross-case substitution, changed key/nonce/ciphertext/signature, duplicate message IDs, downgrade and wrong recovery phrase remain negative tests. Authenticated encryption alone is not treated as proof of a sender's identity.
- Attachment ownership, strict UUID references, encryption overhead limits, claim transactions, interrupted upload recovery and conservative orphan cleanup remain covered by M3 tests. File bytes are decrypted locally; filenames/MIME/key metadata remains inside ciphertext.
- UI renders report text as text, not HTML. Downloads use attachment disposition and `nosniff`; no new third-party scripts/fonts/analytics were added. This is a source review plus regression coverage, not an exhaustive XSS penetration test.
- Recovery credentials still appear in the intended recovery screen and may use existing optional tab storage. Storage errors do not convert success to failure. JavaScript strings and browser-managed storage cannot be reliably zeroed; same-origin malicious scripts/extensions remain a risk.

## Accepted limitations and unverified areas

1. Single local API process and one Investigator workspace; not a multi-tenant or multi-worker security model. Challenge/session state is process-local. SQLite was exercised; PostgreSQL behavior and deployment topologies were not verified.
2. A database dump alone cannot supply the new Reporter proof, but it exposes public identities, locators, ciphertext sizes, times/status and relationships. Weak master passwords remain vulnerable to offline guessing of encrypted identity packets. The separate M1 access configuration is itself sensitive and outside the ordinary database dump boundary.
3. Initial reports remain sealed to the Investigator; Reporter recovery restores conversation access, not decryption of the original sealed report. Loss of words/private identity cannot be repaired by the server.
4. Legacy demonstration private material is publicly recoverable and unsuitable for sensitive content. Its archive is not upgraded to authenticated v2 by this milestone.
5. Request signatures do not encrypt HTTP transport or provide anonymity. Logging redaction tests cover selected IPv4 patterns, not all metadata/logging layers. Local endpoint compromise and malicious delivered JavaScript remain out of scope.
6. Filesystem publication and SQL commits cannot form one OS-crash-atomic transaction. Existing receipts/leases/reconciliation and cleanup cover tested failures, not every possible power-loss boundary. Full history snapshots and file rehashing favor auditability over large-scale performance.
7. No dependency-vulnerability scan, formal protocol proof, malicious-server completeness guarantee or external checkpoint was established. Existing Next multiple-lockfile/experimental proxy-limit warnings remain non-fatal.

Executed commands and browser/migration evidence are recorded in [MILESTONE_4_REPORT.md](MILESTONE_4_REPORT.md). The actual user database and identity were not changed during this verification.
