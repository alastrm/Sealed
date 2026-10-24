# Milestone 4 — Security, integrity and finalization

Completed against the existing uncommitted repository state on 25 October 2026. Earlier milestone work was preserved. No commit, push, deployment, dependency installation, real database migration or identity replacement was performed.

## Result

M4 is implemented and verified in disposable environments. Reporter authorization now proves possession of the existing Ed25519 signing key; copying the database's locator/verifier is insufficient. Investigator sessions remain separate. Case closure/reopening is enforced on the server. The former audit indicator is replaced by an explicitly limited server consistency check. The encrypted-message v2 protocol, participant keys and visual design remain unchanged.

**Local activation is intentionally pending:** the user's real database still lacks the two M4 history tables. Updated backend startup requires the explicit additive migration. The current instruction forbids modifying that database, so the migration was verified on a protected copy only.

## Changes delivered

### Reporter proof of possession

Request authentication version 1 signs a fresh challenge, expiry, case, locator, reporter identity, method/path and request digest. JSON proofs bind exact body bytes; upload proofs bind attachment identity and ciphertext bytes. Single-use challenges are consumed under a lock, including invalid attempts, and expire after 60 seconds. The client validates context before signing. Reads, replies, attachment uploads/downloads and audit reads enforce this on the server. The 12-word derivation and signed v2 manifests/messages are unchanged.

Static legacy clients cannot bypass the new requirement. Existing v2 recovery remains compatible. V1 Reporter access returns explicit 410 because it lacks an enrolled signing identity; the Investigator legacy archive remains readable, unverified and read-only. Pending pre-M4 staging leases must be prepared again; finalized attachments are preserved.

### Lifecycle and consistency

| Current status | Explicit Investigator transitions |
|---|---|
| OPEN | IN_REVIEW, CLOSED |
| IN_REVIEW | CLOSED |
| RESPONDED | IN_REVIEW, CLOSED |
| CLOSED | IN_REVIEW (reopen) |

An Investigator reply sets RESPONDED. Reporter replies do not implicitly change status. Closed cases permit reading/downloading but reject new replies and uploads from both roles. Reopening retains case/message identity. Transition requests include a unique request ID and expected revision; matching retries are idempotent, changed payloads/stale revisions fail. Transaction-level case locking prevents conflicting concurrent writes from both succeeding. Uploads do not hold a database write lock across their network stream; closure is checked again before publication.

New history events bind case status, signed content, attachment bytes and event metadata, with a per-case head and consistent 64-character hashes. Mutations and event insertion share a transaction. Inconsistent history blocks writes. Existing v2 records receive an explicit historical baseline only on their first successful mutation. Missing history is unavailable; v1 is unverified. The badge says **Server consistency check passed · Completeness not proven**. Coherent rollback and malicious-server omission remain outside this guarantee.

Additional focused hardening covers anonymous attachment/audit reads, spoofed forwarding headers in rate-limit identity, validation-error input echo and API caching. Final browser review also confirmed stale-revision handling; refresh errors now use existing error/unauthorized UI handling instead of leaving an unhandled rejected promise.

## Migration verification and preservation

`tests/verify_m4_migration_copy.py --source whistleblower.db` created a protected SQLite online backup and applied `migrate_m4.py` twice to that copy. Windows ACLs restrict its directory to the local owner and SYSTEM. The copy is retained at:

```text
storage/backups/sealed-m4-schema-copy-824qgbv4/copy.db
```

Results: **8 prior tables / 32 prior rows preserved; idempotent migration; SQLite integrity check OK**. A final read-only comparison on 25 October confirmed every original table's rows still match the real source. The real source still lacks `case_history_heads` and `case_history_events`, confirming activation was not applied. Existing key records, ciphertext and legacy audit rows were not rewritten. Migration adds tables only and does not certify earlier history.

## Executed verification

| Command / check | Actual result |
|---|---|
| `python -m unittest test_submission_reliability test_investigator_auth test_message_protocol test_milestone4 -q` | **74 tests passed**; disposable databases, including separate-connection concurrency |
| `python test_api.py` | **22 PASS assertions/groups**, all successful |
| `npm run test:frontend` | **24 reliability/crypto groups + 27 request-authentication checks passed** |
| Root `npx tsc --noEmit` | Passed; test/PoC scope explicitly separated from Next's own TS project |
| Frontend `npm run lint` | Passed |
| Frontend `npx tsc --noEmit` | Passed |
| Frontend `npm run build` | Passed with Next 16.3.8 / Turbopack; all application routes generated |
| `npm run demo:e2e` | **8 live workflow groups passed**, through Next's API proxy with actual frontend crypto; owned servers/files cleaned up |
| Adapted `e2e.ts` against the owned disposable API | Passed: independent pin, local unlock, recovery, signed replies both ways, replay and authorization checks |
| Protected-copy migration | Applied twice to the copy; original rows preserved; integrity OK; source read-only |
| Browser workflow | Passed on a separate synthetic loopback environment, described below |

M4's 29 backend tests cover copied verifier/public data, valid/expired/reused/concurrently replayed challenge, wrong key, case/body/operation substitution, status authorization/CSRF, stale/idempotent/concurrent transition requests, closed-case writes/uploads, corrupt/missing/reordered/truncated history, deleted messages, digest width, legacy policy, migration baseline, validation redaction, cross-case download and ciphertext mutation, upload digest substitution, failed-commit rollback and forwarded-header rate-limit spoofing. An explicit test demonstrates that coherent full rollback can remain consistent; it is a limitation test, not a protection claim.

Existing suites retain v2 forgery/reflection/key substitution/replay tests, M1 authentication/logout/expiry/CSRF, M3 ambiguous submission/storage failures/attachment boundaries/ownership/interruption/orphan cleanup, and actual frontend signed conversations. New frontend checks exercise actual request signing, context mismatch rejection, signed-field tampering, domain separation, exact-body digest binding, upload-context binding and wiped signing keys.

### Browser evidence

Using only synthetic credentials and a fresh disposable DB, the in-app browser verified:

- Report preparation with 12 words before transmission; successful confirmation after the fixture deliberately corrupted the post-commit acknowledgement.
- Track recovery, Reporter follow-up, Investigator authentication and local decryption.
- Signed Investigator reply with an encrypted text attachment; Reporter decryption/download matched the original bytes exactly.
- Stale-revision conflict, refresh and successful start-review transition.
- Close reflected in both views, disabled reply/file controls, successful reopen and restored Reporter composer with existing conversation preserved.
- Lock/logout and explicit legacy mode: decrypted synthetic v1 report/message, visible UNVERIFIED/READ-ONLY labels, disabled writes.
- Clearing the Reporter session then entering invalid words produced an explicit error with no stale conversation.

Non-secret screenshots are retained locally in ignored `scratch/m4-browser-closed.png` and `scratch/m4-browser-legacy.png`. Browser attachment initially timed out; retrying the attached visible test tab succeeded. Slow first route compilation was transient. No user interaction or real password was required.

## Files modified for M4

The working tree also contains earlier uncommitted M1–M3 changes. The following list attributes **M4 work**, not every file in `git status`:

- New backend: `reporter_auth.py`, `routers/reporter_authentication.py`, `history_service.py`, `migrate_m4.py`.
- Backend integration: `models.py`, `schemas.py`, `main.py`, `routers/cases.py`, `routers/investigators.py`, `attachment_service.py`, `rate_limiter.py`; legacy-scope documentation in `audit_service.py`.
- New frontend request signer: `frontend/src/lib/reporterAuth.ts`.
- Frontend integration: `frontend/src/lib/api.ts`, `types.ts`, `attachments.ts`, `replyDelivery.ts`, `submission.ts`; `frontend/src/hooks/useReporterCase.ts`, `useInvestigatorSession.ts`; `frontend/src/components/AuditBadge.tsx`, `AttachmentList.tsx`, `Conversation.tsx`, `TrackReport.tsx`; `frontend/src/app/investigator/page.tsx`.
- New regression/migration checks: `test_milestone4.py`, `tests/reporter_auth.ts`, `tests/verify_m4_migration_copy.py`.
- Adapted test clients/fixtures: `test_support.py`, `test_investigator_auth.py`, `test_message_protocol.py`, `test_submission_reliability.py`, `test_api.py`, `e2e.ts`, `tests/frontend_crypto.ts`, `tests/reliability.ts`, `tests/reliability_e2e.ts`, `tests/start_reliability_environment.py`, `tests/reliability_server.py`, `tests/run_reliability_e2e.py`.
- Commands/configuration: `package.json`, `tsconfig.json`.
- Documentation: this report, `MILESTONE_4_SECURITY_AUDIT.md`, `DEMO.md`, `README.md`, and superseding notes in `INVESTIGATOR_ACCESS.md` / `CRYPTOGRAPHIC_AUTHENTICITY.md`.

## Remaining limitations and next action

No unresolved assertion, lint, typecheck or build failure remains in the executed final checks. Existing Next warnings about multiple lockfiles and the experimental proxy-size option remain. Restricted-process execution initially stalled a TypeScript invocation; the completed normal local check passed. Docker, PostgreSQL, multiple API workers and an external dependency-vulnerability scan were not verified.

Server consistency is not complete-history authenticity: no trusted external checkpoint exists, and a coordinated DB rollback remains undetectable. Browser-delivered code, endpoint security, optional tab mnemonic storage and network metadata remain trust limitations. The single-workspace/process model and public legacy demonstration identity remain explicitly limited. M4 does not promise complete anonymity, malicious-server protection or non-repudiation.

For a demonstration now, use `npm run demo:e2e`. For the real local workspace, the only activation step pending is a separately approved backup/migration/restart procedure in [DEMO.md](DEMO.md). Do not regenerate the current identity. See [the security audit](MILESTONE_4_SECURITY_AUDIT.md) for evidence and the complete threat-model boundaries.
