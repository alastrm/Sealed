# Milestone 3 — Submission, recovery and attachment reliability

Completed **22 October 2026**, for the local SQLite portfolio application.
The technical review and M1/M2 documentation were checked against the source.
No `AGENTS.md` was present. Existing uncommitted M1/M2 work was preserved.

## What changed

### Recovery credentials and submission outcomes

The earlier post-commit `sessionStorage` write had already acquired a catch in
M2. Inspection confirmed that the broader problem remained: a retry regenerated
the reporter identity, report ciphertext and case ID, with no reconciliation.

Submission now has explicit preparing, ready, uploading, sending, unknown,
rejected and confirmed states. The UI uses the existing form/panel design.

1. Preflight the UTF-8 payload and file budget; encrypt files locally and assign
   their stable UUIDs. Prepare one signed v2 report and its recovery credentials.
2. Display the 12 words **before transmitting uploads or the report**. The user
   confirms they have saved them before sending. Preparing a report alone does
   not create a case or upload files.
3. Upload the same ciphertext under the same attachment IDs, then send the same
   signed report/case ID on every retry. An immediate operation guard also blocks
   repeated clicks before React has rendered a disabled button.
4. Identical report POSTs return the existing case; a changed body using that ID
   returns 409. A receipt stores the canonical request digest, with attachment
   order normalized. A separate unique credential digest prevents two new cases
   from acquiring the same recovery credential, including concurrent attempts.
   Existing legacy duplicate credentials are not rewritten.
5. Lost, malformed, timed-out or 5xx acknowledgements are reconciled through the
   reporter's existing credential. The client verifies the exact v2 manifest,
   case and reporter identity. A failed lookup after a timeout is **not** treated
   as proof the original request can never commit.

A confirmed rejection/pre-transmission failure retains the prepared report and
credentials. An unknown outcome remains visibly unknown and retries the same
operation. Editing a draft is available before sending or after a confirmed
rejection; it cannot silently replace an ambiguous submission.

Storage reads, writes, removals and access to the storage property are optional
and guarded. They cannot change confirmed success to failure or hide the words.
When available, tab storage keeps the mnemonic and the ready encrypted request
for restoration after reload. Restoration verifies the credential/manifest
binding and never silently treats v1 as authenticated v2. Ciphertext file blobs
and plaintext file keys are not put into this saved request. There is no new
localStorage persistence, analytics, external request or server recovery-phrase
field. Recovery words are never logged or transmitted to the API.

### Attachments

The padding algorithm, bucket sizes, secretbox encryption and encrypted metadata
format remain unchanged. The actual limits are now explicit:

| Quantity | Limit / calculation |
| --- | --- |
| Plaintext per file | Less than 10 MiB: maximum **10,485,759 bytes** |
| Padded plaintext | First bucket strictly larger than the file: 256 KiB, 1 MiB, 5 MiB or 10 MiB |
| Ciphertext | Selected bucket **plus 16 bytes** for the authentication tag |
| Maximum ciphertext | **10,485,776 bytes**, accepted inclusively |
| Batch | At most 10 distinct files and 32 MiB of encrypted data per report/reply |
| Text plus attachment metadata | At most 65,536 UTF-8 bytes, checked before uploads |

Both sides calculate/enforce the same bounds. Files at exactly 5 MiB and at the
maximum supported plaintext now work. The installed Next.js source also revealed
a default 10 MiB rewrite body limit; its allowance is now 12 MiB to accommodate
the ciphertext plus multipart headers. FastAPI still enforces the exact file
limit. A real browser exercised this path and downloaded the correctly decrypted
5 MiB file.

Uploads are now staged rather than immediately added to a case. Initial staging
is bound to the reporter's existing presented credential; case-linked staging
requires the reporter credential or M1 Investigator authentication/CSRF checks.
Only owner hashes and ciphertext digests are added to the staging table. No new
cryptographic identity or private-key exchange is involved.

An upload retry must match the UUID, owner, intended case, size and ciphertext
digest. Reusing an ID for different bytes/ownership returns 409. A matching retry
can restore a missing ciphertext file. Files are read in bounded chunks into
unique temporary paths, then published; interrupted reads and failed commits
remove only the current request's uncommitted files. An ambiguous commit is
checked for a committed owner before removing anything.

Finalization validates canonical, distinct IDs, ownership, intended case, presence,
size, digest, batch limits and the staging lease. Claims occur in the **same DB
transaction** as report/message creation and status changes. A failed later claim
rolls back earlier claims too. Cross-case and cross-role reassignment is rejected.
Follow-up DTOs carry attachment IDs for this transactional claim; the existing v2
signature still authenticates the encrypted payload containing the file metadata.
The v2 signed bytes and ciphertext formats were not changed.

Decrypted metadata is validated before rendering. Downloads check ciphertext and
plaintext lengths against that metadata and report missing/damaged files without
crashing the page.

### Interrupted operations and orphan cleanup

New staging leases last 24 hours, renewed by a matching active upload retry.
Expired staging returns 410; it cannot be silently revived under the same ID.
Successful finalization permanently protects an attachment from staging cleanup.

Local maintenance is explicit:

```powershell
python cleanup_attachments.py          # read-only preview
python cleanup_attachments.py --apply  # intentional maintenance
```

The apply path marks only expired managed/unclaimed uploads with tombstones and
removes their ciphertext. A conditional DB update serializes expiration against
finalization. Fresh staging, finalized files, existing legacy records and
unmanaged files are retained. Abandoned new-format temporary files and untracked
new-format ciphertext are quarantined after the grace period, rather than
deleted. Quarantine is not automatically purged.

Cleanup mutation was executed **only in disposable fixtures**, never on the
developer's attachment store. No background cleanup job was added.

### Recovery and replies

Editing a recovery phrase immediately clears the old case, keys, draft, audit
result and reply state. A new lookup cancels/supersedes the previous lookup;
failed recovery cannot leave an old conversation paired with new credentials.
Audit refresh clears stale success before making its request. Requests have
timeouts covering both headers and body consumption.

Both reply flows preflight attachments before uploading and keep one signed
message ID/ciphertext through a retry. If its acknowledgement is lost, the client
fetches history, matches that exact signed operation and independently verifies
it. M2's server-side replay rejection remains **409**, rather than being weakened
to accept repeated message writes. A pending reply's draft is locked while the
same operation is checked. Generation guards prevent late preparation from
installing a previous case's pending reply after clear/lock/selection.

Investigator Refresh reloads the selected conversation as well as the list, and
does not discard a pending reply. Expired Investigator authentication still
clears the local workspace. V1 remains explicitly UNVERIFIED and READ-ONLY in
both browser views and on the backend.

## Files modified for this milestone

This list distinguishes M3 changes from M1/M2 files already modified/untracked
when this task began.

| Files | M3 responsibility |
| --- | --- |
| `attachment_service.py`, `cleanup_attachments.py` | Ownership, leases, transactional claims, bounds and conservative maintenance |
| `models.py` | Add `submission_receipts` and `attachment_uploads`; no existing columns changed |
| `routers/cases.py`, `routers/investigators.py`, `schemas.py` | Idempotent initial POSTs, streamed/retryable staging, atomic attachment finalization |
| `frontend/src/lib/submission.ts` | Tested submission lifecycle, optional storage and reconciliation |
| `frontend/src/lib/attachments.ts`, `replyDelivery.ts` | Shared preflight, stable encrypted uploads and signed reply reconciliation |
| `frontend/src/lib/api.ts`, `types.ts` | Bounded request lifecycle, structured errors, upload/reply DTO additions |
| `frontend/src/lib/crypto.ts` | Validate decrypted attachment metadata; primitives and v2 signed encoding unchanged |
| `frontend/src/app/page.tsx` | Recovery-first submission using existing components/styles |
| `frontend/src/hooks/useReporterCase.ts`, `useInvestigatorSession.ts` | Recovery invalidation, stable replies, stale-operation guards and selected-thread refresh |
| `frontend/src/components/AttachmentPicker.tsx`, `AttachmentList.tsx`, `Conversation.tsx`, `TrackReport.tsx`, `ui.tsx`, `frontend/src/app/investigator/page.tsx` | Consistent bounds, safe downloads, pending/error/success states and accurate instructions |
| `frontend/next.config.ts` | Multipart rewrite allowance; no pin or backend destination changes |
| `test_submission_reliability.py` | 16 new isolated backend reliability regressions |
| `test_investigator_auth.py`, `test_message_protocol.py`, `test_api.py` | Adapt existing assertions to owned staging and immutable-submission conflicts; retain authorization/signature/legacy checks |
| `tests/reliability.ts` | Actual frontend lifecycle and crypto failure-path tests |
| `tests/create_reliability_fixture.ts`, `reliability_server.py`, `start_reliability_environment.py`, `reliability_e2e.ts`, `run_reliability_e2e.py`, `tests/__init__.py` | Reproducible synthetic test stack and automated live regression |
| `package.json`, `README.md`, `INVESTIGATOR_ACCESS.md`, `CRYPTOGRAPHIC_AUTHENTICITY.md`, this report | Commands and updated reliability/compatibility documentation |

No dependencies were installed. CSS, the v2 protocol implementation in
`protocol.ts`, signing-key generation/derivation, private-key storage, the real
identity and trusted pin were not changed.

## Executed verification

| Check | Result |
| --- | --- |
| `python -m unittest test_submission_reliability test_investigator_auth test_message_protocol -v` | **45 passed**: 16 M3 + 18 M1 + 11 M2/migration tests |
| `python test_api.py` | **Passed**, disposable database/storage |
| `npm run test:frontend` | **24 passed assertion groups**, actual frontend modules, in-memory synthetic credentials |
| `npm run test:reliability:e2e` | **Passed**; starts/stops its own disposable stack on free loopback ports |
| `npm run lint` in `frontend` | **Passed** |
| `npx tsc --noEmit` in `frontend` | **Passed** |
| `npm run build` in `frontend` | **Passed**, default Turbopack production build |
| Targeted strict TypeScript check of the frontend crypto bridge, original live caller and new test utilities | **Passed** |
| Browser on a separate synthetic workspace | **Passed**: words before transmission, acknowledgement gate, 5 MiB proxy upload/decryption/download, fresh recovery, stale clearing, wrong phrase, both verified reply directions, M1 sign-in/lock and legacy read-only views |
| `python cleanup_attachments.py` | **Read-only local preview passed**, zero expiry/removal/quarantine candidates; no apply operation on local data |
| `git diff --check` | **Passed**; existing Windows line-ending warnings are nonfatal |

The live regression deliberately corrupts a response **after** a successful
database commit. The actual submission controller reconciles it correctly even
with unavailable tab storage. A signed reply's acknowledgement is also lost and
recovered from history. The original frontend crypto security bridge remains
part of the M1/M2 test execution.

Browser evidence is retained in ignored `scratch/m3-verified-workflow.png` and
`scratch/m3-legacy-readonly.png`. It contains synthetic content only, with no
recovery words or passwords.

## Local data and startup

Before starting the updated local application, a protected online SQLite backup,
attachment copy, access configuration and public pin were saved under
`storage/backups/20261022-161719Z-pre-m3-startup`. Backup access is restricted to
the current Windows user and SYSTEM.

Normal startup adds the two new tables idempotently with `create_all`; no
destructive migration or existing-row rewrite is needed. Startup was verified at
`http://127.0.0.1:8000/health` and `http://127.0.0.1:3000/` with HTTP 200. Every
pre-existing database row and attachment, the encrypted identity, access
configuration and pin were compared with the backup and remain unchanged. The
two new local tables are empty: all workflow tests used disposable environments.
No real master password was requested or used.

## Remaining limitations

- With storage disabled, a full tab/process loss cannot preserve the encrypted
  retry request or file blobs. The pre-transmission save acknowledgement and
  visible warning make the retained recovery phrase the fallback: use Track
  before starting another report. No disk persistence is silently introduced.
- A restored request can retry finalized uploads/report commit; it cannot
  recreate expired or missing uploaded file bytes after the original tab is
  gone. Expiration/missing-file errors remain explicit; there is no silent new
  identity/report or attachment substitution. Active matching retries repair a
  missing blob while the original encrypted bytes are still available.
- Pending reply retry state is in tab memory. After reload/lock, recover/read
  history before deliberately sending another message.
- Cleanup is local and opt-in. Pre-M3 unowned files and quarantine require
  deliberate review; tombstones/receipts are retained. This favors preservation
  over speculative deletion.
- Filesystem and SQL cannot be one crash-atomic transaction. Atomic publication,
  owned receipts, rollback cleanup, replay-safe retries and quarantine cover the
  tested boundaries; abrupt OS failure at every possible instruction was not
  simulated. The M1 single-process local-server constraint remains.
- SQLite was exercised, including separate-connection concurrent creation.
  PostgreSQL and multiple API workers were not verified. The existing multiple
  lockfile warning remains; the installed Next version exposes the proxy limit
  under its experimental configuration.
- This milestone does not fix audit-log integrity, stored bearer-verifier replay,
  malicious JavaScript delivery, anonymity/metadata exposure, or original-report
  recovery by the reporter (the initial sealed box remains Investigator-only).
  Signatures, backend authentication and the audit badge remain separate checks.
- The backend cannot inspect file references inside ciphertext. Updated clients
  send matching claim IDs; a malicious sender can still describe an unavailable
  attachment, but cannot use the claim API to reassign another case's files.

No deployment, commit or push was performed.
