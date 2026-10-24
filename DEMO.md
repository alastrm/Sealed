# Reproducible local Sealed demo

This project is a local portfolio demonstration. The automated demo uses fresh synthetic identities, its own SQLite database, attachment directory and loopback ports. It does not use the real Investigator password, encrypted identity or `whistleblower.db`.

## Prerequisites

Python 3.10+ and Node.js 22 were used for verification. From a fresh checkout, install the declared dependencies yourself in a virtual environment and the two npm projects:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
npm ci
npm --prefix frontend ci
```

Dependency installation was not performed during M4 finalization. Existing local dependencies were reused. No Docker, cloud account, real credentials or external service is needed for the verified demo.

## One-command complete workflow

From the repository root:

```powershell
npm run demo:e2e
```

The runner generates independent encryption/signing keys and encrypted identity packets using the actual frontend implementation, installs the synthetic signing pin independently of API responses, starts FastAPI and a copied Next frontend, and exercises requests through Next's API proxy. Both processes bind loopback. Next telemetry is disabled for these disposable processes. The runner cleans up only its own processes and validated disposable directory; it detaches the dependency junction before directory cleanup.

Expected output is eight `PASS` groups and a cleanup confirmation:

1. Fresh identity, pin and isolated services.
2. Words available before submission; disabled storage and a deliberately lost post-commit acknowledgement reconciled.
3. Recovery from the words, manifest identity binding and duplicate submission handling.
4. Investigator backend authentication and denial of anonymous access.
5. Investigator decryption and a maximum ciphertext-bucket attachment, checked byte-for-byte.
6. Signed replies and attachments in both directions; duplicate-message rejection; explicit read-only legacy archive.
7. Copied database verifier denied, protected downloads, close/idempotent retry, closed-case write rejection and reopening.
8. Logout invalidates the session.

This command exercises the **actual frontend crypto and API modules**, not a second implementation. It is an automated live HTTP/crypto test, not a browser-click test. Browser verification is recorded separately in `MILESTONE_4_REPORT.md`.

For a deliberately retained browser sandbox, `python tests/start_reliability_environment.py` prints its loopback URLs and new `scratch/sealed-demo-*` directory. `scratch/m3-environment.json` is the historical name of its private local connection descriptor. Its fixture file contains synthetic test-only credentials: do not publish it or use those identities for real reports. The manual launcher leaves servers running; prefer `npm run demo:e2e` for automatic cleanup. Stop only the PIDs belonging to that specific descriptor and verify their process command lines before doing so. Do not terminate unrelated local servers.

## Browser demonstration sequence

On the isolated URL, submit clearly synthetic text. Save the displayed 12 words before sending. Open Track and check status; send a Reporter follow-up. Sign into Investigator using the sandbox fixture's existing access credentials, select the new report, read its decrypted contents, start review and send a reply with a small synthetic attachment. In Track, refresh, read the reply and download the attachment.

Close the case in Investigator. Both views must display Closed and disable replies/attachments. Refresh Track after reopening: the existing conversation and identities remain, and replies are enabled again. A stale status revision produces an explicit conflict; refresh before retrying. The consistency badge must also say **Completeness not proven**.

Lock the workspace and enter legacy archive mode with the synthetic legacy key. The old report remains readable with **UNVERIFIED / READ-ONLY** labels and disabled writes. Legacy Reporter recovery intentionally returns 410 because there is no enrolled signing identity; it must not fall back to the copied-verifier credential.

## Existing database: safe migration procedure

**M4 was not applied to the user's real database.** It still lacks `case_history_heads` and `case_history_events`. Updated API startup refuses that old schema until the explicitly approved additive migration is applied. No reset, identity regeneration or ciphertext conversion is required.

Inspect without applying:

```powershell
python migrate_m4.py --database "sqlite:///./whistleblower.db"
```

To repeat protected-copy verification instead of modifying the source:

```powershell
python tests/verify_m4_migration_copy.py --source whistleblower.db
```

The verifier opens the source SQLite database read-only, uses SQLite's online backup, protects the new backup directory with owner/SYSTEM ACLs on Windows (0700 on POSIX), applies migration twice **only to the copy**, compares every existing table's rows and runs `PRAGMA integrity_check`. It retains the protected copy under ignored `storage/backups/`. It does not copy unencrypted private material or print data rows.

Before a future real activation, stop that API process, retain protected backups of the DB, encrypted storage and local access configuration, and obtain explicit approval for the target. Only then run:

```powershell
# Administrative action for an explicitly approved target, NOT part of demo:e2e:
python migrate_m4.py --database "sqlite:///./whistleblower.db" --apply
```

This creates two tables without rewriting existing data. Existing M3 schemas need no destructive operation. Retain the current encrypted Investigator identity and independently installed public pins. Existing v2 cases show history unavailable until the first successful mutation records a clearly labelled baseline. Old history is never silently certified.

After an approved activation, the normal local launch is:

```powershell
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --no-access-log
# Separate terminal:
npm --prefix frontend run dev
```

Use one API worker. `SEALED_ALLOWED_ORIGINS`, frontend origin and proxy configuration must agree. Investigator access setup/rotation is in `INVESTIGATOR_ACCESS.md`; independent identity initialization/pinning is in `CRYPTOGRAPHIC_AUTHENTICITY.md`. Do not rerun key initialization on an already configured workspace. The repository's Docker example does not automatically provision identities, pins, access configuration or approved migrations and was not validated for M4.

## Final regression commands

```powershell
python -m unittest test_submission_reliability test_investigator_auth test_message_protocol test_milestone4 -q
python test_api.py
npm run test:frontend
npx tsc --noEmit
npm --prefix frontend run lint
# In frontend/: npx tsc --noEmit
npm --prefix frontend run build
npm run demo:e2e
```

The legacy `npm run e2e` utility requires explicit disposable credentials/URL and also creates a report. Prefer the self-contained `demo:e2e`; never point test clients at personal data. A build succeeding does not migrate a database or establish a trusted signing pin.
