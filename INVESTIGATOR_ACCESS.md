# Investigator access control — Milestone 1

Milestone 2 retains these authentication controls and adds v2 cryptographic identities,
independent pins, and read-only legacy handling. Its current key/protocol setup is
documented in [CRYPTOGRAPHIC_AUTHENTICITY.md](CRYPTOGRAPHIC_AUTHENTICITY.md).
The details below describe the original Milestone 1 implementation.

Milestone 3 retains these session/CSRF controls. Uploads now remain owner-bound
staging leases until a signed report/reply commits; neither role can reassign
another case's files. See [MILESTONE_3_REPORT.md](MILESTONE_3_REPORT.md) for the
current attachment, retry, expiry and maintenance contract.

## M4 update

M1 Investigator authentication remains unchanged. Reporter operations now require
one-time Ed25519 request proofs; the stored locator alone no longer authorizes
access. Attachment downloads and consistency reads are authenticated, and closed
cases reject replies/uploads. V1 remains available only through the authenticated
Investigator read-only archive. See [M4 audit](MILESTONE_4_SECURITY_AUDIT.md) and
[migration/demo instructions](DEMO.md); older Reporter-contract descriptions below
describe the M1 implementation, not the current M4 authorization boundary.

## Root cause and scope

The old Investigator screen only downloaded an encrypted private-key record and
unlocked it locally. No server dependency authenticated the caller of the case
list, account record, conversation, or investigator reply endpoints. A direct
HTTP client could read those endpoints and POST an investigator-labelled reply,
which also changed case status to `RESPONDED`. Hiding controls or failing local
decryption did not stop those requests. Case-linked attachment uploads also
accepted a bare case ID, and anonymous creation could reassign an existing file.
These findings from `SEALED_TECHNICAL_REVIEW.md` were verified against the routes
and frontend callers before implementation.

This implementation keeps the existing **single investigator / single workspace**
model: the configured investigator can access every case. There is no per-case
owner in the existing schema. This is not a multi-tenant or multi-user access
model. Public report submission and the existing reporter credential contract
remain available.

## Local setup

Use the existing database and investigator encryption record. After seeding a
fresh demonstration database, configure access once:

```powershell
python seed.py
python configure_investigator_access.py --username "compliance.lead@integrity-trust.corp"
```

The command refuses unknown accounts and refuses to overwrite existing access
configuration without `--rotate`. It generates a random **256-bit workspace access
key**, prints it once, and writes `storage/investigator-auth.json`. Save the key
privately. This directory is gitignored and excluded from Docker build context.
Do not place this file in frontend assets, commit it, or put its value into a
`NEXT_PUBLIC_*` variable. File creation requests owner-only permissions on POSIX;
Windows uses the containing directory's ACL, which the local machine owner must
control. The backend needs access to this file, not to the decryption password.

Restart the backend, then enter the configured username, generated workspace
access key, and the **existing decryption master password** at `/investigator`.
The setup command does not create, rotate, migrate, or decrypt report keys. The
legacy `seed.py` encrypted investigator record is a public demonstration fixture
whose decryption password is known from the existing PoC. It is unsuitable for
sensitive data. This milestone removes automatic password prefilling and password
printing from the seeder; it does not replace that existing encryption identity.

For rotation, run the same command with `--rotate` and restart **all** backend
processes. Configuration is read once per process. Restart invalidates every
session and pending challenge. Losing the access key can be resolved by local
rotation; losing the decryption password cannot be resolved by this mechanism.

Configuration:

| Setting | Default / purpose |
| --- | --- |
| `SEALED_AUTH_FILE` | Absolute repository `storage/investigator-auth.json`; an optional private alternative path |
| `SEALED_ALLOWED_ORIGINS` | `http://localhost:3000,http://127.0.0.1:3000`; comma-separated exact frontend origins, no wildcard |
| `SEALED_COOKIE_SECURE` | `false` for loopback HTTP; set `true` if using HTTPS |

Use matching hostnames for frontend and API. The existing Next.js `/api` rewrite
is the preferred same-origin browser path. Cross-origin local API calls use
`credentials: include`, exact CORS origins, and must still be same-site (for
example, two `localhost` ports). Different `localhost` and `127.0.0.1` hosts are
not interchangeable for cookies. For a custom frontend port, set
`SEALED_ALLOWED_ORIGINS` before starting the backend. Run a **single backend
worker**: sessions and challenges are intentionally in memory. Reloads log users
out. Bind the local API to loopback; HTTP is appropriate only for this local
demonstration, not a network deployment.

Docker was not deployed or changed into a hosting platform. An existing local
container needs its own access setup (run the command inside the backend
container, then restart it). Its current disposable filesystem also loses the
access file when the container is replaced unless a private persistent mount is
explicitly provided. No access key is baked into images.

## Authentication and trust boundaries

1. The browser requests a random challenge for the username. The server records
   its ID, nonce, exact Origin, and 60-second expiry. Authentication endpoints
   require the allowed Origin and `X-Sealed-Request: 1`.
2. Browser Web Crypto signs the UTF-8 string below with HMAC-SHA256 using the
   **independent random access key**. Only the resulting hex proof is POSTed.

   ```text
   sealed:investigator-auth:v1\n<challengeId>\n<nonce>\n<username>\n<Origin>
   ```

   The ID and nonce are 32 random bytes each, encoded as lowercase hex. The
   username excludes newlines. The access key is exactly 32 random bytes encoded
   as 64 hex characters. It is not a human password or a password-derived key.
3. The backend consumes the challenge, including after an incorrect proof,
   checks its identity/origin/expiry, and compares the HMAC in constant time.
   Replaying a consumed or expired proof fails. Login challenges and verification
   are limited separately to 15/minute per peer address seen by ASGI; these new
   limits do not directly trust caller-provided forwarding headers. Existing
   public reporter rate-limit behaviour is unchanged.
4. Successful authentication sets a random opaque session cookie. Only its
   SHA-256 digest and absolute expiry are retained in server memory. Sessions last
   one hour without sliding renewal. Reauthentication revokes the previous token
   in that cookie jar; logout revokes it server-side. Challenge/session stores are
   locked, expire entries, and have finite size limits.
5. The cookie is `HttpOnly`, host-only, `SameSite=Strict`, path `/api/v1`, and
   optionally `Secure` as above. Its value is never returned in JSON, placed in
   JavaScript state, or saved in web storage. Investigator API responses use
   `Cache-Control: no-store`.
6. Only after authentication may the browser download its own encrypted key
   record. The master password, derived key-encryption key, investigator private
   key, reporter mnemonic, and report plaintext are not used as backend login
   credentials. Existing Argon2id, libsodium encryption, and ciphertext formats
   remain unchanged. The browser unlocks the key locally. Wrong local unlocking
   attempts trigger server logout; input values are cleared after an attempt.
7. Locking clears local keys/decrypted state and calls server logout. A backend
   `401` clears the workspace; a timer locks after the session lifetime. Late
   asynchronous completions cannot repopulate a locked workspace. If logout fails
   due to a network error, the screen reports it: local clearing cannot by itself
   revoke the server session. Server-side expiry still applies.

The server must know the high-entropy **authentication** key to verify proofs.
A stolen access file or compromised backend can therefore authenticate, replace
data, or serve malicious JavaScript. It does not learn decryption keys through
this login exchange. A hostile script or extension running in the legitimate
frontend origin can still read entered secrets or invoke authenticated APIs;
HttpOnly prevents direct cookie reading, not same-origin request abuse. Browser
garbage collection prevents guarantees that JavaScript strings are erased.
Cookies are not port-isolated; other software served on the same local hostname
must also be trusted.

This small challenge-response scheme is deliberately scoped to a local,
high-entropy workspace credential. It is not a PAKE, password login system, MFA,
or substitute for HTTPS or browser delivery integrity. No new dependency or
identity service is introduced. The HMAC operation uses the browser's native
[Web Crypto signing API](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/sign).

## Route policy and CSRF

| Route | Required authority |
| --- | --- |
| `GET /api/v1/investigators/public-key` | Public, unchanged |
| `POST /api/v1/investigators/auth/challenge` | Allowed Origin + custom header; no session yet |
| `POST /api/v1/investigators/auth/session` | Allowed Origin + custom header + one-time valid proof |
| `GET /api/v1/investigators/auth/session` | Investigator cookie |
| `DELETE /api/v1/investigators/auth/session` | Allowed Origin + custom header; clears even expired cookies |
| `GET /api/v1/investigators/account` | Investigator cookie, own account only |
| `GET /api/v1/investigators/cases` | Investigator cookie |
| `GET /api/v1/investigators/cases/{id}/messages` | Investigator cookie |
| `POST /api/v1/investigators/cases/{id}/messages` | Investigator cookie + CSRF checks; body case ID matches path and reply public key matches authenticated account |
| `POST /api/v1/cases` | Public; new files may be linked only if currently unassigned |
| `POST /api/v1/cases/attachments`, no case/credential | Public staged encrypted upload |
| Same upload, existing case | Matching reporter credential **or** investigator cookie + CSRF checks |
| Reporter access, lookup, replies | Existing reporter credential; never inferred from investigator cookie |
| Ciphertext file download / audit verification | Existing public-by-ID behaviour, unchanged |

There is no separate case-status endpoint. The investigator reply transaction is
the existing investigator status mutation and now has the same authentication
and CSRF requirements as the reply itself. Reporter follow-ups legitimately
change status to `IN_REVIEW` using their existing credential.

Cookie-authorized writes check an exact allowlisted Origin and the non-simple
`X-Sealed-Request: 1` header, and reject `Sec-Fetch-Site: cross-site`.
This includes login/logout and investigator file uploads, avoiding login CSRF and
bare multipart form CSRF. CORS grants credentials only to explicit allowed
origins. `SameSite=Strict` is an additional layer; CORS and SameSite alone are not
the authorization mechanism. A same-site hostile origin without the exact
allowed Origin/header still fails. These choices follow the
[OWASP CSRF guidance on custom headers and origin checks](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).
Non-browser clients can supply those headers, but still need a valid access proof
and session. Public reporter routes use their existing explicit body credential
and do not gain authority from ambient investigator cookies. An explicitly wrong
reporter upload credential fails even alongside a valid investigator session.

## Verification and remaining work

Run without installing anything new:

```powershell
python -m unittest test_investigator_auth -v
python test_api.py
cd frontend
npm run lint
npx tsc --noEmit
npm run build
```

The Python suites use fresh in-memory SQLite, temporary attachment storage,
random access keys, and real authentication endpoints. `test_api.py` no longer
drops the developer's database. The new suite invokes `tests/frontend_crypto.ts`
through the already installed root `tsx` dependency: it uses the actual frontend
HMAC helper and crypto module to generate a fresh encrypted identity, submit a
sealed report, authenticate, unlock/decrypt, reply, recover with the mnemonic,
decrypt the reply, follow up, and decrypt that follow-up. No report-encryption
implementation is duplicated in the test. The older live `e2e.ts` caller now
requires explicit environment credentials and revokes its test session; it still
creates persistent reports and should only target a disposable backend.

**Not fixed here:** cryptographic sender impersonation/chosen-key/reflection
issues; audit-log integrity; reporter stored-verifier replay; public-key
distribution trust; complete anonymity or metadata protection; staged attachment
cleanup/ownership beyond existing UUID capabilities; attachment size/padding
limits; broader database/concurrency issues. Restricting which API caller may
submit an investigator-labelled message is not cryptographic proof of authorship.
The existing public seeded decryption identity remains a demonstration fixture.
These limitations belong to the subsequent reviewed milestones.

## Implementation record

Files changed for this milestone (the existing `SEALED_TECHNICAL_REVIEW.md` is
preserved without edits):

| Files | Change |
| --- | --- |
| `investigator_auth.py` | Access-key configuration, one-time challenges, expiring opaque sessions, authorization and CSRF checks |
| `configure_investigator_access.py` | Explicit local access-key provisioning and rotation |
| `routers/investigator_sessions.py` | Challenge, login, session inspection and logout endpoints |
| `routers/investigators.py` | Server authorization for account, case list, threads, replies and resulting status changes |
| `routers/cases.py` | Case-linked upload authorization; forbid assigned attachment reassignment |
| `schemas.py` | Strict authentication request DTOs |
| `main.py` | Authentication router, exact credentialed CORS, no-store investigator responses |
| `frontend/src/lib/investigatorAuth.ts` | Native browser HMAC proof generation |
| `frontend/src/lib/api.ts` | Session-aware API calls, CSRF header, typed HTTP errors |
| `frontend/src/hooks/useInvestigatorSession.ts` | Separate API sign-in/local unlock, cleanup, expiry, logout and stale-operation guards |
| `frontend/src/app/investigator/page.tsx` | Access-key field using existing components/styles, no credential prefills |
| `frontend/src/components/ui.tsx` | Explain access authentication versus local key unlocking |
| `seed.py` | Remove password hint printing, retain existing encrypted fixture unchanged |
| `test_investigator_auth.py`, `test_support.py`, `tests/frontend_crypto.ts` | Negative/happy-path access-control, provisioning, CSRF, session and real frontend crypto regression coverage |
| `test_api.py` | Existing regressions now use actual authentication and isolated storage, without destructive DB reset |
| `e2e.ts` | Adapt existing live caller to explicit authentication credentials and logout |
| `.dockerignore` | Keep local access configuration and scratch secrets out of build context |
| `README.md`, `INVESTIGATOR_ACCESS.md` | Setup, design, limitations, changed files and verification |

Executed during implementation:

- `python -m unittest test_investigator_auth -v`: **18 passed**, including actual
  frontend crypto, rejected anonymous reads/writes, unchanged state after denial,
  wrong credentials, challenge replay/expiry, session expiry/revocation, own-account
  boundaries, CSRF/CORS, file authorization, provisioning/rotation, and fail-closed
  configuration.
- `python test_api.py`: **passed**, using only disposable DB/files.
- Root `npm test`: **passed**, existing standalone PoC lifecycle.
- Updated live `e2e.ts` via the installed `ts-node` CLI: **passed**, against a
  dedicated disposable loopback API with fresh random credentials and encryption
  identity, not the developer database.
- Frontend `npm run lint`, `npx tsc --noEmit`, `npm run build`: **passed**. Build
  emits the existing multiple-lockfile/workspace-root warning.
- Targeted root live caller TypeScript check: **passed** (`npx tsc --noEmit
  --target ES2020 --module commonjs --moduleResolution node --esModuleInterop
  --strict --skipLibCheck e2e.ts`).
- An additional **unscoped root** `npx tsc --noEmit` fails: the existing root
  `tsconfig.json` recursively includes frontend JSX without the Next project's JSX
  and `@/` path settings. The dedicated frontend check and build pass; the root
  configuration was not broadened in this access-control milestone.
- Browser verification with disposable keys/data: wrong local unlock rejected;
  valid API sign-in and local report decryption; encrypted investigator reply;
  workspace lock; public reporter recovery and reply decryption. The visual
  design and report encryption module were not changed.
- `git diff --check`: **passed**. No dependency installation, deployment, commit
  or push was performed.
