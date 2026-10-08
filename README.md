# SEALED

A pet project demonstrating client-side WebAssembly cryptography with an untrusted, blind backend.

- **Backend:** FastAPI (Python 3.12), SQLite / PostgreSQL, SlowAPI rate limiting
- **Frontend:** Next.js 16 (React 19, TypeScript), Tailwind CSS, IBM Plex Sans / Mono
- **Cryptography:** libsodium (`libsodium-wrappers-sumo` via WebAssembly), BIP-39

---

## Overview

SEALED is an anonymous drop prototype. The client encrypts all data in browser memory before transmission. The server acts solely as a blind relay: it stores ciphertexts, validates blinded access tokens, and cannot decrypt messages or inspect file metadata.

1. **Anonymous Credentials:** The reporter receives a 12-word BIP-39 mnemonic. The client derives an X25519 keypair and a blinded access token hash using BLAKE2b with domain separation tags. No accounts, emails, or technical UUIDs are required from the reporter.
2. **Anonymous Sealed Box:** The initial report is padded to a fixed 4 KB block size and encrypted with `crypto_box_seal` using the investigator's public key. The ephemeral keypair used during encryption is destroyed immediately afterward.
3. **Bidirectional Dialogue:** Follow-up messages are exchanged using authenticated asymmetric encryption (`crypto_box_easy`), with constant 4 KB padding on each message.
4. **Blind Attachments:** Files up to 10 MB are padded to discrete bucket boundaries (256 KB, 1 MB, 5 MB, 10 MB) and encrypted with a fresh symmetric key (`crypto_secretbox_easy`). The server stores raw ciphertext blobs without knowing filenames, MIME types, or keys. File metadata is sealed inside the encrypted message payload.
5. **Tamper-Evident Audit Chain:** Mutations (case creation, messages, attachments, status changes) are recorded in an append-only BLAKE2b hash chain:
   $$\text{hash}_n = \text{BLAKE2b}(\text{hash}_{n-1} \mathbin{\Vert} \text{event\_type} \mathbin{\Vert} \text{payload\_hash} \mathbin{\Vert} \text{timestamp})$$
   Any retroactive database edit breaks chain continuity, which the client verifies against the genesis hash.
6. **Investigator Key Storage:** The investigator's private key is stored on the server encrypted with Argon2id + XChaCha20-Poly1305. The master password never leaves the browser; decryption happens locally in tab memory.

---

## Threat Model & Security Analysis

This section outlines the security guarantees and explicit limitations of the architecture.

### What Is Protected (In-Scope Defenses)

- **Compromised Database / Storage Dump:**  
  If the database or server disk is seized or leaked, an attacker gains no access to report plaintexts, message history, file attachments, or attachment metadata (filenames, extensions, MIME types). All sensitive payloads are stored as ciphertexts.
- **Credential Storage:**  
  The server stores only `case_access_token_hash` (a BLAKE2b digest of the client-derived token). The server cannot reverse this hash to recover the reporter's 12-word mnemonic or private key.
- **Traffic Analysis by Message Size:**  
  Messages are padded to a uniform 4 KB boundary, and attachments are padded to discrete buckets (256 KB, 1 MB, 5 MB, 10 MB). A passive network eavesdropper cannot infer the exact length of messages or files by inspecting packet sizes.
- **Database Record Tampering:**  
  If an administrator or attacker modifies past messages or status fields directly in the database, the cryptographic BLAKE2b hash chain breaks, allowing both reporter and investigator clients to detect the tampering.
- **In-Memory Key Wiping:**  
  Sensitive cryptographic keys and intermediate buffers in WebAssembly memory are zeroed out via `sodium.memzero` within `finally` blocks upon completion or failure.

### What Is NOT Protected (Critical Limitations)

Any realistic evaluation of browser-based end-to-end encryption must acknowledge its fundamental boundaries:

1. **The JavaScript Delivery Problem (Primary Weakness of Web-Crypto):**  
   The browser fetches application JavaScript from the server on each load. If the server, hosting provider, or CDN is compromised, an attacker can serve a malicious version of the JavaScript bundle that exfiltrates mnemonics or plaintexts before encryption occurs.  
   *Production whistleblowing tools (e.g., SecureDrop) avoid browser-delivered code entirely, relying on Tor Onion services, strict sandbox environments, or signed native binaries.*
2. **Network Metadata and IP Correlation:**  
   While application-level logs strip client IP addresses, the transport and network layers (TCP/IP, reverse proxies, ISPs, cloud providers) still observe incoming connections. An observer monitoring network traffic can correlate the timing and volume of requests between a reporter and an investigator.  
   *Without routing traffic through Tor Browser or a multi-hop VPN, network anonymity is not guaranteed.*
3. **Public Key Distribution (Trust On First Use):**  
   The client fetches the investigator's public key over HTTP/TLS (`GET /api/v1/investigators/public-key`). A compromised or malicious server could substitute this with an attacker's public key, enabling a man-in-the-middle attack on initial submissions. There is currently no out-of-band fingerprint verification mechanism.
4. **Browser Runtime and Garbage Collection:**  
   While WebAssembly buffers are zeroed using `sodium.memzero`, JavaScript strings (such as text entered in HTML form fields or stored in React state) are immutable and managed by the V8 garbage collector. They may persist in process memory until garbage collection runs, leaving them vulnerable to local memory inspection or rogue browser extensions.
5. **Endpoint Security:**  
   If the reporter's machine has malware, a keylogger, or malicious browser extensions installed, data can be captured prior to encryption or when the 12-word mnemonic is displayed on screen.

---

## Cryptographic Primitives

| Purpose | Algorithm / Primitive | Library |
| :--- | :--- | :--- |
| Initial Report Encryption | `crypto_box_seal` (X25519, XSalsa20-Poly1305, ephemeral key) | libsodium |
| Bidirectional Messages | `crypto_box_easy` (X25519 ECDH, XSalsa20-Poly1305) | libsodium |
| File Attachment Encryption | `crypto_secretbox_easy` (XChaCha20-Poly1305, 32-byte key) | libsodium |
| Mnemonic Generation | BIP-39 (128 bits entropy $\rightarrow$ 12 English words) | `@scure/bip39` |
| Key & Token Derivation | BLAKE2b (`crypto_generichash` with domain tags) | libsodium |
| Investigator Key KDF | Argon2id (`crypto_pwhash`, ops=2, mem=64MB) | libsodium |
| Audit Hash Chain | BLAKE2b (`crypto_generichash`) | libsodium / Python `hashlib` |
| Length Padding | `crypto_pad` / `crypto_unpad` (PKCS#7 equivalent) | libsodium |

---

## Project Structure

```
Sealed/
├── backend/ (root directory)
│   ├── main.py              # FastAPI app, middleware, CORS
│   ├── models.py            # SQLAlchemy 2.0 models (Investigator, Case, Message, Attachment, AuditLog)
│   ├── schemas.py           # Pydantic v2 schemas
│   ├── audit_service.py     # BLAKE2b audit hash chain implementation
│   ├── rate_limiter.py      # SlowAPI rate limiting (5 req/min create, 15 req/min lookup)
│   ├── logging_config.py    # IP stripping filter for stdout/stderr logs
│   ├── seed.py              # Test database seeder
│   ├── test_api.py          # Backend integration test suite (18 tests)
│   └── routers/
│       ├── cases.py         # Submission, lookup, attachments, audit endpoints
│       └── investigators.py # Key exchange, cases listing, replies
├── frontend/                # Next.js 16 App Router
│   ├── src/
│   │   ├── lib/
│   │   │   ├── crypto.ts    # libsodium WASM, BIP-39, bucket padding, KDF
│   │   │   ├── api.ts       # Backend API client
│   │   │   └── types.ts     # DTO types
│   │   ├── components/
│   │   │   ├── ParticlesBackground.tsx # Canvas background
│   │   │   ├── Navbar.tsx              # Minimal navigation
│   │   │   ├── AuditBadge.tsx          # BLAKE2b audit chain status
│   │   │   ├── AttachmentList.tsx      # In-memory decryption & download
│   │   │   └── AttachmentPicker.tsx    # Evidence upload picker
│   │   └── app/
│   │       ├── layout.tsx              # IBM Plex Sans / Mono fonts, root shell
│   │       ├── page.tsx                # Report submission & 12-word mnemonic screen
│   │       ├── track/page.tsx          # Case tracking & message thread
│   │       └── investigator/page.tsx   # Investigator login & dashboard
├── docker-compose.yml       # Docker Compose configuration
└── Dockerfile               # Backend container
```

---

## Quickstart

### Docker Compose

```bash
docker compose up --build
```

- **Frontend:** `http://localhost:3000`
- **Backend API:** `http://localhost:8000`
- **Swagger Docs:** `http://localhost:8000/docs`

---

### Local Setup

#### Backend (Python 3.10+)

```bash
# Create and activate virtual environment
python -m venv venv
venv\Scripts\activate   # Linux/macOS: source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Seed test database
python seed.py

# Run API server
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

#### Frontend (Node.js 18+)

```bash
cd frontend
npm install
npm run dev
```

---

## Test Credentials

For testing the investigator portal (`/investigator`):

- **Username:** `investigator@sealed.org` (or `compliance.lead@integrity-trust.corp`)
- **Password:** `Password123!` (or `Correct-Horse-Battery-Staple-2026!#`)

---

## Running Automated Tests

```bash
# 1. Backend integration tests (18 tests covering crypto, rate limits, attachments, audit chain)
python test_api.py

# 2. Frontend build and TypeScript validation
cd frontend && npm run build
```

---

## License

MIT
