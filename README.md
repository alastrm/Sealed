# SEALED — E2EE Anonymous Whistleblower Dropbox

> **Pet project:** End-to-End Encrypted (E2EE) anonymous dropbox with a Zero-Knowledge backend.  
> **Tech stack:** FastAPI (Python 3.12), Next.js 16 (React 19, TypeScript), libsodium (WebAssembly), SQLite / PostgreSQL, Docker Compose.

---

## Motivation

This is a pet project built to explore two engineering concepts in practice:
1. **Client-side WebAssembly cryptography (`libsodium-wrappers-sumo`)**: generating keys, deriving credentials via BIP-39 and BLAKE2b, performing anonymous public-key encryption (Sealed Box) and authenticated X25519 messaging directly in browser memory without exposing private keys to the server.
2. **Zero-Knowledge backend storage**: designing an API where the server acts strictly as an untrusted blind relay. The backend stores ciphertexts, has no access to plaintext reports or user passwords, and cannot decrypt correspondence even in the event of a full database compromise.

---

## How It Works

### 1. Anonymous Access via 12-Word Mnemonic (BIP-39)
- Reporters submit reports without accounts, emails, or passwords.
- The browser generates a **12-word BIP-39 mnemonic** (128 bits of entropy).
- Using `crypto_generichash` (BLAKE2b with domain separation tags), the client deterministically derives:
  - An X25519 keypair (`reporterPrivateKey`, `reporterPublicKey`);
  - A case access token and its 32-byte BLAKE2b hash (`caseAccessTokenHash`).
- The reporter does not need to remember technical database UUIDs. The 12 words serve as the sole credential to look up the case and decrypt responses.

### 2. Anonymous Sealed Box & Traffic Analysis Mitigation
- The browser fetches the investigator's public key (`GET /api/v1/investigators/public-key`).
- The report plaintext is padded to a constant **4 KB** block size (`crypto_pad`) before encryption, masking the true message length against packet-size fingerprinting.
- The padded payload is encrypted using `crypto_box_seal` (ECIES: ephemeral X25519 keypair generated on the fly, with the ephemeral private key immediately wiped after encryption).
- The server receives `{ reporterPublicKey, caseAccessTokenHash, encryptedReport }`. The backend cannot decrypt the payload.

### 3. Zero-Knowledge Investigator Authentication
- The investigator's private key is stored on the server encrypted with `crypto_secretbox_easy`.
- Upon login, the browser downloads the encrypted key blob, salt, and Argon2id parameters (`GET /api/v1/investigators/account`).
- The Key Encryption Key (KEK) is derived client-side via `crypto_pwhash` (Argon2id) to decrypt the private key into tab memory. The master password never leaves the browser.

### 4. Bidirectional Encrypted Dialogue
- Investigator replies are encrypted with `crypto_box_easy` (X25519 ECDH + XSalsa20-Poly1305) targeting the reporter's public key, with 4 KB padding.
- When checking status at `/track`, the reporter enters their 12 words. The browser derives the access token hash and queries `POST /api/v1/cases/lookup`.
- The reporter can post follow-up replies (`POST /api/v1/cases/{case_id}/messages`). The server verifies ownership using constant-time `secrets.compare_digest(caseAccessTokenHash)`.
- Because both parties compute the identical Diffie-Hellman shared secret, both can decrypt the thread while guaranteeing message authenticity via Poly1305 MACs.

### 5. API Rate Limiting
- An in-memory sliding-window rate limiter is applied to sensitive endpoints:
  - `POST /cases`: 10 requests / minute (case submission throttle);
  - `POST /cases/lookup`: 20 requests / minute (token lookup throttle);
  - `GET /account`: 15 requests / minute (credential brute-force throttle).
- Requests exceeding the limit receive HTTP `429 Too Many Requests` with a `Retry-After` header.

---

## Architectural Limitations

Any realistic security assessment of browser-based E2EE must recognize practical threat boundaries:

1. **Web-E2EE Trust-On-First-Use (TOFU)**  
   The browser executes code downloaded from the server on each load. If the hosting infrastructure or CDN is compromised, an adversary could inject malicious JavaScript to exfiltrate mnemonics or plaintexts before encryption. In production environments, mitigations include strict Content Security Policies (CSP), Subresource Integrity (SRI), or distributing the client as a signed browser extension / standalone desktop binary.
2. **Network Layer & IP Metadata**  
   Cryptography protects payload contents, but the HTTP layer exposes client IP addresses to ISPs, routers, and server hosts. For true anonymity, reporters must route traffic through **Tor Browser** or run the application as an Onion service (`.onion`).
3. **Endpoint Security**  
   If the user's device is compromised by malware or keyloggers, encryption cannot protect data that is intercepted during entry or when the mnemonic is displayed on screen.

---

## Project Structure

```
Sealed/
├── backend/ (root directory)
│   ├── main.py              # FastAPI app setup, middleware, CORS
│   ├── models.py            # SQLAlchemy 2.0 models (Investigator, Case, CaseMessage)
│   ├── schemas.py           # Pydantic v2 schemas with camelCase aliasing
│   ├── rate_limiter.py      # Thread-safe in-memory sliding-window rate limiter
│   ├── seed.py              # Test investigator seeder
│   ├── test_api.py          # 10 integration tests covering all flows
│   └── routers/
│       ├── cases.py         # Reporter endpoints: create, lookup, follow-up messages
│       └── investigators.py # Investigator endpoints: keys, case listing, replies
├── frontend/                # Next.js 16 App Router
│   ├── src/
│   │   ├── lib/
│   │   │   ├── crypto.ts    # Libsodium WASM, BIP-39, 4KB padding helpers
│   │   │   ├── api.ts       # Backend REST API client
│   │   │   └── types.ts     # TypeScript DTO interfaces
│   │   └── app/
│   │       ├── page.tsx          # Submission page (client-side encryption)
│   │       ├── track/page.tsx    # Case tracking & dialogue (12-word lookup)
│   │       └── investigator/page.tsx # Investigator dashboard (Argon2id login & thread)
├── poc.ts                   # Standalone TypeScript PoC validating the cryptographic lifecycle
├── docker-compose.yml       # Multi-container setup (backend + frontend)
└── Dockerfile               # Production container for FastAPI backend
```

---

## Quickstart

### Option 1: Docker Compose

```bash
docker compose up --build
```

- **Frontend:** [http://localhost:3000](http://localhost:3000)
- **Backend API:** [http://localhost:8000](http://localhost:8000)
- **Interactive OpenAPI Docs:** [http://localhost:8000/docs](http://localhost:8000/docs)

*The database and a test investigator account are provisioned automatically on startup.*

---

### Option 2: Local Development (Without Docker)

#### Backend (Python 3.10+)

```bash
# Set up virtual environment
python -m venv venv
venv\Scripts\activate   # Linux/macOS: source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Seed the test investigator
python seed.py

# Start API server
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
- **Email:** `compliance.lead@integrity-trust.corp`
- **Password:** `Correct-Horse-Battery-Staple-2026!#`

---

## Running Automated Tests

```bash
# 1. Backend integration tests (10 tests: creation, access control, rate limits, dialogue)
python test_api.py

# 2. Standalone cryptographic lifecycle PoC (pure TypeScript)
npx tsx poc.ts

# 3. Frontend production build and TypeScript type-check
cd frontend && npm run build
```

---

## License

[MIT](LICENSE)
