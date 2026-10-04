/**
 * ============================================================================
 * E2EE Whistleblower System - Standalone Cryptographic Lifecycle PoC
 * ============================================================================
 * 
 * Launch command via Bun:
 *   bun run poc.ts
 * 
 * Launch command via npx ts-node:
 *   npx ts-node poc.ts
 * 
 * Alternative launch via npx tsx:
 *   npx tsx poc.ts
 * ============================================================================
 */

import assert from 'node:assert';
import { randomUUID } from 'node:crypto';
import * as bip39 from 'bip39';
import sodium from 'libsodium-wrappers-sumo';

// ============================================================================
// 1. STRICT TYPES & INTERFACES (DTOs & DATABASE MODELS)
// ============================================================================

/**
 * Native Libsodium X25519 KeyPair representation holding binary Uint8Array keys.
 */
export interface SodiumKeyPair {
  keyType: string;
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

/**
 * Database Model: Stored in the backend database.
 * The server acts as a blind Zero-Knowledge storage:
 * - Public key is visible to enable incoming sealed boxes.
 * - Private key is encrypted client-side using Argon2id-derived KEK.
 * - Raw passwords and plaintext private keys NEVER touch the server.
 */
export interface InvestigatorAccountRecord {
  id: string; // Investigator UUID
  username: string; // Investigator username / corporate email
  publicKey: string; // Base64 (X25519 public key, 32 bytes)
  encryptedPrivateKey: string; // Base64 (crypto_secretbox_easy ciphertext + Poly1305 MAC, 48 bytes)
  privateKeyNonce: string; // Base64 (crypto_secretbox_NONCEBYTES, 24 bytes)
  kdfSalt: string; // Base64 (crypto_pwhash_SALTBYTES, 16 bytes)
  kdfOpsLimit: number; // Argon2id opslimit
  kdfMemLimit: number; // Argon2id memory cost in bytes
  kdfAlgorithm: number; // Argon2id algorithm identifier
  createdAt: string; // ISO 8601 timestamp
}

/**
 * Client-to-Server DTO: Sent by the anonymous reporter when submitting a new case.
 */
export interface CreateCaseDto {
  caseId: string; // Client-generated UUID v4
  reporterPublicKey: string; // Base64 (X25519 public key for investigator's replies)
  caseAccessTokenHash: string; // Base64 (BLAKE2b hash of case_access_token)
  encryptedReport: string; // Base64 (crypto_box_seal anonymous sealed box ciphertext)
}

/**
 * Database Model: Stored in the backend 'cases' table.
 * The server cannot decrypt the report or reverse the access token hash.
 */
export interface CaseRecord {
  id: string; // Case UUID
  caseAccessTokenHash: string; // Base64 (BLAKE2b hash for query verification)
  reporterPublicKey: string; // Base64 (X25519 public key)
  encryptedReport: string; // Base64 (crypto_box_seal ciphertext)
  status: 'OPEN' | 'IN_REVIEW' | 'RESPONDED' | 'CLOSED';
  createdAt: string; // ISO 8601 timestamp
}

/**
 * Client-to-Server DTO: Sent by the investigator to reply to a case.
 */
export interface InvestigatorResponseDto {
  caseId: string; // Case UUID
  encryptedResponse: string; // Base64 (crypto_box_easy authenticated ciphertext)
  nonce: string; // Base64 (crypto_box_NONCEBYTES, 24 bytes)
  investigatorPublicKey: string; // Base64 (X25519 public key of investigator)
}

/**
 * Database Model: Stored in the backend 'case_messages' table.
 */
export interface CaseMessageRecord {
  id: string; // Message UUID
  caseId: string; // Reference to CaseRecord.id
  encryptedResponse: string; // Base64 (crypto_box_easy authenticated ciphertext)
  nonce: string; // Base64 (crypto_box_NONCEBYTES, 24 bytes)
  investigatorPublicKey: string; // Base64 (Investigator's X25519 public key)
  createdAt: string; // ISO 8601 timestamp
}

// ============================================================================
// 2. CRYPTOGRAPHIC UTILITIES & DOMAIN SEPARATION CONSTANTS
// ============================================================================

/**
 * Domain separation tags prevent cross-protocol attacks and ensure
 * that derived cryptographic material remains strictly orthogonal.
 */
const KDF_CONTEXT = {
  MASTER_SEED: 'whistleblower:master_seed:v1',
  REPORTER_KEYPAIR: 'whistleblower:box_keypair:v1',
  CASE_ACCESS_TOKEN: 'whistleblower:case_token:v1',
} as const;

/**
 * Encodes a Uint8Array buffer into standard Base64 string.
 */
function toBase64(bytes: Uint8Array): string {
  return sodium.to_base64(bytes, sodium.base64_variants.ORIGINAL);
}

/**
 * Decodes a standard Base64 string into a Uint8Array buffer.
 */
function fromBase64(base64Str: string): Uint8Array {
  return sodium.from_base64(base64Str, sodium.base64_variants.ORIGINAL);
}

// ============================================================================
// 3. INVESTIGATOR SUBSYSTEM
// ============================================================================

export class InvestigatorService {
  /**
   * Initializes a new investigator account.
   * Generates X25519 keypair and encrypts the private key using Argon2id-derived key.
   */
  static createAccount(username: string, password: string): {
    record: InvestigatorAccountRecord;
    rawKeyPair: SodiumKeyPair;
  } {
    // 1. Generate asymmetric X25519 keypair for investigator
    const keyPair = sodium.crypto_box_keypair('uint8array');

    // 2. Generate cryptographically secure random salt for Argon2id KDF
    const kdfSalt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
    const kdfOpsLimit = sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE;
    const kdfMemLimit = sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE;
    const kdfAlgorithm = sodium.crypto_pwhash_ALG_ARGON2ID13;

    // 3. Derive symmetric key encryption key (KEK) from password via Argon2id
    const kek = sodium.crypto_pwhash(
      sodium.crypto_secretbox_KEYBYTES,
      password,
      kdfSalt,
      kdfOpsLimit,
      kdfMemLimit,
      kdfAlgorithm
    );

    // 4. Encrypt the private key using crypto_secretbox_easy
    const privateKeyNonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
    const encryptedPrivateKey = sodium.crypto_secretbox_easy(
      keyPair.privateKey,
      privateKeyNonce,
      kek,
      'uint8array'
    );

    // 5. Secure memory wipe: clear sensitive plaintext KEK
    sodium.memzero(kek);

    const record: InvestigatorAccountRecord = {
      id: randomUUID(),
      username,
      publicKey: toBase64(keyPair.publicKey),
      encryptedPrivateKey: toBase64(encryptedPrivateKey),
      privateKeyNonce: toBase64(privateKeyNonce),
      kdfSalt: toBase64(kdfSalt),
      kdfOpsLimit,
      kdfMemLimit,
      kdfAlgorithm,
      createdAt: new Date().toISOString(),
    };

    return { record, rawKeyPair: keyPair };
  }

  /**
   * Models the investigator login on the client side:
   * Decrypts the stored encrypted private key using the password.
   */
  static loginAndUnlockPrivateKey(
    record: InvestigatorAccountRecord,
    password: string
  ): Uint8Array {
    const kdfSalt = fromBase64(record.kdfSalt);

    // 1. Re-derive symmetric KEK from password and stored salt
    const kek = sodium.crypto_pwhash(
      sodium.crypto_secretbox_KEYBYTES,
      password,
      kdfSalt,
      record.kdfOpsLimit,
      record.kdfMemLimit,
      record.kdfAlgorithm
    );

    // 2. Decrypt private key blob
    const encryptedPrivateKey = fromBase64(record.encryptedPrivateKey);
    const nonce = fromBase64(record.privateKeyNonce);

    try {
      const decryptedPrivateKey = sodium.crypto_secretbox_open_easy(
        encryptedPrivateKey,
        nonce,
        kek,
        'uint8array'
      );
      return decryptedPrivateKey;
    } catch {
      throw new Error('Authentication failed: Invalid investigator password or corrupted key blob.');
    } finally {
      // Secure memory wipe of derived KEK
      sodium.memzero(kek);
    }
  }

  /**
   * Decrypts an anonymous sealed report using investigator's keypair.
   * Primitives: crypto_box_seal_open (ECIES-style ephemeral-static X25519).
   */
  static decryptAnonymousReport(
    encryptedReportBase64: string,
    investigatorPublicKeyBase64: string,
    investigatorPrivateKey: Uint8Array
  ): string {
    const ciphertext = fromBase64(encryptedReportBase64);
    const publicKey = fromBase64(investigatorPublicKeyBase64);

    const decryptedBytes = sodium.crypto_box_seal_open(
      ciphertext,
      publicKey,
      investigatorPrivateKey,
      'uint8array'
    );

    return sodium.to_string(decryptedBytes);
  }

  /**
   * Encrypts an authenticated response addressed to the reporter.
   * Primitives: crypto_box_easy (X25519-XSalsa20-Poly1305 authenticated encryption).
   */
  static createResponse(
    caseId: string,
    responseText: string,
    reporterPublicKeyBase64: string,
    investigatorPublicKeyBase64: string,
    investigatorPrivateKey: Uint8Array
  ): InvestigatorResponseDto {
    const reporterPublicKey = fromBase64(reporterPublicKeyBase64);
    const nonce = sodium.randombytes_buf(sodium.crypto_box_NONCEBYTES);
    const messageBytes = sodium.from_string(responseText);

    const encryptedResponse = sodium.crypto_box_easy(
      messageBytes,
      nonce,
      reporterPublicKey,
      investigatorPrivateKey,
      'uint8array'
    );

    return {
      caseId,
      encryptedResponse: toBase64(encryptedResponse),
      nonce: toBase64(nonce),
      investigatorPublicKey: investigatorPublicKeyBase64,
    };
  }
}

// ============================================================================
// 4. REPORTER SUBSYSTEM (MNEMONIC & DETERMINISTIC DERIVATION)
// ============================================================================

export interface ReporterSecrets {
  mnemonic: string;
  keyPair: SodiumKeyPair;
  caseAccessToken: Uint8Array;
  caseAccessTokenHash: Uint8Array;
}

export class ReporterService {
  /**
   * Generates a 12-word BIP-39 mnemonic (128 bits entropy).
   */
  static generateMnemonic(): string {
    return bip39.generateMnemonic(128);
  }

  /**
   * Deterministically derives all cryptographic materials from the 12-word mnemonic.
   * Guarantees that the reporter can recover their keypair and case access token anytime.
   * 
   * Derivation Tree:
   *   12-word Mnemonic -> BIP-39 512-bit Seed
   *     -> BLAKE2b (32-byte Master Seed)
   *        |-- BLAKE2b (ctx: box_keypair) -> crypto_box_seed_keypair (X25519 KeyPair)
   *        |-- BLAKE2b (ctx: case_token)  -> case_access_token (32 bytes)
   *             |-- BLAKE2b               -> case_access_token_hash (Sent to server)
   */
  static deriveSecretsFromMnemonic(mnemonic: string): ReporterSecrets {
    if (!bip39.validateMnemonic(mnemonic)) {
      throw new Error('Invalid BIP-39 mnemonic phrase.');
    }

    // 1. Generate 512-bit (64 bytes) BIP-39 seed
    const bip39Seed = bip39.mnemonicToSeedSync(mnemonic);

    // 2. Derive 32-byte master seed with domain separation
    const masterSeed = sodium.crypto_generichash(
      32,
      sodium.from_string(KDF_CONTEXT.MASTER_SEED),
      bip39Seed,
      'uint8array'
    );

    // 3. Derive 32-byte seed for X25519 Box Keypair
    const keypairSeed = sodium.crypto_generichash(
      sodium.crypto_box_SEEDBYTES,
      sodium.from_string(KDF_CONTEXT.REPORTER_KEYPAIR),
      masterSeed,
      'uint8array'
    );
    const keyPair = sodium.crypto_box_seed_keypair(keypairSeed, 'uint8array');

    // 4. Derive 32-byte case_access_token (kept private on client)
    const caseAccessToken = sodium.crypto_generichash(
      32,
      sodium.from_string(KDF_CONTEXT.CASE_ACCESS_TOKEN),
      masterSeed,
      'uint8array'
    );

    // 5. Derive preimage-resistant hash for server verification (stored in DB)
    const caseAccessTokenHash = sodium.crypto_generichash(
      32,
      caseAccessToken,
      null,
      'uint8array'
    );

    // 6. Secure memory wipe of intermediate seed material
    sodium.memzero(masterSeed);
    sodium.memzero(keypairSeed);

    return {
      mnemonic,
      keyPair,
      caseAccessToken,
      caseAccessTokenHash,
    };
  }

  /**
   * Creates and anonymously encrypts a whistleblower case report using investigator's public key.
   * Primitives: crypto_box_seal (Anonymous Sealed Box: sender generates ephemeral keypair).
   */
  static createCase(
    reportText: string,
    investigatorPublicKeyBase64: string,
    reporterSecrets: ReporterSecrets
  ): CreateCaseDto {
    const investigatorPublicKey = fromBase64(investigatorPublicKeyBase64);
    const messageBytes = sodium.from_string(reportText);

    // Anonymous encryption: ephemeral X25519 keypair is generated and discarded by libsodium
    const encryptedReport = sodium.crypto_box_seal(
      messageBytes,
      investigatorPublicKey,
      'uint8array'
    );

    return {
      caseId: randomUUID(),
      reporterPublicKey: toBase64(reporterSecrets.keyPair.publicKey),
      caseAccessTokenHash: toBase64(reporterSecrets.caseAccessTokenHash),
      encryptedReport: toBase64(encryptedReport),
    };
  }

  /**
   * Decrypts an authenticated response received from the investigator.
   * Primitives: crypto_box_open_easy (Verifies investigator identity via Poly1305 MAC).
   */
  static decryptResponse(
    messageRecord: CaseMessageRecord,
    reporterPrivateKey: Uint8Array
  ): string {
    const ciphertext = fromBase64(messageRecord.encryptedResponse);
    const nonce = fromBase64(messageRecord.nonce);
    const investigatorPublicKey = fromBase64(messageRecord.investigatorPublicKey);

    const decryptedBytes = sodium.crypto_box_open_easy(
      ciphertext,
      nonce,
      investigatorPublicKey,
      reporterPrivateKey,
      'uint8array'
    );

    return sodium.to_string(decryptedBytes);
  }
}

// ============================================================================
// 5. IN-MEMORY ZERO-KNOWLEDGE BACKEND SIMULATOR
// ============================================================================

/**
 * Simulates a blind Zero-Knowledge server.
 * Holds ciphertexts and hashes. Performs access control verification without seeing secrets.
 */
export class ZeroKnowledgeBackendMock {
  private investigators = new Map<string, InvestigatorAccountRecord>();
  private cases = new Map<string, CaseRecord>();
  private messages = new Map<string, CaseMessageRecord[]>();

  saveInvestigator(record: InvestigatorAccountRecord): void {
    this.investigators.set(record.id, record);
  }

  getInvestigator(id: string): InvestigatorAccountRecord | undefined {
    return this.investigators.get(id);
  }

  createCase(dto: CreateCaseDto): CaseRecord {
    const caseRecord: CaseRecord = {
      id: dto.caseId,
      caseAccessTokenHash: dto.caseAccessTokenHash,
      reporterPublicKey: dto.reporterPublicKey,
      encryptedReport: dto.encryptedReport,
      status: 'OPEN',
      createdAt: new Date().toISOString(),
    };
    this.cases.set(caseRecord.id, caseRecord);
    this.messages.set(caseRecord.id, []);
    return caseRecord;
  }

  getCaseForInvestigator(caseId: string): CaseRecord {
    const record = this.cases.get(caseId);
    if (!record) {
      throw new Error(`Case with ID ${caseId} not found.`);
    }
    return record;
  }

  saveInvestigatorResponse(dto: InvestigatorResponseDto): CaseMessageRecord {
    const caseRecord = this.cases.get(dto.caseId);
    if (!caseRecord) {
      throw new Error(`Case with ID ${dto.caseId} not found.`);
    }

    const messageRecord: CaseMessageRecord = {
      id: randomUUID(),
      caseId: dto.caseId,
      encryptedResponse: dto.encryptedResponse,
      nonce: dto.nonce,
      investigatorPublicKey: dto.investigatorPublicKey,
      createdAt: new Date().toISOString(),
    };

    caseRecord.status = 'RESPONDED';
    const list = this.messages.get(dto.caseId) ?? [];
    list.push(messageRecord);
    this.messages.set(dto.caseId, list);

    return messageRecord;
  }

  /**
   * Authenticated case lookup for the reporter.
   * The reporter presents their derived caseAccessTokenHash.
   * Backend strictly checks that the hash matches the database record.
   */
  getCaseMessagesForReporter(
    caseId: string,
    providedAccessTokenHashBase64: string
  ): { caseRecord: CaseRecord; messages: CaseMessageRecord[] } {
    const caseRecord = this.cases.get(caseId);
    if (!caseRecord) {
      throw new Error(`Case with ID ${caseId} not found.`);
    }

    // Zero-Knowledge authentication check via constant-time comparison
    const providedHash = fromBase64(providedAccessTokenHashBase64);
    const storedHash = fromBase64(caseRecord.caseAccessTokenHash);

    if (!sodium.memcmp(providedHash, storedHash)) {
      throw new Error('Access Denied: Invalid case access token hash.');
    }

    const msgs = this.messages.get(caseId) ?? [];
    return { caseRecord, messages: msgs };
  }
}

// ============================================================================
// 6. MAIN SIMULATION & VALIDATION RUNNER
// ============================================================================

async function main(): Promise<void> {
  // CRITICAL REQUIREMENT 1: Wait for libsodium WASM/crypto initialization
  await sodium.ready;
  console.log('✔ Libsodium initialized successfully (WASM/ASM ready).\n');

  const backend = new ZeroKnowledgeBackendMock();

  console.log('================================================================');
  console.log('STAGE 1: INVESTIGATOR INITIALIZATION & LOGIN');
  console.log('================================================================');
  const investigatorPassword = 'Correct-Horse-Battery-Staple-2026!#';
  const username = 'compliance.lead@integrity-trust.corp';

  // 1.1 Investigator registers account
  const { record: investigatorDbRecord, rawKeyPair: originalInvestigatorKeyPair } =
    InvestigatorService.createAccount(username, investigatorPassword);
  backend.saveInvestigator(investigatorDbRecord);
  console.log('✔ Investigator account created and stored in DB.');
  console.log(`  Investigator ID: ${investigatorDbRecord.id}`);
  console.log(`  Investigator Public Key (Base64): ${investigatorDbRecord.publicKey}`);
  console.log(`  Encrypted Private Key Blob (Base64): ${investigatorDbRecord.encryptedPrivateKey.slice(0, 32)}...`);

  // 1.2 Investigator logs in: unlocks private key using password
  const unlockedInvestigatorPrivateKey = InvestigatorService.loginAndUnlockPrivateKey(
    investigatorDbRecord,
    investigatorPassword
  );

  // Assertion: verify that decrypted private key is identical to the original private key
  assert.strictEqual(
    sodium.memcmp(unlockedInvestigatorPrivateKey, originalInvestigatorKeyPair.privateKey),
    true,
    'Investigator decrypted private key does not match original!'
  );
  console.log('✔ Investigator login successful: Private key decrypted and cryptographically verified.\n');

  console.log('================================================================');
  console.log('STAGE 2: REPORTER ANONYMOUS SUBMISSION FLOW');
  console.log('================================================================');
  // 2.1 Generate 12 words BIP-39 mnemonic
  const reporterMnemonic = ReporterService.generateMnemonic();
  const wordCount = reporterMnemonic.trim().split(/\s+/).length;
  assert.strictEqual(wordCount, 12, 'Mnemonic must contain exactly 12 words');
  console.log(`✔ Generated BIP-39 Mnemonic (12 words): "${reporterMnemonic}"`);

  // 2.2 Deterministically derive keypair, case token, and token hash
  const reporterSecrets = ReporterService.deriveSecretsFromMnemonic(reporterMnemonic);
  console.log('✔ Deterministic cryptographic derivation completed:');
  console.log(`  Reporter Public Key (Base64): ${toBase64(reporterSecrets.keyPair.publicKey)}`);
  console.log(`  Case Access Token Hash (Base64): ${toBase64(reporterSecrets.caseAccessTokenHash)}`);

  // 2.3 Compose confidential report and encrypt via crypto_box_seal (Anonymous Sealed Box)
  const originalReportContent =
    'URGENT COMPLIANCE REPORT: Discovered systemic kickbacks in European logistics contract #982-A. ' +
    'Bribes channeled through offshore entity "Vanguard Holdings Ltd". Financial records attached to offline drop.';

  const createCaseDto = ReporterService.createCase(
    originalReportContent,
    investigatorDbRecord.publicKey,
    reporterSecrets
  );

  // 2.4 Server receives CreateCaseDto and stores CaseRecord
  const storedCaseRecord = backend.createCase(createCaseDto);
  console.log('✔ Case submitted to Zero-Knowledge backend:');
  console.log(`  Case ID: ${storedCaseRecord.id}`);
  console.log(`  Encrypted Sealed Report (Base64): ${storedCaseRecord.encryptedReport.slice(0, 48)}...\n`);

  console.log('================================================================');
  console.log('STAGE 3: INVESTIGATOR REVIEW & AUTHENTICATED RESPONSE');
  console.log('================================================================');
  // 3.1 Investigator retrieves case from blind backend
  const investigatorFetchedCase = backend.getCaseForInvestigator(storedCaseRecord.id);

  // 3.2 Decrypt anonymous sealed report with investigator's private key
  const investigatorDecryptedReport = InvestigatorService.decryptAnonymousReport(
    investigatorFetchedCase.encryptedReport,
    investigatorDbRecord.publicKey,
    unlockedInvestigatorPrivateKey
  );

  // Assertion: verify decrypted report matches original plaintext
  assert.strictEqual(
    investigatorDecryptedReport,
    originalReportContent,
    'Decrypted report text mismatch!'
  );
  console.log('✔ Investigator successfully decrypted anonymous sealed report:');
  console.log(`  Decrypted Text: "${investigatorDecryptedReport}"`);

  // 3.3 Investigator drafts and encrypts response using crypto_box_easy
  const originalResponseContent =
    'OFFICIAL INVESTIGATION RESPONSE: Case #982-A has been escalated to Forensic Accounting. ' +
    'Your anonymity is protected. Please preserve any transaction hashes and check back in 72 hours for instructions.';

  const investigatorResponseDto = InvestigatorService.createResponse(
    investigatorFetchedCase.id,
    originalResponseContent,
    investigatorFetchedCase.reporterPublicKey,
    investigatorDbRecord.publicKey,
    unlockedInvestigatorPrivateKey
  );

  // 3.4 Save response to backend
  const storedMessageRecord = backend.saveInvestigatorResponse(investigatorResponseDto);
  console.log('✔ Investigator response encrypted with nonce and saved to backend:');
  console.log(`  Response Message ID: ${storedMessageRecord.id}`);
  console.log(`  Nonce (Base64): ${storedMessageRecord.nonce}`);
  console.log(`  Encrypted Response (Base64): ${storedMessageRecord.encryptedResponse.slice(0, 48)}...\n`);

  console.log('================================================================');
  console.log('STAGE 4: REPORTER RETURN, DERIVATION VERIFICATION & DECRYPTION');
  console.log('================================================================');
  // 4.1 Reporter re-enters the 12-word mnemonic on a new/clean client session
  const enteredMnemonic = reporterMnemonic; // Same 12 words re-entered
  console.log(`✔ Reporter enters mnemonic: "${enteredMnemonic}"`);

  // 4.2 Deterministic re-derivation
  const rederivedSecrets = ReporterService.deriveSecretsFromMnemonic(enteredMnemonic);

  // 4.3 Cryptographic Assertions: Ensure 100% deterministic reproducibility
  assert.strictEqual(
    toBase64(rederivedSecrets.keyPair.publicKey),
    toBase64(reporterSecrets.keyPair.publicKey),
    'Assertion Failed: Re-derived Reporter Public Key does not match!'
  );
  assert.strictEqual(
    toBase64(rederivedSecrets.keyPair.privateKey),
    toBase64(reporterSecrets.keyPair.privateKey),
    'Assertion Failed: Re-derived Reporter Private Key does not match!'
  );
  assert.strictEqual(
    toBase64(rederivedSecrets.caseAccessToken),
    toBase64(reporterSecrets.caseAccessToken),
    'Assertion Failed: Re-derived Case Access Token does not match!'
  );
  assert.strictEqual(
    toBase64(rederivedSecrets.caseAccessTokenHash),
    toBase64(reporterSecrets.caseAccessTokenHash),
    'Assertion Failed: Re-derived Case Access Token Hash does not match!'
  );
  console.log('✔ All cryptographic assertions PASSED: Keys and tokens re-derived with 100% fidelity.');

  // 4.4 Query backend with re-derived access token hash
  const queryResult = backend.getCaseMessagesForReporter(
    storedCaseRecord.id,
    toBase64(rederivedSecrets.caseAccessTokenHash)
  );
  console.log(`✔ Backend authenticated reporter and returned ${queryResult.messages.length} message(s).`);

  // 4.5 Reporter decrypts the investigator's message using crypto_box_open_easy
  const reporterDecryptedResponse = ReporterService.decryptResponse(
    queryResult.messages[0],
    rederivedSecrets.keyPair.privateKey
  );

  // Assertion: verify decrypted response matches original response
  assert.strictEqual(
    reporterDecryptedResponse,
    originalResponseContent,
    'Decrypted investigator response does not match original!'
  );
  console.log('✔ Reporter successfully decrypted authenticated investigator response:');
  console.log(`  Decrypted Text: "${reporterDecryptedResponse}"\n`);

  // 4.6 Secure Memory Cleanup
  sodium.memzero(unlockedInvestigatorPrivateKey);
  sodium.memzero(rederivedSecrets.keyPair.privateKey);
  sodium.memzero(reporterSecrets.keyPair.privateKey);
  sodium.memzero(originalInvestigatorKeyPair.privateKey);

  console.log('================================================================');
  console.log('STAGE 5: FINAL OUTPUTS & DATABASE DUMPS (REQUIREMENT 4)');
  console.log('================================================================');
  console.log('\n--- [FINAL DECRYPTED STRINGS] ---');
  console.log('1. Decrypted Anonymous Whistleblower Report (by Investigator):');
  console.log(`   "${investigatorDecryptedReport}"`);
  console.log('\n2. Decrypted Authenticated Response (by Reporter):');
  console.log(`   "${reporterDecryptedResponse}"`);

  console.log('\n--- [BACKEND API REQUEST DTO: CREATE CASE (CreateCaseDto)] ---');
  console.log(JSON.stringify(createCaseDto, null, 2));

  console.log('\n--- [BACKEND DB RECORD: CASE (CaseRecord)] ---');
  console.log(JSON.stringify(storedCaseRecord, null, 2));

  console.log('\n--- [BACKEND API REQUEST DTO: INVESTIGATOR RESPONSE (InvestigatorResponseDto)] ---');
  console.log(JSON.stringify(investigatorResponseDto, null, 2));

  console.log('\n--- [BACKEND DB RECORD: CASE MESSAGE (CaseMessageRecord)] ---');
  console.log(JSON.stringify(storedMessageRecord, null, 2));

  console.log('\n--- [BACKEND DB RECORD: INVESTIGATOR ACCOUNT (InvestigatorAccountRecord)] ---');
  console.log(JSON.stringify(investigatorDbRecord, null, 2));

  console.log('\n================================================================');
  console.log('✔ FULL CRYPTOGRAPHIC LIFECYCLE MODEL COMPLETED SUCCESSFULLY!');
  console.log('================================================================');
}

// Execute simulation
main().catch((err) => {
  console.error('Cryptographic Lifecycle Error:', err);
  process.exit(1);
});
