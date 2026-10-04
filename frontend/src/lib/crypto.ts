/**
 * Client-Side Cryptographic Engine for E2EE Whistleblower System.
 * 
 * Cryptographic Primitives:
 * - Mnemonic generation: BIP-39 (128 bits entropy -> 12 words)
 * - Seed & Key Derivation: BLAKE2b (crypto_generichash) with domain separation tags
 * - Reporter Keypair: X25519 (crypto_box_seed_keypair)
 * - Anonymous Report Encryption: ECIES Sealed Box (crypto_box_seal)
 * - Authenticated Response: X25519 + XSalsa20 + Poly1305 MAC (crypto_box_easy / crypto_box_open_easy)
 * - Investigator Key Derivation: Argon2id (crypto_pwhash) + XSalsa20-Poly1305 (crypto_secretbox_easy)
 */

import { Buffer } from 'buffer';
import * as bip39 from 'bip39';
import type sodiumType from 'libsodium-wrappers-sumo';
import type { InvestigatorAccountRecord } from './types';

// Ensure Buffer is present in client browser environment
if (typeof window !== 'undefined') {
  (window as unknown as { Buffer: typeof Buffer }).Buffer =
    (window as unknown as { Buffer: typeof Buffer }).Buffer || Buffer;
}

const KDF_CONTEXT = {
  MASTER_SEED: 'whistleblower:master_seed:v1',
  REPORTER_KEYPAIR: 'whistleblower:box_keypair:v1',
  CASE_ACCESS_TOKEN: 'whistleblower:case_token:v1',
} as const;

export interface ReporterSecrets {
  mnemonic: string;
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  publicKeyBase64: string;
  caseAccessToken: Uint8Array;
  caseAccessTokenHash: Uint8Array;
  caseAccessTokenHashBase64: string;
}

// Global cached sodium instance
let sodium: typeof sodiumType | null = null;

/**
 * Initializes and awaits libsodium WASM. Safe to call multiple times.
 */
export async function initCrypto(): Promise<typeof sodiumType> {
  if (sodium) return sodium;

  const libsodium = await import('libsodium-wrappers-sumo').then((m) => m.default || m);
  await libsodium.ready;
  sodium = libsodium;
  return sodium;
}

/**
 * Helper to encode Uint8Array to standard Base64 string.
 */
export function toBase64(bytes: Uint8Array): string {
  if (!sodium) throw new Error('Crypto not initialized. Call initCrypto() first.');
  return sodium.to_base64(bytes, sodium.base64_variants.ORIGINAL);
}

/**
 * Helper to decode standard Base64 string to Uint8Array.
 */
export function fromBase64(base64Str: string): Uint8Array {
  if (!sodium) throw new Error('Crypto not initialized. Call initCrypto() first.');
  return sodium.from_base64(base64Str, sodium.base64_variants.ORIGINAL);
}

/**
 * Deterministically derives X25519 keypair and case access tokens from 12-word mnemonic.
 */
export async function deriveReporterSecrets(mnemonic: string): Promise<ReporterSecrets> {
  const s = await initCrypto();

  const cleanMnemonic = mnemonic.trim().toLowerCase();
  if (!bip39.validateMnemonic(cleanMnemonic)) {
    throw new Error('Invalid 12-word BIP-39 mnemonic phrase.');
  }

  // 1. Generate 512-bit BIP-39 seed
  const bip39Seed = bip39.mnemonicToSeedSync(cleanMnemonic);

  // 2. Derive 32-byte master seed with domain separation
  const masterSeed = s.crypto_generichash(
    32,
    s.from_string(KDF_CONTEXT.MASTER_SEED),
    bip39Seed,
    'uint8array'
  );

  // 3. Derive 32-byte seed for X25519 Box Keypair
  const keypairSeed = s.crypto_generichash(
    s.crypto_box_SEEDBYTES,
    s.from_string(KDF_CONTEXT.REPORTER_KEYPAIR),
    masterSeed,
    'uint8array'
  );
  const keyPair = s.crypto_box_seed_keypair(keypairSeed, 'uint8array');

  // 4. Derive 32-byte case_access_token (kept on client)
  const caseAccessToken = s.crypto_generichash(
    32,
    s.from_string(KDF_CONTEXT.CASE_ACCESS_TOKEN),
    masterSeed,
    'uint8array'
  );

  // 5. Derive preimage-resistant hash for server verification (stored in DB)
  const caseAccessTokenHash = s.crypto_generichash(
    32,
    caseAccessToken,
    null,
    'uint8array'
  );

  // Secure memory wipe of intermediate seed material
  s.memzero(masterSeed);
  s.memzero(keypairSeed);

  return {
    mnemonic: cleanMnemonic,
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
    publicKeyBase64: s.to_base64(keyPair.publicKey, s.base64_variants.ORIGINAL),
    caseAccessToken,
    caseAccessTokenHash,
    caseAccessTokenHashBase64: s.to_base64(caseAccessTokenHash, s.base64_variants.ORIGINAL),
  };
}

/**
 * Generates a fresh 12-word mnemonic and derives the initial reporter secrets bundle.
 */
export async function generateReporterBundle(): Promise<{
  mnemonic: string;
  secrets: ReporterSecrets;
}> {
  await initCrypto();
  const mnemonic = bip39.generateMnemonic(128);
  const secrets = await deriveReporterSecrets(mnemonic);
  return { mnemonic, secrets };
}

export const CONSTANT_BLOCK_SIZE = 4096; // 4 KB constant padding against traffic analysis

/**
 * Safely removes Libsodium padding, falling back to raw bytes if unpadded.
 */
export function safeUnpad(
  s: typeof sodiumType,
  bytes: Uint8Array,
  blockSize: number = CONSTANT_BLOCK_SIZE
): Uint8Array {
  try {
    return s.unpad(bytes, blockSize);
  } catch {
    return bytes;
  }
}

/**
 * Anonymously encrypts a whistleblower report using the investigator's public key.
 * Uses crypto_box_seal with 4KB padding: generates an ephemeral keypair on the fly, discards the private key.
 */
export async function encryptReport(
  text: string,
  investigatorPubKeyBase64: string
): Promise<string> {
  const s = await initCrypto();
  const investigatorPubKey = s.from_base64(
    investigatorPubKeyBase64,
    s.base64_variants.ORIGINAL
  );
  const messageBytes = s.from_string(text);
  const paddedBytes = s.pad(messageBytes, CONSTANT_BLOCK_SIZE);

  const sealedBytes = s.crypto_box_seal(paddedBytes, investigatorPubKey, 'uint8array');
  return s.to_base64(sealedBytes, s.base64_variants.ORIGINAL);
}

/**
 * Decrypts an authenticated investigator reply using reporter's private key.
 * Verifies authenticity and integrity via Poly1305 MAC, then strips 4KB padding.
 */
export async function decryptInvestigatorResponse(
  record: {
    encryptedResponse: string;
    nonce: string;
    investigatorPublicKey: string;
  },
  reporterPrivKey: Uint8Array
): Promise<string> {
  const s = await initCrypto();

  const ciphertext = s.from_base64(record.encryptedResponse, s.base64_variants.ORIGINAL);
  const nonce = s.from_base64(record.nonce, s.base64_variants.ORIGINAL);
  const investigatorPubKey = s.from_base64(
    record.investigatorPublicKey,
    s.base64_variants.ORIGINAL
  );

  const decryptedBytes = s.crypto_box_open_easy(
    ciphertext,
    nonce,
    investigatorPubKey,
    reporterPrivKey,
    'uint8array'
  );

  const unpadded = safeUnpad(s, decryptedBytes, CONSTANT_BLOCK_SIZE);
  return s.to_string(unpadded);
}

/**
 * Unlocks the investigator's private key using password and stored Argon2id parameters.
 */
export async function unlockInvestigatorKey(
  accountRecord: InvestigatorAccountRecord,
  password: string
): Promise<Uint8Array> {
  const s = await initCrypto();
  const kdfSalt = s.from_base64(accountRecord.kdfSalt, s.base64_variants.ORIGINAL);

  // Derive symmetric Key Encryption Key (KEK) via Argon2id
  const kek = s.crypto_pwhash(
    s.crypto_secretbox_KEYBYTES,
    password,
    kdfSalt,
    accountRecord.kdfOpsLimit,
    accountRecord.kdfMemLimit,
    accountRecord.kdfAlgorithm,
    'uint8array'
  );

  const encryptedPrivateKey = s.from_base64(
    accountRecord.encryptedPrivateKey,
    s.base64_variants.ORIGINAL
  );
  const nonce = s.from_base64(accountRecord.privateKeyNonce, s.base64_variants.ORIGINAL);

  try {
    const decryptedPrivateKey = s.crypto_secretbox_open_easy(
      encryptedPrivateKey,
      nonce,
      kek,
      'uint8array'
    );
    return decryptedPrivateKey;
  } catch {
    throw new Error('Invalid investigator password or corrupted key blob.');
  } finally {
    s.memzero(kek);
  }
}

/**
 * Decrypts an anonymous sealed report for the investigator and strips 4KB padding.
 */
export async function decryptReport(
  encryptedReportBase64: string,
  investigatorPubKeyBase64: string,
  investigatorPrivateKey: Uint8Array
): Promise<string> {
  const s = await initCrypto();
  const ciphertext = s.from_base64(encryptedReportBase64, s.base64_variants.ORIGINAL);
  const publicKey = s.from_base64(investigatorPubKeyBase64, s.base64_variants.ORIGINAL);

  const decryptedBytes = s.crypto_box_seal_open(
    ciphertext,
    publicKey,
    investigatorPrivateKey,
    'uint8array'
  );

  const unpadded = safeUnpad(s, decryptedBytes, CONSTANT_BLOCK_SIZE);
  return s.to_string(unpadded);
}

/**
 * Encrypts an investigator response to a reporter.
 * Applies 4KB padding and uses crypto_box_easy with a fresh 24-byte CSPRNG nonce.
 */
export async function encryptInvestigatorReply(
  text: string,
  reporterPubKeyBase64: string,
  investigatorPrivKey: Uint8Array
): Promise<{ encryptedResponse: string; nonce: string }> {
  const s = await initCrypto();
  const reporterPubKey = s.from_base64(
    reporterPubKeyBase64,
    s.base64_variants.ORIGINAL
  );
  const nonce = s.randombytes_buf(s.crypto_box_NONCEBYTES);
  const messageBytes = s.from_string(text);
  const paddedBytes = s.pad(messageBytes, CONSTANT_BLOCK_SIZE);

  const encrypted = s.crypto_box_easy(
    paddedBytes,
    nonce,
    reporterPubKey,
    investigatorPrivKey,
    'uint8array'
  );

  return {
    encryptedResponse: s.to_base64(encrypted, s.base64_variants.ORIGINAL),
    nonce: s.to_base64(nonce, s.base64_variants.ORIGINAL),
  };
}

/**
 * Encrypts a reporter follow-up message using investigator's public key and reporter's private key.
 * Uses crypto_box_easy with 4KB padding.
 */
export async function encryptReporterReply(
  text: string,
  investigatorPubKeyBase64: string,
  reporterPrivKey: Uint8Array
): Promise<{ encryptedMessage: string; nonce: string }> {
  const s = await initCrypto();
  const investigatorPubKey = s.from_base64(
    investigatorPubKeyBase64,
    s.base64_variants.ORIGINAL
  );
  const nonce = s.randombytes_buf(s.crypto_box_NONCEBYTES);
  const messageBytes = s.from_string(text);
  const paddedBytes = s.pad(messageBytes, CONSTANT_BLOCK_SIZE);

  const encrypted = s.crypto_box_easy(
    paddedBytes,
    nonce,
    investigatorPubKey,
    reporterPrivKey,
    'uint8array'
  );

  return {
    encryptedMessage: s.to_base64(encrypted, s.base64_variants.ORIGINAL),
    nonce: s.to_base64(nonce, s.base64_variants.ORIGINAL),
  };
}

/**
 * Decrypts a message from the case thread for the investigator.
 * Uses crypto_box_open_easy with investigator's private key and reporter's public key.
 */
export async function decryptCaseMessageForInvestigator(
  record: {
    encryptedResponse: string;
    nonce: string;
  },
  reporterPubKeyBase64: string,
  investigatorPrivKey: Uint8Array
): Promise<string> {
  const s = await initCrypto();
  const ciphertext = s.from_base64(record.encryptedResponse, s.base64_variants.ORIGINAL);
  const nonce = s.from_base64(record.nonce, s.base64_variants.ORIGINAL);
  const reporterPubKey = s.from_base64(reporterPubKeyBase64, s.base64_variants.ORIGINAL);

  const decryptedBytes = s.crypto_box_open_easy(
    ciphertext,
    nonce,
    reporterPubKey,
    investigatorPrivKey,
    'uint8array'
  );

  const unpadded = safeUnpad(s, decryptedBytes, CONSTANT_BLOCK_SIZE);
  return s.to_string(unpadded);
}

/**
 * Wipes sensitive Uint8Array buffers from client memory.
 */
export function wipeMemory(...buffers: (Uint8Array | undefined)[]): void {
  if (!sodium) return;
  for (const buf of buffers) {
    if (buf && buf instanceof Uint8Array) {
      try {
        sodium.memzero(buf);
      } catch {
        // Ignore if already freed
      }
    }
  }
}
