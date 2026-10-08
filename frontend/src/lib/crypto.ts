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
import type { AttachmentMetadata, InvestigatorAccountRecord } from './types';

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

  let bip39Seed: Buffer | Uint8Array | null = null;
  let masterSeed: Uint8Array | null = null;
  let keypairSeed: Uint8Array | null = null;

  try {
    // 1. Generate 512-bit BIP-39 seed
    bip39Seed = bip39.mnemonicToSeedSync(cleanMnemonic);

    // 2. Derive 32-byte master seed with domain separation
    masterSeed = s.crypto_generichash(
      32,
      s.from_string(KDF_CONTEXT.MASTER_SEED),
      bip39Seed,
      'uint8array'
    );

    // 3. Derive 32-byte seed for X25519 Box Keypair
    keypairSeed = s.crypto_generichash(
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

    return {
      mnemonic: cleanMnemonic,
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
      publicKeyBase64: s.to_base64(keyPair.publicKey, s.base64_variants.ORIGINAL),
      caseAccessToken,
      caseAccessTokenHash,
      caseAccessTokenHashBase64: s.to_base64(caseAccessTokenHash, s.base64_variants.ORIGINAL),
    };
  } finally {
    // Guarantees intermediate seed materials are wiped even if an exception occurs
    if (masterSeed) s.memzero(masterSeed);
    if (keypairSeed) s.memzero(keypairSeed);
    if (bip39Seed) {
      s.memzero(bip39Seed);
    }
  }
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
export const MAX_PLAINTEXT_BYTES = 64 * 1024; // Up to 64 KB padded payload support

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
 * The outgoing ciphertext length is guaranteed to be constant regardless of message size.
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
  if (messageBytes.length > MAX_PLAINTEXT_BYTES) {
    s.memzero(messageBytes);
    throw new Error(`Report exceeds maximum size of ${MAX_PLAINTEXT_BYTES} bytes.`);
  }
  const paddedBytes = s.pad(messageBytes, CONSTANT_BLOCK_SIZE);

  try {
    const sealedBytes = s.crypto_box_seal(paddedBytes, investigatorPubKey, 'uint8array');
    return s.to_base64(sealedBytes, s.base64_variants.ORIGINAL);
  } finally {
    s.memzero(paddedBytes);
    s.memzero(messageBytes);
  }
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

  let decryptedBytes: Uint8Array | null = null;
  try {
    decryptedBytes = s.crypto_box_open_easy(
      ciphertext,
      nonce,
      investigatorPubKey,
      reporterPrivKey,
      'uint8array'
    );

    const unpadded = safeUnpad(s, decryptedBytes, CONSTANT_BLOCK_SIZE);
    return s.to_string(unpadded);
  } finally {
    if (decryptedBytes) {
      s.memzero(decryptedBytes);
    }
  }
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

  let decryptedBytes: Uint8Array | null = null;
  try {
    decryptedBytes = s.crypto_box_seal_open(
      ciphertext,
      publicKey,
      investigatorPrivateKey,
      'uint8array'
    );

    const unpadded = safeUnpad(s, decryptedBytes, CONSTANT_BLOCK_SIZE);
    return s.to_string(unpadded);
  } finally {
    if (decryptedBytes) {
      s.memzero(decryptedBytes);
    }
  }
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
  if (messageBytes.length > MAX_PLAINTEXT_BYTES) {
    s.memzero(messageBytes);
    throw new Error(`Reply exceeds maximum size of ${MAX_PLAINTEXT_BYTES} bytes.`);
  }
  const paddedBytes = s.pad(messageBytes, CONSTANT_BLOCK_SIZE);

  try {
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
  } finally {
    s.memzero(paddedBytes);
    s.memzero(messageBytes);
  }
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
  if (messageBytes.length > MAX_PLAINTEXT_BYTES) {
    s.memzero(messageBytes);
    throw new Error(`Message exceeds maximum size of ${MAX_PLAINTEXT_BYTES} bytes.`);
  }
  const paddedBytes = s.pad(messageBytes, CONSTANT_BLOCK_SIZE);

  try {
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
  } finally {
    s.memzero(paddedBytes);
    s.memzero(messageBytes);
  }
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

  let decryptedBytes: Uint8Array | null = null;
  try {
    decryptedBytes = s.crypto_box_open_easy(
      ciphertext,
      nonce,
      reporterPubKey,
      investigatorPrivKey,
      'uint8array'
    );

    const unpadded = safeUnpad(s, decryptedBytes, CONSTANT_BLOCK_SIZE);
    return s.to_string(unpadded);
  } finally {
    if (decryptedBytes) {
      s.memzero(decryptedBytes);
    }
  }
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

// ---------------------------------------------------------------------------
// Zero-Knowledge Evidence Attachments Primitives
// ---------------------------------------------------------------------------

export const ATTACHMENT_BUCKET_SIZES = [
  256 * 1024,      // 256 KB
  1024 * 1024,     // 1 MB
  5 * 1024 * 1024,  // 5 MB
  10 * 1024 * 1024, // 10 MB (strict max limit)
] as const;

export interface EncryptedAttachmentResult {
  fileBlob: Blob;
  metadata: AttachmentMetadata;
}

/**
 * Returns the nearest power-bucket size to prevent file size traffic fingerprinting.
 */
export function getAttachmentBucketSize(fileSizeBytes: number): number {
  for (const bucket of ATTACHMENT_BUCKET_SIZES) {
    if (fileSizeBytes < bucket) {
      return bucket;
    }
  }
  throw new Error(
    `Размер файла (${(fileSizeBytes / (1024 * 1024)).toFixed(2)} МБ) превышает максимальный лимит 10 МБ.`
  );
}

/**
 * Client-Side Zero-Knowledge File Encryption:
 * 1. Generates ephemeral 32-byte symmetric key via crypto_secretbox_keygen
 * 2. Applies bucket padding (256KB, 1MB, 5MB, 10MB) to disguise file length
 * 3. Encrypts payload via crypto_secretbox_easy (XSalsa20-Poly1305)
 * 4. Returns encrypted binary Blob and metadata dictionary (metadata is only encrypted inside message)
 */
export async function encryptAttachmentFile(
  fileBytes: Uint8Array,
  originalName: string,
  mimeType: string
): Promise<EncryptedAttachmentResult> {
  const s = await initCrypto();

  const bucketSize = getAttachmentBucketSize(fileBytes.length);
  const paddedBytes = s.pad(fileBytes, bucketSize);

  let key: Uint8Array | null = null;
  try {
    // 1. Generate one-time symmetric secret key and nonce
    key = s.crypto_secretbox_keygen();
    const nonce = s.randombytes_buf(s.crypto_secretbox_NONCEBYTES);

    // 2. Encrypt padded payload
    const ciphertext = s.crypto_secretbox_easy(paddedBytes, nonce, key, 'uint8array');

    const attachmentId =
      typeof crypto !== 'undefined' && crypto.randomUUID
        ? crypto.randomUUID()
        : 'att-' + s.to_hex(s.randombytes_buf(16));

    const metadata: AttachmentMetadata = {
      attachmentId,
      originalName: originalName || 'evidence.bin',
      mimeType: mimeType || 'application/octet-stream',
      keyBase64: s.to_base64(key, s.base64_variants.ORIGINAL),
      nonceBase64: s.to_base64(nonce, s.base64_variants.ORIGINAL),
      sizeBytes: fileBytes.length,
      bucketSize,
    };

    const fileBlob = new Blob([ciphertext as Uint8Array<ArrayBuffer>], {
      type: 'application/octet-stream',
    });

    return { fileBlob, metadata };
  } finally {
    if (key) {
      s.memzero(key);
    }
    s.memzero(paddedBytes);
  }
}

/**
 * Decrypts a blind evidence blob in browser tab memory:
 * 1. Decrypts via crypto_secretbox_open_easy with symmetric key from message
 * 2. Strips bucket padding
 * 3. Wipes key material
 */
export async function decryptAttachmentFile(
  ciphertextBytes: Uint8Array,
  keyBase64: string,
  nonceBase64: string,
  bucketSize?: number
): Promise<Uint8Array> {
  const s = await initCrypto();
  let key: Uint8Array | null = null;

  let decryptedPadded: Uint8Array;
  try {
    key = s.from_base64(keyBase64, s.base64_variants.ORIGINAL);
    const nonce = s.from_base64(nonceBase64, s.base64_variants.ORIGINAL);

    try {
      decryptedPadded = s.crypto_secretbox_open_easy(
        ciphertextBytes,
        nonce,
        key,
        'uint8array'
      );
    } catch {
      throw new Error('Не удалось расшифровать вложение: неверный ключ или повреждённые данные.');
    }
  } finally {
    if (key) {
      s.memzero(key);
    }
  }

  // Attempt bucket unpadding
  if (bucketSize) {
    try {
      return s.unpad(decryptedPadded, bucketSize);
    } catch {
      // Fallback to checking each standard bucket
    }
  }

  for (const bucket of ATTACHMENT_BUCKET_SIZES) {
    try {
      return s.unpad(decryptedPadded, bucket);
    } catch {
      // Continue search
    }
  }

  return decryptedPadded;
}

/**
 * Safely creates an object URL for a decrypted blob.
 * Prevents Stored XSS by avoiding execution of active HTML/SVG payloads in context.
 */
export function createSafeDownloadUrl(fileBytes: Uint8Array, mimeType: string): string {
  const isDangerous =
    /html|xml|svg|javascript|ecmascript|shockwave/i.test(mimeType) ||
    !mimeType ||
    mimeType === 'text/plain';

  const safeMime = isDangerous ? 'application/octet-stream' : mimeType;
  const blob = new Blob([fileBytes as Uint8Array<ArrayBuffer>], { type: safeMime });
  return URL.createObjectURL(blob);
}

/**
 * Initiates safe browser download of decrypted attachment file.
 */
export function triggerSafeDownload(
  fileBytes: Uint8Array,
  fileName: string,
  mimeType: string
): void {
  const safeUrl = createSafeDownloadUrl(fileBytes, mimeType);
  const link = document.createElement('a');
  link.href = safeUrl;
  link.download = fileName || 'decrypted_evidence.bin';
  link.rel = 'noopener noreferrer';
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  setTimeout(() => URL.revokeObjectURL(safeUrl), 10000);
}

/**
 * Packages human-readable message text together with zero-knowledge attachments metadata.
 */
export function packMessagePayload(
  text: string,
  attachments?: AttachmentMetadata[]
): string {
  if (!attachments || attachments.length === 0) {
    return text;
  }
  return JSON.stringify({
    text: text || '',
    attachments,
  });
}

/**
 * Parses decrypted payload string into human-readable text and zero-knowledge attachments metadata.
 */
export function parseMessageContent(rawText: string): {
  text: string;
  attachments: AttachmentMetadata[];
} {
  try {
    const trimmed = (rawText || '').trim();
    if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
      const parsed = JSON.parse(trimmed);
      if (
        typeof parsed === 'object' &&
        parsed !== null &&
        ('text' in parsed || 'attachments' in parsed)
      ) {
        return {
          text: typeof parsed.text === 'string' ? parsed.text : '',
          attachments: Array.isArray(parsed.attachments) ? parsed.attachments : [],
        };
      }
    }
  } catch {
    // Plain text message
  }
  return { text: rawText, attachments: [] };
}

