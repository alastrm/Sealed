/** V2: separate Ed25519 authorship, existing libsodium encryption confidentiality. */
import {
  initCrypto, fromBase64, toBase64, encryptReport, decryptReport,
  encryptInvestigatorReply, encryptReporterReply, decryptInvestigatorResponse,
  decryptCaseMessageForInvestigator, parseMessageContent, wipeMemory,
  type ReporterSecrets,
} from './crypto';
import type { CaseMessageDto, IdentityPacket, IdentityPublic, ReportManifest } from './types';

export interface UnlockedIdentity {
  packet: IdentityPacket;
  privateKey: Uint8Array;
  signingPrivateKey: Uint8Array;
}

export function configuredPins(): string[] {
  // Build-time LOCAL configuration. Never populate this from API/storage/TOFU.
  return (process.env.NEXT_PUBLIC_INVESTIGATOR_SIGNING_KEYS || '').split(',').map((s) => s.trim()).filter(Boolean);
}

export function wire(values: (string | number)[]): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(values));
}

export function identityBytes(identity: IdentityPublic): Uint8Array {
  return wire(['sealed:identity', 2, identity.publicKey, identity.signingPublicKey]);
}

export function reportBytes(m: ReportManifest): Uint8Array {
  return wire(['sealed:report', 2, m.caseId, 'REPORTER', m.reporterPublicKey,
    m.reporterSigningPublicKey, m.investigatorPublicKey, m.investigatorSigningPublicKey,
    m.identitySignature, m.credentialCommitment, m.encryptedReport]);
}

export function messageBytes(m: ReportManifest, id: string, role: string, nonce: string, ciphertext: string): Uint8Array {
  return wire(['sealed:message', 2, m.caseId, id, role, m.reporterPublicKey,
    m.reporterSigningPublicKey, m.investigatorPublicKey, m.investigatorSigningPublicKey,
    m.reportSignature, nonce, ciphertext]);
}

function bytes(value: string, length?: number): Uint8Array {
  if (typeof value !== 'string' || value.length > 100000) throw new Error('Invalid protocol encoding.');
  const decoded = fromBase64(value);
  if (toBase64(decoded) !== value || (length !== undefined && decoded.length !== length)) {
    throw new Error('Invalid protocol encoding or length.');
  }
  return decoded;
}

function uuid(value: string): void {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value)) {
    throw new Error('Invalid protocol UUID.');
  }
}

export async function verifyIdentity(identity: IdentityPublic, pins = configuredPins()): Promise<void> {
  const s = await initCrypto();
  if (identity.protocolVersion !== 2 || !pins.includes(identity.signingPublicKey)) {
    throw new Error('Investigator identity is not pinned. Install the trusted local signing-key pin.');
  }
  bytes(identity.publicKey, 32);
  if (!s.crypto_sign_verify_detached(bytes(identity.identitySignature, 64), identityBytes(identity), bytes(identity.signingPublicKey, 32))) {
    throw new Error('Investigator encryption identity signature is invalid.');
  }
}

export async function credentialCommitment(tokenHash: string): Promise<string> {
  bytes(tokenHash, 32);
  return toBase64(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(tokenHash))));
}

export async function verifyManifest(m: ReportManifest, secrets?: ReporterSecrets, pins = configuredPins()): Promise<void> {
  const s = await initCrypto();
  if (!m || m.protocolVersion !== 2) throw new Error('Unsupported report protocol.');
  uuid(m.caseId);
  await verifyIdentity({ protocolVersion: 2, publicKey: m.investigatorPublicKey,
    signingPublicKey: m.investigatorSigningPublicKey, identitySignature: m.identitySignature }, pins);
  bytes(m.reporterPublicKey, 32);
  bytes(m.credentialCommitment, 32);
  bytes(m.encryptedReport);
  if (!s.crypto_sign_verify_detached(bytes(m.reportSignature, 64), reportBytes(m), bytes(m.reporterSigningPublicKey, 32))) {
    throw new Error('Report identity/manifest signature is invalid.');
  }
  if (secrets && (m.reporterPublicKey !== secrets.publicKeyBase64 ||
      m.reporterSigningPublicKey !== secrets.signingPublicKeyBase64 ||
      m.credentialCommitment !== await credentialCommitment(secrets.caseAccessTokenHashBase64))) {
    throw new Error('Report identity does not match these recovery credentials.');
  }
}

export async function createReportManifest(text: string, identity: IdentityPublic, secrets: ReporterSecrets,
  pins = configuredPins()): Promise<ReportManifest> {
  const s = await initCrypto();
  await verifyIdentity(identity, pins);
  const m: ReportManifest = {
    protocolVersion: 2, caseId: crypto.randomUUID(), reporterPublicKey: secrets.publicKeyBase64,
    reporterSigningPublicKey: secrets.signingPublicKeyBase64, investigatorPublicKey: identity.publicKey,
    investigatorSigningPublicKey: identity.signingPublicKey, identitySignature: identity.identitySignature,
    credentialCommitment: await credentialCommitment(secrets.caseAccessTokenHashBase64),
    encryptedReport: await encryptReport(text, identity.publicKey), reportSignature: '',
  };
  m.reportSignature = toBase64(s.crypto_sign_detached(reportBytes(m), secrets.signingPrivateKey));
  return m;
}

export async function signMessage(m: ReportManifest, role: 'REPORTER' | 'INVESTIGATOR', text: string,
  privateKey: Uint8Array, signingPrivateKey: Uint8Array, pins = configuredPins()) {
  const s = await initCrypto();
  await verifyManifest(m, undefined, pins);
  const expectedSignKey = role === 'REPORTER' ? m.reporterSigningPublicKey : m.investigatorSigningPublicKey;
  const expectedBoxKey = role === 'REPORTER' ? m.reporterPublicKey : m.investigatorPublicKey;
  if (toBase64(s.crypto_sign_ed25519_sk_to_pk(signingPrivateKey)) !== expectedSignKey ||
      toBase64(s.crypto_scalarmult_base(privateKey)) !== expectedBoxKey) throw new Error('Wrong case signing/encryption identity.');
  const id = crypto.randomUUID();
  const encrypted = role === 'INVESTIGATOR'
    ? await encryptInvestigatorReply(text, m.reporterPublicKey, privateKey)
    : await encryptReporterReply(text, m.investigatorPublicKey, privateKey);
  const ciphertext = 'encryptedResponse' in encrypted ? encrypted.encryptedResponse : encrypted.encryptedMessage;
  return { protocolVersion: 2, caseId: m.caseId, messageId: id,
    encryptedResponse: ciphertext, nonce: encrypted.nonce, investigatorPublicKey: m.investigatorPublicKey,
    signature: toBase64(s.crypto_sign_detached(messageBytes(m, id, role, encrypted.nonce, ciphertext), signingPrivateKey)) };
}

export async function verifyMessage(record: CaseMessageDto, m: ReportManifest, seen: Set<string>): Promise<void> {
  const s = await initCrypto();
  uuid(record.id);
  if (record.protocolVersion !== 2 || record.caseId !== m.caseId || seen.has(record.id) ||
      (record.sender !== 'INVESTIGATOR' && record.sender !== 'REPORTER') ||
      (record.senderType !== undefined && record.senderType !== record.sender) ||
      record.investigatorPublicKey !== m.investigatorPublicKey) throw new Error('Message context or replay rejected.');
  bytes(record.nonce, 24);
  bytes(record.encryptedResponse);
  const key = record.sender === 'INVESTIGATOR' ? m.investigatorSigningPublicKey : m.reporterSigningPublicKey;
  if (!record.signature || !s.crypto_sign_verify_detached(bytes(record.signature, 64),
    messageBytes(m, record.id, record.sender, record.nonce, record.encryptedResponse), bytes(key, 32))) {
    throw new Error('Message signature is invalid.');
  }
  seen.add(record.id);
}

export async function readThread(records: CaseMessageDto[], m: ReportManifest | null, version: number,
  viewer: 'REPORTER' | 'INVESTIGATOR', privateKey: Uint8Array, legacyReporterKey?: string) {
  if (version !== 1 && version !== 2) throw new Error('Unsupported conversation protocol.');
  if (version === 1 && m !== null) throw new Error('Protocol downgrade rejected.');
  if (version === 2) {
    if (!m) throw new Error('Missing v2 case identity.');
    await verifyManifest(m);
  }
  const seen = new Set<string>();
  const result: (CaseMessageDto & { decryptedText: string })[] = [];
  for (const record of records) {
    try {
      if (version === 2) await verifyMessage(record, m!, seen);
      else if (record.protocolVersion !== 1 || record.signature) throw new Error('Protocol downgrade rejected.');
      const raw = viewer === 'REPORTER'
        ? await decryptInvestigatorResponse(record, privateKey)
        : await decryptCaseMessageForInvestigator(record, m?.reporterPublicKey || legacyReporterKey!, privateKey);
      result.push({ ...record, authentication: version === 2 ? 'verified' : 'legacy',
        decryptedText: parseMessageContent(raw).text, attachments: parseMessageContent(raw).attachments });
    } catch {
      result.push({ ...record, authentication: 'invalid', decryptedText: '[UNVERIFIED — message rejected]', attachments: [] });
    }
  }
  return result;
}

export async function decryptVerifiedReport(m: ReportManifest, privateKey: Uint8Array): Promise<string> {
  await verifyManifest(m);
  return decryptReport(m.encryptedReport, m.investigatorPublicKey, privateKey);
}

export async function createInvestigatorIdentity(password: string): Promise<IdentityPacket> {
  const s = await initCrypto();
  if (password.length < 16) throw new Error('Choose a fresh master password of at least 16 characters.');
  const box = s.crypto_box_keypair();
  const signing = s.crypto_sign_keypair();
  const salt = s.randombytes_buf(16), nonce = s.randombytes_buf(24);
  let kek: Uint8Array | undefined;
  // Fixed 128-byte binary key bundle: domain (32), box private (32), signing private (64).
  const bundle = new Uint8Array(128);
  bundle.set(new TextEncoder().encode('sealed:identity-private:v2'));
  bundle.set(box.privateKey, 32);
  bundle.set(signing.privateKey, 64);
  try {
    kek = s.crypto_pwhash(32, password, salt, 2, 67108864, 2);
    const packet: IdentityPacket = { protocolVersion: 2, publicKey: toBase64(box.publicKey),
      signingPublicKey: toBase64(signing.publicKey), identitySignature: '',
      encryptedPrivateKey: toBase64(s.crypto_secretbox_easy(bundle, nonce, kek)),
      privateKeyNonce: toBase64(nonce), kdfSalt: toBase64(salt), kdfOpsLimit: 2, kdfMemLimit: 67108864, kdfAlgorithm: 2 };
    packet.identitySignature = toBase64(s.crypto_sign_detached(identityBytes(packet), signing.privateKey));
    return packet;
  } finally { wipeMemory(box.privateKey, signing.privateKey, kek, bundle); }
}

export async function unlockIdentity(packet: IdentityPacket, password: string,
  pins = configuredPins()): Promise<UnlockedIdentity> {
  const s = await initCrypto();
  await verifyIdentity(packet, pins);
  if (packet.kdfOpsLimit !== 2 || packet.kdfMemLimit !== 67108864 || packet.kdfAlgorithm !== 2) throw new Error('Unsupported identity KDF.');
  const kek = s.crypto_pwhash(32, password, bytes(packet.kdfSalt, 16), 2, 67108864, 2);
  let plain: Uint8Array | undefined;
  try {
    plain = s.crypto_secretbox_open_easy(bytes(packet.encryptedPrivateKey), bytes(packet.privateKeyNonce, 24), kek);
    const expected = new Uint8Array(32);
    expected.set(new TextEncoder().encode('sealed:identity-private:v2'));
    if (plain.length !== 128 || !s.memcmp(plain.subarray(0, 32), expected)) throw new Error('Invalid key bundle domain.');
    const privateKey = plain.slice(32, 64), signingPrivateKey = plain.slice(64);
    if (toBase64(s.crypto_scalarmult_base(privateKey)) !== packet.publicKey ||
        toBase64(s.crypto_sign_ed25519_sk_to_pk(signingPrivateKey)) !== packet.signingPublicKey) {
      wipeMemory(privateKey, signingPrivateKey);
      throw new Error('Key bundle identity mismatch.');
    }
    // Check full Ed25519 secret integrity, including seed-derived public key.
    const derived = s.crypto_sign_seed_keypair(signingPrivateKey.subarray(0, 32));
    const valid = s.memcmp(derived.privateKey, signingPrivateKey);
    wipeMemory(derived.privateKey);
    if (!valid) { wipeMemory(privateKey, signingPrivateKey); throw new Error('Invalid signing secret.'); }
    return { packet, privateKey, signingPrivateKey };
  } finally { wipeMemory(kek, plain); }
}
