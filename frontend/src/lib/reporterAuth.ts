/** Request authentication v1; the signed/encrypted message protocol stays v2. */
import { initCrypto, toBase64, type ReporterSecrets } from './crypto';
import { wire } from './protocol';

export interface ReporterChallenge {
  authVersion: number; protocolVersion: number; challengeId: string; nonce: string;
  caseId: string; locator: string; signingPublicKey: string; operation: string;
  requestDigest: string; expiresAt: number;
}

export async function requestDigest(bytes: Uint8Array): Promise<string> {
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes as Uint8Array<ArrayBuffer>));
  return Array.from(hash, value => value.toString(16).padStart(2, '0')).join('');
}

export function reporterProofBytes(c: ReporterChallenge): Uint8Array {
  return wire(['sealed:reporter-auth', 1, 2, c.challengeId, c.nonce, c.caseId, c.locator,
    c.signingPublicKey, c.operation, c.requestDigest, c.expiresAt]);
}

export async function signReporterChallenge(c: ReporterChallenge, secrets: ReporterSecrets,
  expected: { operation: string; requestDigest: string; caseId?: string }): Promise<string> {
  const now = Date.now() / 1000;
  if (c.authVersion !== 1 || c.protocolVersion !== 2 ||
      !/^[0-9a-f]{64}$/.test(c.challengeId) || !/^[0-9a-f]{64}$/.test(c.nonce) ||
      (c.caseId !== '' && !/^[0-9a-f-]{36}$/.test(c.caseId)) ||
      c.locator !== secrets.caseAccessTokenHashBase64 || c.signingPublicKey !== secrets.signingPublicKeyBase64 ||
      c.operation !== expected.operation || c.requestDigest !== expected.requestDigest ||
      (expected.caseId !== undefined && c.caseId !== expected.caseId) ||
      !Number.isSafeInteger(c.expiresAt) || c.expiresAt < now - 5 || c.expiresAt > now + 65) {
    throw new Error('Reporter authentication challenge does not match the intended request.');
  }
  const s = await initCrypto();
  if (toBase64(s.crypto_sign_ed25519_sk_to_pk(secrets.signingPrivateKey)) !== c.signingPublicKey) {
    throw new Error('Reporter signing key is unavailable. Recover the case again.');
  }
  return toBase64(s.crypto_sign_detached(reporterProofBytes(c), secrets.signingPrivateKey));
}

export async function uploadRequestDigest(id: string, caseId: string | undefined, ciphertextDigest: string,
  stagingToken?: string, credential?: string) {
  return requestDigest(wire(['sealed:upload', 1, id, caseId || '', ciphertextDigest, stagingToken || '', credential || '']));
}
