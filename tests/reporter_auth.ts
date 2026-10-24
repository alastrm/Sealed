/** Actual browser request-signing implementation; no real credentials or network. */
import assert from 'node:assert/strict';
import { generateReporterBundle, initCrypto, fromBase64, wipeMemory } from '../frontend/src/lib/crypto';
import { reporterProofBytes, requestDigest, signReporterChallenge, uploadRequestDigest, type ReporterChallenge } from '../frontend/src/lib/reporterAuth';

async function main() {
  const { secrets } = await generateReporterBundle();
  const sodium = await initCrypto();
  const operation = 'POST /api/v1/cases/lookup';
  const digest = await requestDigest(new TextEncoder().encode('{"test":true}'));
  const caseId = crypto.randomUUID();
  const challenge: ReporterChallenge = { authVersion: 1, protocolVersion: 2,
    challengeId: 'a'.repeat(64), nonce: 'b'.repeat(64), caseId,
    locator: secrets.caseAccessTokenHashBase64, signingPublicKey: secrets.signingPublicKeyBase64,
    operation, requestDigest: digest, expiresAt: Math.floor(Date.now() / 1000) + 60 };
  const expected = { operation, requestDigest: digest, caseId };
  let checks = 0;
  try {
    const proof = fromBase64(await signReporterChallenge(challenge, secrets, expected));
    assert(sodium.crypto_sign_verify_detached(proof, reporterProofBytes(challenge), fromBase64(secrets.signingPublicKeyBase64))); checks++;
    for (const patch of [
      { authVersion: 2 }, { protocolVersion: 1 }, { challengeId: 'bad' }, { nonce: 'bad' },
      { caseId: crypto.randomUUID() }, { locator: 'replaced' }, { signingPublicKey: 'replaced' },
      { operation: 'POST /api/v1/cases/messages' }, { requestDigest: '0'.repeat(64) },
      { expiresAt: Math.floor(Date.now() / 1000) - 10 }, { expiresAt: Math.floor(Date.now() / 1000) + 120 },
      { expiresAt: NaN },
    ]) {
      await assert.rejects(signReporterChallenge({ ...challenge, ...patch }, secrets, expected)); checks++;
    }
    // Every signed context field and the protocol domain affect signature validity.
    for (const patch of [{ nonce: 'c'.repeat(64) }, { challengeId: 'd'.repeat(64) },
      { caseId: crypto.randomUUID() }, { operation: 'GET /api/v1/cases/other' },
      { requestDigest: 'e'.repeat(64) }, { expiresAt: challenge.expiresAt + 1 }]) {
      assert(!sodium.crypto_sign_verify_detached(proof, reporterProofBytes({ ...challenge, ...patch }), fromBase64(secrets.signingPublicKeyBase64))); checks++;
    }
    const differentDomain = new TextEncoder().encode(new TextDecoder().decode(reporterProofBytes(challenge)).replace('sealed:reporter-auth', 'sealed:message'));
    assert(!sodium.crypto_sign_verify_detached(proof, differentDomain, fromBase64(secrets.signingPublicKeyBase64))); checks++;
    assert.notEqual(await requestDigest(new TextEncoder().encode('{}')), await requestDigest(new TextEncoder().encode('{ }'))); checks++;
    const upload = await uploadRequestDigest(caseId, caseId, digest, 'stage', 'locator');
    for (const args of [[crypto.randomUUID(), caseId, digest, 'stage', 'locator'],
      [caseId, crypto.randomUUID(), digest, 'stage', 'locator'], [caseId, caseId, 'e'.repeat(64), 'stage', 'locator'],
      [caseId, caseId, digest, 'other', 'locator'], [caseId, caseId, digest, 'stage', 'other']]) {
      assert.notEqual(upload, await uploadRequestDigest(args[0], args[1], args[2], args[3], args[4])); checks++;
    }
    wipeMemory(secrets.signingPrivateKey);
    await assert.rejects(signReporterChallenge(challenge, secrets, expected)); checks++;
    console.log(`PASS: ${checks} frontend reporter authentication checks.`);
  } finally { wipeMemory(secrets.privateKey, secrets.signingPrivateKey, secrets.caseAccessToken, secrets.caseAccessTokenHash); }
}
main().catch(() => { console.error('Reporter authentication regression failed; secret payloads withheld.'); process.exitCode = 1; });
