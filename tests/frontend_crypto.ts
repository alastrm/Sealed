/** Test bridge: actual frontend crypto, disposable secrets, JSON over stdin only. */
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import {
  initCrypto, toBase64, generateReporterBundle, deriveReporterSecrets,
  encryptReport, decryptReport, unlockInvestigatorKey, encryptInvestigatorReply,
  decryptInvestigatorResponse, encryptReporterReply, decryptCaseMessageForInvestigator,
  wipeMemory,
} from '../frontend/src/lib/crypto';
import { createInvestigatorIdentity, unlockIdentity, createReportManifest, signMessage, readThread, verifyManifest, verifyIdentity, verifyMessage, messageBytes, reportBytes } from '../frontend/src/lib/protocol';
import type { CaseMessageDto, ReportManifest } from '../frontend/src/lib/types';
import { createInvestigatorProof } from '../frontend/src/lib/investigatorAuth';
import { signReporterChallenge } from '../frontend/src/lib/reporterAuth';

async function main() {
  const input = JSON.parse(readFileSync(0, 'utf8'));
  if (input.operation === 'proof') {
    return { proof: await createInvestigatorProof(input.accessKey, input.challengeId,
      input.nonce, input.username, input.origin) };
  }
  const sodium = await initCrypto();
  if (input.operation === 'create' || input.operation === 'create-case') {
    const password = input.fixture?.password || randomBytes(32).toString('hex');
    const account = input.fixture?.account || await createInvestigatorIdentity(password);
    const reporter = await generateReporterBundle();
    const text = 'Disposable report: verify authenticated access preserves sealed-box decryption.';
    const manifest = await createReportManifest(text, account, reporter.secrets, [account.signingPublicKey]);
    const report = { protocolVersion: 2, manifest, caseId: manifest.caseId,
      reporterPublicKey: reporter.secrets.publicKeyBase64,
      caseAccessTokenHash: reporter.secrets.caseAccessTokenHashBase64, encryptedReport: manifest.encryptedReport };
    wipeMemory(reporter.secrets.privateKey, reporter.secrets.signingPrivateKey);
    return { account, password, mnemonic: reporter.mnemonic, case: report, text };
  }
  if (input.operation === 'legacy') {
    const reporter = await generateReporterBundle();
    const key = await unlockInvestigatorKey(input.account, input.password);
    try {
      return { caseId: randomUUID(), mnemonic: reporter.mnemonic, caseAccessTokenHash: reporter.secrets.caseAccessTokenHashBase64,
        reporterPublicKey: reporter.secrets.publicKeyBase64, encryptedReport: await encryptReport('Legacy archive report', input.account.publicKey),
        reply: await encryptInvestigatorReply('Legacy unverified reply', reporter.secrets.publicKeyBase64, key) };
    } finally { wipeMemory(key, reporter.secrets.privateKey, reporter.secrets.signingPrivateKey); }
  }
  const fixture = input.fixture;
  process.env.NEXT_PUBLIC_INVESTIGATOR_SIGNING_KEYS = fixture.account.signingPublicKey;
  if (input.operation === 'auth-proof') {
    const reporter = await deriveReporterSecrets(fixture.mnemonic);
    try { return { proof: await signReporterChallenge(input.challenge, reporter, {
      operation: input.challenge.operation, requestDigest: input.challenge.requestDigest,
    }) }; } finally { wipeMemory(reporter.privateKey, reporter.signingPrivateKey, reporter.caseAccessToken); }
  }
  if (input.operation === 'investigator') {
    await assert.rejects(unlockIdentity(input.account, randomBytes(32).toString('hex')));
    const identity = await unlockIdentity(input.account, fixture.password);
    try {
      await verifyManifest(input.case.manifest);
      assert.equal(await decryptReport(input.case.encryptedReport, input.account.publicKey, identity.privateKey), fixture.text);
      return await signMessage(input.case.manifest, 'INVESTIGATOR', 'Authenticated investigator reply', identity.privateKey, identity.signingPrivateKey);
    } finally { wipeMemory(identity.privateKey, identity.signingPrivateKey); }
  }
  if (input.operation === 'reporter') {
    const reporter = await deriveReporterSecrets(fixture.mnemonic);
    try {
      await verifyManifest(fixture.case.manifest, reporter);
      const messages = await readThread([input.message], fixture.case.manifest, 2, 'REPORTER', reporter.privateKey);
      assert.equal(messages[0].authentication, 'verified');
      assert.equal(messages[0].decryptedText, 'Authenticated investigator reply');
      const reply = await signMessage(fixture.case.manifest, 'REPORTER', 'Reporter follow-up', reporter.privateKey, reporter.signingPrivateKey);
      return { ...reply, encryptedMessage: reply.encryptedResponse, caseAccessTokenHash: reporter.caseAccessTokenHashBase64 };
    } finally { wipeMemory(reporter.privateKey, reporter.signingPrivateKey); }
  }
  if (input.operation === 'read-followup') {
    const identity = await unlockIdentity(input.account, fixture.password);
    try {
      const messages = await readThread([input.message], fixture.case.manifest, 2, 'INVESTIGATOR', identity.privateKey);
      assert.equal(messages[0].authentication, 'verified');
      assert.equal(messages[0].decryptedText, 'Reporter follow-up');
      return { ok: true };
    } finally { wipeMemory(identity.privateKey, identity.signingPrivateKey); }
  }
  if (input.operation === 'security') {
    const manifest = fixture.case.manifest;
    const reporter = await deriveReporterSecrets(fixture.mnemonic);
    const identity = await unlockIdentity(fixture.account, fixture.password);
    const outsider = sodium.crypto_sign_keypair();
    const outsiderBox = sodium.crypto_box_keypair();
    const toRecord = (reply: Awaited<ReturnType<typeof signMessage>>, role: 'REPORTER' | 'INVESTIGATOR'): CaseMessageDto => ({ ...reply, id: reply.messageId, sender: role, senderType: role, createdAt: new Date().toISOString() });
    const investigatorReply = await signMessage(manifest, 'INVESTIGATOR', 'Genuine investigator', identity.privateKey, identity.signingPrivateKey);
    const reporterReply = await signMessage(manifest, 'REPORTER', 'Genuine reporter', reporter.privateKey, reporter.signingPrivateKey);
    const genuine = toRecord(investigatorReply, 'INVESTIGATOR');
    const repRecord = toRecord(reporterReply, 'REPORTER');
    let checks = 0;
    const reject = async (record: CaseMessageDto, context: ReportManifest = manifest, seen = new Set<string>()) => {
      await assert.rejects(verifyMessage(record, context, seen)); checks++;
    };
    try {
      await verifyMessage(genuine, manifest, new Set()); checks++;
      await verifyMessage(repRecord, manifest, new Set()); checks++;
      // Exact original chosen-key attack: the legacy primitive decrypts it,
      // while v2 refuses the untrusted sender key/signature before plaintext display.
      const outsiderCipher = await encryptInvestigatorReply('Outsider chosen-key forgery', reporter.publicKeyBase64, outsiderBox.privateKey);
      const outsiderRecord = { ...genuine, ...outsiderCipher, id: randomUUID(), investigatorPublicKey: toBase64(outsiderBox.publicKey) };
      outsiderRecord.signature = toBase64(sodium.crypto_sign_detached(messageBytes(manifest, outsiderRecord.id,
        'INVESTIGATOR', outsiderRecord.nonce, outsiderRecord.encryptedResponse), outsider.privateKey));
      assert.equal(await decryptInvestigatorResponse(outsiderRecord, reporter.privateKey), 'Outsider chosen-key forgery');
      await reject(outsiderRecord);
      // Even the other participant can compute a valid box MAC, but cannot sign as their peer.
      const forgeries: [CaseMessageDto, Uint8Array][] = [[genuine, reporter.signingPrivateKey], [repRecord, identity.signingPrivateKey], [genuine, outsider.privateKey]];
      for (const [record, signingKey] of forgeries) {
        await reject({ ...record, signature: toBase64(sodium.crypto_sign_detached(messageBytes(manifest, record.id, record.sender, record.nonce, record.encryptedResponse), signingKey)) });
      }
      await reject({ ...genuine, investigatorPublicKey: toBase64(sodium.crypto_box_keypair().publicKey) });
      await reject({ ...genuine, caseId: randomUUID() });
      await reject(genuine, { ...manifest, caseId: randomUUID() });
      await reject({ ...genuine, id: randomUUID() });
      await reject({ ...repRecord, sender: 'INVESTIGATOR', senderType: 'INVESTIGATOR' });
      await reject({ ...genuine, sender: 'REPORTER', senderType: 'REPORTER' });
      await reject({ ...genuine, senderType: 'REPORTER' });
      const ciphertext = Buffer.from(genuine.encryptedResponse, 'base64'); ciphertext[20] ^= 1;
      await reject({ ...genuine, encryptedResponse: ciphertext.toString('base64') });
      await reject({ ...genuine, nonce: toBase64(sodium.randombytes_buf(24)) });
      await reject({ ...genuine, signature: toBase64(sodium.randombytes_buf(64)) });
      await reject({ ...genuine, protocolVersion: 1 });
      await reject({ ...genuine, protocolVersion: 99 });
      const seen = new Set<string>(); await verifyMessage(genuine, manifest, seen); await reject(genuine, manifest, seen);
      const duplicates = await readThread([genuine, genuine], manifest, 2, 'REPORTER', reporter.privateKey);
      assert.equal(duplicates[0].authentication, 'verified'); assert.equal(duplicates[1].authentication, 'invalid'); checks++;
      const legacy = await readThread([{ ...genuine, protocolVersion: 1, signature: null }], null, 1, 'REPORTER', reporter.privateKey);
      assert.equal(legacy[0].authentication, 'legacy');
      assert.equal(legacy[0].decryptedText, 'Genuine investigator'); checks++;
      await assert.rejects(readThread([genuine], manifest, 99, 'REPORTER', reporter.privateKey)); checks++;
      await assert.rejects(readThread([genuine], manifest, 1, 'REPORTER', reporter.privateKey)); checks++;
      assert.equal((await readThread([{ ...genuine, protocolVersion: 1 }], null, 1, 'REPORTER', reporter.privateKey))[0].authentication, 'invalid'); checks++;
      // A normal refresh may verify the same history once again.
      assert.equal((await readThread([genuine], manifest, 2, 'REPORTER', reporter.privateKey))[0].authentication, 'verified'); checks++;
      await assert.rejects(verifyIdentity(fixture.account, [])); checks++;
      await assert.rejects(verifyIdentity({ ...fixture.account, publicKey: toBase64(sodium.crypto_box_keypair().publicKey) })); checks++;
      await assert.rejects(verifyManifest({ ...manifest, reporterPublicKey: toBase64(sodium.crypto_box_keypair().publicKey) })); checks++;
      await assert.rejects(verifyManifest({ ...manifest, reporterSigningPublicKey: toBase64(outsider.publicKey) })); checks++;
      await assert.rejects(verifyManifest({ ...manifest, caseId: randomUUID() })); checks++;
      const wrong = await generateReporterBundle();
      await assert.rejects(verifyManifest(manifest, wrong.secrets));
      const wrongReads = await readThread([genuine], manifest, 2, 'REPORTER', wrong.secrets.privateKey);
      assert.equal(wrongReads[0].authentication, 'invalid'); checks++;
      wipeMemory(wrong.secrets.privateKey, wrong.secrets.signingPrivateKey);
      await assert.rejects(unlockIdentity(fixture.account, randomBytes(32).toString('hex'))); checks++;
      const encrypted = Buffer.from(fixture.account.encryptedPrivateKey, 'base64'); encrypted[0] ^= 1;
      await assert.rejects(unlockIdentity({ ...fixture.account, encryptedPrivateKey: encrypted.toString('base64') }, fixture.password)); checks++;
      const reloaded = await unlockIdentity(JSON.parse(JSON.stringify(fixture.account)), fixture.password);
      assert.equal(toBase64(reloaded.signingPrivateKey), toBase64(identity.signingPrivateKey)); checks++;
      wipeMemory(reloaded.privateKey, reloaded.signingPrivateKey);
      const recovered = await deriveReporterSecrets('  '+fixture.mnemonic.toUpperCase().replaceAll(' ', '  ')+' ');
      assert.equal(recovered.signingPublicKeyBase64, reporter.signingPublicKeyBase64); checks++;
      wipeMemory(recovered.privateKey, recovered.signingPrivateKey);
      // Wire bytes returned to Python for cross-language verification vectors.
      return { ok: true, checks, reportBytes: Buffer.from(reportBytes(manifest)).toString('base64'),
        messageBytes: Buffer.from(messageBytes(manifest, genuine.id, genuine.sender, genuine.nonce, genuine.encryptedResponse)).toString('base64'), message: genuine };
    } finally { wipeMemory(identity.privateKey, identity.signingPrivateKey, reporter.privateKey, reporter.signingPrivateKey, outsider.privateKey, outsiderBox.privateKey); }
  }
  throw new Error('Unknown test operation');
}

main().then((result) => process.stdout.write(JSON.stringify(result))).catch(() => {
  // Do not print payloads or randomly generated test credentials on failure.
  process.stderr.write('Frontend crypto contract assertion failed.\n');
  process.exitCode = 1;
});
