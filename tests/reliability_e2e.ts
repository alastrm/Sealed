/** Automated live regression: only the explicitly disposable M3 test server. */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { api, ApiError } from '../frontend/src/lib/api';
import { SubmissionFlow } from '../frontend/src/lib/submission';
import { deriveReporterSecrets, decryptAttachmentFile, parseMessageContent, unlockInvestigatorKey, wipeMemory } from '../frontend/src/lib/crypto';
import { unlockIdentity, decryptVerifiedReport, signMessage, readThread, verifyManifest } from '../frontend/src/lib/protocol';
import { prepareReply, deliverReply } from '../frontend/src/lib/replyDelivery';
import { createInvestigatorProof } from '../frontend/src/lib/investigatorAuth';
import type { CaseMessageDto, IdentityPacket } from '../frontend/src/lib/types';

async function main() {
  assert(/sealed-(m3|demo)-/.test(process.env.SEALED_TEST_FIXTURE || ''));
  const fixture = JSON.parse(readFileSync(process.env.SEALED_TEST_FIXTURE!, 'utf8'));
  const base = process.env.NEXT_PUBLIC_API_URL!;
  const origin = process.env.SEALED_TEST_ORIGIN!;
  process.env.NEXT_PUBLIC_INVESTIGATOR_SIGNING_KEYS = fixture.packet.signingPublicKey;
  console.log('PASS 1: isolated application, fresh browser crypto identity and independent public pin initialized.');
  const flow = new SubmissionFlow(api, () => { throw new Error('Synthetic storage unavailable'); });
  const fileBytes = new Uint8Array(5*1024*1024); fileBytes[fileBytes.length-1] = 42;
  await flow.prepare('Synthetic M3 live submission', [new File([fileBytes], 'synthetic-5MiB.bin')]);
  assert.equal(flow.snapshot().phase, 'ready');
  await flow.send(); // Test-only server corrupts the first committed acknowledgement.
  assert.equal(flow.snapshot().phase, 'success');
  console.log('PASS 2: recovery phrase retained before submission; lost commit acknowledgement reconciled with unavailable storage.');
  const pending = flow.snapshot().pending!;
  const recovered = await deriveReporterSecrets(pending.mnemonic);
  const tracked = await api.accessCase(pending.dto.caseId, recovered.caseAccessTokenHashBase64, recovered);
  await verifyManifest(tracked.manifest!, recovered);
  assert.equal((await api.createCase(pending.dto)).caseId, pending.dto.caseId);
  console.log('PASS 3: phrase recovery, signed manifest binding and idempotent submission verified.');
  const headers = { Origin: origin, 'X-Sealed-Request': '1', 'Content-Type': 'application/json' };
  const challenge = await (await fetch(base+'/api/v1/investigators/auth/challenge', { method: 'POST', headers,
    body: JSON.stringify({ username: fixture.account.username }) })).json();
  const proof = await createInvestigatorProof(fixture.accessKey, challenge.challengeId, challenge.nonce, fixture.account.username, origin);
  const login = await fetch(base+'/api/v1/investigators/auth/session', { method: 'POST', headers,
    body: JSON.stringify({ username: fixture.account.username, challengeId: challenge.challengeId, proof }) });
  assert.equal(login.status, 200);
  const cookie = login.headers.get('set-cookie')!.split(';')[0];
  const auth = { ...headers, Cookie: cookie };
  assert.equal((await fetch(base+'/api/v1/investigators/cases')).status, 401);
  const identities: IdentityPacket[] = await (await fetch(base+'/api/v1/investigators/identities', { headers: auth })).json();
  console.log('PASS 4: Investigator authenticated; anonymous Investigator access rejected.');
  const identity = await unlockIdentity(identities[0], fixture.password);
  const report = parseMessageContent(await decryptVerifiedReport(tracked.manifest!, identity.privateKey));
  assert.equal(report.text, 'Synthetic M3 live submission');
  const metadata = report.attachments[0];
  const ciphertext = await api.downloadAttachment(metadata.attachmentId, recovered, tracked.caseId);
  assert.equal(ciphertext.byteLength, 10*1024*1024+16);
  const plaintext = await decryptAttachmentFile(new Uint8Array(ciphertext), metadata.keyBase64, metadata.nonceBase64, metadata.bucketSize);
  assert.equal(plaintext.length, fileBytes.length); assert.deepEqual(plaintext, fileBytes); plaintext.fill(0);
  assert.deepEqual(plaintext, new Uint8Array(fileBytes.length)); // plaintext was explicitly wiped above
  console.log('PASS 5: original report and maximum-bucket attachment decrypted locally; bytes checked.');
  const thread = async (): Promise<CaseMessageDto[]> => (await fetch(base+`/api/v1/investigators/cases/${tracked.caseId}/messages`, { headers: auth })).json();
  const investigatorReply = await prepareReply('Signed M3 investigator reply', [new File(['test evidence'], 'reply.txt')],
    payload => signMessage(tracked.manifest!, 'INVESTIGATOR', payload, identity.privateKey, identity.signingPrivateKey));
  const investigatorUpload: typeof api.uploadAttachment = async (blob, caseId, _credential, attachmentId) => {
    assert(blob instanceof Blob);
    const form = new FormData(); form.append('file', blob, 'evidence.enc'); form.append('case_id', caseId!); form.append('attachment_id', attachmentId!);
    const response = await fetch(base+'/api/v1/cases/attachments', { method: 'POST', headers: { Origin: origin, Cookie: cookie, 'X-Sealed-Request': '1' }, body: form });
    assert.equal(response.status, 201); return response.json();
  };
  const delivered = await deliverReply(investigatorReply, { caseId: tracked.caseId }, async dto => {
    const response = await fetch(base+`/api/v1/investigators/cases/${tracked.caseId}/messages`, { method: 'POST', headers: auth, body: JSON.stringify(dto) });
    assert.equal(response.status, 201); await response.json();
    throw new TypeError('Synthetic lost reply acknowledgement');
  }, thread, investigatorUpload);
  const reporterRead = await readThread([delivered], tracked.manifest, 2, 'REPORTER', recovered.privateKey);
  assert.equal(reporterRead[0].authentication, 'verified'); assert.equal(reporterRead[0].decryptedText, 'Signed M3 investigator reply');
  const followup = await prepareReply('Signed M3 reporter follow-up', [new File(['followup evidence'], 'followup.txt')],
    payload => signMessage(tracked.manifest!, 'REPORTER', payload, recovered.privateKey, recovered.signingPrivateKey));
  await deliverReply(followup, { caseId: tracked.caseId, credential: recovered.caseAccessTokenHashBase64, reporter: recovered }, dto => api.sendReporterReply({
    ...dto, encryptedMessage: dto.encryptedResponse, caseAccessTokenHash: recovered.caseAccessTokenHashBase64,
  }, tracked.caseId, recovered), thread);
  const investigatorRead = await readThread(await thread(), tracked.manifest, 2, 'INVESTIGATOR', identity.privateKey);
  assert.equal(investigatorRead.length, 2); assert(investigatorRead.every(x => x.authentication === 'verified'));
  assert.equal(investigatorRead[1].decryptedText, 'Signed M3 reporter follow-up');
  const replay = await fetch(base+`/api/v1/investigators/cases/${tracked.caseId}/messages`, { method: 'POST', headers: auth, body: JSON.stringify(investigatorReply.dto) });
  assert.equal(replay.status, 409);
  const cases = await (await fetch(base+'/api/v1/investigators/cases', { headers: auth })).json();
  assert.equal(cases.filter((x: {protocolVersion: number}) => x.protocolVersion === 2).length, 1);
  const legacy = cases.find((x: {id: string}) => x.id === fixture.legacy.id);
  assert.equal(legacy.protocolVersion, 1); assert.equal(legacy.readOnly, true);
  const legacyKey = await unlockInvestigatorKey(fixture.account, fixture.password);
  const legacyReporter = await deriveReporterSecrets(fixture.legacy.mnemonic);
  await assert.rejects(api.lookupCase(legacyReporter.caseAccessTokenHashBase64, undefined, legacyReporter), (error: unknown) => error instanceof ApiError && error.status === 410);
  const legacyMessages = await (await fetch(base+`/api/v1/investigators/cases/${fixture.legacy.id}/messages`, { headers: auth })).json();
  const legacyRead = await readThread(legacyMessages, null, 1, 'INVESTIGATOR', legacyKey, fixture.legacy.reporterPublicKey);
  assert.equal(legacyRead[0].authentication, 'legacy'); assert.equal(legacyRead[0].decryptedText, 'Synthetic unverified legacy reply');
  const legacyWrite = await fetch(base+`/api/v1/investigators/cases/${fixture.legacy.id}/messages`, { method: 'POST', headers: auth,
    body: JSON.stringify({ ...investigatorReply.dto, caseId: fixture.legacy.id }) });
  assert.equal(legacyWrite.status, 409);
  await assert.rejects(api.lookupCase(Buffer.alloc(32).toString('base64')), (error: unknown) => error instanceof ApiError && error.status === 404);
  console.log('PASS 6: genuine signed replies and evidence both directions; message replay rejected; legacy archive remains read-only.');
  // Copied DB locator and public manifest do not authenticate the reporter.
  assert.equal((await fetch(base+'/api/v1/cases/lookup', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ caseAccessTokenHash: recovered.caseAccessTokenHashBase64 }) })).status, 401);
  assert.equal((await fetch(base+`/api/v1/cases/attachments/${metadata.attachmentId}`)).status, 401);
  const fresh = await api.lookupCase(recovered.caseAccessTokenHashBase64, undefined, recovered);
  const statusUrl = base+`/api/v1/investigators/cases/${tracked.caseId}/status`;
  const transition = async (targetStatus: string, expectedRevision: number, requestId = crypto.randomUUID()) => {
    const dto = { targetStatus, expectedRevision, requestId };
    const response = await fetch(statusUrl, { method: 'POST', headers: auth, body: JSON.stringify(dto) });
    assert.equal(response.status, 200);
    return { dto, result: await response.json() };
  };
  assert.equal((await fetch(statusUrl, { method: 'POST', headers, body: JSON.stringify({ targetStatus: 'CLOSED', expectedRevision: fresh.revision, requestId: crypto.randomUUID() }) })).status, 401);
  const review = await transition('IN_REVIEW', fresh.revision);
  const closed = await transition('CLOSED', review.result.revision);
  assert.equal((await fetch(statusUrl, { method: 'POST', headers: auth, body: JSON.stringify(closed.dto) })).status, 200);
  const closedView = await api.lookupCase(recovered.caseAccessTokenHashBase64, undefined, recovered);
  assert.equal(closedView.status, 'CLOSED'); assert(closedView.readOnly);
  const forbidden = await signMessage(tracked.manifest!, 'REPORTER', 'Blocked after closure', recovered.privateKey, recovered.signingPrivateKey);
  await assert.rejects(api.sendReporterReply({ ...forbidden, encryptedMessage: forbidden.encryptedResponse,
    caseAccessTokenHash: recovered.caseAccessTokenHashBase64 }, tracked.caseId, recovered), (error: unknown) => error instanceof ApiError && error.status === 409);
  await assert.rejects(api.uploadAttachment(new Blob(['blocked ciphertext']), tracked.caseId,
    recovered.caseAccessTokenHashBase64, crypto.randomUUID(), undefined, recovered), (error: unknown) => error instanceof ApiError && error.status === 409);
  const audit = await api.verifyAuditChain(tracked.caseId, recovered);
  assert.equal(audit.status, 'consistent'); assert.equal(audit.completenessVerified, false);
  const reopened = await transition('IN_REVIEW', closed.result.revision);
  assert.equal(reopened.result.status, 'IN_REVIEW');
  const finalView = await api.lookupCase(recovered.caseAccessTokenHashBase64, undefined, recovered);
  assert.equal(finalView.status, 'IN_REVIEW'); assert.equal(finalView.readOnly, false);
  console.log('PASS 7: copied verifier denied; private download and status boundaries; close, duplicate retry, blocked replies/uploads and reopening verified.');
  const logout = await fetch(base+'/api/v1/investigators/auth/session', { method: 'DELETE', headers: auth }); assert.equal(logout.status, 204);
  assert.equal((await fetch(base+'/api/v1/investigators/cases', { headers: auth })).status, 401);
  wipeMemory(identity.privateKey, identity.signingPrivateKey, recovered.privateKey, recovered.signingPrivateKey, legacyKey, legacyReporter.privateKey, legacyReporter.signingPrivateKey);
  console.log('PASS 8: logout revoked Investigator session. Full API/actual frontend crypto demo passed (browser interactions reported separately).');
}
main().catch(error => { console.error('Isolated live reliability regression failed; payloads withheld.');
  console.error((error instanceof Error ? error.stack : '')?.split('\n').filter(x => /^\s+at /.test(x)).join('\n')); process.exitCode = 1; });
