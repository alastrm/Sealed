/** Live v2 regression. Use a disposable API: this creates a report. No demo defaults. */
import assert from 'node:assert/strict';
import { createInvestigatorProof } from './frontend/src/lib/investigatorAuth';
import { generateReporterBundle, deriveReporterSecrets, wipeMemory } from './frontend/src/lib/crypto';
import { createReportManifest, unlockIdentity, decryptVerifiedReport, readThread, signMessage, verifyManifest } from './frontend/src/lib/protocol';
import type { CaseMessageDto, IdentityPacket } from './frontend/src/lib/types';
import { requestDigest, signReporterChallenge } from './frontend/src/lib/reporterAuth';

async function main() {
  const base = process.env.SEALED_E2E_API_URL || 'http://127.0.0.1:8000';
  const origin = process.env.SEALED_E2E_ORIGIN || 'http://localhost:3000';
  const username = process.env.SEALED_E2E_USERNAME;
  const accessKey = process.env.SEALED_E2E_ACCESS_KEY;
  const password = process.env.SEALED_E2E_MASTER_PASSWORD;
  const pin = process.env.SEALED_E2E_PIN;
  assert(username && accessKey && password && pin, 'Set explicit username/access key/master password/trusted SEALED_E2E_PIN for a disposable API.');
  // Explicit test configuration, never obtained from the response being verified.
  process.env.NEXT_PUBLIC_INVESTIGATOR_SIGNING_KEYS = pin;
  const headers = { Origin: origin, 'X-Sealed-Request': '1', 'Content-Type': 'application/json' };
  const challengeRes = await fetch(`${base}/api/v1/investigators/auth/challenge`, { method: 'POST', headers, body: JSON.stringify({ username }) });
  assert.equal(challengeRes.status, 200);
  const challenge = await challengeRes.json();
  const proof = await createInvestigatorProof(accessKey, challenge.challengeId, challenge.nonce, username, origin);
  const login = await fetch(`${base}/api/v1/investigators/auth/session`, { method: 'POST', headers,
    body: JSON.stringify({ username, challengeId: challenge.challengeId, proof }) });
  assert.equal(login.status, 200);
  const cookie = login.headers.get('set-cookie')?.split(';')[0];
  assert(cookie);
  const authenticated = { ...headers, Cookie: cookie };
  const reporter = await generateReporterBundle();
  let identity: Awaited<ReturnType<typeof unlockIdentity>> | undefined;
  try {
    const publicResponse = await fetch(`${base}/api/v1/investigators/public-key`);
    assert.equal(publicResponse.status, 200);
    const publicIdentity = await publicResponse.json();
    const manifest = await createReportManifest('Disposable v2 live report', publicIdentity, reporter.secrets);
    const submitted = await fetch(`${base}/api/v1/cases`, { method: 'POST', headers,
      body: JSON.stringify({ protocolVersion: 2, manifest, caseId: manifest.caseId,
        reporterPublicKey: reporter.secrets.publicKeyBase64, caseAccessTokenHash: reporter.secrets.caseAccessTokenHashBase64,
        encryptedReport: manifest.encryptedReport }) });
    assert.equal(submitted.status, 201);
    assert.equal((await fetch(`${base}/api/v1/investigators/cases`)).status, 401);
    const packets: IdentityPacket[] = await (await fetch(`${base}/api/v1/investigators/identities`, { headers: authenticated })).json();
    identity = await unlockIdentity(packets.find((packet) => packet.signingPublicKey === pin)!, password);
    assert.equal(await decryptVerifiedReport(manifest, identity.privateKey), 'Disposable v2 live report');
    const reply = await signMessage(manifest, 'INVESTIGATOR', 'Verified investigator reply', identity.privateKey, identity.signingPrivateKey);
    const threadUrl = `${base}/api/v1/investigators/cases/${manifest.caseId}/messages`;
    const replyResponse = await fetch(threadUrl, { method: 'POST', headers: authenticated, body: JSON.stringify(reply) });
    assert.equal(replyResponse.status, 201);
    assert.equal((await fetch(threadUrl, { method: 'POST', headers: authenticated, body: JSON.stringify(reply) })).status, 409);
    const recovered = await deriveReporterSecrets(reporter.mnemonic);
    try {
      const reporterPost = async (path: string, value: unknown) => {
        const body = JSON.stringify(value);
        const digest = await requestDigest(new TextEncoder().encode(body));
        const operation = 'POST ' + path;
        const response = await fetch(`${base}/api/v1/reporter-auth/challenge`, { method: 'POST', headers,
          body: JSON.stringify({ authVersion: 1, locator: recovered.caseAccessTokenHashBase64,
            signingPublicKey: recovered.signingPublicKeyBase64, operation, requestDigest: digest }) });
        assert.equal(response.status, 200);
        const challenge = await response.json();
        const proof = await signReporterChallenge(challenge, recovered, { operation, requestDigest: digest, caseId: manifest.caseId });
        return fetch(base + path, { method: 'POST', body, headers: { ...headers,
          'X-Sealed-Challenge': challenge.challengeId, 'X-Sealed-Proof': proof } });
      };
      const trackResponse = await reporterPost('/api/v1/cases/lookup', { caseAccessTokenHash: recovered.caseAccessTokenHashBase64 });
      assert.equal(trackResponse.status, 200);
      const track = await trackResponse.json();
      await verifyManifest(track.manifest, recovered);
      const messages = await readThread(track.messages, manifest, 2, 'REPORTER', recovered.privateKey);
      assert.equal(messages[0].authentication, 'verified');
      assert.equal(messages[0].decryptedText, 'Verified investigator reply');
      const followup = await signMessage(manifest, 'REPORTER', 'Verified reporter follow-up', recovered.privateKey, recovered.signingPrivateKey);
      const followupResponse = await reporterPost('/api/v1/cases/messages', { ...followup,
        encryptedMessage: followup.encryptedResponse, caseAccessTokenHash: recovered.caseAccessTokenHashBase64 });
      assert.equal(followupResponse.status, 201);
      const thread: CaseMessageDto[] = await (await fetch(threadUrl, { headers: authenticated })).json();
      const read = await readThread(thread, manifest, 2, 'INVESTIGATOR', identity.privateKey);
      assert.equal(read[1].authentication, 'verified');
      assert.equal(read[1].decryptedText, 'Verified reporter follow-up');
    } finally { wipeMemory(recovered.privateKey, recovered.signingPrivateKey); }
    console.log('PASS: v2 submission, pinned identities, local unlock, signed replies both ways, recovery, replay denial, API authorization.');
  } finally {
    wipeMemory(identity?.privateKey, identity?.signingPrivateKey, reporter.secrets.privateKey, reporter.secrets.signingPrivateKey);
    assert.equal((await fetch(`${base}/api/v1/investigators/auth/session`, { method: 'DELETE', headers: authenticated })).status, 204);
  }
}
main().catch(() => { console.error('Live v2 regression failed (no secret payloads logged).'); process.exitCode = 1; });
