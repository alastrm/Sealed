/**
 * ============================================================================
 * E2E Integration Test: Real Client -> Real Python FastAPI Backend
 * ============================================================================
 * 
 * Prerequisites:
 *   1. Start Python backend:
 *      python -m uvicorn main:app --port 8000
 * 
 *   2. Run this script in another terminal:
 *      npx ts-node e2e.ts
 * ============================================================================
 */

import assert from 'node:assert';
import {
  InvestigatorService,
  ReporterService,
  InvestigatorAccountRecord,
} from './poc';
import sodium from 'libsodium-wrappers-sumo';

const API_BASE = 'http://127.0.0.1:8000';

async function main(): Promise<void> {
  await sodium.ready;

  console.log('==================================================================');
  console.log('E2EE Whistleblower System: Live Client -> FastAPI Backend E2E Test');
  console.log('==================================================================\n');

  // Step 0: Check if backend is alive
  try {
    const healthRes = await fetch(`${API_BASE}/health`);
    if (!healthRes.ok) {
      throw new Error(`Health check failed: ${healthRes.statusText}`);
    }
    const health = await healthRes.json();
    console.log(`[OK] Connected to Python backend: ${JSON.stringify(health)}`);
  } catch (err) {
    console.error(
      '\n[ERROR] Could not connect to Python FastAPI backend at ' + API_BASE + '.\n' +
      'Please start the server first by running in a separate terminal:\n' +
      '  python -m uvicorn main:app --port 8000\n'
    );
    process.exit(1);
  }

  // Step 1: Reporter fetches investigator's public key from backend
  console.log('\n--- STEP 1: Reporter fetches Investigator Public Key ---');
  const pubKeyRes = await fetch(`${API_BASE}/api/v1/investigators/public-key`);
  assert.strictEqual(pubKeyRes.status, 200, 'Failed to fetch investigator public key');
  const { publicKey: investigatorPublicKey } = await pubKeyRes.json();
  console.log(`[OK] Fetched Public Key: ${investigatorPublicKey}`);

  // Step 2: Reporter generates 12-word mnemonic and seals the report
  console.log('\n--- STEP 2: Reporter creates and seals confidential report ---');
  const mnemonic = ReporterService.generateMnemonic();
  console.log(`[OK] Generated 12-word Mnemonic: "${mnemonic}"`);

  const secrets = ReporterService.deriveSecretsFromMnemonic(mnemonic);
  const secretReport =
    'LIVE TEST REPORT: Unauthorized financial transfers detected in Eastern division. ' +
    'Funds routed to unverified vendor account.';

  const createCaseDto = ReporterService.createCase(
    secretReport,
    investigatorPublicKey,
    secrets
  );

  // Step 3: Reporter POSTs case to Python backend
  console.log('\n--- STEP 3: Submitting case to backend (POST /api/v1/cases) ---');
  const postCaseRes = await fetch(`${API_BASE}/api/v1/cases`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(createCaseDto),
  });
  assert.strictEqual(postCaseRes.status, 201, 'Case creation failed');
  const caseCreated = await postCaseRes.json();
  console.log(`[OK] Case created on server with ID: ${caseCreated.caseId} (Status: ${caseCreated.status})`);

  // Step 4: Investigator logs in, downloads case, and decrypts sealed report
  console.log('\n--- STEP 4: Investigator reads and decrypts case ---');
  const investigatorPassword = 'Correct-Horse-Battery-Staple-2026!#';
  const accountRes = await fetch(`${API_BASE}/api/v1/investigators/account`);
  assert.strictEqual(accountRes.status, 200, 'Failed to fetch investigator account');
  const investigatorAccount: InvestigatorAccountRecord = await accountRes.json();

  const unlockedPrivateKey = InvestigatorService.loginAndUnlockPrivateKey(
    investigatorAccount,
    investigatorPassword
  );
  console.log('[OK] Investigator password verified and private key unlocked in memory.');

  // Fetch all cases from backend
  const casesRes = await fetch(`${API_BASE}/api/v1/investigators/cases`);
  assert.strictEqual(casesRes.status, 200, 'Failed to list investigator cases');
  const casesList = await casesRes.json();
  const currentCase = casesList.find((c: any) => c.id === caseCreated.caseId);
  assert(currentCase, 'Created case not found in investigator list');

  const decryptedReport = InvestigatorService.decryptAnonymousReport(
    currentCase.encryptedReport,
    investigatorAccount.publicKey,
    unlockedPrivateKey
  );
  assert.strictEqual(decryptedReport, secretReport, 'Decrypted report does not match original');
  console.log(`[OK] Investigator successfully decrypted report:\n     "${decryptedReport}"`);

  // Step 5: Investigator drafts encrypted response and sends to backend
  console.log('\n--- STEP 5: Investigator replies to reporter ---');
  const responseText =
    'OFFICIAL LIVE RESPONSE: Audit team deployed. Transaction logs are being preserved. ' +
    'Please maintain secure custody of your 12-word mnemonic phrase.';

  const responseDto = InvestigatorService.createResponse(
    caseCreated.caseId,
    responseText,
    currentCase.reporterPublicKey,
    investigatorAccount.publicKey,
    unlockedPrivateKey
  );

  const sendMsgRes = await fetch(
    `${API_BASE}/api/v1/investigators/cases/${caseCreated.caseId}/messages`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(responseDto),
    }
  );
  assert.strictEqual(sendMsgRes.status, 201, 'Failed to post investigator response');
  const createdMsg = await sendMsgRes.json();
  console.log(`[OK] Investigator reply stored in backend (Message ID: ${createdMsg.id})`);

  // Step 6: Reporter returns, inputs mnemonic, queries backend and decrypts reply
  console.log('\n--- STEP 6: Reporter returns with mnemonic and decrypts reply ---');
  const rederived = ReporterService.deriveSecretsFromMnemonic(mnemonic);
  const tokenHashBase64 = sodium.to_base64(rederived.caseAccessTokenHash, sodium.base64_variants.ORIGINAL);

  const accessRes = await fetch(`${API_BASE}/api/v1/cases/${caseCreated.caseId}/access`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ caseAccessTokenHash: tokenHashBase64 }),
  });
  assert.strictEqual(accessRes.status, 200, 'Reporter access denied');
  const threadData = await accessRes.json();
  assert.strictEqual(threadData.status, 'RESPONDED');
  assert.strictEqual(threadData.messages.length, 1);

  const decryptedResponse = ReporterService.decryptResponse(
    threadData.messages[0],
    rederived.keyPair.privateKey
  );
  assert.strictEqual(decryptedResponse, responseText, 'Decrypted response mismatch');
  console.log(`[OK] Reporter successfully decrypted investigator reply:\n     "${decryptedResponse}"`);

  // Step 7: Test access denial with incorrect mnemonic / token hash
  console.log('\n--- STEP 7: Security check - Verify access denial on wrong hash ---');
  const badAccessRes = await fetch(`${API_BASE}/api/v1/cases/${caseCreated.caseId}/access`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ caseAccessTokenHash: 'INVALID_HASH_SIMULATING_WRONG_MNEMONIC====' }),
  });
  assert.strictEqual(badAccessRes.status, 403, 'Server should reject invalid token hash with 403');
  console.log('[OK] Server returned 403 Forbidden on invalid token hash as expected.');

  console.log('\n==================================================================');
  console.log('ALL LIVE INTEGRATION CHECKS PASSED: END-TO-END CRYPTO & API VERIFIED!');
  console.log('==================================================================');
}

main().catch((err) => {
  console.error('E2E Execution Error:', err);
  process.exit(1);
});
