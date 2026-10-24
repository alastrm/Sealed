/** Actual frontend lifecycle/crypto tests. Secrets stay in memory; no browser account needed. */
import assert from 'node:assert/strict';
import { SubmissionFlow } from '../frontend/src/lib/submission';
import { api, ApiError } from '../frontend/src/lib/api';
import { encryptedAttachmentSize, prepareAttachments, validateFiles, checkedPayload, MAX_ATTACHMENT_PLAINTEXT } from '../frontend/src/lib/attachments';
import { createInvestigatorIdentity, unlockIdentity, decryptVerifiedReport, verifyManifest, signMessage, readThread } from '../frontend/src/lib/protocol';
import { deriveReporterSecrets, encryptAttachmentFile, decryptAttachmentFile, wipeMemory } from '../frontend/src/lib/crypto';
import { prepareReply, deliverReply } from '../frontend/src/lib/replyDelivery';
import type { CreateCaseDto, CaseMessageDto } from '../frontend/src/lib/types';

class MemoryStorage implements Storage {
  data = new Map<string, string>();
  get length() { return this.data.size; }
  clear() { this.data.clear(); }
  key(i: number) { return [...this.data.keys()][i] || null; }
  getItem(key: string) { return this.data.get(key) ?? null; }
  setItem(key: string, value: string) { this.data.set(key, value); }
  removeItem(key: string) { this.data.delete(key); }
}
async function main() {
  const password = 'synthetic-M3-fixture-only-' + crypto.randomUUID();
  const identity = await createInvestigatorIdentity(password);
  process.env.NEXT_PUBLIC_INVESTIGATOR_SIGNING_KEYS = identity.signingPublicKey;
  let checks = 0;
  function fixture(storage: () => Storage = () => new MemoryStorage()) {
    const cases = new Map<string, CreateCaseDto>();
    const calls: CreateCaseDto[] = [];
    const uploads = new Map<string, Blob>();
    const client = { ...api,
      getInvestigatorPublicKey: async () => ({ ...identity, investigatorId: 'synthetic', username: 'test' }),
      createCase: async (dto: CreateCaseDto) => { calls.push(dto); cases.set(dto.caseId, dto); return { caseId: dto.caseId, status: 'OPEN' as const, createdAt: new Date().toISOString() }; },
      accessCase: async (id: string) => {
        const dto = cases.get(id); if (!dto) throw new ApiError('Missing', 404);
        return { caseId: id, status: 'OPEN' as const, createdAt: new Date().toISOString(), protocolVersion: 2,
          readOnly: false, revision: 1, reporterPublicKey: dto.reporterPublicKey, manifest: dto.manifest, messages: [] };
      },
      uploadAttachment: async (blob: Blob | Uint8Array, _case?: string, _credential?: string, id?: string) => {
        assert(id && blob instanceof Blob); uploads.set(id, blob);
        return { attachmentId: id, sizeBytes: blob.size, createdAt: new Date().toISOString() };
      },
    };
    return { client, cases, calls, uploads, flow: new SubmissionFlow(client, storage) };
  }
  // Storage getter/get/set/remove failures cannot suppress credentials or undo success.
  for (const failure of ['getter', 'getItem', 'setItem', 'removeItem']) {
    const storage = new MemoryStorage();
    if (failure !== 'getter') storage[failure as 'getItem' | 'setItem' | 'removeItem'] = () => { throw new Error('Synthetic blocked storage'); };
    const f = fixture(() => { if (failure === 'getter') throw new Error('Disabled storage'); return storage; });
    await f.flow.restore();
    await f.flow.prepare('Synthetic report', []);
    const words = f.flow.snapshot().pending!.mnemonic;
    assert.equal(words.split(' ').length, 12);
    assert.equal(f.cases.size, 0); // Words precede any report transmission.
    await f.flow.send();
    assert.equal(f.flow.snapshot().phase, 'success');
    assert.equal(f.flow.snapshot().pending!.mnemonic, words); checks++;
  }
  const concurrent = fixture();
  await Promise.all([concurrent.flow.prepare('Only one report', []), concurrent.flow.prepare('Another accidental click', [])]);
  await Promise.all([concurrent.flow.send(), concurrent.flow.send()]);
  await concurrent.flow.send(); assert.equal(concurrent.calls.length, 1); checks++;

  const lost = fixture(); const realCreate = lost.client.createCase;
  lost.client.createCase = async dto => { await realCreate(dto); throw new TypeError('Lost acknowledgement'); };
  await lost.flow.prepare('A committed report', []); await lost.flow.send();
  assert.equal(lost.flow.snapshot().phase, 'success'); assert.equal(lost.cases.size, 1); checks++;
  const downgraded = fixture(); const saveDowngraded = downgraded.client.createCase; const readDowngraded = downgraded.client.accessCase;
  downgraded.client.createCase = async dto => { await saveDowngraded(dto); throw new TypeError('Lost response'); };
  downgraded.client.accessCase = async id => ({ ...await readDowngraded(id), protocolVersion: 1 });
  await downgraded.flow.prepare('Never reinterpret v1', []); await downgraded.flow.send();
  assert.equal(downgraded.flow.snapshot().phase, 'unknown'); checks++;

  const storage = new MemoryStorage(); const unknown = fixture(() => storage);
  const create = unknown.client.createCase; const access = unknown.client.accessCase;
  unknown.client.createCase = async dto => { await create(dto); throw new TypeError('Lost response'); };
  unknown.client.accessCase = async () => { throw new TypeError('Recovery temporarily offline'); };
  await unknown.flow.prepare('Ambiguous network outcome', []); await unknown.flow.send();
  assert.equal(unknown.flow.snapshot().phase, 'unknown');
  const original = unknown.flow.snapshot().pending!;
  unknown.client.createCase = async () => { throw new ApiError('Conflicting retry', 409); };
  await unknown.flow.send(); assert.equal(unknown.flow.snapshot().phase, 'unknown'); checks++;
  unknown.client.createCase = create; unknown.client.accessCase = access;
  const restored = new SubmissionFlow(unknown.client, () => storage);
  await restored.restore(); assert.equal(restored.snapshot().phase, 'unknown');
  assert.equal(restored.snapshot().pending!.mnemonic, original.mnemonic);
  await restored.send(); assert.equal(restored.snapshot().phase, 'success');
  assert.equal(unknown.cases.size, 1); assert.equal(unknown.calls[unknown.calls.length-1].caseId, original.dto.caseId); checks++;
  const recovered = await deriveReporterSecrets(original.mnemonic);
  const unlocked = await unlockIdentity(identity, password);
  await verifyManifest(original.dto.manifest, recovered);
  assert.equal(await decryptVerifiedReport(original.dto.manifest, unlocked.privateKey), 'Ambiguous network outcome'); checks++;

  const rejected = fixture(); rejected.client.createCase = async () => { throw new ApiError('Invalid reference', 403); };
  await rejected.flow.prepare('Rejected report', []); await rejected.flow.send();
  assert.equal(rejected.flow.snapshot().phase, 'failed'); assert(rejected.flow.snapshot().pending); checks++;
  rejected.flow.editDraft(); assert.equal(rejected.flow.snapshot().phase, 'idle'); assert.equal(rejected.flow.snapshot().pending, null); checks++;

  const interrupted = fixture(); const upload = interrupted.client.uploadAttachment;
  let dropped = false;
  interrupted.client.uploadAttachment = async (...args) => { const result = await upload(...args); if (!dropped) { dropped = true; throw new TypeError('Lost upload response'); } return result; };
  const file = new File([new Uint8Array(128)], 'synthetic-evidence.txt', { type: 'text/plain' });
  await interrupted.flow.prepare('Interrupted upload', [file]);
  const id = interrupted.flow.snapshot().pending!.uploads[0].metadata.attachmentId;
  await interrupted.flow.send(); assert.equal(interrupted.calls.length, 0);
  await interrupted.flow.send(); assert.equal(interrupted.flow.snapshot().phase, 'success');
  assert.deepEqual([...interrupted.uploads.keys()], [id]); checks++;
  assert(!JSON.stringify(interrupted.calls).includes(interrupted.flow.snapshot().pending!.mnemonic)); checks++;

  // All actual padding boundaries, including 5 MiB and the precise advertised max.
  for (const size of [0, 262143, 262144, 1048575, 1048576, 5242879, 5242880, MAX_ATTACHMENT_PLAINTEXT]) {
    const bytes = new Uint8Array(size); if (size) bytes[size-1] = 37;
    const encrypted = await encryptAttachmentFile(bytes, 'evidence.bin', 'application/octet-stream');
    assert.equal(encrypted.fileBlob.size, encryptedAttachmentSize(size));
    const plain = await decryptAttachmentFile(new Uint8Array(await encrypted.fileBlob.arrayBuffer()),
      encrypted.metadata.keyBase64, encrypted.metadata.nonceBase64, encrypted.metadata.bucketSize);
    assert.equal(plain.length, size); if (size) assert.equal(plain[size-1], 37); checks++;
  }
  assert.throws(() => encryptedAttachmentSize(10*1024*1024));
  assert.throws(() => validateFiles(Array.from({length: 11}, () => ({size: 0}))));
  assert.throws(() => validateFiles(Array.from({length: 4}, () => ({size: MAX_ATTACHMENT_PLAINTEXT}))));
  assert.throws(() => checkedPayload('😀'.repeat(16385)));
  await assert.rejects(prepareAttachments('x'.repeat(65536), [new File(['x'], 'metadata-overflow.txt')])); checks++;

  const pending = await prepareReply('Signed reply with evidence', [file], payload => signMessage(
    original.dto.manifest, 'INVESTIGATOR', payload, unlocked.privateKey, unlocked.signingPrivateKey));
  const record: CaseMessageDto = { ...pending.dto, protocolVersion: 2, id: pending.dto.messageId,
    caseId: original.dto.caseId, sender: 'INVESTIGATOR', senderType: 'INVESTIGATOR', createdAt: new Date().toISOString() };
  const sent = await deliverReply(pending, { caseId: original.dto.caseId }, async () => { throw new TypeError('Lost reply response'); }, async () => [record], fixture().client.uploadAttachment);
  assert.equal(sent.id, record.id);
  const verified = await readThread([sent], original.dto.manifest, 2, 'REPORTER', recovered.privateKey);
  assert.equal(verified[0].authentication, 'verified'); assert.equal(verified[0].decryptedText, 'Signed reply with evidence'); checks++;
  wipeMemory(recovered.privateKey, recovered.signingPrivateKey, unlocked.privateKey, unlocked.signingPrivateKey);
  console.log(`PASS: ${checks} frontend reliability/crypto groups (synthetic credentials withheld).`);
}
main().catch(error => { console.error('Frontend reliability regression failed; credentials and payloads withheld.');
  console.error((error instanceof Error ? error.stack : '')?.split('\n').filter(x => /^\s+at /.test(x)).join('\n'));
  process.exitCode = 1; });
