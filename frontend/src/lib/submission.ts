/** Stable submission lifecycle. Recovery display never depends on tab storage. */
import { api, ApiError } from './api';
import { generateReporterBundle, deriveReporterSecrets, wipeMemory } from './crypto';
import { createReportManifest, verifyManifest } from './protocol';
import { checkedPayload, prepareAttachments, uploadPrepared, type PreparedAttachment } from './attachments';
import type { CreateCaseDto } from './types';

const PENDING_KEY = 'sealed_pending_submission_v3';
export const MNEMONIC_KEY = 'sealed_mnemonic';
type StorageLike = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>;
export function optionalStorage(operation: (storage: StorageLike) => void, getStorage = () => window.sessionStorage): boolean {
  try { operation(getStorage()); return true; } catch { return false; }
}
export interface PendingSubmission { mnemonic: string; dto: CreateCaseDto; uploads: PreparedAttachment[] }
export interface SubmissionState {
  phase: 'idle' | 'preparing' | 'ready' | 'uploading' | 'sending' | 'unknown' | 'failed' | 'success';
  pending: PendingSubmission | null; error: string | null; storageAvailable: boolean;
}
const INITIAL: SubmissionState = { phase: 'idle', pending: null, error: null, storageAvailable: true };
export class SubmissionFlow {
  private state = INITIAL;
  private listeners = new Set<() => void>();
  private busy = false;
  private ambiguous = false;
  constructor(private client = api, private storage = () => window.sessionStorage) {}
  subscribe = (listener: () => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  snapshot = () => this.state;
  serverSnapshot = () => INITIAL;
  private set(change: Partial<SubmissionState>) {
    this.state = { ...this.state, ...change };
    this.listeners.forEach(listener => listener());
  }
  private store(operation: (storage: StorageLike) => void) {
    if (!optionalStorage(operation, this.storage)) this.set({ storageAvailable: false });
  }
  async restore() {
    if (this.busy || this.state.pending) return;
    let raw: string | null = null;
    this.store(storage => { raw = storage.getItem(PENDING_KEY); });
    if (!raw) return;
    this.busy = true;
    this.set({ phase: 'preparing' });
    try {
      const saved = JSON.parse(raw) as { mnemonic: string; dto: CreateCaseDto };
      const secrets = await deriveReporterSecrets(saved.mnemonic);
      try {
        await verifyManifest(saved.dto.manifest, secrets);
        if (saved.dto.protocolVersion !== 2 || saved.dto.caseId !== saved.dto.manifest.caseId || saved.dto.encryptedReport !== saved.dto.manifest.encryptedReport ||
            saved.dto.reporterPublicKey !== secrets.publicKeyBase64 || saved.dto.caseAccessTokenHash !== secrets.caseAccessTokenHashBase64) {
          throw new Error('Invalid pending submission.');
        }
      } finally { wipeMemory(secrets.privateKey, secrets.signingPrivateKey, secrets.caseAccessToken, secrets.caseAccessTokenHash); }
      this.set({ pending: { ...saved, uploads: [] }, phase: 'unknown', error: 'An earlier submission may have completed. Check or retry this same report.' });
      this.ambiguous = true;
    } catch {
      this.set({ phase: 'failed', error: 'Saved submission could not be verified. Keep your saved words and check Track before starting another report.' });
    } finally { this.busy = false; }
  }
  async prepare(text: string, files: File[]) {
    if (this.busy || this.state.pending) return;
    this.busy = true;
    this.set({ phase: 'preparing', error: null });
    let secrets: Awaited<ReturnType<typeof generateReporterBundle>>['secrets'] | undefined;
    try {
      const uploads = await prepareAttachments(text.trim(), files);
      const identity = await this.client.getInvestigatorPublicKey();
      if (!identity.signingPublicKey || !identity.identitySignature) throw new Error('Initialize a pinned v2 investigator identity first.');
      const generated = await generateReporterBundle(); secrets = generated.secrets;
      const manifest = await createReportManifest(checkedPayload(text.trim(), uploads.map(x => x.metadata)),
        { ...identity, signingPublicKey: identity.signingPublicKey, identitySignature: identity.identitySignature }, secrets);
      const dto: CreateCaseDto = { protocolVersion: 2, manifest, caseId: manifest.caseId,
        reporterPublicKey: secrets.publicKeyBase64, caseAccessTokenHash: secrets.caseAccessTokenHashBase64,
        encryptedReport: manifest.encryptedReport, attachmentIds: uploads.map(x => x.metadata.attachmentId) };
      this.set({ pending: { mnemonic: generated.mnemonic, dto, uploads }, phase: 'ready' });
      this.store(storage => storage.setItem(MNEMONIC_KEY, generated.mnemonic));
    } catch (error) {
      this.set({ phase: 'failed', error: error instanceof Error ? error.message : 'Could not prepare the report. Nothing was submitted.' });
    } finally {
      wipeMemory(secrets?.privateKey, secrets?.signingPrivateKey, secrets?.caseAccessToken, secrets?.caseAccessTokenHash);
      this.busy = false;
    }
  }
  async send() {
    if (this.busy || !this.state.pending || this.state.phase === 'success') return;
    this.busy = true;
    const pending = this.state.pending;
    let transmitted = this.state.phase === 'unknown';
    const authentication = await deriveReporterSecrets(pending.mnemonic);
    try {
      this.set({ phase: 'uploading', error: null });
      await uploadPrepared(pending.uploads, { stagingToken: pending.dto.caseAccessTokenHash, reporter: authentication }, this.client.uploadAttachment);
      this.store(storage => storage.setItem(PENDING_KEY, JSON.stringify({ mnemonic: pending.mnemonic, dto: pending.dto })));
      this.set({ phase: 'sending' });
      transmitted = true;
      const response = await this.client.createCase(pending.dto);
      if (response.caseId !== pending.dto.caseId) throw new Error('Submission acknowledgement mismatch.');
      this.confirm();
    } catch (error) {
      if (transmitted) {
        try {
          const recovered = await this.client.accessCase(pending.dto.caseId, pending.dto.caseAccessTokenHash, authentication);
          const secrets = await deriveReporterSecrets(pending.mnemonic);
          try { if (recovered.protocolVersion !== 2 || recovered.caseId !== pending.dto.caseId ||
              recovered.reporterPublicKey !== pending.dto.reporterPublicKey || !recovered.manifest ||
              recovered.manifest.reportSignature !== pending.dto.manifest.reportSignature) throw new Error();
            await verifyManifest(recovered.manifest, secrets);
          } finally { wipeMemory(secrets.privateKey, secrets.signingPrivateKey, secrets.caseAccessToken, secrets.caseAccessTokenHash); }
          this.confirm(); return;
        } catch { /* absence now cannot prove a timed-out request will not commit later */ }
      }
      const definite = !this.ambiguous && (!transmitted || (error instanceof ApiError && error.status >= 400 && error.status < 500));
      if (!definite) this.ambiguous = true;
      this.set({ phase: definite ? 'failed' : 'unknown', error: definite
        ? 'This attempt was rejected or stopped before report submission. Keep your words; retry this same report. ' + (error instanceof Error ? error.message : '')
        : 'Submission status is unknown. Keep these words. Check or retry this same report; do not create a new report.' });
    } finally { wipeMemory(authentication.privateKey, authentication.signingPrivateKey, authentication.caseAccessToken, authentication.caseAccessTokenHash); this.busy = false; }
  }
  private confirm() {
    // UI confirmation comes first. Optional storage can never turn it into failure.
    this.set({ phase: 'success', error: null });
    this.store(storage => { storage.removeItem(PENDING_KEY); storage.setItem(MNEMONIC_KEY, this.state.pending!.mnemonic); });
  }
  editDraft() {
    if (this.busy || this.ambiguous || !['ready', 'failed'].includes(this.state.phase)) return;
    this.store(storage => storage.removeItem(PENDING_KEY));
    this.set({ pending: null, phase: 'idle', error: null });
  }
}
