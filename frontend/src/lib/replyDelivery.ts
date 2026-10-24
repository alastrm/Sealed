import type { ReporterSecrets } from './crypto';
import { prepareAttachments, checkedPayload, uploadPrepared, type PreparedAttachment } from './attachments';
import type { CaseMessageDto, AttachmentMetadata } from './types';
import { api, ApiError } from './api';

export interface SignedReply {
  messageId: string; nonce: string; signature: string; encryptedResponse: string;
  attachmentIds?: string[];
}
export interface PendingReply<T extends SignedReply> { dto: T; uploads: PreparedAttachment[] }
export async function prepareReply<T extends SignedReply>(text: string, files: File[],
  sign: (payload: string, attachments: AttachmentMetadata[]) => Promise<T>): Promise<PendingReply<T>> {
  const uploads = await prepareAttachments(text, files);
  const metadata = uploads.map(x => x.metadata);
  const dto = await sign(checkedPayload(text, metadata), metadata);
  dto.attachmentIds = metadata.map(x => x.attachmentId);
  return { dto, uploads };
}

export async function deliverReply<T extends SignedReply>(pending: PendingReply<T>,
  context: { caseId: string; credential?: string; reporter?: ReporterSecrets },
  send: (dto: T) => Promise<CaseMessageDto>, recover: () => Promise<CaseMessageDto[]>,
  uploader = api.uploadAttachment): Promise<CaseMessageDto> {
  await uploadPrepared(pending.uploads, context, uploader);
  try { return await send(pending.dto); }
  catch (error) {
    // M2 replay rejection remains unchanged. Recover the exact signed ID instead
    // of signing the same text a second time after a lost response.
    try {
      const delivered = (await recover()).find(x => x.id === pending.dto.messageId);
      if (delivered && delivered.caseId === context.caseId && delivered.signature === pending.dto.signature &&
          delivered.nonce === pending.dto.nonce && delivered.encryptedResponse === pending.dto.encryptedResponse) return delivered;
    } catch { /* status is still unknown; retain this exact signed operation */ }
    if (error instanceof ApiError && (error.status === 401 || error.status === 410)) throw error;
    throw new Error('Reply delivery is not confirmed. Retry to check the same signed message; your draft is retained.');
  }
}
