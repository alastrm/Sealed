import type { ReporterSecrets } from './crypto';
import { encryptAttachmentFile, getAttachmentBucketSize, MAX_PLAINTEXT_BYTES, packMessagePayload } from './crypto';
import type { AttachmentMetadata } from './types';
import { api } from './api';

export const MAX_ATTACHMENT_PLAINTEXT = 10 * 1024 * 1024 - 1;
export const MAX_ATTACHMENT_CIPHERTEXT = 10 * 1024 * 1024 + 16;
export const MAX_ATTACHMENT_COUNT = 10;
export const MAX_ATTACHMENT_BATCH = 32 * 1024 * 1024;

export function encryptedAttachmentSize(size: number): number {
  if (!Number.isSafeInteger(size) || size < 0) throw new Error('Invalid file size.');
  return getAttachmentBucketSize(size) + 16;
}

export function validateFiles(files: Pick<File, 'size'>[]): void {
  if (files.length > MAX_ATTACHMENT_COUNT) throw new Error('Choose at most 10 attachments.');
  const bytes = files.reduce((total, file) => total + encryptedAttachmentSize(file.size), 0);
  if (bytes > MAX_ATTACHMENT_BATCH) throw new Error('Encrypted attachments must total at most 32 MiB.');
}

export function checkedPayload(text: string, metadata: AttachmentMetadata[] = []): string {
  const payload = packMessagePayload(text, metadata);
  if (new TextEncoder().encode(payload).length > MAX_PLAINTEXT_BYTES) {
    throw new Error('Text and attachment metadata must fit within 64 KiB (UTF-8).');
  }
  return payload;
}

export interface PreparedAttachment { blob: Blob; metadata: AttachmentMetadata }

export async function prepareAttachments(text: string, files: File[]): Promise<PreparedAttachment[]> {
  validateFiles(files);
  checkedPayload(text);
  const prepared: PreparedAttachment[] = [];
  for (const file of files) {
    const bytes = new Uint8Array(await file.arrayBuffer());
    try {
      const result = await encryptAttachmentFile(bytes, file.name, file.type);
      if (result.fileBlob.size !== encryptedAttachmentSize(file.size)) throw new Error('Encrypted file size mismatch.');
      prepared.push({ blob: result.fileBlob, metadata: result.metadata });
    } finally { bytes.fill(0); }
  }
  // This preflight must finish before the first network upload.
  checkedPayload(text, prepared.map(x => x.metadata));
  return prepared;
}

export async function uploadPrepared(prepared: PreparedAttachment[], options: {
  caseId?: string; credential?: string; stagingToken?: string; reporter?: ReporterSecrets;
}, uploader = api.uploadAttachment): Promise<void> {
  for (const item of prepared) {
    const result = await uploader(item.blob, options.caseId, options.credential,
      item.metadata.attachmentId, options.stagingToken, options.reporter);
    if (result.attachmentId !== item.metadata.attachmentId || result.sizeBytes !== item.blob.size) {
      throw new Error('Upload acknowledgement does not match the prepared attachment.');
    }
  }
}
