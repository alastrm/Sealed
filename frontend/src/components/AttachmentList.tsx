'use client';

import { useState } from 'react';
import { Download, Loader2, AlertCircle } from 'lucide-react';
import { api } from '@/lib/api';
import { decryptAttachmentFile, triggerSafeDownload } from '@/lib/crypto';
import type { AttachmentMetadata } from '@/lib/types';

interface AttachmentListProps {
  attachments: AttachmentMetadata[];
  title?: string;
}

export function AttachmentList({ attachments, title = 'Вложения:' }: AttachmentListProps) {
  const [downloadingId, setDownloadingId] = useState<string | null>(null);
  const [downloadError, setDownloadError] = useState<string | null>(null);

  if (!attachments || attachments.length === 0) {
    return null;
  }

  function formatBytes(bytes: number): string {
    if (bytes < 1024) return `${bytes} Б`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} КБ`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} МБ`;
  }

  async function handleDownload(att: AttachmentMetadata) {
    setDownloadingId(att.attachmentId);
    setDownloadError(null);

    try {
      const rawBuffer = await api.downloadAttachment(att.attachmentId);
      const ciphertextBytes = new Uint8Array(rawBuffer);

      const decryptedBytes = await decryptAttachmentFile(
        ciphertextBytes,
        att.keyBase64,
        att.nonceBase64,
        att.bucketSize
      );

      triggerSafeDownload(decryptedBytes, att.originalName, att.mimeType);
    } catch (err: unknown) {
      console.error(err);
      const msg = err instanceof Error ? err.message : 'Не удалось расшифровать файл';
      setDownloadError(msg);
    } finally {
      setDownloadingId(null);
    }
  }

  return (
    <div className="space-y-2 pt-1">
      <div className="text-xs text-zinc-400">
        {title}
      </div>

      {downloadError && (
        <div className="p-2 rounded-lg bg-red-950/20 border border-red-500/20 text-red-300 text-xs flex items-center gap-2">
          <AlertCircle className="w-3.5 h-3.5 text-red-400 flex-shrink-0" />
          <span>{downloadError}</span>
        </div>
      )}

      <div className="flex flex-wrap gap-2">
        {attachments.map((att) => {
          const isDownloading = downloadingId === att.attachmentId;

          return (
            <div
              key={att.attachmentId}
              className="inline-flex items-center gap-3 px-3 py-2 rounded-lg bg-neutral-900/60 border border-white/5 text-xs text-zinc-200"
            >
              <div className="flex items-center gap-2 min-w-0">
                <span className="truncate max-w-[160px]" title={att.originalName}>
                  {att.originalName}
                </span>
                <span className="text-zinc-500 font-mono text-[11px]">
                  {formatBytes(att.sizeBytes)}
                </span>
              </div>

              <button
                type="button"
                onClick={() => handleDownload(att)}
                disabled={isDownloading}
                className="text-zinc-400 hover:text-white transition-colors cursor-pointer disabled:opacity-50"
                title="Скачать файл"
              >
                {isDownloading ? (
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <Download className="w-3.5 h-3.5" />
                )}
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
}
