'use client';

import { useState } from 'react';
import { Download, File, Loader2, AlertCircle } from 'lucide-react';
import { api } from '@/lib/api';
import { decryptAttachmentFile, triggerSafeDownload } from '@/lib/crypto';
import type { AttachmentMetadata } from '@/lib/types';

interface AttachmentListProps {
  attachments: AttachmentMetadata[];
  title?: string;
}

export function AttachmentList({ attachments, title = 'Прикреплённые доказательства (Zero-Knowledge Evidence):' }: AttachmentListProps) {
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
      // 1. Download blind encrypted ciphertext blob from backend
      const rawBuffer = await api.downloadAttachment(att.attachmentId);
      const ciphertextBytes = new Uint8Array(rawBuffer);

      // 2. Decrypt in-memory in browser tab & strip bucket padding
      const decryptedBytes = await decryptAttachmentFile(
        ciphertextBytes,
        att.keyBase64,
        att.nonceBase64,
        att.bucketSize
      );

      // 3. Initiate safe browser download via temporary object URL
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
    <div className="space-y-2 pt-2">
      <div className="text-[11px] font-mono text-zinc-400 uppercase tracking-wider flex items-center gap-1.5">
        <File className="w-3.5 h-3.5 text-zinc-400" />
        <span>{title} ({attachments.length})</span>
      </div>

      {downloadError && (
        <div className="p-2 rounded-lg bg-red-950/20 border border-red-500/30 text-red-300 text-xs flex items-center gap-2">
          <AlertCircle className="w-3.5 h-3.5 text-red-400 flex-shrink-0" />
          <span>{downloadError}</span>
        </div>
      )}

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
        {attachments.map((att) => {
          const isDownloading = downloadingId === att.attachmentId;

          return (
            <div
              key={att.attachmentId}
              className="flex items-center justify-between gap-3 p-2.5 rounded-xl border border-zinc-800 bg-zinc-950/80 hover:border-zinc-700 transition-colors"
            >
              <div className="min-w-0 flex-1">
                <div className="text-xs font-medium text-zinc-200 truncate" title={att.originalName}>
                  {att.originalName}
                </div>
                <div className="text-[10px] font-mono text-zinc-500 mt-0.5 flex items-center gap-2">
                  <span>{formatBytes(att.sizeBytes)}</span>
                  {att.bucketSize && (
                    <span>• Корзина: {formatBytes(att.bucketSize)}</span>
                  )}
                </div>
              </div>

              <button
                type="button"
                onClick={() => handleDownload(att)}
                disabled={isDownloading}
                className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-zinc-700 bg-zinc-900 hover:bg-zinc-800 text-zinc-300 hover:text-white text-xs transition-colors flex-shrink-0 disabled:opacity-50"
                title="Скачать и расшифровать локально"
              >
                {isDownloading ? (
                  <>
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    <span>Расшифровка...</span>
                  </>
                ) : (
                  <>
                    <Download className="w-3.5 h-3.5" />
                    <span>Скачать</span>
                  </>
                )}
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
}
