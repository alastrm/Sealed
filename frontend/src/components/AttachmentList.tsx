"use client";

import { useState } from "react";
import { Download, Loader2, File } from "lucide-react";
import { api } from "@/lib/api";
import { decryptAttachmentFile, triggerSafeDownload } from "@/lib/crypto";
import type { AttachmentMetadata } from "@/lib/types";
import { Notice } from "./ui";

interface AttachmentListProps {
  attachments: AttachmentMetadata[];
  title?: string;
}

export function AttachmentList({
  attachments,
  title = "Attachments",
}: AttachmentListProps) {
  const [downloadingId, setDownloadingId] = useState<string | null>(null);
  const [downloadError, setDownloadError] = useState<string | null>(null);

  if (!attachments || attachments.length === 0) {
    return null;
  }

  function formatBytes(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
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
        att.bucketSize,
      );

      triggerSafeDownload(decryptedBytes, att.originalName, att.mimeType);
    } catch (err: unknown) {
      console.error(err);
      const msg = err instanceof Error ? err.message : "Failed to decrypt file";
      setDownloadError(msg);
    } finally {
      setDownloadingId(null);
    }
  }

  return (
    <div className="attachment-list">
      <div className="muted">{title}</div>

      {downloadError && <Notice>{downloadError}</Notice>}

      <div className="file-chips">
        {attachments.map((att) => {
          const isDownloading = downloadingId === att.attachmentId;

          return (
            <div key={att.attachmentId} className="file-chip">
              <File size={13} />
              <span className="file-name" title={att.originalName}>
                {att.originalName}
              </span>
              <span className="file-size">{formatBytes(att.sizeBytes)}</span>

              <button
                type="button"
                onClick={() => handleDownload(att)}
                disabled={downloadingId !== null}
                className="btn btn-ghost btn-icon"
                aria-label={`Download ${att.originalName}`}
              >
                {isDownloading ? (
                  <Loader2 size={14} className="spin" />
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
