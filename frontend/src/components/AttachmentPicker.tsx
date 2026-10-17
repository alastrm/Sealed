"use client";

import { useRef, useState } from "react";
import { File, Paperclip, X } from "lucide-react";
import { ATTACHMENT_BUCKET_SIZES } from "@/lib/crypto";
import { Notice } from "./ui";

interface AttachmentPickerProps {
  files: File[];
  onChange: (files: File[]) => void;
  disabled?: boolean;
}

export function AttachmentPicker({
  files,
  onChange,
  disabled,
}: AttachmentPickerProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [error, setError] = useState<string | null>(null);

  function formatBytes(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  }

  function handleFileSelect(e: React.ChangeEvent<HTMLInputElement>) {
    if (!e.target.files) return;
    const selected = Array.from(e.target.files);
    const valid: File[] = [];
    const rejected: string[] = [];

    for (const file of selected) {
      if (
        file.size >= ATTACHMENT_BUCKET_SIZES[ATTACHMENT_BUCKET_SIZES.length - 1]
      ) {
        rejected.push(file.name);
        continue;
      }
      valid.push(file);
    }

    onChange([...files, ...valid]);
    setError(
      rejected.length
        ? `Each file must be smaller than 10 MB. Not added: ${rejected.join(", ")}.`
        : null,
    );
    if (inputRef.current) {
      inputRef.current.value = "";
    }
  }

  function handleRemove(index: number) {
    onChange(files.filter((_, i) => i !== index));
  }

  return (
    <div className="attachment-area">
      <input
        ref={inputRef}
        type="file"
        multiple
        onChange={handleFileSelect}
        hidden
        aria-label="Choose attachments"
        disabled={disabled}
      />

      <div className="attachment-toolbar">
        <button
          type="button"
          onClick={() => inputRef.current?.click()}
          disabled={disabled}
          className="btn btn-small"
        >
          <Paperclip className="w-3.5 h-3.5" />
          <span>Attach files</span>
        </button>

        <span className="attachment-limit">Under 10 MB per file</span>
      </div>
      {error && (
        <div className="attachment-error">
          <Notice>{error}</Notice>
        </div>
      )}

      {files.length > 0 && (
        <div className="file-chips" aria-label="Selected attachments">
          {files.map((file, idx) => (
            <div key={`${file.name}-${idx}`} className="file-chip">
              <File size={13} />
              <span className="file-name" title={file.name}>
                {file.name}
              </span>
              <span className="file-size">{formatBytes(file.size)}</span>
              <button
                type="button"
                onClick={() => handleRemove(idx)}
                disabled={disabled}
                className="btn btn-ghost btn-icon"
                aria-label={`Remove ${file.name}`}
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
