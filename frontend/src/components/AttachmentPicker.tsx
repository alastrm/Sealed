"use client";

import { useRef, useState } from "react";
import { File, Paperclip, X } from "lucide-react";
import { validateFiles } from "@/lib/attachments";
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
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MiB`;
  }

  function handleFileSelect(e: React.ChangeEvent<HTMLInputElement>) {
    if (!e.target.files) return;
    const selected = Array.from(e.target.files);
    try {
      const combined = [...files, ...selected];
      validateFiles(combined);
      onChange(combined);
      setError(null);
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Cannot add attachments.');
    }
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

        <span className="attachment-limit">Under 10 MiB each | 10 files maximum</span>
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
