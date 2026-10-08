'use client';

import { useRef } from 'react';
import { Paperclip, X } from 'lucide-react';
import { ATTACHMENT_BUCKET_SIZES } from '@/lib/crypto';

interface AttachmentPickerProps {
  files: File[];
  onChange: (files: File[]) => void;
  disabled?: boolean;
}

export function AttachmentPicker({ files, onChange, disabled }: AttachmentPickerProps) {
  const inputRef = useRef<HTMLInputElement>(null);

  function formatBytes(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  }

  function handleFileSelect(e: React.ChangeEvent<HTMLInputElement>) {
    if (!e.target.files) return;
    const selected = Array.from(e.target.files);
    const valid: File[] = [];

    for (const file of selected) {
      if (file.size >= ATTACHMENT_BUCKET_SIZES[ATTACHMENT_BUCKET_SIZES.length - 1]) {
        alert(`File "${file.name}" exceeds the 10 MB limit.`);
        continue;
      }
      valid.push(file);
    }

    onChange([...files, ...valid]);
    if (inputRef.current) {
      inputRef.current.value = '';
    }
  }

  function handleRemove(index: number) {
    onChange(files.filter((_, i) => i !== index));
  }

  return (
    <div className="space-y-2">
      <input
        ref={inputRef}
        type="file"
        multiple
        onChange={handleFileSelect}
        className="hidden"
        disabled={disabled}
      />

      <div className="flex items-center justify-between">
        <button
          type="button"
          onClick={() => inputRef.current?.click()}
          disabled={disabled}
          className="inline-flex items-center gap-1.5 text-xs text-zinc-400 hover:text-white transition-colors cursor-pointer disabled:opacity-50"
        >
          <Paperclip className="w-3.5 h-3.5" />
          <span>Attach files</span>
        </button>

        <span className="text-[11px] text-zinc-500 font-mono">up to 10 MB</span>
      </div>

      {files.length > 0 && (
        <div className="flex flex-wrap gap-2 pt-1">
          {files.map((file, idx) => (
            <div
              key={`${file.name}-${idx}`}
              className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-neutral-900/60 border border-white/5 text-xs text-zinc-200"
            >
              <span className="truncate max-w-[180px]">{file.name}</span>
              <span className="text-zinc-500 text-[11px] font-mono">{formatBytes(file.size)}</span>
              <button
                type="button"
                onClick={() => handleRemove(idx)}
                disabled={disabled}
                className="text-zinc-500 hover:text-zinc-300 transition-colors cursor-pointer"
                title="Remove file"
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
