'use client';

import { useRef } from 'react';
import { Paperclip, X } from 'lucide-react';
import { ATTACHMENT_BUCKET_SIZES, getAttachmentBucketSize } from '@/lib/crypto';

interface AttachmentPickerProps {
  files: File[];
  onChange: (files: File[]) => void;
  disabled?: boolean;
}

export function AttachmentPicker({ files, onChange, disabled }: AttachmentPickerProps) {
  const inputRef = useRef<HTMLInputElement>(null);

  function formatBytes(bytes: number): string {
    if (bytes < 1024) return `${bytes} Б`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} КБ`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} МБ`;
  }

  function handleFileSelect(e: React.ChangeEvent<HTMLInputElement>) {
    if (!e.target.files) return;
    const selected = Array.from(e.target.files);
    const valid: File[] = [];

    for (const file of selected) {
      if (file.size >= ATTACHMENT_BUCKET_SIZES[ATTACHMENT_BUCKET_SIZES.length - 1]) {
        alert(`Файл "${file.name}" (${formatBytes(file.size)}) превышает максимальный лимит 10 МБ.`);
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
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md border border-white/[0.08] bg-white/[0.03] hover:bg-white/[0.08] text-zinc-300 hover:text-white text-xs font-mono transition-colors disabled:opacity-50"
        >
          <Paperclip className="w-3.5 h-3.5 text-zinc-400" />
          <span>Прикрепить вложение (Evidence)</span>
        </button>

        <span className="text-[10px] font-mono text-zinc-500">
          Слепое хранилище &bull; до 10 МБ &bull; паддинг
        </span>
      </div>

      {files.length > 0 && (
        <div className="space-y-2 pt-1">
          <div className="p-2 rounded-md bg-black/40 border border-white/[0.06] text-[11px] font-mono text-zinc-400">
            Метаданные (имя, MIME) зашифрованы E2EE. Файл будет дополнен паддингом до корзины (256 КБ, 1 МБ, 5 МБ, 10 МБ).
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {files.map((file, idx) => {
              let bucketSize = 0;
              try {
                bucketSize = getAttachmentBucketSize(file.size);
              } catch {
                bucketSize = 0;
              }

              return (
                <div
                  key={`${file.name}-${idx}`}
                  className="flex items-center justify-between gap-2 p-2.5 rounded-md border border-white/[0.08] bg-black/60 text-xs"
                >
                  <div className="min-w-0 flex-1">
                    <p className="text-zinc-200 font-medium truncate" title={file.name}>
                      {file.name}
                    </p>
                    <p className="text-[10px] font-mono text-zinc-500 mt-0.5">
                      {formatBytes(file.size)} &rarr; корзина {formatBytes(bucketSize)}
                    </p>
                  </div>

                  <button
                    type="button"
                    onClick={() => handleRemove(idx)}
                    disabled={disabled}
                    className="p-1 rounded-md text-zinc-500 hover:text-red-400 hover:bg-white/[0.04] transition-colors"
                    title="Удалить файл"
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
