'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { Copy, Check, ArrowRight, Loader2 } from 'lucide-react';
import { api } from '@/lib/api';
import {
  encryptAttachmentFile,
  encryptReport,
  generateReporterBundle,
  packMessagePayload,
} from '@/lib/crypto';
import type { AttachmentMetadata } from '@/lib/types';
import { AttachmentPicker } from '@/components/AttachmentPicker';

export default function ReporterHomePage() {
  const router = useRouter();
  const [reportText, setReportText] = useState('');
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Success state after submission
  const [createdMnemonic, setCreatedMnemonic] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!reportText.trim()) return;

    setIsSubmitting(true);
    setError(null);

    try {
      // 1. Fetch investigator's public key from backend
      const pubKeyData = await api.getInvestigatorPublicKey();

      // 2. Generate 12-word BIP-39 mnemonic & derive secrets
      const { mnemonic, secrets } = await generateReporterBundle();

      // 3. Process and encrypt all attachments
      const attachmentsMeta: AttachmentMetadata[] = [];
      const attachmentIds: string[] = [];

      for (const file of selectedFiles) {
        const fileBuffer = await file.arrayBuffer();
        const fileBytes = new Uint8Array(fileBuffer);

        const encrypted = await encryptAttachmentFile(
          fileBytes,
          file.name,
          file.type
        );

        const uploadRes = await api.uploadAttachment(encrypted.fileBlob);
        encrypted.metadata.attachmentId = uploadRes.attachmentId;

        attachmentsMeta.push(encrypted.metadata);
        attachmentIds.push(uploadRes.attachmentId);
      }

      // 4. Pack plaintext with attachment metadata
      const packedPayload = packMessagePayload(reportText.trim(), attachmentsMeta);

      // 5. Encrypt packed payload using crypto_box_seal
      const encryptedReport = await encryptReport(packedPayload, pubKeyData.publicKey);

      // 6. Submit to backend
      await api.createCase({
        caseId: crypto.randomUUID(),
        reporterPublicKey: secrets.publicKeyBase64,
        caseAccessTokenHash: secrets.caseAccessTokenHashBase64,
        encryptedReport,
        attachmentIds: attachmentIds.length > 0 ? attachmentIds : undefined,
      });

      // 7. Store in session & set state
      sessionStorage.setItem('sealed_mnemonic', mnemonic);
      setCreatedMnemonic(mnemonic);
      setReportText('');
      setSelectedFiles([]);
    } catch (err: unknown) {
      console.error(err);
      const msg = err instanceof Error ? err.message : 'Неизвестная ошибка';
      setError(msg || 'Ошибка при отправке обращения.');
    } finally {
      setIsSubmitting(false);
    }
  }

  function handleCopyMnemonic() {
    if (!createdMnemonic) return;
    navigator.clipboard.writeText(createdMnemonic);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  function handleGoToTrack() {
    if (createdMnemonic) {
      sessionStorage.setItem('sealed_mnemonic', createdMnemonic);
    }
    router.push('/track');
  }

  // --- SCREEN: CASE CREATED SUCCESS ---
  if (createdMnemonic) {
    const words = createdMnemonic.split(' ');

    return (
      <div className="space-y-6 animate-in fade-in duration-200">
        <div className="space-y-2">
          <h1 className="text-2xl sm:text-3xl font-semibold tracking-tight text-white">
            Ключ доступа
          </h1>
          <p className="text-sm font-light text-zinc-400 leading-relaxed">
            Сохраните эти 12 слов. Это единственный ключ для проверки ответа или продолжения диалога.
          </p>
        </div>

        <div className="space-y-4 pt-2">
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
            {words.map((word, idx) => (
              <div
                key={idx}
                className="flex items-center gap-2 px-3 py-2.5 rounded-lg bg-neutral-900/50 border border-white/5 font-mono text-xs select-all"
              >
                <span className="text-zinc-600 w-4 text-right">{idx + 1}.</span>
                <span className="text-zinc-200 font-medium">{word}</span>
              </div>
            ))}
          </div>

          <div className="flex items-center gap-3 pt-2">
            <button
              onClick={handleCopyMnemonic}
              className="inline-flex items-center gap-1.5 px-4 py-2.5 rounded-lg bg-neutral-900 hover:bg-neutral-800 text-xs text-zinc-300 transition-colors border border-white/5 cursor-pointer"
            >
              {copied ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Скопировано</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5 text-zinc-400" />
                  <span>Скопировать слова</span>
                </>
              )}
            </button>

            <button
              onClick={handleGoToTrack}
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-[#ededed] text-[#0a0a0a] text-xs font-medium hover:bg-white transition-colors cursor-pointer"
            >
              <span>Перейти к диалогу</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>
    );
  }

  // --- SCREEN: INITIAL SUBMISSION FORM ---
  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      <div className="space-y-2">
        <h1 className="text-2xl sm:text-3xl font-semibold tracking-tight text-white">
          Анонимный ящик доверия
        </h1>
        <p className="text-sm font-light text-zinc-400 leading-relaxed">
          Сообщение шифруется в браузере до отправки. Сервер не имеет доступа к содержимому.
        </p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4 pt-2">
        <div>
          <textarea
            id="report"
            rows={8}
            value={reportText}
            onChange={(e) => setReportText(e.target.value)}
            placeholder="Опишите ситуацию: факты, даты, вовлечённые лица..."
            className="w-full rounded-lg bg-neutral-900/60 border border-white/10 px-4 py-3.5 text-sm text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:border-white/20 transition-colors font-sans resize-y leading-relaxed"
            required
          />
        </div>

        <AttachmentPicker
          files={selectedFiles}
          onChange={setSelectedFiles}
          disabled={isSubmitting}
        />

        {error && (
          <div className="p-3 rounded-lg bg-red-950/20 border border-red-500/20 text-red-300 text-xs">
            {error}
          </div>
        )}

        <div className="flex items-center justify-between pt-2">
          <span className="text-xs text-zinc-500 font-mono">
            {reportText.length > 0 ? `${reportText.length} симв.` : ''}
          </span>

          <button
            type="submit"
            disabled={isSubmitting || !reportText.trim()}
            className="inline-flex items-center gap-2 px-6 py-2.5 rounded-lg bg-[#ededed] text-[#0a0a0a] text-sm font-medium hover:bg-white disabled:opacity-40 transition-all cursor-pointer"
          >
            {isSubmitting ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin text-[#0a0a0a]" />
                <span>Шифрование...</span>
              </>
            ) : (
              <span>Отправить отчёт</span>
            )}
          </button>
        </div>
      </form>
    </div>
  );
}
