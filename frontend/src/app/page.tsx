'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import {
  Lock,
  Copy,
  Check,
  ArrowRight,
  ShieldAlert,
  Loader2,
  RefreshCw,
  EyeOff,
  Database,
  Terminal,
} from 'lucide-react';
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

      // 3. Process and encrypt all attachments with bucket padding
      const attachmentsMeta: AttachmentMetadata[] = [];
      const attachmentIds: string[] = [];

      for (const file of selectedFiles) {
        const fileBuffer = await file.arrayBuffer();
        const fileBytes = new Uint8Array(fileBuffer);

        // Encrypt with ephemeral key & apply bucket padding (256KB, 1MB, 5MB, 10MB)
        const encrypted = await encryptAttachmentFile(
          fileBytes,
          file.name,
          file.type
        );

        // Upload blind encrypted blob to backend
        const uploadRes = await api.uploadAttachment(encrypted.fileBlob);
        encrypted.metadata.attachmentId = uploadRes.attachmentId;

        attachmentsMeta.push(encrypted.metadata);
        attachmentIds.push(uploadRes.attachmentId);
      }

      // 4. Pack plaintext with Zero-Knowledge attachment metadata
      const packedPayload = packMessagePayload(reportText.trim(), attachmentsMeta);

      // 5. Encrypt packed payload using crypto_box_seal (Anonymous Sealed Box)
      const encryptedReport = await encryptReport(packedPayload, pubKeyData.publicKey);

      // 6. Submit to blind backend with associated attachment IDs
      await api.createCase({
        caseId: crypto.randomUUID(),
        reporterPublicKey: secrets.publicKeyBase64,
        caseAccessTokenHash: secrets.caseAccessTokenHashBase64,
        encryptedReport,
        attachmentIds: attachmentIds.length > 0 ? attachmentIds : undefined,
      });

      // 7. Store in state & prefill session storage for frictionless track transition
      sessionStorage.setItem('sealed_mnemonic', mnemonic);
      setCreatedMnemonic(mnemonic);
      setReportText('');
      setSelectedFiles([]);
    } catch (err: unknown) {
      console.error(err);
      const msg = err instanceof Error ? err.message : 'Неизвестная ошибка';
      setError(msg || 'Ошибка при отправке обращения. Убедитесь, что бэкенд запущен.');
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
          <div className="flex items-center gap-2 text-xs font-mono text-emerald-400">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            <span>Шифрование завершено • Отчёт отправлен</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-semibold tracking-tight text-[#ededed]">
            Ключ доступа <span className="font-light text-zinc-500">— 12 слов BIP-39</span>
          </h1>
          <p className="text-sm font-light text-zinc-400 leading-relaxed max-w-2xl">
            Сервер сохранил зашифрованный блок и не знает вашего имени, IP или текста. Сохраните мнемонику: это ваш единственный ключ для проверки статуса и расшифровки ответов.
          </p>
        </div>

        {/* 12 Words Box */}
        <div className="border border-white/[0.08] bg-[#0e0e0e]/80 rounded-lg p-5 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-white/[0.06]">
            <span className="text-[11px] font-mono text-zinc-500 uppercase tracking-wider">
              Mnemonic Seed (128-bit entropy)
            </span>
            <button
              onClick={handleCopyMnemonic}
              className="inline-flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md border border-white/[0.08] bg-white/[0.03] text-zinc-300 hover:text-white hover:bg-white/[0.08] transition-colors"
            >
              {copied ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Скопировано</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5 text-zinc-400" />
                  <span>Копировать</span>
                </>
              )}
            </button>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
            {words.map((word, idx) => (
              <div
                key={idx}
                className="flex items-center gap-2 px-3 py-2 rounded-md bg-black/60 border border-white/[0.06] select-all font-mono"
              >
                <span className="text-[11px] text-zinc-600 w-4 text-right">
                  {idx + 1}.
                </span>
                <span className="text-xs text-zinc-200 font-medium">
                  {word}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Actions */}
        <div className="flex items-center gap-3 pt-2">
          <button
            onClick={handleGoToTrack}
            className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-[#ededed] text-[#0a0a0a] text-xs sm:text-sm font-medium hover:bg-white transition-opacity"
          >
            <span>Перейти к переписке</span>
            <ArrowRight className="w-4 h-4" />
          </button>
          <button
            onClick={() => setCreatedMnemonic(null)}
            className="inline-flex items-center gap-1.5 px-4 py-2.5 rounded-lg text-xs text-zinc-400 hover:text-zinc-200 hover:bg-white/[0.04] transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5 text-zinc-500" />
            <span>Новое обращение</span>
          </button>
        </div>
      </div>
    );
  }

  // --- SCREEN: INITIAL SUBMISSION FORM ---
  return (
    <div className="space-y-8 animate-in fade-in duration-200">
      {/* Hero Header */}
      <section className="space-y-3">
        <div className="flex items-center gap-2 text-xs font-mono text-zinc-500">
          <span>Zero-Knowledge Relay</span>
          <span className="text-zinc-700">/</span>
          <span>Libsodium X25519</span>
          <span className="text-zinc-700">/</span>
          <span>4KB Padding</span>
        </div>
        <h1 className="text-2xl sm:text-3xl font-semibold tracking-tight text-[#ededed]">
          Анонимный ящик доверия
          <span className="font-light text-zinc-500"> — E2EE, Zero-Knowledge.</span>
        </h1>
        <p className="text-sm font-light text-zinc-400 leading-relaxed max-w-2xl">
          Передайте факты нарушений в полной безопасности. Содержимое шифруется в вашем браузере до отправки. Следователь расшифрует отчёт персональным ключом, а сервер сохранит только нечитаемый шифртекст.
        </p>
      </section>

      {/* Submission Form */}
      <form
        onSubmit={handleSubmit}
        className="border border-white/[0.08] bg-[#0e0e0e]/70 backdrop-blur-sm rounded-lg p-5 sm:p-6 space-y-4"
      >
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <label htmlFor="report" className="text-xs font-medium text-zinc-300">
              Текст сообщения
            </label>
            <span className="text-[11px] font-mono text-zinc-500">
              {reportText.length} симв.
            </span>
          </div>
          <textarea
            id="report"
            rows={7}
            value={reportText}
            onChange={(e) => setReportText(e.target.value)}
            placeholder="Опишите ситуацию: факты, даты, вовлечённые лица. Избегайте сведений, которые могут непреднамеренно деанонимизировать вас..."
            className="w-full rounded-md bg-black/60 border border-white/[0.08] px-3.5 py-3 text-sm text-[#ededed] placeholder:text-zinc-600 focus:outline-none focus:border-zinc-500 focus:ring-0 transition-all font-sans resize-y leading-relaxed"
            required
          />
        </div>

        {/* Zero-Knowledge Evidence Upload Picker */}
        <AttachmentPicker
          files={selectedFiles}
          onChange={setSelectedFiles}
          disabled={isSubmitting}
        />

        {error && (
          <div className="p-3 rounded-md border border-red-500/30 bg-red-950/20 text-red-300 text-xs">
            {error}
          </div>
        )}

        <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 pt-3 border-t border-white/[0.06]">
          <div className="flex items-center gap-1.5 text-[11px] font-mono text-zinc-500">
            <span className="w-1.5 h-1.5 rounded-full bg-zinc-600"></span>
            <span>Client sealed: crypto_box_seal (ephemeral key discarded)</span>
          </div>

          <button
            type="submit"
            disabled={isSubmitting || !reportText.trim()}
            className="inline-flex items-center justify-center gap-2 px-5 py-2.5 rounded-lg bg-[#ededed] text-[#0a0a0a] text-xs sm:text-sm font-medium hover:bg-white disabled:opacity-40 disabled:cursor-not-allowed transition-all"
          >
            {isSubmitting ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin text-[#0a0a0a]" />
                <span>Шифрование...</span>
              </>
            ) : (
              <>
                <span>Запечатать и отправить</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </>
            )}
          </button>
        </div>
      </form>
    </div>
  );
}

