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
      <div className="space-y-8 animate-in fade-in duration-200">
        <div className="space-y-2">
          <div className="inline-flex items-center gap-2 px-2.5 py-0.5 rounded-full border border-emerald-500/30 bg-emerald-950/20 text-emerald-400 text-xs font-mono">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            Отчёт успешно запечатан и отправлен
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-white">
            Ваш ключ доступа — 12 слов
          </h1>
          <p className="text-zinc-400 text-sm leading-relaxed">
            Сервер сохранил зашифрованный блок и не знает вашего имени, IP или содержания текста. Сохраните эти 12 слов в надёжном месте. Это ваш единственный способ прочитать ответ следователя.
          </p>
        </div>

        {/* 12 Words Box */}
        <div className="border border-zinc-800 bg-zinc-950/70 rounded-2xl p-5 space-y-4">
          <div className="flex items-center justify-between pb-1 border-b border-zinc-900">
            <span className="text-[11px] font-mono uppercase tracking-wider text-zinc-400">
              Мнемоническая фраза (BIP-39)
            </span>
            <button
              onClick={handleCopyMnemonic}
              className="flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-lg border border-zinc-800 bg-zinc-900 text-zinc-300 hover:text-white hover:border-zinc-700 transition-colors"
            >
              {copied ? (
                <>
                  <Check className="w-3.5 h-3.5 text-zinc-300" />
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
                className="flex items-center gap-2 px-3 py-2 rounded-xl bg-black border border-zinc-800/80 select-all"
              >
                <span className="text-xs font-mono text-zinc-400 w-5 text-right">
                  {idx + 1}.
                </span>
                <span className="text-sm font-mono text-zinc-200">
                  {word}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Actions */}
        <div className="flex flex-col sm:flex-row items-center gap-3 pt-2">
          <button
            onClick={handleGoToTrack}
            className="w-full sm:w-auto flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl bg-white text-black font-medium text-sm hover:bg-zinc-200 transition-colors"
          >
            <span>Перейти к переписке</span>
            <ArrowRight className="w-4 h-4" />
          </button>
          <button
            onClick={() => setCreatedMnemonic(null)}
            className="w-full sm:w-auto flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl border border-zinc-800 text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900/50 text-sm transition-colors"
          >
            <RefreshCw className="w-4 h-4 text-zinc-400" />
            <span>Отправить ещё одно обращение</span>
          </button>
        </div>
      </div>
    );
  }

  // --- SCREEN: INITIAL SUBMISSION FORM ---
  return (
    <div className="space-y-10 animate-in fade-in duration-200">
      {/* Hero Header */}
      <div className="space-y-4">
        <div className="flex items-center gap-3">
          <div className="w-12 h-12 rounded-full border border-zinc-800 bg-zinc-900 flex items-center justify-center">
            <Lock className="w-5 h-5 text-zinc-200" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-semibold text-white text-base">SEALED Protocol</span>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border border-zinc-800 bg-zinc-900 text-zinc-400">
                Zero-Knowledge
              </span>
            </div>
            <p className="text-xs text-zinc-400">End-to-End Encrypted Whistleblower Relaying</p>
          </div>
        </div>

        <div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-white">
            Анонимный ящик доверия — E2EE, Zero-Knowledge.
          </h1>
          <p className="text-zinc-400 text-sm mt-2 leading-relaxed">
            Передайте факты нарушений или злоупотреблений в полной безопасности. Содержимое шифруется прямо в вашем браузере до отправки по сети. Следователь расшифрует отчёт персональным ключом, а сервер сохранит исключительно нечитаемый шифртекст.
          </p>
        </div>
      </div>

      {/* Security Invariants - Minimalist cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <div className="p-4 rounded-xl border border-zinc-800/80 bg-zinc-950/60 space-y-1">
          <div className="flex items-center gap-2 text-zinc-200 text-xs font-semibold">
            <EyeOff className="w-4 h-4 text-zinc-400" />
            <span>Без аккаунта</span>
          </div>
          <p className="text-xs text-zinc-400 leading-relaxed">
            Никаких логинов, email или телефонных номеров.
          </p>
        </div>

        <div className="p-4 rounded-xl border border-zinc-800/80 bg-zinc-950/60 space-y-1">
          <div className="flex items-center gap-2 text-zinc-200 text-xs font-semibold">
            <Database className="w-4 h-4 text-zinc-400" />
            <span>Слепой бэкенд</span>
          </div>
          <p className="text-xs text-zinc-400 leading-relaxed">
            X25519 Sealed Box. Дамп базы данных не раскроет текст.
          </p>
        </div>

        <div className="p-4 rounded-xl border border-zinc-800/80 bg-zinc-950/60 space-y-1">
          <div className="flex items-center gap-2 text-zinc-200 text-xs font-semibold">
            <Terminal className="w-4 h-4 text-zinc-400" />
            <span>Доступ по мнемонике</span>
          </div>
          <p className="text-xs text-zinc-400 leading-relaxed">
            12 слов BIP-39 — ваш единственный криптографический ключ.
          </p>
        </div>
      </div>

      {/* Submission Form */}
      <form onSubmit={handleSubmit} className="border border-zinc-800/90 bg-zinc-950/40 rounded-2xl p-6 space-y-5">
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <label htmlFor="report" className="text-xs font-semibold text-zinc-200 tracking-wide">
              Текст сообщения
            </label>
            <span className="text-[11px] font-mono text-zinc-400">
              {reportText.length} символов
            </span>
          </div>
          <textarea
            id="report"
            rows={7}
            value={reportText}
            onChange={(e) => setReportText(e.target.value)}
            placeholder="Опишите ситуацию подробно: факты, даты, вовлечённые лица, подразделения. Избегайте информации, которая может непреднамеренно деанонимизировать вас..."
            className="w-full rounded-xl bg-black border border-zinc-800 px-4 py-3 text-sm text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-500 focus:ring-1 focus:ring-zinc-500 transition-all font-sans resize-y leading-relaxed"
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
          <div className="p-3.5 rounded-xl border border-red-500/30 bg-red-950/20 text-red-300 text-xs">
            {error}
          </div>
        )}

        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pt-1 border-t border-zinc-900">
          <div className="flex items-center gap-2 text-xs text-zinc-400">
            <ShieldAlert className="w-3.5 h-3.5 text-zinc-400" />
            <span>Клиентское шифрование: Libsodium crypto_box_seal</span>
          </div>

          <button
            type="submit"
            disabled={isSubmitting || !reportText.trim()}
            className="w-full sm:w-auto flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl bg-white text-black font-medium text-sm hover:bg-zinc-200 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
          >
            {isSubmitting ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin text-black" />
                <span>Шифрование...</span>
              </>
            ) : (
              <>
                <span>Запечатать и отправить</span>
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
        </div>
      </form>
    </div>
  );
}

