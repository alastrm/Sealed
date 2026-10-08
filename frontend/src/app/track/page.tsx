'use client';

import { useState } from 'react';
import {
  CheckCircle2,
  Clock,
  ArrowRight,
  Loader2,
  MessageSquare,
  Trash2,
  RefreshCw,
  Send,
} from 'lucide-react';
import { useReporterCase } from '@/hooks/useReporterCase';
import { AuditBadge } from '@/components/AuditBadge';
import { AttachmentList } from '@/components/AttachmentList';
import { AttachmentPicker } from '@/components/AttachmentPicker';

export default function TrackCasePage() {
  const {
    mnemonicInput,
    setMnemonicInput,
    fromSession,
    setFromSession,
    isVerifying,
    error,
    caseData,
    decryptedMessages,
    auditVerification,
    isVerifyingAudit,
    isSendingReply,
    replyError,
    lookupCase,
    sendReply,
    clearSession,
    fetchAuditVerification,
  } = useReporterCase();

  // Local form state for draft reply
  const [replyText, setReplyText] = useState('');
  const [replyFiles, setReplyFiles] = useState<File[]>([]);

  // Count words entered
  const words = mnemonicInput.trim() ? mnemonicInput.trim().split(/\s+/) : [];
  const wordCount = words.length;

  async function handleLookup(e?: React.FormEvent) {
    if (e) e.preventDefault();
    await lookupCase();
  }

  async function handleSendReply(e: React.FormEvent) {
    e.preventDefault();
    const success = await sendReply(replyText, replyFiles);
    if (success) {
      setReplyText('');
      setReplyFiles([]);
    }
  }

  function getStatusBadge(status: string) {
    switch (status) {
      case 'OPEN':
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-mono border border-white/[0.08] bg-white/[0.04] text-zinc-300">
            <Clock className="w-3 h-3 text-zinc-500" />
            <span>Ожидает ответа</span>
          </span>
        );
      case 'RESPONDED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-mono border border-emerald-500/30 bg-emerald-950/20 text-emerald-400">
            <CheckCircle2 className="w-3 h-3 text-emerald-400" />
            <span>Получен ответ</span>
          </span>
        );
      case 'IN_REVIEW':
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-mono border border-white/[0.08] bg-white/[0.04] text-zinc-300">
            <Clock className="w-3 h-3 text-zinc-500" />
            <span>В обработке</span>
          </span>
        );
      case 'CLOSED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-mono border border-white/[0.08] bg-black text-zinc-500">
            Закрыт
          </span>
        );
      default:
        return (
          <span className="px-2 py-0.5 rounded text-xs font-mono border border-white/[0.08] bg-white/[0.04] text-zinc-400">
            {status}
          </span>
        );
    }
  }

  return (
    <div className="space-y-8 animate-in fade-in duration-200">
      {/* Header */}
      <section className="space-y-3">
        <div className="flex items-center gap-2 text-xs font-mono text-zinc-500">
          <span>Client-Side KDF</span>
          <span className="text-zinc-700">/</span>
          <span>BIP-39 Mnemonic</span>
          <span className="text-zinc-700">/</span>
          <span>Zero-UUID Lookup</span>
        </div>
        <h1 className="text-2xl sm:text-3xl font-semibold tracking-tight text-[#ededed]">
          Проверить статус
          <span className="font-light text-zinc-500"> — по 12 словам</span>
        </h1>
        <p className="text-sm font-light text-zinc-400 leading-relaxed max-w-2xl">
          Вам не нужно помнить UUID кейса. Введите 12 слов мнемоники: приватный ключ будет детерминированно восстановлен прямо в браузере, а сервер вернёт тред сообщений.
        </p>
      </section>

      {/* Mnemonic Input Card */}
      <form
        onSubmit={handleLookup}
        className="border border-white/[0.08] bg-[#0e0e0e]/70 backdrop-blur-sm rounded-lg p-5 sm:p-6 space-y-4"
      >
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <label htmlFor="mnemonic" className="text-xs font-medium text-zinc-300">
              12 слов мнемоники (BIP-39)
            </label>
            <div className="flex items-center gap-2">
              {fromSession && (
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border border-white/[0.08] bg-white/[0.03] text-zinc-400">
                  Текущая сессия
                </span>
              )}
              <span
                className={`text-[11px] font-mono ${
                  wordCount === 12 ? 'text-emerald-400' : 'text-zinc-500'
                }`}
              >
                {wordCount} / 12 слов
              </span>
            </div>
          </div>

          <textarea
            id="mnemonic"
            rows={3}
            value={mnemonicInput}
            onChange={(e) => {
              setMnemonicInput(e.target.value);
              setFromSession(false);
            }}
            placeholder="например: abandon ability able about above absent absorb abstract absurd abuse access accident"
            className="w-full rounded-md bg-black/60 border border-white/[0.08] px-3.5 py-3 text-sm font-mono text-[#ededed] placeholder:text-zinc-600 focus:outline-none focus:border-zinc-500 focus:ring-0 transition-all resize-y leading-relaxed"
            required
          />
        </div>

        {error && (
          <div className="p-3 rounded-md border border-red-500/30 bg-red-950/20 text-red-300 text-xs">
            {error}
          </div>
        )}

        <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 pt-2 border-t border-white/[0.06]">
          <div className="flex items-center gap-2">
            {fromSession && (
              <button
                type="button"
                onClick={clearSession}
                className="flex items-center gap-1.5 text-xs text-zinc-500 hover:text-zinc-300 transition-colors"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Очистить сессию</span>
              </button>
            )}
          </div>

          <button
            type="submit"
            disabled={isVerifying || wordCount !== 12}
            className="inline-flex items-center justify-center gap-2 px-5 py-2.5 rounded-lg bg-[#ededed] text-[#0a0a0a] text-xs sm:text-sm font-medium hover:bg-white disabled:opacity-40 disabled:cursor-not-allowed transition-all"
          >
            {isVerifying ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin text-[#0a0a0a]" />
                <span>Проверка...</span>
              </>
            ) : (
              <>
                <span>Проверить статус</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </>
            )}
          </button>
        </div>
      </form>

      {/* Authenticated Case Thread */}
      {caseData && (
        <div className="space-y-6 pt-2 animate-in fade-in duration-300">
          {/* Case Meta Box */}
          <div className="border border-white/[0.08] bg-[#0e0e0e]/70 rounded-lg p-5 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-white/[0.06]">
              <div className="flex items-center gap-3">
                <span className="text-[11px] font-mono text-zinc-500 uppercase tracking-wider">
                  Статус
                </span>
                {getStatusBadge(caseData.status)}
              </div>

              <div className="text-xs text-zinc-500 font-mono">
                Создано: {new Date(caseData.createdAt).toLocaleDateString('ru-RU')}
              </div>
            </div>

            <div className="flex items-center gap-2 text-xs text-zinc-400 font-mono">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
              <span>
                Криптографическая связь подтверждена. Ответы расшифрованы вашим приватным ключом X25519.
              </span>
            </div>

            {/* Cryptographic BLAKE2b Audit Chain Integrity Badge */}
            <AuditBadge
              verification={auditVerification}
              isLoading={isVerifyingAudit}
              onRefresh={() => caseData && fetchAuditVerification(caseData.caseId)}
            />
          </div>

          {/* Messages Thread */}
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-[#ededed]">
                История переписки ({decryptedMessages.length})
              </h2>
              <button
                onClick={() => handleLookup()}
                className="flex items-center gap-1.5 text-xs text-zinc-500 hover:text-zinc-200 transition-colors"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>Обновить тред</span>
              </button>
            </div>

            {decryptedMessages.length === 0 ? (
              <div className="border border-white/[0.07] bg-black/40 rounded-lg p-8 text-center space-y-2">
                <MessageSquare className="w-5 h-5 text-zinc-600 mx-auto" />
                <p className="text-sm text-zinc-300 font-medium">Ответов пока нет</p>
                <p className="text-xs text-zinc-500 max-w-sm mx-auto">
                  Следователь ещё не отправил ответ. Сохраните 12 слов и проверьте обращение позже.
                </p>
              </div>
            ) : (
              <div className="space-y-3">
                {decryptedMessages.map((msg) => {
                  const isMe = (msg.senderType || msg.sender) === 'REPORTER';
                  return (
                    <div
                      key={msg.id}
                      className={`border rounded-lg p-4 space-y-3 ${
                        isMe
                          ? 'border-white/[0.1] bg-white/[0.02]'
                          : 'border-white/[0.07] bg-black/60'
                      }`}
                    >
                      <div className="flex items-center justify-between text-xs pb-2 border-b border-white/[0.05]">
                        <div className="flex items-center gap-2">
                          <span className="font-medium text-[#ededed]">
                            {isMe ? 'Вы (репортёр)' : 'Следователь (комплаенс)'}
                          </span>
                          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border border-white/[0.08] bg-white/[0.03] text-zinc-400">
                            E2EE
                          </span>
                        </div>
                        <span className="font-mono text-[11px] text-zinc-500">
                          {new Date(msg.createdAt).toLocaleString('ru-RU')}
                        </span>
                      </div>

                      <p className="text-sm text-zinc-200 whitespace-pre-wrap leading-relaxed font-sans">
                        {msg.decryptedText}
                      </p>

                      {/* Decrypted Attachments */}
                      {msg.attachments && msg.attachments.length > 0 && (
                        <AttachmentList attachments={msg.attachments} />
                      )}
                    </div>
                  );
                })}
              </div>
            )}

            {/* Reporter Follow-Up Reply Form */}
            <form
              onSubmit={handleSendReply}
              className="border border-white/[0.08] bg-[#0e0e0e]/70 rounded-lg p-5 space-y-3 pt-4"
            >
              <div className="flex items-center justify-between">
                <label htmlFor="reporterReply" className="text-xs font-medium text-zinc-300">
                  Ответить следователю
                </label>
                <span className="text-[10px] font-mono text-zinc-500">
                  Двусторонний E2EE диалог
                </span>
              </div>

              <textarea
                id="reporterReply"
                rows={3}
                value={replyText}
                onChange={(e) => setReplyText(e.target.value)}
                placeholder="Напишите уточнение или ответ на вопросы следователя..."
                className="w-full rounded-md bg-black/60 border border-white/[0.08] px-3.5 py-2.5 text-xs text-[#ededed] placeholder:text-zinc-600 focus:outline-none focus:border-zinc-500 focus:ring-0 transition-all font-sans resize-y leading-relaxed"
                required
              />

              {/* Attachments Picker */}
              <AttachmentPicker
                files={replyFiles}
                onChange={setReplyFiles}
                disabled={isSendingReply}
              />

              {replyError && (
                <div className="p-2.5 rounded-md border border-red-500/30 bg-red-950/20 text-red-300 text-xs">
                  {replyError}
                </div>
              )}

              <div className="flex justify-end pt-1">
                <button
                  type="submit"
                  disabled={isSendingReply || !replyText.trim()}
                  className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-[#ededed] text-[#0a0a0a] font-medium text-xs hover:bg-white disabled:opacity-40 transition-all"
                >
                  {isSendingReply ? (
                    <>
                      <Loader2 className="w-3.5 h-3.5 animate-spin text-[#0a0a0a]" />
                      <span>Шифрование...</span>
                    </>
                  ) : (
                    <>
                      <Send className="w-3.5 h-3.5" />
                      <span>Отправить ответ</span>
                    </>
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
