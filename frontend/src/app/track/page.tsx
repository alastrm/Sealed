'use client';

import { useState } from 'react';
import {
  CheckCircle2,
  Clock,
  Loader2,
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
          <span className="inline-flex items-center gap-1.5 text-xs text-zinc-400">
            <Clock className="w-3.5 h-3.5 text-zinc-500" />
            <span>Ожидает ответа</span>
          </span>
        );
      case 'RESPONDED':
        return (
          <span className="inline-flex items-center gap-1.5 text-xs text-emerald-400">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            <span>Получен ответ</span>
          </span>
        );
      case 'IN_REVIEW':
        return (
          <span className="inline-flex items-center gap-1.5 text-xs text-zinc-400">
            <Clock className="w-3.5 h-3.5 text-zinc-500" />
            <span>В обработке</span>
          </span>
        );
      case 'CLOSED':
        return <span className="text-xs text-zinc-500">Закрыт</span>;
      default:
        return <span className="text-xs text-zinc-400">{status}</span>;
    }
  }

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      <div className="space-y-2">
        <h1 className="text-2xl sm:text-3xl font-semibold tracking-tight text-white">
          Проверить статус
        </h1>
        <p className="text-sm font-light text-zinc-400 leading-relaxed">
          Введите 12 слов, полученных при отправке обращения.
        </p>
      </div>

      <form onSubmit={handleLookup} className="space-y-4 pt-2">
        <div>
          <textarea
            id="mnemonic"
            rows={3}
            value={mnemonicInput}
            onChange={(e) => {
              setMnemonicInput(e.target.value);
              setFromSession(false);
            }}
            placeholder="например: abandon ability able about above absent absorb abstract absurd abuse access accident"
            className="w-full rounded-lg bg-neutral-900/60 border border-white/10 px-4 py-3 text-sm font-mono text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:border-white/20 transition-colors resize-y leading-relaxed"
            required
          />
        </div>

        {error && (
          <div className="p-3 rounded-lg bg-red-950/20 border border-red-500/20 text-red-300 text-xs">
            {error}
          </div>
        )}

        <div className="flex items-center justify-between pt-1">
          <div className="flex items-center gap-3">
            <span
              className={`text-xs font-mono ${
                wordCount === 12 ? 'text-emerald-400' : 'text-zinc-500'
              }`}
            >
              {wordCount} / 12 слов
            </span>

            {fromSession && (
              <button
                type="button"
                onClick={clearSession}
                className="text-xs text-zinc-500 hover:text-zinc-300 transition-colors cursor-pointer"
              >
                Очистить
              </button>
            )}
          </div>

          <button
            type="submit"
            disabled={isVerifying || wordCount !== 12}
            className="inline-flex items-center gap-2 px-6 py-2.5 rounded-lg bg-[#ededed] text-[#0a0a0a] text-sm font-medium hover:bg-white disabled:opacity-40 transition-all cursor-pointer"
          >
            {isVerifying ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin text-[#0a0a0a]" />
                <span>Проверка...</span>
              </>
            ) : (
              <span>Проверить статус</span>
            )}
          </button>
        </div>
      </form>

      {/* Authenticated Case Thread */}
      {caseData && (
        <div className="space-y-6 pt-6 border-t border-white/5 animate-in fade-in duration-300">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs text-zinc-400">
            <div className="flex items-center gap-3">
              <span>Статус:</span>
              {getStatusBadge(caseData.status)}
            </div>
            <div className="text-zinc-500 font-mono">
              Создано: {new Date(caseData.createdAt).toLocaleDateString('ru-RU')}
            </div>
          </div>

          <AuditBadge
            verification={auditVerification}
            isLoading={isVerifyingAudit}
            onRefresh={() => caseData && fetchAuditVerification(caseData.caseId)}
          />

          {/* Messages Thread */}
          <div className="space-y-4 pt-2">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-medium text-white">
                Сообщения ({decryptedMessages.length})
              </h2>
              <button
                onClick={() => handleLookup()}
                className="flex items-center gap-1.5 text-xs text-zinc-500 hover:text-zinc-300 transition-colors cursor-pointer"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>Обновить</span>
              </button>
            </div>

            {decryptedMessages.length === 0 ? (
              <div className="p-6 text-center text-xs text-zinc-500 font-mono">
                Ответов пока нет. Проверьте обращение позже.
              </div>
            ) : (
              <div className="space-y-3">
                {decryptedMessages.map((msg) => {
                  const isMe = (msg.senderType || msg.sender) === 'REPORTER';
                  return (
                    <div
                      key={msg.id}
                      className="p-4 rounded-lg bg-neutral-900/40 border border-white/5 space-y-2.5"
                    >
                      <div className="flex items-center justify-between text-xs pb-1.5 border-b border-white/5">
                        <span className="font-medium text-zinc-200">
                          {isMe ? 'Вы (репортёр)' : 'Следователь'}
                        </span>
                        <span className="font-mono text-[11px] text-zinc-500">
                          {new Date(msg.createdAt).toLocaleString('ru-RU')}
                        </span>
                      </div>

                      <p className="text-sm text-zinc-200 whitespace-pre-wrap leading-relaxed font-sans">
                        {msg.decryptedText}
                      </p>

                      {msg.attachments && msg.attachments.length > 0 && (
                        <AttachmentList attachments={msg.attachments} />
                      )}
                    </div>
                  );
                })}
              </div>
            )}

            {/* Reporter Reply Form */}
            <form onSubmit={handleSendReply} className="space-y-3 pt-4">
              <textarea
                id="reporterReply"
                rows={3}
                value={replyText}
                onChange={(e) => setReplyText(e.target.value)}
                placeholder="Напишите ответ следователю..."
                className="w-full rounded-lg bg-neutral-900/60 border border-white/10 px-4 py-3 text-sm text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:border-white/20 transition-colors font-sans resize-y leading-relaxed"
                required
              />

              <AttachmentPicker
                files={replyFiles}
                onChange={setReplyFiles}
                disabled={isSendingReply}
              />

              {replyError && (
                <div className="p-3 rounded-lg bg-red-950/20 border border-red-500/20 text-red-300 text-xs">
                  {replyError}
                </div>
              )}

              <div className="flex justify-end pt-1">
                <button
                  type="submit"
                  disabled={isSendingReply || !replyText.trim()}
                  className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-[#ededed] text-[#0a0a0a] font-medium text-xs hover:bg-white disabled:opacity-40 transition-all cursor-pointer"
                >
                  {isSendingReply ? (
                    <>
                      <Loader2 className="w-3.5 h-3.5 animate-spin text-[#0a0a0a]" />
                      <span>Шифрование...</span>
                    </>
                  ) : (
                    <>
                      <span>Отправить ответ</span>
                      <Send className="w-3.5 h-3.5" />
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
