'use client';

import { useState } from 'react';
import {
  CheckCircle2,
  Clock,
  ArrowRight,
  Shield,
  Loader2,
  MessageSquare,
  Key,
  Trash2,
  RefreshCw,
  Send,
} from 'lucide-react';
import { api } from '@/lib/api';
import {
  decryptInvestigatorResponse,
  deriveReporterSecrets,
  encryptReporterReply,
  type ReporterSecrets,
} from '@/lib/crypto';
import type { CaseAccessResponseDto, CaseMessageDto } from '@/lib/types';

export default function TrackCasePage() {
  const [mnemonicInput, setMnemonicInput] = useState(() => {
    if (typeof window !== 'undefined') {
      try {
        return sessionStorage.getItem('sealed_mnemonic') || '';
      } catch {
        return '';
      }
    }
    return '';
  });
  const [fromSession, setFromSession] = useState(() => {
    if (typeof window !== 'undefined') {
      try {
        return !!sessionStorage.getItem('sealed_mnemonic');
      } catch {
        return false;
      }
    }
    return false;
  });
  const [isVerifying, setIsVerifying] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Authenticated state
  const [caseData, setCaseData] = useState<CaseAccessResponseDto | null>(null);
  const [activeSecrets, setActiveSecrets] = useState<ReporterSecrets | null>(null);
  const [decryptedMessages, setDecryptedMessages] = useState<
    (CaseMessageDto & { decryptedText: string })[]
  >([]);

  // Reply state
  const [replyText, setReplyText] = useState('');
  const [isSendingReply, setIsSendingReply] = useState(false);
  const [replyError, setReplyError] = useState<string | null>(null);

  function handleClearSession() {
    try {
      sessionStorage.removeItem('sealed_mnemonic');
    } catch {
      // ignore
    }
    setMnemonicInput('');
    setFromSession(false);
    setCaseData(null);
    setActiveSecrets(null);
    setDecryptedMessages([]);
    setReplyText('');
  }

  // Count words entered
  const words = mnemonicInput.trim() ? mnemonicInput.trim().split(/\s+/) : [];
  const wordCount = words.length;

  async function handleLookup(e?: React.FormEvent) {
    if (e) e.preventDefault();
    const cleanMnemonic = mnemonicInput.trim();
    if (!cleanMnemonic) return;

    setIsVerifying(true);
    setError(null);

    try {
      // 1. Deterministically derive keys and token hash on client
      const secrets = await deriveReporterSecrets(cleanMnemonic);
      setActiveSecrets(secrets);

      // 2. Query blind backend purely by caseAccessTokenHash (NO UUID NEEDED)
      const res = await api.lookupCase(secrets.caseAccessTokenHashBase64);
      setCaseData(res);

      // 3. Decrypt each message locally using reporter's derived private key
      const decrypted = await Promise.all(
        res.messages.map(async (msg) => {
          try {
            const text = await decryptInvestigatorResponse(msg, secrets.privateKey);
            return { ...msg, decryptedText: text };
          } catch {
            return {
              ...msg,
              decryptedText: '[Ошибка расшифровки: сообщение повреждено или не адресовано вам]',
            };
          }
        })
      );

      setDecryptedMessages(decrypted);
    } catch (err: unknown) {
      console.error(err);
      const errMsg = err instanceof Error ? err.message : '';
      if (errMsg.includes('404') || errMsg.includes('не найдено')) {
        setError('Обращение с такой мнемонической фразой не найдено. Проверьте правильность введённых 12 слов.');
      } else if (errMsg.includes('Invalid 12-word BIP-39')) {
        setError('Некорректная мнемоническая фраза BIP-39. Убедитесь, что все 12 английских слов написаны правильно.');
      } else {
        setError(errMsg || 'Ошибка при запросе к серверу.');
      }
    } finally {
      setIsVerifying(false);
    }
  }

  async function handleSendReply(e: React.FormEvent) {
    e.preventDefault();
    if (!replyText.trim() || !caseData || !activeSecrets) return;

    setIsSendingReply(true);
    setReplyError(null);

    try {
      const pubKeyData = await api.getInvestigatorPublicKey();
      const { encryptedMessage, nonce } = await encryptReporterReply(
        replyText.trim(),
        pubKeyData.publicKey,
        activeSecrets.privateKey
      );

      const newMsg = await api.sendReporterReply(
        {
          caseAccessTokenHash: activeSecrets.caseAccessTokenHashBase64,
          encryptedMessage,
          nonce,
          investigatorPublicKey: pubKeyData.publicKey,
        },
        caseData.caseId
      );

      setCaseData((prev) => (prev ? { ...prev, status: 'IN_REVIEW' } : prev));
      setDecryptedMessages((prev) => [
        ...prev,
        { ...newMsg, decryptedText: replyText.trim() },
      ]);
      setReplyText('');
    } catch (err: unknown) {
      console.error(err);
      const msg = err instanceof Error ? err.message : '';
      setReplyError(msg || 'Не удалось отправить ответ следователю.');
    } finally {
      setIsSendingReply(false);
    }
  }

  function getStatusBadge(status: string) {
    switch (status) {
      case 'OPEN':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono border border-zinc-700 bg-zinc-900 text-zinc-300">
            <Clock className="w-3 h-3 text-zinc-400" />
            Ожидает рассмотрения
          </span>
        );
      case 'RESPONDED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono border border-emerald-500/40 bg-emerald-950/20 text-emerald-400">
            <CheckCircle2 className="w-3 h-3 text-emerald-400" />
            Получен ответ
          </span>
        );
      case 'IN_REVIEW':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono border border-zinc-700 bg-zinc-900 text-zinc-300">
            <Clock className="w-3 h-3 text-zinc-400" />
            В обработке
          </span>
        );
      case 'CLOSED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono border border-zinc-800 bg-zinc-950 text-zinc-400">
            Закрыт
          </span>
        );
      default:
        return (
          <span className="px-2 py-0.5 rounded text-xs font-mono border border-zinc-800 bg-zinc-900 text-zinc-400">
            {status}
          </span>
        );
    }
  }

  return (
    <div className="space-y-8 animate-in fade-in duration-200">
      {/* Header */}
      <div className="space-y-2">
        <div className="flex items-center gap-2 text-xs font-mono text-zinc-400">
          <Key className="w-3.5 h-3.5 text-zinc-400" />
          <span>Детерминированный доступ без идентификатора</span>
        </div>
        <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-white">
          Проверить статус обращения
        </h1>
        <p className="text-zinc-400 text-sm leading-relaxed">
          Вам не нужно помнить технический ID кейса. Введите 12 слов, полученных при отправке. Приватный ключ будет восстановлен в браузере, а сервер вернёт зашифрованные ответы.
        </p>
      </div>

      {/* Mnemonic Input Card */}
      <form onSubmit={handleLookup} className="border border-zinc-800/90 bg-zinc-950/40 rounded-2xl p-6 space-y-4">
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <label htmlFor="mnemonic" className="text-xs font-semibold text-zinc-200 tracking-wide">
              12 слов мнемоники (BIP-39)
            </label>
            <div className="flex items-center gap-2">
              {fromSession && (
                <span className="text-[10px] font-mono px-2 py-0.5 rounded border border-zinc-800 bg-zinc-900 text-zinc-400">
                  Из текущей сессии
                </span>
              )}
              <span
                className={`text-[11px] font-mono ${
                  wordCount === 12 ? 'text-zinc-300' : 'text-zinc-400'
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
            className="w-full rounded-xl bg-black border border-zinc-800 px-4 py-3 text-sm font-mono text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-500 focus:ring-1 focus:ring-zinc-500 transition-all resize-y leading-relaxed"
            required
          />
        </div>

        {error && (
          <div className="p-3.5 rounded-xl border border-red-500/30 bg-red-950/20 text-red-300 text-xs">
            {error}
          </div>
        )}

        <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 pt-1 border-t border-zinc-900">
          <div className="flex items-center gap-2">
            {fromSession && (
              <button
                type="button"
                onClick={handleClearSession}
                className="flex items-center gap-1.5 text-xs text-zinc-400 hover:text-zinc-300 transition-colors"
              >
                <Trash2 className="w-3.5 h-3.5" />
                <span>Очистить память сессии</span>
              </button>
            )}
          </div>

          <button
            type="submit"
            disabled={isVerifying || wordCount !== 12}
            className="flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl bg-white text-black font-medium text-sm hover:bg-zinc-200 disabled:opacity-40 disabled:cursor-not-allowed transition-all"
          >
            {isVerifying ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin text-black" />
                <span>Проверка...</span>
              </>
            ) : (
              <>
                <span>Проверить статус</span>
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
        </div>
      </form>

      {/* Authenticated Case Thread */}
      {caseData && (
        <div className="space-y-6 pt-4 animate-in fade-in duration-300">
          {/* Case Meta Box */}
          <div className="border border-zinc-800 bg-zinc-950/70 rounded-2xl p-6 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-zinc-900">
              <div className="space-y-1">
                <span className="text-[11px] font-mono uppercase tracking-wider text-zinc-400">
                  Статус обращения
                </span>
                <div className="flex items-center gap-3">
                  {getStatusBadge(caseData.status)}
                </div>
              </div>

              <div className="text-right text-xs text-zinc-400 font-mono">
                Создано: {new Date(caseData.createdAt).toLocaleString('ru-RU')}
              </div>
            </div>

            <div className="flex items-center gap-2 text-xs text-zinc-400 font-mono">
              <Shield className="w-3.5 h-3.5 text-zinc-400" />
              <span>
                Криптографическая связь подтверждена. Ответы расшифровываются вашим ключом X25519.
              </span>
            </div>
          </div>

          {/* Messages Thread */}
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-zinc-200">
                Переписка по обращению ({decryptedMessages.length})
              </h2>
              <button
                onClick={() => handleLookup()}
                className="flex items-center gap-1.5 text-xs text-zinc-400 hover:text-zinc-200 transition-colors"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>Обновить</span>
              </button>
            </div>

            {decryptedMessages.length === 0 ? (
              <div className="border border-zinc-900 bg-zinc-950/30 rounded-2xl p-8 text-center space-y-2">
                <MessageSquare className="w-6 h-6 text-zinc-400 mx-auto" />
                <p className="text-sm text-zinc-300 font-medium">Ответов пока нет</p>
                <p className="text-xs text-zinc-400 max-w-sm mx-auto">
                  Следователь рассматривает ваше обращение. Сохраните 12 слов и проверьте статус позже.
                </p>
              </div>
            ) : (
              <div className="space-y-3">
                {decryptedMessages.map((msg) => {
                  const isMe = (msg.senderType || msg.sender) === 'REPORTER';
                  return (
                    <div
                      key={msg.id}
                      className={`border rounded-2xl p-5 space-y-3 ${
                        isMe
                          ? 'border-zinc-700 bg-zinc-900/60'
                          : 'border-zinc-800 bg-zinc-950/80'
                      }`}
                    >
                      <div className="flex items-center justify-between text-xs pb-2 border-b border-zinc-900">
                        <div className="flex items-center gap-2">
                          <span className="font-semibold text-zinc-200">
                            {isMe ? 'Вы (репортёр)' : 'Следователь (комплаенс)'}
                          </span>
                          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border border-zinc-800 bg-zinc-900 text-zinc-400">
                            E2EE Box
                          </span>
                        </div>
                        <span className="font-mono text-[11px] text-zinc-400">
                          {new Date(msg.createdAt).toLocaleString('ru-RU')}
                        </span>
                      </div>

                      <p className="text-sm text-zinc-200 whitespace-pre-wrap leading-relaxed font-sans">
                        {msg.decryptedText}
                      </p>

                      <div className="pt-1 text-[11px] font-mono text-zinc-400">
                        &bull; Аутентифицировано через Poly1305 MAC
                      </div>
                    </div>
                  );
                })}
              </div>
            )}

            {/* Reporter Follow-Up Reply Form */}
            <form onSubmit={handleSendReply} className="border border-zinc-800/90 bg-zinc-950/60 rounded-2xl p-5 space-y-3 pt-4">
              <div className="flex items-center justify-between">
                <label htmlFor="reporterReply" className="text-xs font-semibold text-zinc-200">
                  Ответить следователю
                </label>
                <span className="text-[10px] font-mono text-zinc-400">
                  Двусторонний E2EE диалог
                </span>
              </div>

              <textarea
                id="reporterReply"
                rows={3}
                value={replyText}
                onChange={(e) => setReplyText(e.target.value)}
                placeholder="Напишите уточнение или ответ на вопросы следователя..."
                className="w-full rounded-xl bg-black border border-zinc-800 px-4 py-2.5 text-xs text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-500 focus:ring-1 focus:ring-zinc-500 transition-all font-sans resize-y leading-relaxed"
                required
              />

              {replyError && (
                <div className="p-2.5 rounded-xl border border-red-500/30 bg-red-950/20 text-red-300 text-xs">
                  {replyError}
                </div>
              )}

              <div className="flex justify-end">
                <button
                  type="submit"
                  disabled={isSendingReply || !replyText.trim()}
                  className="flex items-center gap-2 px-4 py-2 rounded-xl bg-white text-black font-medium text-xs hover:bg-zinc-200 disabled:opacity-40 transition-all"
                >
                  {isSendingReply ? (
                    <>
                      <Loader2 className="w-3.5 h-3.5 animate-spin text-black" />
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
