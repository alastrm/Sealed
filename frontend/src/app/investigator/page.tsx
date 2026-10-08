'use client';

import { useState } from 'react';
import {
  Unlock,
  AlertTriangle,
  Loader2,
  FileText,
  Send,
  CheckCircle2,
  UserCheck,
  LogOut,
  RefreshCw,
  ArrowRight,
} from 'lucide-react';
import { useInvestigatorSession } from '@/hooks/useInvestigatorSession';
import type { InvestigatorCaseListItem } from '@/lib/types';
import { AuditBadge } from '@/components/AuditBadge';
import { AttachmentList } from '@/components/AttachmentList';
import { AttachmentPicker } from '@/components/AttachmentPicker';

export default function InvestigatorPortalPage() {
  const {
    username,
    setUsername,
    password,
    setPassword,
    isUnlocking,
    loginError,
    account,
    privateKey,
    cases,
    isLoadingCases,
    selectedCaseId,
    selectedCase,
    decryptedReportText,
    reportAttachments,
    isDecryptingReport,
    threadMessages,
    isLoadingThread,
    isSendingReply,
    replySuccess,
    actionError,
    auditVerification,
    isVerifyingAudit,
    login,
    loadCases,
    selectCase,
    sendReply,
    logout,
    fetchAuditVerification,
  } = useInvestigatorSession();

  // Local form state for draft reply
  const [replyText, setReplyText] = useState('');
  const [replyFiles, setReplyFiles] = useState<File[]>([]);

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault();
    await login();
  }

  async function handleSelectCase(c: InvestigatorCaseListItem) {
    setReplyText('');
    setReplyFiles([]);
    await selectCase(c);
  }

  async function handleSendReply(e: React.FormEvent) {
    e.preventDefault();
    const success = await sendReply(replyText, replyFiles);
    if (success) {
      setReplyText('');
      setReplyFiles([]);
    }
  }

  // =========================================================================
  // VIEW: UNLOCKED INVESTIGATOR DASHBOARD
  // =========================================================================
  if (account && privateKey) {
    return (
      <div className="space-y-6 animate-in fade-in duration-200">
        {/* Top Investigator Bar */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 sm:p-5 rounded-lg border border-white/[0.08] bg-[#0e0e0e]/70 backdrop-blur-sm">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-md bg-white/[0.04] border border-white/[0.08] text-zinc-300 flex items-center justify-center">
              <UserCheck className="w-4 h-4" />
            </div>
            <div>
              <div className="text-xs sm:text-sm font-medium text-[#ededed] flex items-center gap-2">
                <span>{account.username}</span>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border border-emerald-500/30 bg-emerald-950/20 text-emerald-400">
                  Ключ в памяти
                </span>
              </div>
              <p className="text-[11px] text-zinc-500 font-mono truncate max-w-sm sm:max-w-md mt-0.5">
                Pubkey: {account.publicKey}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={loadCases}
              disabled={isLoadingCases}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md border border-white/[0.08] bg-white/[0.03] hover:bg-white/[0.08] text-zinc-300 text-xs font-mono transition-colors disabled:opacity-50"
            >
              <RefreshCw className={`w-3 h-3 ${isLoadingCases ? 'animate-spin' : ''}`} />
              <span>Обновить</span>
            </button>
            <button
              onClick={logout}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md border border-white/[0.08] bg-white/[0.03] hover:border-red-500/40 hover:bg-red-950/20 text-zinc-400 hover:text-red-300 text-xs font-mono transition-colors"
            >
              <LogOut className="w-3 h-3" />
              <span>Заблокировать</span>
            </button>
          </div>
        </div>

        {/* Two-Column Workspace: Cases List & Detail View */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          {/* Left Column: Cases List */}
          <div className="lg:col-span-5 border border-white/[0.08] bg-[#0e0e0e]/70 rounded-lg p-4 space-y-3">
            <div className="flex items-center justify-between border-b border-white/[0.06] pb-3">
              <h2 className="text-xs font-mono uppercase tracking-wider text-zinc-400 flex items-center gap-2">
                <FileText className="w-3.5 h-3.5 text-zinc-500" />
                <span>Поступившие кейсы ({cases.length})</span>
              </h2>
              {isLoadingCases && <Loader2 className="w-3.5 h-3.5 text-zinc-500 animate-spin" />}
            </div>

            {cases.length === 0 ? (
              <div className="text-center py-12 text-zinc-500 text-xs font-mono">
                {isLoadingCases ? 'Загрузка списка...' : 'Обращений пока нет.'}
              </div>
            ) : (
              <div className="space-y-2 max-h-[600px] overflow-y-auto pr-1">
                {cases.map((c) => {
                  const isSelected = c.id === selectedCaseId;
                  return (
                    <div
                      key={c.id}
                      onClick={() => handleSelectCase(c)}
                      className={`p-3 rounded-md border text-left cursor-pointer transition-all ${
                        isSelected
                          ? 'bg-white/[0.06] border-white/20 text-white'
                          : 'bg-black/50 border-white/[0.06] hover:border-white/10 text-zinc-300'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2 mb-1.5">
                        <span className="font-mono text-xs font-medium truncate text-[#ededed]">
                          {c.id.slice(0, 16)}...
                        </span>
                        <span
                          className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                            c.status === 'RESPONDED'
                              ? 'border border-emerald-500/30 bg-emerald-950/20 text-emerald-400'
                              : 'border border-white/[0.08] bg-white/[0.03] text-zinc-400'
                          }`}
                        >
                          {c.status}
                        </span>
                      </div>

                      <div className="flex items-center justify-between text-[11px] text-zinc-500 font-mono">
                        <span>{new Date(c.createdAt).toLocaleDateString('ru-RU')}</span>
                        <span>{c.messageCount} ответов</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Right Column: Case Detail & Response Form */}
          <div className="lg:col-span-7 border border-white/[0.08] bg-[#0e0e0e]/70 rounded-lg p-5 sm:p-6 space-y-6">
            {!selectedCase ? (
              <div className="text-center py-20 text-zinc-500 text-xs space-y-2">
                <FileText className="w-6 h-6 mx-auto text-zinc-600" />
                <p>Выберите обращение из списка слева для расшифровки.</p>
              </div>
            ) : (
              <div className="space-y-6">
                {/* Header */}
                <div className="border-b border-white/[0.06] pb-4 space-y-3">
                  <div className="space-y-1">
                    <span className="text-[11px] uppercase font-mono text-zinc-500 block">
                      Детализация обращения
                    </span>
                    <div className="font-mono text-xs text-zinc-300 select-all">
                      {selectedCase.id}
                    </div>
                  </div>

                  {/* Cryptographic BLAKE2b Audit Chain Integrity Badge */}
                  <AuditBadge
                    verification={auditVerification}
                    isLoading={isVerifyingAudit}
                    onRefresh={() => selectedCaseId && fetchAuditVerification(selectedCaseId)}
                  />
                </div>

                {/* Decrypted Report Box */}
                <div className="space-y-3">
                  <div className="flex items-center justify-between text-xs font-medium text-zinc-300">
                    <span className="flex items-center gap-1.5">
                      <Unlock className="w-3.5 h-3.5 text-zinc-400" />
                      Расшифрованный текст обращения
                    </span>
                    <span className="text-zinc-500 font-mono text-[11px]">
                      Sealed Box &bull; Client Decrypted
                    </span>
                  </div>

                  {isDecryptingReport ? (
                    <div className="p-8 rounded-md bg-black/60 border border-white/[0.08] flex items-center justify-center gap-2 text-zinc-500 text-xs font-mono">
                      <Loader2 className="w-4 h-4 animate-spin text-zinc-400" />
                      <span>Расшифровка закрытого ящика...</span>
                    </div>
                  ) : decryptedReportText ? (
                    <div className="space-y-3">
                      <div className="p-4 rounded-md bg-black/60 border border-white/[0.08] text-sm text-[#ededed] whitespace-pre-wrap leading-relaxed font-sans">
                        {decryptedReportText}
                      </div>

                      {/* Attachments from Initial Sealed Report */}
                      {reportAttachments.length > 0 && (
                        <AttachmentList attachments={reportAttachments} />
                      )}
                    </div>
                  ) : (
                    <div className="p-4 rounded-md bg-red-950/20 border border-red-500/30 text-red-300 text-xs font-mono">
                      Не удалось расшифровать сообщение.
                    </div>
                  )}
                </div>

                {/* Dialogue Thread */}
                <div className="space-y-3 pt-4 border-t border-white/[0.06]">
                  <div className="flex items-center justify-between text-xs font-medium text-zinc-300">
                    <span>История диалога ({threadMessages.length})</span>
                    {isLoadingThread && (
                      <span className="flex items-center gap-1.5 text-zinc-500 text-[11px] font-mono">
                        <Loader2 className="w-3 h-3 animate-spin" />
                        Загрузка сообщений...
                      </span>
                    )}
                  </div>

                  {threadMessages.length === 0 && !isLoadingThread ? (
                    <div className="p-4 rounded-md bg-black/40 border border-white/[0.06] text-zinc-500 text-xs text-center font-mono">
                      Ответов и уточнений по этому кейсу ещё не было.
                    </div>
                  ) : (
                    <div className="space-y-3 max-h-72 overflow-y-auto pr-1">
                      {threadMessages.map((msg, idx) => {
                        const isFromReporter = (msg.senderType || msg.sender) === 'REPORTER';
                        return (
                          <div
                            key={msg.id || idx}
                            className={`p-3.5 rounded-md border space-y-2 ${
                              isFromReporter
                                ? 'bg-amber-950/10 border-amber-900/30'
                                : 'bg-black/60 border-white/[0.08]'
                            }`}
                          >
                            <div className="flex items-center justify-between">
                              <span
                                className={`text-[10px] font-mono px-1.5 py-0.5 rounded font-medium ${
                                  isFromReporter
                                    ? 'bg-amber-950/30 border border-amber-700/40 text-amber-300'
                                    : 'bg-emerald-950/30 border border-emerald-700/40 text-emerald-300'
                                }`}
                              >
                                {isFromReporter ? 'Репортёр (Аноним)' : 'Следователь (Вы)'}
                              </span>
                              <span className="text-[10px] text-zinc-500 font-mono">
                                {new Date(msg.createdAt).toLocaleString('ru-RU')}
                              </span>
                            </div>
                            <p className="text-sm text-zinc-200 whitespace-pre-wrap leading-relaxed font-sans">
                              {msg.decryptedText}
                            </p>

                            {/* Message Attachments */}
                            {msg.attachments && msg.attachments.length > 0 && (
                              <AttachmentList attachments={msg.attachments} />
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>

                {/* Reply Form */}
                <form onSubmit={handleSendReply} className="space-y-4 pt-4 border-t border-white/[0.06]">
                  <div>
                    <label htmlFor="reply" className="block text-xs font-medium text-zinc-300 mb-2">
                      Официальный ответ (шифруется публичным ключом репортёра):
                    </label>
                    <textarea
                      id="reply"
                      rows={5}
                      value={replyText}
                      onChange={(e) => setReplyText(e.target.value)}
                      placeholder="Введите текст ответа. Он будет зашифрован шифром crypto_box_easy..."
                      className="w-full rounded-md bg-black/60 border border-white/[0.08] px-3.5 py-3 text-sm text-[#ededed] placeholder:text-zinc-600 focus:outline-none focus:border-zinc-500 focus:ring-0 transition-all resize-y leading-relaxed font-sans"
                      required
                    />
                  </div>

                  {/* Attachments Picker */}
                  <AttachmentPicker
                    files={replyFiles}
                    onChange={setReplyFiles}
                    disabled={isSendingReply}
                  />

                  {actionError && (
                    <div className="p-3 rounded-md bg-red-950/20 border border-red-500/30 text-red-300 text-xs flex gap-2">
                      <AlertTriangle className="w-4 h-4 flex-shrink-0 text-red-400" />
                      <span>{actionError}</span>
                    </div>
                  )}

                  {replySuccess && (
                    <div className="p-3 rounded-md border border-emerald-500/30 bg-emerald-950/20 text-emerald-300 text-xs flex items-center gap-2">
                      <CheckCircle2 className="w-4 h-4 flex-shrink-0 text-emerald-400" />
                      <span>Ответ зашифрован и сохранён на сервере.</span>
                    </div>
                  )}

                  <div className="flex justify-end">
                    <button
                      type="submit"
                      disabled={isSendingReply || !replyText.trim()}
                      className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-[#ededed] text-[#0a0a0a] font-medium text-xs sm:text-sm hover:bg-white disabled:opacity-40 transition-all"
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
            )}
          </div>
        </div>
      </div>
    );
  }

  // =========================================================================
  // VIEW: LOGIN / UNLOCK SCREEN
  // =========================================================================
  return (
    <div className="max-w-md mx-auto space-y-6 pt-4 animate-in fade-in duration-200">
      <div className="space-y-3">
        <div className="flex items-center gap-2 text-xs font-mono text-zinc-500">
          <span>Argon2id KDF</span>
          <span className="text-zinc-700">/</span>
          <span>X25519 Decryption</span>
        </div>
        <h1 className="text-2xl font-semibold tracking-tight text-[#ededed]">
          Кабинет следователя
          <span className="font-light text-zinc-500"> — комплаенс</span>
        </h1>
        <p className="text-sm font-light text-zinc-400 leading-relaxed">
          Приватный ключ расшифровывается локально в браузере через Argon2id. Сервер хранит только зашифрованный блоб.
        </p>
      </div>

      <form
        onSubmit={handleLogin}
        className="border border-white/[0.08] bg-[#0e0e0e]/70 backdrop-blur-sm rounded-lg p-5 sm:p-6 space-y-4"
      >
        <div className="space-y-1.5">
          <label htmlFor="username" className="block text-xs font-mono uppercase text-zinc-400">
            Email / Логин:
          </label>
          <input
            id="username"
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="w-full rounded-md bg-black/60 border border-white/[0.08] px-3.5 py-2.5 text-xs text-[#ededed] placeholder:text-zinc-600 focus:outline-none focus:border-zinc-500 focus:ring-0 transition-all font-mono"
            required
          />
        </div>

        <div className="space-y-1.5">
          <label htmlFor="password" className="block text-xs font-mono uppercase text-zinc-400">
            Пароль для расшифровки:
          </label>
          <input
            id="password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full rounded-md bg-black/60 border border-white/[0.08] px-3.5 py-2.5 text-xs text-[#ededed] placeholder:text-zinc-600 focus:outline-none focus:border-zinc-500 focus:ring-0 transition-all font-mono"
            required
          />
          <p className="text-[11px] text-zinc-500 font-mono">
            Тестовый аккаунт: investigator@sealed.org / Password123!
          </p>
        </div>

        {loginError && (
          <div className="p-3 rounded-md bg-red-950/20 border border-red-500/30 text-red-300 text-xs flex gap-2">
            <AlertTriangle className="w-4 h-4 flex-shrink-0 text-red-400" />
            <span>{loginError}</span>
          </div>
        )}

        <button
          type="submit"
          disabled={isUnlocking || !password.trim()}
          className="w-full inline-flex items-center justify-center gap-2 px-5 py-2.5 rounded-lg bg-[#ededed] text-[#0a0a0a] font-medium text-xs sm:text-sm hover:bg-white transition-all disabled:opacity-40"
        >
          {isUnlocking ? (
            <>
              <Loader2 className="w-3.5 h-3.5 animate-spin text-[#0a0a0a]" />
              <span>Расшифровка Argon2id...</span>
            </>
          ) : (
            <>
              <span>Войти и разблокировать ключ</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </>
          )}
        </button>
      </form>
    </div>
  );
}
