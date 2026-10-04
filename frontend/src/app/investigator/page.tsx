'use client';

import { useState } from 'react';
import {
  Lock,
  Unlock,
  Shield,
  AlertTriangle,
  Loader2,
  FileText,
  Send,
  CheckCircle2,
  UserCheck,
  LogOut,
} from 'lucide-react';
import { api } from '@/lib/api';
import {
  decryptReport,
  decryptCaseMessageForInvestigator,
  encryptInvestigatorReply,
  unlockInvestigatorKey,
  wipeMemory,
} from '@/lib/crypto';
import type {
  CaseMessageDto,
  InvestigatorAccountRecord,
  InvestigatorCaseListItem,
} from '@/lib/types';

export default function InvestigatorPortalPage() {
  // Login / Unlock state
  const [password, setPassword] = useState('Correct-Horse-Battery-Staple-2026!#');
  const [username, setUsername] = useState('compliance.lead@integrity-trust.corp');
  const [isUnlocking, setIsUnlocking] = useState(false);
  const [loginError, setLoginError] = useState<string | null>(null);

  // Authenticated Investigator State
  const [account, setAccount] = useState<InvestigatorAccountRecord | null>(null);
  const [privateKey, setPrivateKey] = useState<Uint8Array | null>(null);

  // Cases List State
  const [cases, setCases] = useState<InvestigatorCaseListItem[]>([]);
  const [isLoadingCases, setIsLoadingCases] = useState(false);
  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(null);

  // Case Detail / Reply State
  const [decryptedReportText, setDecryptedReportText] = useState<string | null>(null);
  const [isDecryptingReport, setIsDecryptingReport] = useState(false);
  const [threadMessages, setThreadMessages] = useState<
    Array<CaseMessageDto & { decryptedText: string }>
  >([]);
  const [isLoadingThread, setIsLoadingThread] = useState(false);
  const [replyText, setReplyText] = useState('');
  const [isSendingReply, setIsSendingReply] = useState(false);
  const [replySuccess, setReplySuccess] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  // 1. Handle Investigator Login (Unlock Private Key via Argon2id)
  async function handleLogin(e: React.FormEvent) {
    e.preventDefault();
    setIsUnlocking(true);
    setLoginError(null);

    try {
      // Fetch blind account blob from server
      const accountRecord = await api.getInvestigatorAccount(username.trim());

      // Derive KEK via Argon2id and decrypt private key in browser memory
      const unlockedKey = await unlockInvestigatorKey(accountRecord, password);

      setAccount(accountRecord);
      setPrivateKey(unlockedKey);

      // Load cases
      await loadCases();
    } catch (err: unknown) {
      console.error(err);
      const msg = err instanceof Error ? err.message : '';
      setLoginError(
        msg || 'Ошибка входа: неверный пароль или не найден аккаунт.'
      );
    } finally {
      setIsUnlocking(false);
    }
  }

  // 2. Load Cases
  async function loadCases() {
    setIsLoadingCases(true);
    setActionError(null);
    try {
      const list = await api.listInvestigatorCases();
      setCases(list);
    } catch (err: unknown) {
      console.error(err);
      setActionError('Не удалось загрузить список кейсов с сервера.');
    } finally {
      setIsLoadingCases(false);
    }
  }

  // 3. Select Case & Decrypt Sealed Report
  async function handleSelectCase(c: InvestigatorCaseListItem) {
    if (!account || !privateKey) return;

    setSelectedCaseId(c.id);
    setDecryptedReportText(null);
    setThreadMessages([]);
    setReplyText('');
    setReplySuccess(false);
    setActionError(null);
    setIsDecryptingReport(true);
    setIsLoadingThread(true);

    try {
      // 1. Decrypt Sealed Box via crypto_box_seal_open
      const text = await decryptReport(
        c.encryptedReport,
        account.publicKey,
        privateKey
      );
      setDecryptedReportText(text);

      // 2. Fetch and decrypt message thread
      const messages = await api.getCaseMessages(c.id);
      const decrypted = await Promise.all(
        messages.map(async (msg) => {
          try {
            const decText = await decryptCaseMessageForInvestigator(
              msg,
              c.reporterPublicKey,
              privateKey
            );
            return { ...msg, decryptedText: decText };
          } catch {
            return {
              ...msg,
              decryptedText: '[Ошибка расшифровки сообщения: неверный ключ или данные]',
            };
          }
        })
      );
      setThreadMessages(decrypted);
    } catch (err: unknown) {
      console.error(err);
      setActionError('Ошибка расшифровки Sealed Box сообщения: повреждённые данные.');
    } finally {
      setIsDecryptingReport(false);
      setIsLoadingThread(false);
    }
  }

  // 4. Send Encrypted Reply
  async function handleSendReply(e: React.FormEvent) {
    e.preventDefault();
    if (!selectedCaseId || !replyText.trim() || !account || !privateKey) return;

    const currentCase = cases.find((c) => c.id === selectedCaseId);
    if (!currentCase) return;

    setIsSendingReply(true);
    setActionError(null);

    try {
      // Authenticated encryption via crypto_box_easy (investigatorPrivKey -> reporterPubKey)
      const { encryptedResponse, nonce } = await encryptInvestigatorReply(
        replyText.trim(),
        currentCase.reporterPublicKey,
        privateKey
      );

      // POST to backend
      const newMsg = await api.sendInvestigatorResponse(selectedCaseId, {
        caseId: selectedCaseId,
        encryptedResponse,
        nonce,
        investigatorPublicKey: account.publicKey,
      });

      setThreadMessages((prev) => [
        ...prev,
        { ...newMsg, decryptedText: replyText.trim() },
      ]);
      setReplySuccess(true);
      setReplyText('');

      // Refresh cases list
      await loadCases();
    } catch (err: unknown) {
      console.error(err);
      const msg = err instanceof Error ? err.message : '';
      setActionError(msg || 'Ошибка отправки ответа.');
    } finally {
      setIsSendingReply(false);
    }
  }

  // 5. Logout & Wipe Memory
  function handleLogout() {
    if (privateKey) {
      wipeMemory(privateKey);
    }
    setPrivateKey(null);
    setAccount(null);
    setCases([]);
    setSelectedCaseId(null);
    setDecryptedReportText(null);
    setThreadMessages([]);
  }

  const selectedCase = cases.find((c) => c.id === selectedCaseId);

  // =========================================================================
  // VIEW: UNLOCKED INVESTIGATOR DASHBOARD
  // =========================================================================
  if (account && privateKey) {
    return (
      <div className="space-y-6 animate-in fade-in duration-200">
        {/* Top Investigator Bar */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-2xl bg-zinc-950/70 border border-zinc-800">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-zinc-900 border border-zinc-800 text-zinc-300 flex items-center justify-center">
              <UserCheck className="w-5 h-5" />
            </div>
            <div>
              <div className="text-sm font-semibold text-white flex items-center gap-2">
                <span>{account.username}</span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full border border-emerald-500/40 bg-emerald-950/20 text-emerald-400">
                  Ключ в памяти
                </span>
              </div>
              <p className="text-xs text-zinc-400 font-mono truncate max-w-sm sm:max-w-md mt-0.5">
                Pubkey: {account.publicKey}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={loadCases}
              disabled={isLoadingCases}
              className="px-3.5 py-1.5 rounded-xl border border-zinc-800 bg-zinc-900 hover:bg-zinc-800 text-zinc-300 text-xs font-medium transition-colors"
            >
              Обновить
            </button>
            <button
              onClick={handleLogout}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl border border-zinc-800 bg-zinc-900/60 hover:bg-red-950/30 text-zinc-400 hover:text-red-400 text-xs font-medium transition-colors"
            >
              <LogOut className="w-3.5 h-3.5" />
              <span>Заблокировать</span>
            </button>
          </div>
        </div>

        {/* Two-Column Workspace: Cases List & Detail View */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          {/* Left Column: Cases List */}
          <div className="lg:col-span-5 bg-zinc-950/50 border border-zinc-800 rounded-2xl p-4 space-y-3">
            <div className="flex items-center justify-between border-b border-zinc-900 pb-3">
              <h2 className="text-xs font-mono uppercase tracking-wider text-zinc-400 flex items-center gap-2">
                <FileText className="w-3.5 h-3.5 text-zinc-400" />
                <span>Поступившие кейсы ({cases.length})</span>
              </h2>
              {isLoadingCases && <Loader2 className="w-3.5 h-3.5 text-zinc-400 animate-spin" />}
            </div>

            {cases.length === 0 ? (
              <div className="text-center py-12 text-zinc-400 text-xs">
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
                      className={`p-3.5 rounded-xl border text-left cursor-pointer transition-all ${
                        isSelected
                          ? 'bg-zinc-900 border-zinc-600 text-white'
                          : 'bg-black border-zinc-800/80 hover:border-zinc-700 text-zinc-300'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2 mb-1.5">
                        <span className="font-mono text-xs font-medium truncate">
                          {c.id.slice(0, 16)}...
                        </span>
                        <span
                          className={`text-[10px] font-mono px-2 py-0.5 rounded ${
                            c.status === 'RESPONDED'
                              ? 'border border-emerald-500/40 bg-emerald-950/20 text-emerald-400'
                              : 'border border-zinc-800 bg-zinc-900 text-zinc-400'
                          }`}
                        >
                          {c.status}
                        </span>
                      </div>

                      <div className="flex items-center justify-between text-[11px] text-zinc-400 font-mono">
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
          <div className="lg:col-span-7 bg-zinc-950/50 border border-zinc-800 rounded-2xl p-6 space-y-6">
            {!selectedCase ? (
              <div className="text-center py-20 text-zinc-400 text-xs space-y-2">
                <FileText className="w-7 h-7 mx-auto text-zinc-400" />
                <p>Выберите обращение из списка слева для расшифровки.</p>
              </div>
            ) : (
              <div className="space-y-6">
                {/* Header */}
                <div className="border-b border-zinc-900 pb-4 space-y-1">
                  <span className="text-[11px] uppercase font-mono text-zinc-400 block">
                    Детализация обращения
                  </span>
                  <div className="font-mono text-xs text-zinc-300 select-all">
                    {selectedCase.id}
                  </div>
                </div>

                {/* Decrypted Report Box */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-xs font-semibold text-zinc-200">
                    <span className="flex items-center gap-1.5 text-zinc-200">
                      <Unlock className="w-3.5 h-3.5 text-zinc-400" />
                      Расшифрованный текст обращения
                    </span>
                    <span className="text-zinc-400 font-mono text-[11px]">
                      Sealed Box &bull; Client Decrypted
                    </span>
                  </div>

                  {isDecryptingReport ? (
                    <div className="p-8 rounded-xl bg-black border border-zinc-800 flex items-center justify-center gap-2 text-zinc-400 text-xs">
                      <Loader2 className="w-4 h-4 animate-spin text-zinc-400" />
                      <span>Расшифровка закрытого ящика...</span>
                    </div>
                  ) : decryptedReportText ? (
                    <div className="p-4 rounded-xl bg-black border border-zinc-800 text-sm text-zinc-100 whitespace-pre-wrap leading-relaxed font-sans">
                      {decryptedReportText}
                    </div>
                  ) : (
                    <div className="p-4 rounded-xl bg-red-950/20 border border-red-500/30 text-red-300 text-xs">
                      Не удалось расшифровать сообщение.
                    </div>
                  )}
                </div>

                {/* Dialogue Thread */}
                <div className="space-y-3 pt-4 border-t border-zinc-900">
                  <div className="flex items-center justify-between text-xs font-semibold text-zinc-200">
                    <span>История диалога ({threadMessages.length})</span>
                    {isLoadingThread && (
                      <span className="flex items-center gap-1.5 text-zinc-400 text-[11px]">
                        <Loader2 className="w-3 h-3 animate-spin" />
                        Загрузка сообщений...
                      </span>
                    )}
                  </div>

                  {threadMessages.length === 0 && !isLoadingThread ? (
                    <div className="p-4 rounded-xl bg-black/40 border border-zinc-900 text-zinc-500 text-xs text-center">
                      Ответов и уточнений по этому кейсу ещё не было.
                    </div>
                  ) : (
                    <div className="space-y-3 max-h-72 overflow-y-auto pr-1">
                      {threadMessages.map((msg, idx) => {
                        const isFromReporter = msg.sender === 'REPORTER';
                        return (
                          <div
                            key={msg.id || idx}
                            className={`p-3.5 rounded-xl border space-y-1.5 ${
                              isFromReporter
                                ? 'bg-amber-950/10 border-amber-900/30'
                                : 'bg-zinc-900/40 border-zinc-800'
                            }`}
                          >
                            <div className="flex items-center justify-between">
                              <span
                                className={`text-[10px] font-mono px-2 py-0.5 rounded font-medium ${
                                  isFromReporter
                                    ? 'bg-amber-950/30 border border-amber-700/40 text-amber-300'
                                    : 'bg-emerald-950/30 border border-emerald-700/40 text-emerald-300'
                                }`}
                              >
                                {isFromReporter ? 'Репортёр (Аноним)' : 'Следователь (Вы)'}
                              </span>
                              <span className="text-[10px] text-zinc-400 font-mono">
                                {new Date(msg.createdAt).toLocaleString('ru-RU')}
                              </span>
                            </div>
                            <p className="text-sm text-zinc-200 whitespace-pre-wrap leading-relaxed font-sans">
                              {msg.decryptedText}
                            </p>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>

                {/* Reply Form */}
                <form onSubmit={handleSendReply} className="space-y-4 pt-4 border-t border-zinc-900">
                  <div>
                    <label htmlFor="reply" className="block text-xs font-semibold text-zinc-200 mb-2">
                      Официальный ответ (шифруется публичным ключом репортёра):
                    </label>
                    <textarea
                      id="reply"
                      rows={5}
                      value={replyText}
                      onChange={(e) => setReplyText(e.target.value)}
                      placeholder="Введите текст ответа. Он будет зашифрован шифром crypto_box_easy..."
                      className="w-full rounded-xl bg-black border border-zinc-800 px-4 py-3 text-sm text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-500 focus:ring-1 focus:ring-zinc-500 transition-all resize-y leading-relaxed font-sans"
                      required
                    />
                  </div>

                  {actionError && (
                    <div className="p-3 rounded-xl bg-red-950/20 border border-red-500/30 text-red-300 text-xs flex gap-2">
                      <AlertTriangle className="w-4 h-4 flex-shrink-0 text-red-400" />
                      <span>{actionError}</span>
                    </div>
                  )}

                  {replySuccess && (
                    <div className="p-3 rounded-xl border border-emerald-500/30 bg-emerald-950/20 text-emerald-300 text-xs flex items-center gap-2">
                      <CheckCircle2 className="w-4 h-4 flex-shrink-0 text-emerald-400" />
                      <span>Ответ зашифрован и сохранён на сервере.</span>
                    </div>
                  )}

                  <div className="flex justify-end">
                    <button
                      type="submit"
                      disabled={isSendingReply || !replyText.trim()}
                      className="flex items-center gap-2 px-5 py-2.5 rounded-xl bg-white text-black font-medium text-sm hover:bg-zinc-200 disabled:opacity-40 transition-all"
                    >
                      {isSendingReply ? (
                        <>
                          <Loader2 className="w-4 h-4 animate-spin text-black" />
                          <span>Шифрование...</span>
                        </>
                      ) : (
                        <>
                          <Send className="w-4 h-4" />
                          <span>Отправить зашифрованный ответ</span>
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
    <div className="max-w-md mx-auto space-y-6 pt-6 animate-in fade-in duration-200">
      <div className="space-y-2 text-center">
        <div className="w-10 h-10 rounded-full border border-zinc-800 bg-zinc-900 flex items-center justify-center mx-auto text-zinc-300 mb-3">
          <Lock className="w-4 h-4" />
        </div>
        <h1 className="text-xl font-bold tracking-tight text-white">
          Кабинет следователя
        </h1>
        <p className="text-zinc-400 text-xs">
          Приватный ключ расшифровывается локально на вашем клиенте через Argon2id.
        </p>
      </div>

      <form
        onSubmit={handleLogin}
        className="border border-zinc-800/90 bg-zinc-950/40 rounded-2xl p-6 space-y-4"
      >
        <div>
          <label htmlFor="username" className="block text-xs font-mono uppercase text-zinc-400 mb-1.5">
            Email / Логин:
          </label>
          <input
            id="username"
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="w-full rounded-xl bg-black border border-zinc-800 px-4 py-2.5 text-xs text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-500 focus:ring-1 focus:ring-zinc-500 transition-all font-mono"
            required
          />
        </div>

        <div>
          <label htmlFor="password" className="block text-xs font-mono uppercase text-zinc-400 mb-1.5">
            Пароль для расшифровки:
          </label>
          <input
            id="password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full rounded-xl bg-black border border-zinc-800 px-4 py-2.5 text-xs text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-500 focus:ring-1 focus:ring-zinc-500 transition-all font-mono"
            required
          />
          <p className="text-[11px] text-zinc-400 mt-1.5">
            Тестовый пароль из seed.py подставлен для быстрой проверки.
          </p>
        </div>

        {loginError && (
          <div className="p-3 rounded-xl bg-red-950/20 border border-red-500/30 text-red-300 text-xs flex gap-2">
            <AlertTriangle className="w-4 h-4 flex-shrink-0 text-red-400" />
            <span>{loginError}</span>
          </div>
        )}

        <button
          type="submit"
          disabled={isUnlocking || !password.trim()}
          className="w-full flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl bg-white text-black font-medium text-sm hover:bg-zinc-200 transition-all disabled:opacity-40"
        >
          {isUnlocking ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin text-black" />
              <span>Расшифровка Argon2id...</span>
            </>
          ) : (
            <>
              <Unlock className="w-4 h-4" />
              <span>Войти и разблокировать ключ</span>
            </>
          )}
        </button>
      </form>

      <div className="p-4 rounded-xl border border-zinc-800/80 bg-zinc-950/30 text-xs text-zinc-400 flex items-start gap-2.5">
        <Shield className="w-4 h-4 text-zinc-400 flex-shrink-0 mt-0.5" />
        <span>
          <b>Zero-Knowledge гарантия:</b> Сервер хранит зашифрованный блоб ключа. Пароль никогда не покидает браузер.
        </span>
      </div>
    </div>
  );
}
