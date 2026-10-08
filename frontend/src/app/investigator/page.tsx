'use client';

import { useState } from 'react';
import {
  Unlock,
  AlertTriangle,
  Loader2,
  FileText,
  Send,
  CheckCircle2,
  LogOut,
  RefreshCw,
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
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-white/5">
          <div className="space-y-0.5">
            <div className="text-sm font-medium text-white flex items-center gap-2">
              <span>{account.username}</span>
              <span className="text-xs text-emerald-400 font-mono">• key unlocked</span>
            </div>
            <p className="text-xs text-zinc-500 font-mono truncate max-w-sm sm:max-w-md">
              {account.publicKey}
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={loadCases}
              disabled={isLoadingCases}
              className="inline-flex items-center gap-1.5 text-xs text-zinc-400 hover:text-white transition-colors cursor-pointer disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isLoadingCases ? 'animate-spin' : ''}`} />
              <span>Refresh</span>
            </button>
            <button
              onClick={logout}
              className="inline-flex items-center gap-1.5 text-xs text-zinc-500 hover:text-red-400 transition-colors cursor-pointer"
            >
              <LogOut className="w-3.5 h-3.5" />
              <span>Lock</span>
            </button>
          </div>
        </div>

        {/* Two-Column Workspace */}
        <div className="grid grid-cols-1 md:grid-cols-12 gap-6 items-start">
          {/* Left Column: Cases List */}
          <div className="md:col-span-5 space-y-2">
            <div className="text-xs text-zinc-400 font-medium pb-2 flex items-center justify-between">
              <span>Reports ({cases.length})</span>
              {isLoadingCases && <Loader2 className="w-3 h-3 text-zinc-500 animate-spin" />}
            </div>

            {cases.length === 0 ? (
              <div className="py-8 text-center text-xs text-zinc-500">
                {isLoadingCases ? 'Loading...' : 'No reports yet.'}
              </div>
            ) : (
              <div className="space-y-1.5 max-h-[500px] overflow-y-auto pr-1">
                {cases.map((c) => {
                  const isSelected = c.id === selectedCaseId;
                  return (
                    <div
                      key={c.id}
                      onClick={() => handleSelectCase(c)}
                      className={`p-3 rounded-lg text-left cursor-pointer transition-colors ${
                        isSelected
                          ? 'bg-neutral-800 text-white'
                          : 'bg-neutral-900/40 hover:bg-neutral-900 text-zinc-300'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2 mb-1">
                        <span className="font-mono text-xs font-medium truncate">
                          {c.id.slice(0, 16)}...
                        </span>
                        <span className="text-[10px] text-zinc-400">
                          {c.status}
                        </span>
                      </div>

                      <div className="flex items-center justify-between text-[11px] text-zinc-500 font-mono">
                        <span>{new Date(c.createdAt).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}</span>
                        <span>{c.messageCount} msg</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Right Column: Case Detail & Response Form */}
          <div className="md:col-span-7 space-y-5">
            {!selectedCase ? (
              <div className="py-16 text-center text-xs text-zinc-500 space-y-2">
                <FileText className="w-6 h-6 mx-auto text-zinc-600" />
                <p>Select a report from the list.</p>
              </div>
            ) : (
              <div className="space-y-5">
                <div className="space-y-2 pb-3 border-b border-white/5">
                  <div className="text-xs text-zinc-500 font-mono truncate select-all">
                    ID: {selectedCase.id}
                  </div>
                  <AuditBadge
                    verification={auditVerification}
                    isLoading={isVerifyingAudit}
                    onRefresh={() => selectedCaseId && fetchAuditVerification(selectedCaseId)}
                  />
                </div>

                {/* Decrypted Report */}
                <div className="space-y-2">
                  <div className="text-xs text-zinc-400 font-medium">Report content:</div>
                  {isDecryptingReport ? (
                    <div className="p-6 text-center text-xs text-zinc-500 flex items-center justify-center gap-2">
                      <Loader2 className="w-4 h-4 animate-spin text-zinc-500" />
                      <span>Decrypting...</span>
                    </div>
                  ) : decryptedReportText ? (
                    <div className="space-y-2">
                      <div className="p-4 rounded-lg bg-neutral-900/50 border border-white/5 text-sm text-zinc-100 whitespace-pre-wrap leading-relaxed font-sans">
                        {decryptedReportText}
                      </div>
                      {reportAttachments.length > 0 && (
                        <AttachmentList attachments={reportAttachments} />
                      )}
                    </div>
                  ) : (
                    <div className="p-3 text-xs text-red-300">
                      Failed to decrypt report.
                    </div>
                  )}
                </div>

                {/* Dialogue Thread */}
                {threadMessages.length > 0 && (
                  <div className="space-y-3 pt-3 border-t border-white/5">
                    <div className="text-xs text-zinc-400 font-medium">
                      Message thread ({threadMessages.length})
                    </div>
                    <div className="space-y-2.5 max-h-60 overflow-y-auto pr-1">
                      {threadMessages.map((msg, idx) => {
                        const isFromReporter = (msg.senderType || msg.sender) === 'REPORTER';
                        return (
                          <div
                            key={msg.id || idx}
                            className="p-3.5 rounded-lg bg-neutral-900/40 border border-white/5 space-y-1.5"
                          >
                            <div className="flex items-center justify-between text-xs">
                              <span className="font-medium text-zinc-300">
                                {isFromReporter ? 'Reporter' : 'Investigator (You)'}
                              </span>
                              <span className="text-[11px] text-zinc-500 font-mono">
                                {new Date(msg.createdAt).toLocaleString('en-US')}
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
                  </div>
                )}

                {/* Reply Form */}
                <form onSubmit={handleSendReply} className="space-y-3 pt-3 border-t border-white/5">
                  <div className="space-y-1.5">
                    <label htmlFor="reply" className="text-xs text-zinc-400 font-medium block">
                      Reply to reporter:
                    </label>
                    <textarea
                      id="reply"
                      rows={4}
                      value={replyText}
                      onChange={(e) => setReplyText(e.target.value)}
                      placeholder="Type your response..."
                      className="w-full rounded-lg bg-neutral-900/60 border border-white/10 px-4 py-3 text-sm text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:border-white/20 transition-colors resize-y leading-relaxed font-sans"
                      required
                    />
                  </div>

                  <AttachmentPicker
                    files={replyFiles}
                    onChange={setReplyFiles}
                    disabled={isSendingReply}
                  />

                  {actionError && (
                    <div className="p-3 rounded-lg bg-red-950/20 border border-red-500/20 text-red-300 text-xs flex gap-2">
                      <AlertTriangle className="w-4 h-4 flex-shrink-0 text-red-400" />
                      <span>{actionError}</span>
                    </div>
                  )}

                  {replySuccess && (
                    <div className="p-3 rounded-lg border border-emerald-500/20 bg-emerald-950/20 text-emerald-300 text-xs flex items-center gap-2">
                      <CheckCircle2 className="w-4 h-4 flex-shrink-0 text-emerald-400" />
                      <span>Reply encrypted and sent.</span>
                    </div>
                  )}

                  <div className="flex justify-end pt-1">
                    <button
                      type="submit"
                      disabled={isSendingReply || !replyText.trim()}
                      className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg bg-[#ededed] text-[#0a0a0a] font-medium text-xs sm:text-sm hover:bg-white disabled:opacity-40 transition-all cursor-pointer"
                    >
                      {isSendingReply ? (
                        <>
                          <Loader2 className="w-3.5 h-3.5 animate-spin text-[#0a0a0a]" />
                          <span>Encrypting...</span>
                        </>
                      ) : (
                        <>
                          <span>Send reply</span>
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
  // VIEW: LOGIN SCREEN
  // =========================================================================
  return (
    <div className="max-w-md mx-auto space-y-6 pt-4 animate-in fade-in duration-200">
      <div className="space-y-2">
        <h1 className="text-2xl sm:text-3xl font-semibold tracking-tight text-white">
          Investigator Portal
        </h1>
        <p className="text-sm font-light text-zinc-400 leading-relaxed">
          Sign in to decrypt incoming reports locally.
        </p>
      </div>

      <form onSubmit={handleLogin} className="space-y-4 pt-2">
        <div className="space-y-1.5">
          <label htmlFor="username" className="block text-xs text-zinc-400">
            Email or username
          </label>
          <input
            id="username"
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="w-full rounded-lg bg-neutral-900/60 border border-white/10 px-4 py-2.5 text-sm text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:border-white/20 transition-colors font-sans"
            required
          />
        </div>

        <div className="space-y-1.5">
          <label htmlFor="password" className="block text-xs text-zinc-400">
            Password
          </label>
          <input
            id="password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full rounded-lg bg-neutral-900/60 border border-white/10 px-4 py-2.5 text-sm text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:border-white/20 transition-colors font-sans"
            required
          />
          <p className="text-[11px] text-zinc-500 font-mono">
            investigator@sealed.org / Password123!
          </p>
        </div>

        {loginError && (
          <div className="p-3 rounded-lg bg-red-950/20 border border-red-500/20 text-red-300 text-xs flex gap-2">
            <AlertTriangle className="w-4 h-4 flex-shrink-0 text-red-400" />
            <span>{loginError}</span>
          </div>
        )}

        <button
          type="submit"
          disabled={isUnlocking || !password.trim()}
          className="w-full inline-flex items-center justify-center gap-2 px-5 py-2.5 rounded-lg bg-[#ededed] text-[#0a0a0a] font-medium text-sm hover:bg-white transition-all disabled:opacity-40 cursor-pointer"
        >
          {isUnlocking ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin text-[#0a0a0a]" />
              <span>Unlocking key...</span>
            </>
          ) : (
            <>
              <Unlock className="w-4 h-4" />
              <span>Sign in</span>
            </>
          )}
        </button>
      </form>
    </div>
  );
}
