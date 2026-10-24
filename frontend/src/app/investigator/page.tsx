"use client";

import { useState } from "react";
import {
  FileText,
  Inbox,
  Loader2,
  LockKeyhole,
  LogOut,
  MessageSquare,
  RefreshCw,
  ShieldCheck,
  Unlock,
} from "lucide-react";
import { useInvestigatorSession } from "@/hooks/useInvestigatorSession";
import type { InvestigatorCaseListItem } from "@/lib/types";
import { AuditBadge } from "@/components/AuditBadge";
import { AttachmentList } from "@/components/AttachmentList";
import { MessageThread, ReplyComposer } from "@/components/Conversation";
import {
  EmptyState,
  Notice,
  PageHeading,
  PageLayout,
  ReportingGuide,
  StatusBadge,
} from "@/components/ui";

export default function InvestigatorPortalPage() {
  const {
    username,
    setUsername,
    legacyMode,
    setLegacyMode,
    password,
    setPassword,
    accessKey,
    setAccessKey,
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
    replyPending,
    changeStatus,
    isChangingStatus,
    statusPending,
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
  const [replyText, setReplyText] = useState("");
  const [replyFiles, setReplyFiles] = useState<File[]>([]);

  async function handleLogin(event: React.FormEvent) {
    event.preventDefault();
    setReplyText("");
    setReplyFiles([]);
    await login();
  }

  async function handleSelectCase(item: InvestigatorCaseListItem) {
    setReplyText("");
    setReplyFiles([]);
    await selectCase(item);
  }

  async function handleSendReply(event: React.FormEvent) {
    event.preventDefault();
    if (await sendReply(replyText, replyFiles)) {
      setReplyText("");
      setReplyFiles([]);
    }
  }

  function handleLogout() {
    setReplyText("");
    setReplyFiles([]);
    logout();
  }

  if (account && privateKey) {
    return (
      <div className="page-content investigator-page">
        <div className="page-heading investigator-heading">
          <div>
            <div className="eyebrow">Investigator workspace</div>
            <h1>Incoming reports</h1>
            <p className="account-info">{account.username}</p>
          </div>
          <div className="heading-actions">
            <button
              type="button"
              className="btn"
              onClick={loadCases}
              disabled={isLoadingCases || isSendingReply || replyPending || isChangingStatus || statusPending}
            >
              <RefreshCw size={14} className={isLoadingCases ? "spin" : ""} />
              Refresh
            </button>
            <button
              type="button"
              className="btn btn-ghost"
              onClick={handleLogout}
            >
              <LogOut size={14} />
              Lock workspace
            </button>
          </div>
        </div>
        <details className="account-key">
          <summary>
            <span>Key unlocked locally · View public key</span>
          </summary>
          <code>{account.publicKey}</code>
        </details>
        {actionError && !selectedCase && (
          <div className="stack">
            <Notice>{actionError}</Notice>
            <span />
          </div>
        )}
        <div className="investigator-workspace">
          <section className="case-list" aria-label="Incoming reports">
            <h2 className="case-list-header">
              <Inbox size={15} />
              All reports<span className="count">{cases.length}</span>
              {isLoadingCases && <Loader2 size={13} className="spin" />}
            </h2>
            {cases.length === 0 ? (
              isLoadingCases ? (
                <div className="loading-state" role="status">
                  <Loader2 size={15} className="spin" />
                  Loading reports…
                </div>
              ) : (
                <EmptyState icon={Inbox} title="No reports yet">
                  Incoming reports will appear here.
                </EmptyState>
              )
            ) : (
              <div className="case-list-scroll">
                {cases.map((item) => (
                  <button
                    key={item.id}
                    type="button"
                    className={`case-row ${item.id === selectedCaseId ? "selected" : ""}`}
                    aria-pressed={item.id === selectedCaseId}
                    onClick={() => handleSelectCase(item)}
                    disabled={isDecryptingReport || isSendingReply || replyPending || isChangingStatus || statusPending}
                  >
                    <span className="case-row-top">
                      <FileText size={14} />
                      {item.id.slice(0, 8).toUpperCase()}
                    </span>
                    <span className="case-row-bottom">
                      <StatusBadge status={item.status} />
                      <time className="case-row-date" dateTime={item.createdAt}>
                        {new Date(item.createdAt).toLocaleDateString("en-US", {
                          month: "short",
                          day: "numeric",
                        })}
                      </time>
                    </span>
                    <span className="case-row-messages">
                      <MessageSquare size={11} />
                      {item.messageCount}{" "}
                      {item.messageCount === 1 ? "message" : "messages"}
                    </span>
                  </button>
                ))}
              </div>
            )}
          </section>
          <section className="case-detail" aria-label="Selected report">
            {!selectedCase ? (
              <EmptyState
                icon={FileText}
                title="Select a report to get started"
              >
                Review its content, check the audit chain, and respond to the
                reporter.
              </EmptyState>
            ) : (
              <>
                <header className="case-detail-header">
                  <StatusBadge status={selectedCase.status} />
                  {selectedCase.protocolVersion === 2 && (!selectedCase.readOnly || selectedCase.status === 'CLOSED') && (
                    <div className="heading-actions">
                      {statusPending ? (
                        <button className="btn btn-small" disabled={isChangingStatus} onClick={() => changeStatus(selectedCase.status)}>Retry status change</button>
                      ) : <>
                        {selectedCase.status !== 'IN_REVIEW' && (
                          <button className="btn btn-small" disabled={isChangingStatus || isSendingReply || replyPending || isLoadingThread}
                            onClick={() => changeStatus('IN_REVIEW')}>{selectedCase.status === 'CLOSED' ? 'Reopen case' : 'Start review'}</button>
                        )}
                        {selectedCase.status !== 'CLOSED' && (
                          <button className="btn btn-small" disabled={isChangingStatus || isSendingReply || replyPending || isLoadingThread}
                            onClick={() => changeStatus('CLOSED')}>Close case</button>
                        )}
                      </>}
                    </div>
                  )}
                  <h2>Report {selectedCase.id.slice(0, 8).toUpperCase()}</h2>
                  <p className="case-id mono">{selectedCase.id}</p>
                  <div className="conversation-meta">
                    <AuditBadge
                      verification={auditVerification}
                      isLoading={isVerifyingAudit}
                      onRefresh={() => fetchAuditVerification(selectedCase.id)}
                    />
                  </div>
                </header>
                {(selectedCase.protocolVersion !== 2 || selectedCase.readOnly) && (
                  <Notice>{selectedCase.protocolVersion === 1 ? 'UNVERIFIED legacy conversation — READ-ONLY. Sender labels cannot be authenticated.' : selectedCase.status === 'CLOSED' ? 'Case closed. Reopen it to resume replies and uploads.' : 'Archived identity — READ-ONLY.'}</Notice>
                )}
                <div className="report-content">
                  <h3 className="case-section-heading">
                    <span>Original report</span>
                    <span className="panel-meta">
                      <LockKeyhole size={12} /> Decrypted locally
                    </span>
                  </h3>
                  {isDecryptingReport ? (
                    <div className="loading-state" role="status">
                      <Loader2 size={15} className="spin" />
                      Decrypting report…
                    </div>
                  ) : decryptedReportText ? (
                    <>
                      <p className="report-body">{decryptedReportText}</p>
                      <AttachmentList attachments={reportAttachments} />
                    </>
                  ) : (
                    <Notice>
                      Unable to decrypt this report. The key or report data may
                      be invalid.
                    </Notice>
                  )}
                </div>
                <div className="case-thread-header">
                  <MessageSquare size={13} />
                  Conversation
                  <span className="count">{threadMessages.length}</span>
                </div>
                {isLoadingThread ? (
                  <div className="loading-state" role="status">
                    <Loader2 size={15} className="spin" />
                    Loading conversation…
                  </div>
                ) : threadMessages.length ? (
                  <MessageThread
                    messages={threadMessages}
                    viewer="INVESTIGATOR"
                  />
                ) : (
                  <EmptyState title="Start the conversation">
                    Reply to acknowledge the report or ask for more information.
                  </EmptyState>
                )}
                <ReplyComposer
                  pending={replyPending}
                  id="investigatorReply"
                  text={replyText}
                  onTextChange={setReplyText}
                  files={replyFiles}
                  onFilesChange={setReplyFiles}
                  onSubmit={handleSendReply}
                  isSending={isSendingReply}
                  disabled={isChangingStatus || statusPending || isLoadingThread || selectedCase.readOnly || selectedCase.protocolVersion !== 2 || !decryptedReportText}
                  error={actionError}
                  success={replySuccess}
                  label="Reply to reporter"
                />
              </>
            )}
          </section>
        </div>
      </div>
    );
  }

  return (
    <PageLayout aside={<ReportingGuide mode="investigator" />}>
      <PageHeading
        label="Investigator workspace"
        title="Access your workspace"
        description="Sign in to review incoming reports and continue conversations with reporters."
      />
      <section className="panel login-panel" aria-labelledby="login-title">
        <div className="panel-header">
          <h2 className="panel-heading" id="login-title">
            <ShieldCheck size={15} />
            Investigator access
          </h2>
          <span className="panel-meta">
            <LockKeyhole size={12} /> Locked
          </span>
        </div>
        <form
          onSubmit={handleLogin}
          className="panel-body form-fields"
          aria-busy={isUnlocking}
        >
          <div>
            <label htmlFor="username" className="field-label">
              Email or username
            </label>
            <input
              id="username"
              type="text"
              className="input"
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              autoComplete="username"
              autoCapitalize="none"
              spellCheck={false}
              disabled={isUnlocking}
              required
            />
          </div>
          <div>
            <label htmlFor="access-key" className="field-label">
              Workspace access key
            </label>
            <input
              id="access-key"
              type="password"
              className="input"
              value={accessKey}
              onChange={(event) => setAccessKey(event.target.value)}
              autoComplete="off"
              autoCapitalize="none"
              spellCheck={false}
              disabled={isUnlocking}
              required
              aria-describedby="access-key-hint"
            />
            <p id="access-key-hint" className="field-description">
              Generated by local access setup. Authenticates access to the API.
            </p>
          </div>
          <div>
            <label htmlFor="password" className="field-label">
              Master password
            </label>
            <input
              id="password"
              type="password"
              className="input"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              autoComplete="current-password"
              disabled={isUnlocking}
              required
              aria-describedby="password-hint"
            />
            <p id="password-hint" className="field-description">
              Used to unlock your investigator key in this browser.
            </p>
          </div>
          <label className="field-description">
            <input type="checkbox" checked={legacyMode} onChange={(event) => setLegacyMode(event.target.checked)} disabled={isUnlocking} />
            {" "}Open legacy archive (original password; unverified and read-only)
          </label>
          {loginError && <Notice>{loginError}</Notice>}
          <button
            type="submit"
            className="btn btn-primary btn-full"
            disabled={isUnlocking || !password || !username.trim() || !accessKey.trim()}
          >
            {isUnlocking ? (
              <>
                <Loader2 size={14} className="spin" />
                Signing in and unlocking…
              </>
            ) : (
              <>
                <Unlock size={14} />
                Unlock workspace
              </>
            )}
          </button>
        </form>
        <div className="login-footer">
          <LockKeyhole size={13} />
          <span>
            Your password unlocks your key locally. Reports are decrypted in
            your browser. <a href="/investigator/setup">Local identity setup</a>
          </span>
        </div>
      </section>
    </PageLayout>
  );
}
