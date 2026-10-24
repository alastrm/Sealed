"use client";

import { useState } from "react";
import {
  ArrowRight,
  KeyRound,
  Loader2,
  LockKeyhole,
  MessageSquare,
  RefreshCw,
} from "lucide-react";
import { useReporterCase } from "@/hooks/useReporterCase";
import { AuditBadge } from "@/components/AuditBadge";
import { MessageThread, ReplyComposer } from "@/components/Conversation";
import {
  EmptyState,
  Notice,
  PageHeading,
  PageLayout,
  ReportingGuide,
  StatusBadge,
} from "@/components/ui";

export default function TrackCasePage() {
  const {
    mnemonicInput,
    setMnemonicInput,
    fromSession,
    setFromSession,
    isVerifying,
    error,
    caseData,
    downloadAttachment,
    decryptedMessages,
    auditVerification,
    isVerifyingAudit,
    isSendingReply,
    replyError,
    replyPending,
    lookupCase,
    sendReply,
    clearSession,
    fetchAuditVerification,
  } = useReporterCase();
  const [replyText, setReplyText] = useState("");
  const [replyFiles, setReplyFiles] = useState<File[]>([]);
  const [replySuccess, setReplySuccess] = useState(false);
  const wordCount = mnemonicInput.trim()
    ? mnemonicInput.trim().split(/\s+/).length
    : 0;

  async function handleLookup(event?: React.FormEvent) {
    event?.preventDefault();
    setReplySuccess(false);
    await lookupCase();
  }

  async function handleSendReply(event: React.FormEvent) {
    event.preventDefault();
    setReplySuccess(false);
    if (await sendReply(replyText, replyFiles)) {
      setReplyText("");
      setReplyFiles([]);
      setReplySuccess(true);
    }
  }

  function handleClearSession() {
    clearSession();
    setReplyText("");
    setReplyFiles([]);
    setReplySuccess(false);
  }

  return (
    <PageLayout aside={<ReportingGuide mode="track" />}>
      <PageHeading
        label="Pick up where you left off"
        title="Track a report"
        description="Use your 12-word access key to check your report’s status, read replies, and share additional information."
      />
      <form onSubmit={handleLookup} className="panel" aria-busy={isVerifying}>
        <div className="panel-header">
          <h2 className="panel-heading">
            <KeyRound size={15} /> Report access
          </h2>
          <span className="panel-meta">
            <LockKeyhole size={12} /> Private access
          </span>
        </div>
        <div className="panel-body form-fields">
          <div>
            <label htmlFor="mnemonic" className="field-label">
              Your 12-word access key
            </label>
            <textarea
              id="mnemonic"
              rows={3}
              className="input key-input"
              value={mnemonicInput}
              onChange={(event) => {
                handleClearSession();
                setMnemonicInput(event.target.value);
                setFromSession(false);
              }}
              placeholder="Enter your 12 words, separated by spaces…"
              required
              disabled={isVerifying}
              autoComplete="off"
              autoCapitalize="none"
              spellCheck={false}
              aria-describedby="key-hint key-count"
              aria-invalid={!!error}
            />
            <p id="key-hint" className="field-description">
              Enter the words in the same order you received them.
            </p>
          </div>
          {error && <Notice>{error}</Notice>}
          <div className="form-actions">
            <div className="stack-sm">
              <span
                id="key-count"
                className={`word-count ${wordCount === 12 ? "complete" : ""}`}
              >
                {wordCount} / 12 words
              </span>
              {(fromSession || caseData) && (
                <button
                  type="button"
                  className="btn btn-ghost btn-small"
                  onClick={handleClearSession}
                >
                  Clear session
                </button>
              )}
            </div>
            <button
              type="submit"
              className="btn btn-primary"
              disabled={isVerifying || wordCount !== 12}
            >
              {isVerifying ? (
                <>
                  <Loader2 size={14} className="spin" />
                  Checking…
                </>
              ) : (
                <>
                  Check status
                  <ArrowRight size={14} />
                </>
              )}
            </button>
          </div>
        </div>
      </form>
      {caseData ? (
        <section className="conversation" aria-labelledby="conversation-title">
          <div className="conversation-header">
            <div>
              <h2 id="conversation-title" className="conversation-title">
                Your conversation
              </h2>
              <div className="conversation-meta">
                <StatusBadge status={caseData.status} />
                <span className="muted">
                  Submitted{" "}
                  {new Date(caseData.createdAt).toLocaleDateString("en-US", {
                    month: "short",
                    day: "numeric",
                    year: "numeric",
                  })}
                </span>
              </div>
            </div>
            <button
              type="button"
              className="btn btn-ghost btn-small"
              disabled={isVerifying}
              onClick={() => handleLookup()}
            >
              <RefreshCw size={13} className={isVerifying ? "spin" : ""} />
              Refresh
            </button>
          </div>
          <div className="stack">
            <AuditBadge
              verification={auditVerification}
              isLoading={isVerifyingAudit}
              onRefresh={() => fetchAuditVerification(caseData.caseId)}
            />
            <div className="panel">
              <div className="panel-header">
                <h3 className="panel-heading">
                  <MessageSquare size={14} />
                  Messages{" "}
                  <span className="count">{decryptedMessages.length}</span>
                </h3>
                <span className="panel-meta">
                  <LockKeyhole size={12} /> Encrypted
                </span>
              </div>
              {decryptedMessages.length ? (
                <MessageThread messages={decryptedMessages} viewer="REPORTER" downloadAttachment={downloadAttachment} />
              ) : (
                <EmptyState title="No replies yet">
                  Your report is awaiting a response. Check back here for
                  updates, or add more information below.
                </EmptyState>
              )}
              {(caseData.readOnly || caseData.protocolVersion !== 2) && (
                <Notice>{caseData.status === 'CLOSED' ? 'Case closed. Replies and new attachments are disabled until an Investigator reopens it.' : caseData.protocolVersion === 1 ? 'UNVERIFIED legacy conversation — READ-ONLY.' : 'Archived identity — READ-ONLY.'}</Notice>
              )}
            <ReplyComposer
              pending={replyPending}
                id="reporterReply"
                text={replyText}
                onTextChange={(text) => {
                  setReplyText(text);
                  setReplySuccess(false);
                }}
                files={replyFiles}
                onFilesChange={setReplyFiles}
                onSubmit={handleSendReply}
                isSending={isSendingReply}
                disabled={caseData.readOnly || caseData.protocolVersion !== 2}
                error={replyError}
                success={replySuccess}
              />
            </div>
          </div>
        </section>
      ) : (
        <div className="access-note">
          <KeyRound size={16} />
          <div>
            <h3>Your access key is all you need</h3>
            <p>
              No email or account is required. Keep these words private to
              protect access to your conversation.
            </p>
          </div>
        </div>
      )}
    </PageLayout>
  );
}
