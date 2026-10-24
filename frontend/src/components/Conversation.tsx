"use client";

import {
  Fingerprint,
  Loader2,
  LockKeyhole,
  Send,
  ShieldCheck,
} from "lucide-react";
import type { CaseMessageDto } from "@/lib/types";
import { AttachmentList } from "./AttachmentList";
import { AttachmentPicker } from "./AttachmentPicker";
import { Notice } from "./ui";

export function MessageThread({
  messages,
  viewer,
  downloadAttachment,
}: {
  messages: CaseMessageDto[];
  viewer: "REPORTER" | "INVESTIGATOR";
  downloadAttachment?: (id: string) => Promise<ArrayBuffer>;
}) {
  return (
    <div className="message-list">
      {messages.map((message, index) => {
        const verified = message.authentication === 'verified';
        const reporter = (message.senderType || message.sender) === "REPORTER";
        const mine = verified && (reporter ? "REPORTER" : "INVESTIGATOR") === viewer;
        const Icon = !verified || reporter ? Fingerprint : ShieldCheck;
        return (
          <article className="message" key={`${message.id}:${index}`}>
            <div className="message-heading">
              <div className="message-author">
                <span
                  className={`message-avatar ${reporter ? "reporter" : ""}`}
                >
                  <Icon size={13} />
                </span>
                {verified ? (reporter ? "Reporter" : "Investigator") : message.authentication === "legacy" ? "UNVERIFIED legacy sender" : "UNVERIFIED sender"}
                {mine && <span className="muted">You</span>}
              </div>
              <time dateTime={message.createdAt}>
                {new Date(message.createdAt).toLocaleString("en-US", {
                  month: "short",
                  day: "numeric",
                  hour: "numeric",
                  minute: "2-digit",
                })}
              </time>
            </div>
            <p className="message-text">{message.decryptedText}</p>
            {message.attachments && (
              <AttachmentList attachments={message.attachments} downloadAttachment={downloadAttachment} />
            )}
          </article>
        );
      })}
    </div>
  );
}

interface ReplyComposerProps {
  id: string;
  text: string;
  onTextChange: (text: string) => void;
  files: File[];
  onFilesChange: (files: File[]) => void;
  onSubmit: (event: React.FormEvent) => void;
  isSending: boolean;
  disabled?: boolean;
  pending?: boolean;
  error: string | null;
  success?: boolean;
  label?: string;
}

export function ReplyComposer({
  id,
  text,
  onTextChange,
  files,
  onFilesChange,
  onSubmit,
  isSending,
  disabled = false,
  pending = false,
  error,
  success,
  label = "Write a follow-up",
}: ReplyComposerProps) {
  const busy = isSending || disabled;
  return (
    <form onSubmit={onSubmit} className="reply-composer" aria-busy={busy}>
      <label className="field-label" htmlFor={id}>
        {label}
      </label>
      <textarea
        className="input"
        id={id}
        value={text}
        onChange={(event) => onTextChange(event.target.value)}
        rows={4}
        placeholder="Add information to the conversation…"
        required
        disabled={busy || pending}
      />
      <AttachmentPicker
        files={files}
        onChange={onFilesChange}
        disabled={busy || pending}
      />
      <div className="stack-sm">
        {error && <Notice>{error}</Notice>}
        {success && (
          <Notice variant="success">Reply encrypted and sent.</Notice>
        )}
        <div className="form-actions">
          <span className="privacy-note">
            <LockKeyhole size={12} /> Encrypted before sending
          </span>
          <button
            type="submit"
            className="btn btn-primary"
            disabled={busy || !text.trim()}
          >
            {isSending ? (
              <>
                <Loader2 size={14} className="spin" />
                Sending…
              </>
            ) : (
              <>
                {pending ? 'Check / retry same reply' : 'Send reply'}
                <Send size={13} />
              </>
            )}
          </button>
        </div>
      </div>
    </form>
  );
}
