"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import {
  ArrowRight,
  Check,
  CheckCircle2,
  Copy,
  FileText,
  KeyRound,
  Loader2,
  LockKeyhole,
} from "lucide-react";
import { api } from "@/lib/api";
import {
  encryptAttachmentFile,
  encryptReport,
  generateReporterBundle,
  packMessagePayload,
} from "@/lib/crypto";
import type { AttachmentMetadata } from "@/lib/types";
import { AttachmentPicker } from "@/components/AttachmentPicker";
import {
  Notice,
  PageHeading,
  PageLayout,
  ReportingGuide,
} from "@/components/ui";

export default function ReporterHomePage() {
  const router = useRouter();
  const [reportText, setReportText] = useState("");
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [progress, setProgress] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [createdMnemonic, setCreatedMnemonic] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [copyError, setCopyError] = useState<string | null>(null);

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    if (!reportText.trim() || isSubmitting) return;
    setIsSubmitting(true);
    setError(null);
    setProgress("Preparing encryption…");

    try {
      const pubKeyData = await api.getInvestigatorPublicKey();
      const { mnemonic, secrets } = await generateReporterBundle();
      const attachmentsMeta: AttachmentMetadata[] = [];
      const attachmentIds: string[] = [];

      for (const file of selectedFiles) {
        setProgress(
          `Encrypting attachment ${attachmentsMeta.length + 1} of ${selectedFiles.length}…`,
        );
        const fileBuffer = await file.arrayBuffer();
        const fileBytes = new Uint8Array(fileBuffer);
        const encrypted = await encryptAttachmentFile(
          fileBytes,
          file.name,
          file.type,
        );
        setProgress(
          `Uploading encrypted attachment ${attachmentsMeta.length + 1} of ${selectedFiles.length}…`,
        );
        const uploadRes = await api.uploadAttachment(encrypted.fileBlob);
        encrypted.metadata.attachmentId = uploadRes.attachmentId;
        attachmentsMeta.push(encrypted.metadata);
        attachmentIds.push(uploadRes.attachmentId);
      }

      setProgress("Encrypting your report…");
      const packedPayload = packMessagePayload(
        reportText.trim(),
        attachmentsMeta,
      );
      const encryptedReport = await encryptReport(
        packedPayload,
        pubKeyData.publicKey,
      );
      setProgress("Sending encrypted report…");
      await api.createCase({
        caseId: crypto.randomUUID(),
        reporterPublicKey: secrets.publicKeyBase64,
        caseAccessTokenHash: secrets.caseAccessTokenHashBase64,
        encryptedReport,
        attachmentIds: attachmentIds.length > 0 ? attachmentIds : undefined,
      });

      sessionStorage.setItem("sealed_mnemonic", mnemonic);
      setCreatedMnemonic(mnemonic);
      setReportText("");
      setSelectedFiles([]);
    } catch (err: unknown) {
      console.error(err);
      const message = err instanceof Error ? err.message : "Unknown error";
      setError(message || "Failed to submit report. Please try again.");
    } finally {
      setIsSubmitting(false);
      setProgress("");
    }
  }

  async function handleCopyMnemonic() {
    if (!createdMnemonic) return;
    setCopyError(null);
    try {
      await navigator.clipboard.writeText(createdMnemonic);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopyError(
        "Clipboard access is unavailable. Select and copy the words below, or write them down in order.",
      );
    }
  }

  function handleGoToTrack() {
    if (createdMnemonic)
      sessionStorage.setItem("sealed_mnemonic", createdMnemonic);
    router.push("/track");
  }

  if (createdMnemonic) {
    return (
      <PageLayout aside={<ReportingGuide mode="track" />}>
        <div className="success-heading" role="status">
          <CheckCircle2 size={16} /> Report submitted successfully
        </div>
        <PageHeading
          label="Your next step"
          title="Keep your access key safe"
          description="These 12 words are your way back to this report. Save them in order to read replies and continue the conversation."
        />
        <section className="panel" aria-labelledby="access-key-title">
          <div className="panel-header">
            <h2 id="access-key-title" className="panel-heading">
              <KeyRound size={15} /> Your access key
            </h2>
            <span className="panel-meta">12 words</span>
          </div>
          <div className="panel-body">
            <Notice variant="info">
              Keep this key private. Anyone with these words can access your
              conversation.
            </Notice>
            <ol className="phrase-grid" aria-label="Access key words in order">
              {createdMnemonic.split(" ").map((word, index) => (
                <li className="phrase-word" key={index}>
                  <span aria-hidden="true">
                    {String(index + 1).padStart(2, "0")}
                  </span>
                  <strong>{word}</strong>
                </li>
              ))}
            </ol>
            {copyError && (
              <div className="stack-sm">
                <Notice>{copyError}</Notice>
                <p className="mono field-description">{createdMnemonic}</p>
              </div>
            )}
            <div className="form-actions success-actions">
              <button
                type="button"
                className="btn"
                onClick={handleCopyMnemonic}
              >
                {copied ? <Check size={14} /> : <Copy size={14} />}
                {copied ? "Copied to clipboard" : "Copy access key"}
              </button>
              <button
                type="button"
                className="btn btn-primary"
                onClick={handleGoToTrack}
              >
                Open conversation
                <ArrowRight size={14} />
              </button>
            </div>
          </div>
        </section>
        <div className="access-note">
          <LockKeyhole size={16} />
          <div>
            <h3>No account to remember. Just your key.</h3>
            <p>
              You can return to Track a report and enter these words whenever
              you need to follow up.
            </p>
          </div>
        </div>
      </PageLayout>
    );
  }

  return (
    <PageLayout aside={<ReportingGuide />}>
      <PageHeading
        label="Make your voice heard"
        title="Submit a report"
        description="Share what happened, in your own words. Your report is encrypted in your browser before it’s sent."
      />
      <form onSubmit={handleSubmit} className="panel" aria-busy={isSubmitting}>
        <div className="panel-header">
          <h2 className="panel-heading">
            <FileText size={15} /> Report details
          </h2>
          <span className="panel-meta">Required</span>
        </div>
        <div className="panel-body">
          <label className="field-label" htmlFor="report">
            What would you like to report?
          </label>
          <textarea
            id="report"
            className="input report-editor"
            rows={10}
            value={reportText}
            onChange={(event) => setReportText(event.target.value)}
            placeholder={
              "Describe the incident in as much detail as you can.\n\nWhat happened? When and where did it happen? Who was involved?"
            }
            required
            disabled={isSubmitting}
            aria-describedby="report-hint"
          />
          <div className="editor-meta">
            <span id="report-hint">
              Include the details that will help someone understand.
            </span>
            <span>{reportText.length.toLocaleString()} chars</span>
          </div>
        </div>
        <AttachmentPicker
          files={selectedFiles}
          onChange={setSelectedFiles}
          disabled={isSubmitting}
        />
        {error && (
          <div className="form-notice">
            <Notice>
              <strong>We couldn’t submit your report.</strong>
              <br />
              {error} Your draft is still here.
            </Notice>
          </div>
        )}
        <div className="panel-footer">
          <div aria-live="polite">
            {isSubmitting ? (
              <span className="progress-feedback">
                <Loader2 size={13} className="spin" />
                {progress}
              </span>
            ) : (
              <span className="privacy-note">
                <LockKeyhole size={13} /> Your content is encrypted before
                sending
              </span>
            )}
          </div>
          <button
            className="btn btn-primary"
            type="submit"
            disabled={isSubmitting || !reportText.trim()}
          >
            {isSubmitting ? (
              <>
                <Loader2 size={14} className="spin" />
                Submitting…
              </>
            ) : (
              <>
                Submit report
                <ArrowRight size={14} />
              </>
            )}
          </button>
        </div>
      </form>
      <section className="below-panel" aria-labelledby="next-steps-title">
        <h2 id="next-steps-title" className="section-label">
          What happens next
        </h2>
        <div className="next-steps">
          <div className="next-step">
            <span>01</span>
            <h3>Save your access key</h3>
            <p>Receive 12 words to return to your report.</p>
          </div>
          <div className="next-step">
            <span>02</span>
            <h3>Your report is reviewed</h3>
            <p>An investigator can decrypt and review your report.</p>
          </div>
          <div className="next-step">
            <span>03</span>
            <h3>Continue the conversation</h3>
            <p>Use your key to check for replies or add information.</p>
          </div>
        </div>
      </section>
    </PageLayout>
  );
}
