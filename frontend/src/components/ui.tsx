import {
  AlertCircle,
  Check,
  CheckCircle2,
  Circle,
  CircleDashed,
  Clock3,
  FileText,
  LockKeyhole,
  MessageSquare,
  type LucideIcon,
} from "lucide-react";
import type { CaseStatus } from "@/lib/types";

export function PageHeading({
  title,
  description,
  label,
  actions,
}: {
  title: string;
  description: string;
  label?: string;
  actions?: React.ReactNode;
}) {
  return (
    <div className="page-heading">
      <div>
        {label && <div className="eyebrow">{label}</div>}
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {actions && <div className="heading-actions">{actions}</div>}
    </div>
  );
}

export function PageLayout({
  children,
  aside,
}: {
  children: React.ReactNode;
  aside?: React.ReactNode;
}) {
  return (
    <div className={`page-layout ${aside ? "" : "single-column"}`}>
      <div className="page-content">{children}</div>
      {aside && <aside className="context-panel">{aside}</aside>}
    </div>
  );
}

export function Notice({
  children,
  variant = "error",
  id,
}: {
  children: React.ReactNode;
  variant?: "error" | "success" | "info";
  id?: string;
}) {
  const Icon = variant === "success" ? CheckCircle2 : AlertCircle;
  return (
    <div
      id={id}
      className={`notice notice-${variant}`}
      role={variant === "error" ? "alert" : "status"}
    >
      <Icon size={16} />
      <div>{children}</div>
    </div>
  );
}

export function EmptyState({
  icon: Icon = MessageSquare,
  title,
  children,
}: {
  icon?: LucideIcon;
  title: string;
  children?: React.ReactNode;
}) {
  return (
    <div className="empty-state">
      <span className="empty-icon">
        <Icon size={22} strokeWidth={1.5} />
      </span>
      <h3>{title}</h3>
      {children && <p>{children}</p>}
    </div>
  );
}

const statuses: Record<
  CaseStatus,
  { label: string; icon: LucideIcon; className: string }
> = {
  OPEN: {
    label: "Awaiting reply",
    icon: CircleDashed,
    className: "status-open",
  },
  IN_REVIEW: { label: "In review", icon: Clock3, className: "status-review" },
  RESPONDED: {
    label: "Replied",
    icon: CheckCircle2,
    className: "status-replied",
  },
  CLOSED: { label: "Closed", icon: Check, className: "status-closed" },
};

export function StatusBadge({ status }: { status: CaseStatus }) {
  const item = statuses[status] || {
    label: status,
    icon: Circle,
    className: "",
  };
  return (
    <span className={`status-badge ${item.className}`}>
      <item.icon size={13} />
      {item.label}
    </span>
  );
}

export function ReportingGuide({
  mode = "submit",
}: {
  mode?: "submit" | "track" | "investigator";
}) {
  return (
    <>
      <section className="context-section">
        <div className="context-title">
          <FileText size={15} />
          <h2>
            {mode === "submit"
              ? "A clear report makes a difference"
              : mode === "track"
                ? "Your report, continued"
                : "Investigator workspace"}
          </h2>
        </div>
        {mode === "submit" ? (
          <>
            <GuideItem number="01" title="Describe what happened">
              Include the facts, relevant dates, and people or organizations
              involved.
            </GuideItem>
            <GuideItem number="02" title="Add supporting evidence">
              Attach relevant documents or files. Each file must be smaller than
              10 MB.
            </GuideItem>
            <GuideItem number="03" title="Save your access key">
              After submitting, you’ll receive 12 words to access replies and
              follow up.
            </GuideItem>
          </>
        ) : mode === "track" ? (
          <>
            <GuideItem number="01" title="Enter your 12 words">
              Use the access key you received when you submitted your report, in
              the original order.
            </GuideItem>
            <GuideItem number="02" title="Continue the conversation">
              Read replies from the investigator and send additional information
              or files.
            </GuideItem>
            <GuideItem number="03" title="Keep your key private">
              Anyone with these words can access your conversation. Store them
              somewhere safe.
            </GuideItem>
          </>
        ) : (
          <>
            <GuideItem number="01" title="Unlock your workspace">
              Your password unlocks your investigator key in this browser.
            </GuideItem>
            <GuideItem number="02" title="Review incoming reports">
              Select a report to decrypt its content and view the conversation.
            </GuideItem>
            <GuideItem number="03" title="Respond with care">
              Replies and attachments are encrypted before they’re sent to the
              reporter.
            </GuideItem>
          </>
        )}
      </section>
      <section className="context-section">
        <div className="context-title">
          <LockKeyhole size={15} />
          <h2>Encryption, by design</h2>
        </div>
        <p className="context-copy">
          Report content and attachments are encrypted in your browser before
          being sent.
        </p>
        <div className="context-fact">
          <span className="quiet-dot" /> Content is decrypted locally
        </div>
        <div className="context-fact">
          <span className="quiet-dot" /> No email needed to submit a report
        </div>
      </section>
      {mode === "submit" && (
        <p className="context-footnote">
          Only share the personal details you’re comfortable including in your
          report.
        </p>
      )}
    </>
  );
}

function GuideItem({
  number,
  title,
  children,
}: {
  number: string;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="guide-item">
      <span className="guide-number">{number}</span>
      <div>
        <h3>{title}</h3>
        <p>{children}</p>
      </div>
    </div>
  );
}
