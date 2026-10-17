"use client";

import { ShieldAlert, ShieldCheck, Loader2, RefreshCw } from "lucide-react";
import type { AuditVerificationResponse } from "@/lib/types";

interface AuditBadgeProps {
  verification: AuditVerificationResponse | null;
  isLoading?: boolean;
  onRefresh?: () => void;
}

export function AuditBadge({
  verification,
  isLoading,
  onRefresh,
}: AuditBadgeProps) {
  if (isLoading) {
    return (
      <div className="audit-badge" role="status">
        <Loader2 size={13} className="spin" />
        <span>Verifying audit chain...</span>
      </div>
    );
  }

  if (!verification) {
    return null;
  }

  if (!verification.isValid) {
    return (
      <div className="audit-badge invalid" role="alert">
        <ShieldAlert size={14} />
        <span>
          Audit integrity broken ({verification.reason || "tampered"})
        </span>
        {onRefresh && (
          <button
            onClick={onRefresh}
            className="btn btn-ghost btn-icon"
            aria-label="Recheck audit integrity"
          >
            <RefreshCw className="w-3 h-3" />
          </button>
        )}
      </div>
    );
  }

  return (
    <div className="audit-badge" role="status">
      <ShieldCheck size={13} />
      <span>
        Audit chain verified · {verification.eventsCount}{" "}
        {verification.eventsCount === 1 ? "event" : "events"}
      </span>
      {onRefresh && (
        <button
          onClick={onRefresh}
          className="btn btn-ghost btn-icon"
          aria-label="Refresh audit verification"
        >
          <RefreshCw className="w-3 h-3" />
        </button>
      )}
    </div>
  );
}
