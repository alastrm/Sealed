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
        <span>Checking stored history...</span>
      </div>
    );
  }

  if (!verification) {
    return null;
  }

  if (verification.status !== 'consistent') {
    return (
      <div className={`audit-badge ${verification.status === 'inconsistent' ? 'invalid' : ''}`} role="status">
        <ShieldAlert size={14} />
        <span>
          {verification.status === 'inconsistent' ? 'History consistency check failed.' : verification.status === 'legacy' ? 'UNVERIFIED legacy history.' : 'History verification unavailable.'}
          {verification.reason && ` ${verification.reason}`}
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
    <div className="audit-badge" role="status" title="The server checks stored data and signatures against its history. This does not prove complete history or protect against a server rewriting or rolling back all records.">
      <ShieldCheck size={13} />
      <span>
        Server consistency check passed · {verification.eventsCount}{" "}
        {verification.eventsCount === 1 ? "event" : "events"}
        {verification.historicalBaseline ? ' · Earlier history unverified' : ''}
        {' · Completeness not proven'}
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
