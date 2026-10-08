'use client';

import { ShieldCheck, ShieldAlert, Loader2, RefreshCw } from 'lucide-react';
import type { AuditVerificationResponse } from '@/lib/types';

interface AuditBadgeProps {
  verification: AuditVerificationResponse | null;
  isLoading?: boolean;
  onRefresh?: () => void;
}

export function AuditBadge({ verification, isLoading, onRefresh }: AuditBadgeProps) {
  if (isLoading) {
    return (
      <div className="flex items-center gap-2 p-2.5 rounded-md border border-white/[0.08] bg-black/40 text-zinc-400 text-xs font-mono">
        <Loader2 className="w-3.5 h-3.5 animate-spin text-zinc-500" />
        <span>Верификация цепочки BLAKE2b...</span>
      </div>
    );
  }

  if (!verification) {
    return null;
  }

  if (!verification.isValid) {
    return (
      <div className="flex items-start sm:items-center justify-between gap-3 p-3 rounded-md border border-red-500/30 bg-red-950/20 text-red-300 text-xs animate-in fade-in">
        <div className="flex items-start sm:items-center gap-2 font-mono">
          <ShieldAlert className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5 sm:mt-0" />
          <div>
            <div className="font-medium text-red-200">
              Целостность нарушена: Tampered Audit Log
            </div>
            <p className="text-[11px] text-red-400/80 mt-0.5">
              Сбой на записи: {verification.brokenAt || 'неизвестно'}{' '}
              {verification.reason ? `(${verification.reason})` : ''}
            </p>
          </div>
        </div>
        {onRefresh && (
          <button
            onClick={onRefresh}
            className="p-1 rounded text-red-400 hover:text-white transition-colors"
            title="Перепроверить цепочку"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        )}
      </div>
    );
  }

  return (
    <div className="flex items-start sm:items-center justify-between gap-3 p-2.5 rounded-md border border-emerald-500/20 bg-emerald-950/10 text-emerald-400 text-xs animate-in fade-in">
      <div className="flex items-start sm:items-center gap-2 flex-wrap font-mono">
        <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 flex-shrink-0 mt-0.5 sm:mt-0" />
        <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
          <span className="font-medium text-emerald-300">
            BLAKE2b Audit Chain: Verified
          </span>
          <span className="text-[11px] text-emerald-400/70">
            • {verification.eventsCount} {verification.eventsCount === 1 ? 'запись' : 'записей'}
          </span>
          {verification.latestHash && (
            <span
              className="text-[10px] text-emerald-500/70 truncate max-w-[200px] sm:max-w-xs"
              title={verification.latestHash}
            >
              • {verification.latestHash.slice(0, 16)}...
            </span>
          )}
        </div>
      </div>
      {onRefresh && (
        <button
          onClick={onRefresh}
          className="p-1 rounded text-emerald-400/60 hover:text-emerald-200 transition-colors"
          title="Перепроверить цепочку"
        >
          <RefreshCw className="w-3 h-3" />
        </button>
      )}
    </div>
  );
}
