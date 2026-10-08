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
      <div className="flex items-center gap-2 p-2.5 rounded-xl border border-zinc-800 bg-zinc-950/60 text-zinc-400 text-xs">
        <Loader2 className="w-3.5 h-3.5 animate-spin text-zinc-400" />
        <span>Верификация криптографической цепочки BLAKE2b...</span>
      </div>
    );
  }

  if (!verification) {
    return null;
  }

  if (!verification.isValid) {
    return (
      <div className="flex items-start sm:items-center justify-between gap-3 p-3 rounded-xl border border-red-500/40 bg-red-950/30 text-red-300 text-xs animate-in fade-in">
        <div className="flex items-start sm:items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5 sm:mt-0" />
          <div>
            <div className="font-semibold text-red-200">
              Внимание: Нарушение целостности журнала аудита! (Tampered)
            </div>
            <p className="text-[11px] font-mono text-red-400/90 mt-0.5">
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
    <div className="flex items-start sm:items-center justify-between gap-3 p-2.5 rounded-xl border border-emerald-500/40 bg-emerald-950/20 text-emerald-400 text-xs animate-in fade-in">
      <div className="flex items-start sm:items-center gap-2 flex-wrap">
        <ShieldCheck className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5 sm:mt-0" />
        <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5">
          <span className="font-semibold text-emerald-300">
            Целостность аудита подтверждена (BLAKE2b Chain: Verified)
          </span>
          <span className="text-[11px] font-mono text-emerald-400/80">
            • Записей: {verification.eventsCount}
          </span>
          {verification.latestHash && (
            <span
              className="text-[10px] font-mono text-emerald-500/80 truncate max-w-[200px] sm:max-w-xs"
              title={verification.latestHash}
            >
              • Хэш: {verification.latestHash.slice(0, 16)}...
            </span>
          )}
        </div>
      </div>
      {onRefresh && (
        <button
          onClick={onRefresh}
          className="p-1 rounded text-emerald-400/80 hover:text-emerald-200 transition-colors"
          title="Перепроверить цепочку"
        >
          <RefreshCw className="w-3.5 h-3.5" />
        </button>
      )}
    </div>
  );
}
