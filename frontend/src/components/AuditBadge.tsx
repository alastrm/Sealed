'use client';

import { ShieldAlert, Loader2, RefreshCw } from 'lucide-react';
import type { AuditVerificationResponse } from '@/lib/types';

interface AuditBadgeProps {
  verification: AuditVerificationResponse | null;
  isLoading?: boolean;
  onRefresh?: () => void;
}

export function AuditBadge({ verification, isLoading, onRefresh }: AuditBadgeProps) {
  if (isLoading) {
    return (
      <div className="flex items-center gap-2 text-xs text-zinc-500 font-mono">
        <Loader2 className="w-3 h-3 animate-spin" />
        <span>Проверка цепочки аудита...</span>
      </div>
    );
  }

  if (!verification) {
    return null;
  }

  if (!verification.isValid) {
    return (
      <div className="flex items-center justify-between gap-2 p-2.5 rounded-lg bg-red-950/20 border border-red-500/20 text-xs text-red-400 font-mono">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-3.5 h-3.5 flex-shrink-0" />
          <span>Целостность аудита нарушена ({verification.reason || 'tampered'})</span>
        </div>
        {onRefresh && (
          <button
            onClick={onRefresh}
            className="hover:text-white transition-colors cursor-pointer"
            title="Перепроверить"
          >
            <RefreshCw className="w-3 h-3" />
          </button>
        )}
      </div>
    );
  }

  return (
    <div className="flex items-center gap-2 text-xs text-zinc-500 font-mono">
      <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
      <span>Целостность подтверждена (BLAKE2b • {verification.eventsCount} событий)</span>
      {onRefresh && (
        <button
          onClick={onRefresh}
          className="hover:text-zinc-300 transition-colors cursor-pointer"
          title="Обновить аудит"
        >
          <RefreshCw className="w-3 h-3" />
        </button>
      )}
    </div>
  );
}
