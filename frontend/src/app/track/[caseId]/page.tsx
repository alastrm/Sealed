'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';

export default function TrackRedirectPage() {
  const router = useRouter();

  useEffect(() => {
    router.replace('/track');
  }, [router]);

  return (
    <div className="flex items-center justify-center py-20 text-xs font-mono text-zinc-400">
      Перенаправление на страницу проверки статуса...
    </div>
  );
}
