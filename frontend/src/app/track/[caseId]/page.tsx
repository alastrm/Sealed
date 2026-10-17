"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { Loader2 } from "lucide-react";

export default function TrackRedirectPage() {
  const router = useRouter();

  useEffect(() => {
    router.replace("/track");
  }, [router]);

  return (
    <div className="loading-state" role="status">
      <Loader2 size={16} className="spin" /> Opening report tracking…
    </div>
  );
}
