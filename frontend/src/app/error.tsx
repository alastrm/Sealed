"use client";

import { RefreshCw } from "lucide-react";
import { Notice, PageHeading } from "@/components/ui";

export default function ErrorPage({
  retry,
}: {
  error: Error & { digest?: string };
  retry: () => void;
}) {
  return (
    <div className="fallback-page">
      <PageHeading
        title="Something went wrong"
        description="We couldn’t display this page. Try again to reopen the workspace."
      />
      <div className="stack">
        <Notice>
          Check your connection and try again. Keep a copy of your access key
          before leaving this page.
        </Notice>
        <div>
          <button type="button" className="btn" onClick={() => retry()}>
            <RefreshCw size={14} />
            Try again
          </button>
        </div>
      </div>
    </div>
  );
}
