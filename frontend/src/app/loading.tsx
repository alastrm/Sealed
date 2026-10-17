import { Loader2 } from "lucide-react";

export default function Loading() {
  return (
    <div className="loading-state" role="status">
      <Loader2 size={16} className="spin" />
      Loading workspace…
    </div>
  );
}
