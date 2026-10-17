import Link from "next/link";
import { ArrowLeft, FileQuestion } from "lucide-react";
import { PageHeading } from "@/components/ui";

export default function NotFound() {
  return (
    <div className="fallback-page">
      <span className="empty-icon">
        <FileQuestion size={22} />
      </span>
      <PageHeading
        label="404 · Page not found"
        title="This page isn’t here"
        description="Check the address, or return to Sealed to submit or track a report."
      />
      <Link href="/" className="btn">
        <ArrowLeft size={14} />
        Back to Sealed
      </Link>
    </div>
  );
}
