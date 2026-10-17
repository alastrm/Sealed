"use client";

import dynamic from "next/dynamic";
import Loading from "@/app/loading";

// The existing session hook reads tab-local storage on initialization. Mount the
// form in the browser so the server's empty session cannot cause a hydration mismatch.
const TrackReport = dynamic(() => import("@/components/TrackReport"), {
  ssr: false,
  loading: Loading,
});

export default function TrackCasePage() {
  return <TrackReport />;
}
