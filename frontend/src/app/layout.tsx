import type { Metadata } from "next";
import { IBM_Plex_Sans, IBM_Plex_Mono } from "next/font/google";
import "./globals.css";
import Navbar from "@/components/Navbar";
import { ParticlesBackground } from "@/components/ParticlesBackground";

const ibmPlexSans = IBM_Plex_Sans({
  variable: "--font-ibm-sans",
  subsets: ["latin", "cyrillic"],
  weight: ["300", "400", "500", "600"],
  display: "swap",
});

const ibmPlexMono = IBM_Plex_Mono({
  variable: "--font-ibm-mono",
  subsets: ["latin", "cyrillic"],
  weight: ["400", "500"],
  display: "swap",
});

export const metadata: Metadata = {
  title: "SEALED — Анонимный ящик доверия",
  description: "End-to-end encrypted anonymous whistleblower platform.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="ru" className="dark">
      <body
        className={`${ibmPlexSans.variable} ${ibmPlexMono.variable} min-h-screen bg-[#0a0a0a] text-[#ededed] flex flex-col font-sans antialiased selection:bg-white/20 selection:text-white relative`}
      >
        <ParticlesBackground />
        <Navbar />
        <main className="flex-1 max-w-2xl w-full mx-auto px-6 py-12 sm:py-16 relative z-10">
          {children}
        </main>
        <footer className="py-8 text-xs text-zinc-500 relative z-10 border-t border-white/5">
          <div className="max-w-2xl mx-auto px-6 flex items-center justify-between text-zinc-500 text-xs">
            <span>SEALED</span>
            <span>Zero-Knowledge Relay</span>
          </div>
        </footer>
      </body>
    </html>
  );
}
