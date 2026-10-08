import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import Navbar from "@/components/Navbar";
import { ParticlesBackground } from "@/components/ParticlesBackground";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "SEALED — Zero-Knowledge Whistleblower Platform",
  description: "End-to-end encrypted anonymous whistleblower platform powered by Libsodium and BIP-39.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="ru" className="dark">
      <body
        className={`${geistSans.variable} ${geistMono.variable} min-h-screen bg-[#0a0a0a] text-[#ededed] flex flex-col font-sans antialiased selection:bg-white/20 selection:text-white relative`}
      >
        <ParticlesBackground />
        <Navbar />
        <main className="flex-1 max-w-3xl w-full mx-auto px-6 sm:px-8 py-10 sm:py-14 relative z-10">
          {children}
        </main>
        <footer className="border-t border-white/[0.07] py-8 text-xs text-zinc-500 relative z-10">
          <div className="max-w-3xl mx-auto px-6 sm:px-8 flex flex-col sm:flex-row items-center justify-between gap-3 font-mono text-[11px]">
            <span className="text-zinc-400">
              SEALED &bull; Zero-Knowledge Relaying
            </span>
            <span className="text-zinc-600">
              Libsodium X25519 &bull; Argon2id &bull; BLAKE2b &bull; BIP-39
            </span>
          </div>
        </footer>
      </body>
    </html>
  );
}
