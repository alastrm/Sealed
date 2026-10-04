import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import Navbar from "@/components/Navbar";

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
        className={`${geistSans.variable} ${geistMono.variable} min-h-screen bg-black text-zinc-100 flex flex-col font-sans antialiased selection:bg-zinc-800 selection:text-white`}
      >
        <Navbar />
        <main className="flex-1 max-w-3xl w-full mx-auto px-4 py-12">
          {children}
        </main>
        <footer className="border-t border-zinc-900 py-8 text-xs text-zinc-400">
          <div className="max-w-3xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-3">
            <span className="font-mono text-zinc-400">
              SEALED &bull; Zero-Knowledge Architecture
            </span>
            <span className="text-zinc-400 font-mono text-[11px]">
              X25519 &bull; Argon2id &bull; BLAKE2b &bull; BIP-39
            </span>
          </div>
        </footer>
      </body>
    </html>
  );
}
