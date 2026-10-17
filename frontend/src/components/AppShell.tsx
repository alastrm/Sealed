"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  ArrowUpRight,
  ChevronRight,
  FilePlus2,
  Fingerprint,
  LockKeyhole,
  Search,
  Shield,
  ShieldCheck,
} from "lucide-react";

const links = [
  {
    href: "/",
    label: "Submit a report",
    shortLabel: "Submit",
    icon: FilePlus2,
  },
  {
    href: "/track",
    label: "Track a report",
    shortLabel: "Track",
    icon: Search,
  },
  {
    href: "/investigator",
    label: "Investigator",
    shortLabel: "Investigator",
    icon: ShieldCheck,
  },
];

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const current = links.find((link) =>
    link.href === "/" ? pathname === "/" : pathname.startsWith(link.href),
  );

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">
        Skip to content
      </a>
      <aside className="sidebar" aria-label="Application navigation">
        <Link href="/" className="brand" aria-label="Sealed home">
          <span className="brand-mark">
            <Shield size={19} strokeWidth={1.7} />
            <span />
          </span>
          <span>
            sealed<span className="brand-period">.</span>
          </span>
        </Link>
        <div className="sidebar-caption">Anonymous reporting</div>
        <nav className="navigation" aria-label="Main navigation">
          {links.map(({ href, label, shortLabel, icon: Icon }, index) => {
            const active =
              href === "/" ? pathname === "/" : pathname.startsWith(href);
            return (
              <div
                key={href}
                className={index === 2 ? "nav-section" : undefined}
              >
                {index === 2 && (
                  <div className="nav-section-label">Workspace</div>
                )}
                <Link
                  href={href}
                  aria-current={active ? "page" : undefined}
                  className={`nav-link ${active ? "active" : ""}`}
                >
                  <Icon size={16} strokeWidth={1.7} />
                  <span className="nav-label-desktop">{label}</span>
                  <span className="nav-label-mobile">{shortLabel}</span>
                  {active && <span className="nav-active-dot" />}
                </Link>
              </div>
            );
          })}
        </nav>
        <div className="sidebar-bottom">
          <div className="sidebar-privacy">
            <Fingerprint size={20} strokeWidth={1.4} />
            <span>A voice, without a name.</span>
          </div>
          <p>
            Report what matters.
            <br />
            Keep control of your identity.
          </p>
          <div className="sidebar-bottom-label">
            <LockKeyhole size={12} /> Client-side encryption
          </div>
        </div>
      </aside>
      <div className="workspace">
        <header className="topbar">
          <div className="breadcrumbs">
            <span>Reporting</span>
            <ChevronRight size={13} />
            <span>{current?.label || "Sealed"}</span>
          </div>
          <span className="topbar-meta">
            <LockKeyhole size={13} /> Encrypted in your browser
          </span>
        </header>
        <main id="main-content" className="workspace-main">
          {children}
        </main>
        <footer className="workspace-footer">
          <span>
            Sealed <span className="footer-divider">/</span> Anonymous reporting
          </span>
          <Link href="/track">
            Already submitted? Track your report <ArrowUpRight size={12} />
          </Link>
        </footer>
      </div>
    </div>
  );
}
