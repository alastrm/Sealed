'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';

export default function Navbar() {
  const pathname = usePathname();

  const links = [
    { href: '/', label: 'Подать отчёт' },
    { href: '/track', label: 'Проверить статус' },
    { href: '/investigator', label: 'Следователь' },
  ];

  return (
    <header className="sticky top-0 z-50 w-full bg-[#0a0a0a]/80 backdrop-blur-md border-b border-white/[0.07] transition-colors">
      <div className="max-w-3xl mx-auto px-6 sm:px-8 h-14 flex items-center justify-between">
        <Link
          href="/"
          className="flex items-center gap-2 font-semibold text-sm tracking-tight text-[#ededed] hover:opacity-80 transition-opacity"
        >
          <span>SEALED</span>
          <span className="text-zinc-600 font-mono text-xs font-normal">/</span>
          <span className="text-zinc-500 font-mono text-[11px] font-normal hidden sm:inline">
            E2EE
          </span>
        </Link>

        <div className="flex items-center gap-5 sm:gap-6 text-xs sm:text-sm">
          <nav className="flex items-center gap-4 sm:gap-5 text-zinc-400">
            {links.map((link) => {
              const isActive =
                pathname === link.href ||
                (link.href !== '/' && pathname.startsWith(link.href));
              return (
                <Link
                  key={link.href}
                  href={link.href}
                  className={`transition-colors ${
                    isActive
                      ? 'text-white font-medium'
                      : 'hover:text-zinc-200'
                  }`}
                >
                  {link.label}
                </Link>
              );
            })}
          </nav>
          <span className="h-3.5 w-px bg-white/[0.1]"></span>
          <div className="flex items-center gap-1.5" title="Crypto backend active">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
            <span className="text-[11px] font-mono text-zinc-500 hidden sm:inline">
              X25519
            </span>
          </div>
        </div>
      </div>
    </header>
  );
}

