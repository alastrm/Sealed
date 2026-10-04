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
    <header className="border-b border-zinc-900 bg-black/80 backdrop-blur-md sticky top-0 z-50">
      <div className="max-w-3xl mx-auto px-4 h-16 flex items-center justify-between">
        <Link href="/" className="flex items-center gap-2.5 group">
          <div className="w-8 h-8 rounded-lg bg-zinc-900 border border-zinc-800 flex items-center justify-center text-white text-xs font-mono font-bold group-hover:border-zinc-700 transition-colors">
            SL
          </div>
          <span className="font-semibold text-sm tracking-tight text-white">
            SEALED
          </span>
          <span className="hidden sm:inline-block text-[11px] font-mono px-2 py-0.5 rounded border border-zinc-800 bg-zinc-950 text-zinc-400">
            E2EE
          </span>
        </Link>

        <nav className="flex items-center gap-1">
          {links.map((link) => {
            const isActive =
              pathname === link.href ||
              (link.href !== '/' && pathname.startsWith(link.href));
            return (
              <Link
                key={link.href}
                href={link.href}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                  isActive
                    ? 'bg-zinc-900 text-white border border-zinc-800'
                    : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-950'
                }`}
              >
                {link.label}
              </Link>
            );
          })}
        </nav>
      </div>
    </header>
  );
}

