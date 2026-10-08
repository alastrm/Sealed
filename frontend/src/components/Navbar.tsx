'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';

export default function Navbar() {
  const pathname = usePathname();

  const links = [
    { href: '/', label: 'Submit' },
    { href: '/track', label: 'Track' },
    { href: '/investigator', label: 'Investigator' },
  ];

  return (
    <header className="sticky top-0 z-50 w-full bg-[#0a0a0a]/80 backdrop-blur-md transition-colors">
      <div className="max-w-2xl mx-auto px-6 h-16 flex items-center justify-between">
        <Link
          href="/"
          className="font-medium text-sm tracking-tight text-white hover:opacity-80 transition-opacity"
        >
          SEALED
        </Link>

        <nav className="flex items-center gap-6 text-sm text-zinc-400">
          {links.map((link) => {
            const isActive =
              pathname === link.href ||
              (link.href !== '/' && pathname.startsWith(link.href));
            return (
              <Link
                key={link.href}
                href={link.href}
                className={`transition-colors ${
                  isActive ? 'text-white font-medium' : 'hover:text-zinc-200'
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
