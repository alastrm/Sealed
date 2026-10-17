# SEALED — Frontend Client

Next.js 16 (App Router), React 19, TypeScript, Tailwind CSS 4, and Lucide icons. Client-side cryptography is powered by Libsodium WebAssembly and BIP-39.

## Interface

The shared application shell provides navigation, breadcrumbs, and consistent page surfaces. Submit and Track pair a focused form with contextual guidance. The unlocked Investigator workspace uses a report list and detail view. Mobile navigation becomes a compact row; guidance moves below the primary interaction.

Design tokens live in `src/app/globals.css`: graphite surfaces, low-contrast separators, a restrained violet accent, a 4px spacing scale, system typography, and 5–8px component radii. System fonts require no font downloads or CDN requests. Shared notices, status badges, message threads, reply composers, and attachment controls keep interaction states consistent. Controls support visible keyboard focus and reduced motion.

`src/lib/crypto.ts`, `src/lib/api.ts`, and the session hooks retain their existing encryption, request, and storage behavior.

## Development and checks

```bash
npm run dev
npm run lint
npm run build
```

If Turbopack's CSS worker fails in the local Windows environment, Next.js also supports `npm run dev -- --webpack` and `npm run build -- --webpack`.

The frontend proxies `/api` to `http://127.0.0.1:8000` by default. `BACKEND_INTERNAL_URL` can point the development server or build at an isolated test backend. Use a disposable `DATABASE_URL` when running the root API test suite: it resets the database.

For full architecture, threat model, and setup instructions, see the main [README.md](../README.md).
