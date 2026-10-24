'use client';

import { useState } from 'react';
import { KeyRound, Download } from 'lucide-react';
import { createInvestigatorIdentity } from '@/lib/protocol';
import { triggerSafeDownload } from '@/lib/crypto';
import type { IdentityPacket } from '@/lib/types';
import { Notice, PageHeading, PageLayout } from '@/components/ui';

export default function IdentitySetup() {
  const [password, setPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [packet, setPacket] = useState<IdentityPacket | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function generate(event: React.FormEvent) {
    event.preventDefault();
    if (busy) return;
    if (password !== confirmation) { setError('Passwords do not match.'); return; }
    setBusy(true);
    setError(null);
    const secret = password;
    setPassword('');
    setConfirmation('');
    try { setPacket(await createInvestigatorIdentity(secret)); }
    catch (err) { setError(err instanceof Error ? err.message : 'Cannot initialize identity.'); }
    finally { setBusy(false); }
  }

  return <PageLayout>
    <PageHeading label="Local identity setup" title="Initialize an investigator identity"
      description="Generate fresh encryption and signing keys in this browser. This does not activate or replace any account." />
    <section className="panel login-panel">
      <div className="panel-header"><h2 className="panel-heading"><KeyRound size={15} /> Protocol v2 identity</h2></div>
      <div className="panel-body form-fields">
        {!packet ? <form className="form-fields" onSubmit={generate} aria-busy={busy}>
          <p className="field-description">Use a fresh, private master password. Do not use the public demo password. Back up the encrypted export and password separately.</p>
          <label className="field-label" htmlFor="new-master">New master password</label>
          <input id="new-master" className="input" type="password" minLength={16} required
            autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} disabled={busy} />
          <label className="field-label" htmlFor="confirm-master">Confirm master password</label>
          <input id="confirm-master" className="input" type="password" minLength={16} required
            autoComplete="new-password" value={confirmation} onChange={(e) => setConfirmation(e.target.value)} disabled={busy} />
          <button className="btn btn-primary" disabled={busy}>{busy ? 'Generating identity...' : 'Generate fresh identity'}</button>
        </form> : <>
          <Notice variant="success">Identity generated. Only encrypted private material is exported.</Notice>
          <button type="button" className="btn" onClick={() => triggerSafeDownload(
            new TextEncoder().encode(JSON.stringify(packet, null, 2)), 'sealed-identity-v2.json', 'application/json',
          )}><Download size={14} /> Download encrypted identity</button>
          <label htmlFor="identity-pin" className="field-label">Trusted signing-key pin</label>
          <textarea id="identity-pin" className="input mono" readOnly rows={3}
            value={`NEXT_PUBLIC_INVESTIGATOR_SIGNING_KEYS=${packet.signingPublicKey}`} />
          <p className="field-description">Copy this public pin directly from this trusted setup session to frontend/.env.local. It must not be learned from an API response. Keep earlier trusted pins in the comma-separated allowlist to read archived cases.</p>
          <p className="field-description">Run the local import command documented in CRYPTOGRAPHIC_AUTHENTICITY.md, then restart/rebuild the frontend. Importing a new identity archives prior identities and their conversations.</p>
        </>}
        {error && <Notice>{error}</Notice>}
      </div>
    </section>
  </PageLayout>;
}
