/** Access authentication is independent of the report-decryption password. */
export async function createInvestigatorProof(
  accessKey: string,
  challengeId: string,
  nonce: string,
  username: string,
  origin: string,
): Promise<string> {
  if (!/^[0-9a-f]{64}$/i.test(accessKey)) {
    throw new Error('Enter the 64-character workspace access key from local setup.');
  }
  const bytes = Uint8Array.from(accessKey.match(/../g)!, (part) => parseInt(part, 16));
  try {
    const key = await crypto.subtle.importKey(
      'raw', bytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'],
    );
    const message = new TextEncoder().encode(
      `sealed:investigator-auth:v1\n${challengeId}\n${nonce}\n${username}\n${origin}`,
    );
    const signature = await crypto.subtle.sign('HMAC', key, message);
    return Array.from(new Uint8Array(signature), (byte) => byte.toString(16).padStart(2, '0')).join('');
  } finally {
    bytes.fill(0);
  }
}
