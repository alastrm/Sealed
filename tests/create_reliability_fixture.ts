/** Synthetic fixture generator. JSON is captured privately by the test launcher. */
import { randomBytes, randomUUID } from 'node:crypto';
import { createInvestigatorIdentity } from '../frontend/src/lib/protocol';
import { initCrypto, toBase64, generateReporterBundle, encryptReport, encryptInvestigatorReply, wipeMemory } from '../frontend/src/lib/crypto';

async function main() {
  const password = randomBytes(32).toString('hex');
  const packet = await createInvestigatorIdentity(password);
  const sodium = await initCrypto();
  const box = sodium.crypto_box_keypair();
  const salt = sodium.randombytes_buf(16), nonce = sodium.randombytes_buf(24);
  const kek = sodium.crypto_pwhash(32, password, salt, 2, 67108864, 2);
  const reporter = await generateReporterBundle();
  try {
    return { password, accessKey: randomBytes(32).toString('hex'), packet,
      account: { id: randomUUID(), username: 'investigator@local.test', publicKey: toBase64(box.publicKey),
        encryptedPrivateKey: toBase64(sodium.crypto_secretbox_easy(box.privateKey, nonce, kek)),
        privateKeyNonce: toBase64(nonce), kdfSalt: toBase64(salt), kdfOpsLimit: 2, kdfMemLimit: 67108864, kdfAlgorithm: 2 },
      legacy: { id: randomUUID(), mnemonic: reporter.mnemonic, reporterPublicKey: reporter.secrets.publicKeyBase64,
        caseAccessTokenHash: reporter.secrets.caseAccessTokenHashBase64,
        encryptedReport: await encryptReport('Synthetic legacy archive report', toBase64(box.publicKey)),
        reply: await encryptInvestigatorReply('Synthetic unverified legacy reply', reporter.secrets.publicKeyBase64, box.privateKey) },
    };
  } finally { wipeMemory(box.privateKey, kek, reporter.secrets.privateKey, reporter.secrets.signingPrivateKey); }
}
main().then(value => process.stdout.write(JSON.stringify(value))).catch(() => { process.stderr.write('Synthetic fixture generation failed.'); process.exitCode = 1; });
