'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { api, ApiError } from '@/lib/api';
import { prepareReply, deliverReply, type PendingReply } from '@/lib/replyDelivery';
import type { InvestigatorResponseDto } from '@/lib/types';
import { readThread, signMessage, verifyManifest } from '@/lib/protocol';
import {
  deriveReporterSecrets,
  wipeMemory,
  type ReporterSecrets,
} from '@/lib/crypto';
import type {
  AttachmentMetadata,
  AuditVerificationResponse,
  CaseAccessResponseDto,
  CaseMessageDto,
} from '@/lib/types';

export interface DecryptedReporterMessage extends CaseMessageDto {
  decryptedText: string;
  attachments?: AttachmentMetadata[];
}

export function useReporterCase() {
  const [mnemonicInput, setMnemonicInput] = useState(() => {
    if (typeof window !== 'undefined') {
      try {
        return sessionStorage.getItem('sealed_mnemonic') || '';
      } catch {
        return '';
      }
    }
    return '';
  });

  const generation = useRef(0);
  const [fromSession, setFromSession] = useState(() => {
    if (typeof window !== 'undefined') {
      try {
        return !!sessionStorage.getItem('sealed_mnemonic');
      } catch {
        return false;
      }
    }
    return false;
  });

  const [isVerifying, setIsVerifying] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [caseData, setCaseData] = useState<CaseAccessResponseDto | null>(null);
  const [activeSecrets, setActiveSecrets] = useState<ReporterSecrets | null>(null);
  const activeSecretsRef = useRef<ReporterSecrets | null>(null);

  useEffect(() => {
    activeSecretsRef.current = activeSecrets;
  }, [activeSecrets]);

  const [decryptedMessages, setDecryptedMessages] = useState<DecryptedReporterMessage[]>([]);

  // Tamper-evident Audit Chain state
  const [auditVerification, setAuditVerification] = useState<AuditVerificationResponse | null>(null);
  const [isVerifyingAudit, setIsVerifyingAudit] = useState(false);

  // Reply state
  const [isSendingReply, setIsSendingReply] = useState(false);
  const [replyError, setReplyError] = useState<string | null>(null);
  const pendingReply = useRef<PendingReply<InvestigatorResponseDto> | null>(null);
  const replyBusy = useRef(false);
  const [replyPending, setReplyPending] = useState(false);
  const lookupAbort = useRef<AbortController | null>(null);

  // Auto wipe memory on unmount
  useEffect(() => {
    return () => {
      generation.current += 1;
      lookupAbort.current?.abort();
      const sec = activeSecretsRef.current;
      if (sec) {
        wipeMemory(
          sec.publicKey,
          sec.privateKey,
          sec.signingPrivateKey,
          sec.caseAccessToken,
          sec.caseAccessTokenHash
        );
      }
    };
  }, []);

  const fetchAuditVerification = useCallback(async (caseId: string) => {
    const operation = generation.current;
    setIsVerifyingAudit(true);
    setAuditVerification(null);
    try {
      const res = await api.verifyAuditChain(caseId, activeSecretsRef.current || undefined);
      if (operation === generation.current) setAuditVerification(res);
    } catch (err) {
      console.error('Failed to verify audit chain:', err);
    } finally {
      if (operation === generation.current) setIsVerifyingAudit(false);
    }
  }, []);

  const clearSession = useCallback(() => {
    generation.current += 1;
    lookupAbort.current?.abort();
    pendingReply.current = null;
    setReplyPending(false);
    try {
      sessionStorage.removeItem('sealed_mnemonic');
    } catch {
      // ignore
    }

    if (activeSecrets) {
      wipeMemory(
        activeSecrets.publicKey,
        activeSecrets.privateKey,
        activeSecrets.signingPrivateKey,
        activeSecrets.caseAccessToken,
        activeSecrets.caseAccessTokenHash
      );
    }

    activeSecretsRef.current = null;
    setMnemonicInput('');
    setFromSession(false);
    setCaseData(null);
    setActiveSecrets(null);
    setDecryptedMessages([]);
    setAuditVerification(null);
    setError(null);
    setReplyError(null);
    setIsSendingReply(false);
    setIsVerifying(false);
  }, [activeSecrets]);

  const lookupCase = useCallback(
    async (phraseToLookup?: string) => {
      const phrase = (phraseToLookup ?? mnemonicInput).trim();
      if (!phrase) return;

      const operation = ++generation.current;
      lookupAbort.current?.abort();
      const controller = new AbortController();
      lookupAbort.current = controller;
      pendingReply.current = null;
      setReplyPending(false);
      setReplyError(null);
      setIsSendingReply(false);
      setIsVerifyingAudit(false);
      if (activeSecretsRef.current) wipeMemory(activeSecretsRef.current.privateKey, activeSecretsRef.current.signingPrivateKey,
        activeSecretsRef.current.caseAccessToken, activeSecretsRef.current.caseAccessTokenHash);
      activeSecretsRef.current = null;
      setActiveSecrets(null);
      setCaseData(null);
      setDecryptedMessages([]);
      setAuditVerification(null);
      setIsVerifying(true);
      setError(null);

      let secrets: ReporterSecrets | null = null;
      try {
        // 1. Deterministically derive keys and token hash on client
        secrets = await deriveReporterSecrets(phrase);

        // 2. Query blind backend purely by caseAccessTokenHash (NO UUID NEEDED)
        const res = await api.lookupCase(secrets.caseAccessTokenHashBase64, controller.signal, secrets);
        if (res.protocolVersion === 2) {
          if (!res.manifest || res.manifest.caseId !== res.caseId || res.reporterPublicKey !== secrets.publicKeyBase64) {
            throw new Error('Case recovery identity mismatch.');
          }
          await verifyManifest(res.manifest, secrets);
        } else if (res.protocolVersion !== 1 || res.manifest) {
          throw new Error('Unsupported or downgraded report protocol.');
        }
        const decrypted = await readThread(res.messages, res.manifest, res.protocolVersion, 'REPORTER', secrets.privateKey);
        if (operation !== generation.current) {
          wipeMemory(secrets.privateKey, secrets.signingPrivateKey);
          return;
        }
        activeSecretsRef.current = secrets;
        setActiveSecrets(secrets);
        setCaseData(res);
        setDecryptedMessages(decrypted);
        fetchAuditVerification(res.caseId);
      } catch (err: unknown) {
        if (secrets) wipeMemory(secrets.privateKey, secrets.signingPrivateKey);
        if (operation !== generation.current) return;
        const errMsg = err instanceof Error ? err.message : '';
        if ((err instanceof ApiError && err.status === 404) || errMsg.includes('не найдено')) {
          setError('No case found for this phrase. Check the 12 words.');
        } else if (errMsg.includes('Invalid 12-word BIP-39')) {
          setError('Invalid 12-word BIP-39 phrase. Check your word spelling.');
        } else {
          setError(errMsg || 'Server request failed.');
        }
      } finally {
        if (operation === generation.current) setIsVerifying(false);
      }
    },
    [mnemonicInput, fetchAuditVerification]
  );

  const sendReply = useCallback(
    async (text: string, files: File[]) => {
      if (replyBusy.current || !text.trim() || !caseData || !activeSecrets || caseData.readOnly ||
          caseData.protocolVersion !== 2 || !caseData.manifest) return false;
      const operation = generation.current;

      replyBusy.current = true;
      setIsSendingReply(true);
      setReplyError(null);

      try {
        await verifyManifest(caseData.manifest, activeSecrets);

        if (!pendingReply.current) {
          const prepared = await prepareReply(text.trim(), files, (payload) => signMessage(
            caseData.manifest!, 'REPORTER', payload, activeSecrets.privateKey, activeSecrets.signingPrivateKey));
          if (operation !== generation.current) return false;
          pendingReply.current = prepared;
        }
        if (operation !== generation.current) return false;
        setReplyPending(true);
        const pending = pendingReply.current;
        const reply = pending.dto;
        const newMsg = await deliverReply(pending, { caseId: caseData.caseId,
          credential: activeSecrets.caseAccessTokenHashBase64, reporter: activeSecrets }, (dto) => api.sendReporterReply({
            protocolVersion: 2, messageId: dto.messageId, signature: dto.signature,
            caseAccessTokenHash: activeSecrets.caseAccessTokenHashBase64,
            encryptedMessage: dto.encryptedResponse, nonce: dto.nonce,
            investigatorPublicKey: caseData.manifest!.investigatorPublicKey, attachmentIds: dto.attachmentIds,
          }, caseData.caseId, activeSecrets), async () => (await api.accessCase(caseData.caseId, activeSecrets.caseAccessTokenHashBase64, activeSecrets)).messages);
        const verified = await readThread([newMsg], caseData.manifest, 2, 'REPORTER', activeSecrets.privateKey);
        if (verified[0].authentication !== 'verified' || newMsg.id !== reply.messageId) throw new Error('Server reply verification failed.');
        if (operation !== generation.current) return false;
        const refreshed = await api.accessCase(caseData.caseId, activeSecrets.caseAccessTokenHashBase64, activeSecrets);
        if (operation !== generation.current) return false;
        setCaseData(refreshed);
        setDecryptedMessages((prev) => [
          ...prev,
          {
            ...verified[0],
            decryptedText: text.trim(),
            attachments: verified[0].attachments,
          },
        ]);

        // Refresh audit chain verification after adding message
        fetchAuditVerification(caseData.caseId);
        pendingReply.current = null;
        setReplyPending(false);
        return true;
      } catch (err: unknown) {
        if (operation !== generation.current) return false;
        if (err instanceof ApiError && err.status === 410) { pendingReply.current = null; setReplyPending(false); }
        const msg = err instanceof Error ? err.message : '';
        setReplyError(msg || 'Failed to send reply.');
        return false;
      } finally {
        replyBusy.current = false;
        if (operation === generation.current) setIsSendingReply(false);
      }
    },
    [caseData, activeSecrets, fetchAuditVerification]
  );

  return {
    mnemonicInput,
    setMnemonicInput,
    fromSession,
    setFromSession,
    isVerifying,
    error,
    caseData,
    activeSecrets,
    downloadAttachment: (id: string) => api.downloadAttachment(id, activeSecrets || undefined, caseData?.caseId),
    decryptedMessages,
    auditVerification,
    isVerifyingAudit,
    isSendingReply,
    replyError,
    replyPending,
    lookupCase,
    sendReply,
    clearSession,
    fetchAuditVerification,
  };
}
