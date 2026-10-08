'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { api } from '@/lib/api';
import {
  decryptInvestigatorResponse,
  deriveReporterSecrets,
  encryptAttachmentFile,
  encryptReporterReply,
  packMessagePayload,
  parseMessageContent,
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

  // Auto wipe memory on unmount
  useEffect(() => {
    return () => {
      const sec = activeSecretsRef.current;
      if (sec) {
        wipeMemory(
          sec.publicKey,
          sec.privateKey,
          sec.caseAccessToken,
          sec.caseAccessTokenHash
        );
      }
    };
  }, []);

  const fetchAuditVerification = useCallback(async (caseId: string) => {
    setIsVerifyingAudit(true);
    try {
      const res = await api.verifyAuditChain(caseId);
      setAuditVerification(res);
    } catch (err) {
      console.error('Failed to verify audit chain:', err);
    } finally {
      setIsVerifyingAudit(false);
    }
  }, []);

  const clearSession = useCallback(() => {
    try {
      sessionStorage.removeItem('sealed_mnemonic');
    } catch {
      // ignore
    }

    if (activeSecrets) {
      wipeMemory(
        activeSecrets.publicKey,
        activeSecrets.privateKey,
        activeSecrets.caseAccessToken,
        activeSecrets.caseAccessTokenHash
      );
    }

    setMnemonicInput('');
    setFromSession(false);
    setCaseData(null);
    setActiveSecrets(null);
    setDecryptedMessages([]);
    setAuditVerification(null);
    setError(null);
    setReplyError(null);
  }, [activeSecrets]);

  const lookupCase = useCallback(
    async (phraseToLookup?: string) => {
      const phrase = (phraseToLookup ?? mnemonicInput).trim();
      if (!phrase) return;

      setIsVerifying(true);
      setError(null);

      try {
        // 1. Deterministically derive keys and token hash on client
        const secrets = await deriveReporterSecrets(phrase);
        setActiveSecrets(secrets);

        // 2. Query blind backend purely by caseAccessTokenHash (NO UUID NEEDED)
        const res = await api.lookupCase(secrets.caseAccessTokenHashBase64);
        setCaseData(res);

        // Fetch and verify BLAKE2b audit chain
        fetchAuditVerification(res.caseId);

        // 3. Decrypt each message locally using reporter's derived private key and parse attachments
        const decrypted = await Promise.all(
          res.messages.map(async (msg) => {
            try {
              const rawText = await decryptInvestigatorResponse(msg, secrets.privateKey);
              const parsed = parseMessageContent(rawText);
              return {
                ...msg,
                decryptedText: parsed.text,
                attachments: parsed.attachments,
              };
            } catch {
              return {
                ...msg,
                decryptedText: '[Ошибка расшифровки: сообщение повреждено или не адресовано вам]',
                attachments: [],
              };
            }
          })
        );

        setDecryptedMessages(decrypted);
      } catch (err: unknown) {
        console.error(err);
        const errMsg = err instanceof Error ? err.message : '';
        if (errMsg.includes('404') || errMsg.includes('не найдено')) {
          setError('Обращение с такой мнемонической фразой не найдено. Проверьте правильность введённых 12 слов.');
        } else if (errMsg.includes('Invalid 12-word BIP-39')) {
          setError('Некорректная мнемоническая фраза BIP-39. Убедитесь, что все 12 английских слов написаны правильно.');
        } else {
          setError(errMsg || 'Ошибка при запросе к серверу.');
        }
      } finally {
        setIsVerifying(false);
      }
    },
    [mnemonicInput, fetchAuditVerification]
  );

  const sendReply = useCallback(
    async (text: string, files: File[]) => {
      if (!text.trim() || !caseData || !activeSecrets) return false;

      setIsSendingReply(true);
      setReplyError(null);

      try {
        const pubKeyData = await api.getInvestigatorPublicKey();

        // 1. Encrypt and upload any attachments
        const attachmentsMeta: AttachmentMetadata[] = [];
        for (const file of files) {
          const fileBuffer = await file.arrayBuffer();
          const fileBytes = new Uint8Array(fileBuffer);
          const encrypted = await encryptAttachmentFile(fileBytes, file.name, file.type);
          const uploadRes = await api.uploadAttachment(
            encrypted.fileBlob,
            caseData.caseId,
            activeSecrets.caseAccessTokenHashBase64
          );
          encrypted.metadata.attachmentId = uploadRes.attachmentId;
          attachmentsMeta.push(encrypted.metadata);
        }

        // 2. Pack plaintext with Zero-Knowledge attachment metadata
        const packedPayload = packMessagePayload(text.trim(), attachmentsMeta);

        const { encryptedMessage, nonce } = await encryptReporterReply(
          packedPayload,
          pubKeyData.publicKey,
          activeSecrets.privateKey
        );

        const newMsg = await api.sendReporterReply(
          {
            caseAccessTokenHash: activeSecrets.caseAccessTokenHashBase64,
            encryptedMessage,
            nonce,
            investigatorPublicKey: pubKeyData.publicKey,
          },
          caseData.caseId
        );

        setCaseData((prev) => (prev ? { ...prev, status: 'IN_REVIEW' } : prev));
        setDecryptedMessages((prev) => [
          ...prev,
          {
            ...newMsg,
            decryptedText: text.trim(),
            attachments: attachmentsMeta,
          },
        ]);

        // Refresh audit chain verification after adding message
        fetchAuditVerification(caseData.caseId);
        return true;
      } catch (err: unknown) {
        console.error(err);
        const msg = err instanceof Error ? err.message : '';
        setReplyError(msg || 'Не удалось отправить ответ следователю.');
        return false;
      } finally {
        setIsSendingReply(false);
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
    decryptedMessages,
    auditVerification,
    isVerifyingAudit,
    isSendingReply,
    replyError,
    lookupCase,
    sendReply,
    clearSession,
    fetchAuditVerification,
  };
}
