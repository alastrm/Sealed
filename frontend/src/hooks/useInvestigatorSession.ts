'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { api } from '@/lib/api';
import {
  decryptCaseMessageForInvestigator,
  decryptReport,
  encryptAttachmentFile,
  encryptInvestigatorReply,
  packMessagePayload,
  parseMessageContent,
  unlockInvestigatorKey,
  wipeMemory,
} from '@/lib/crypto';
import type {
  AttachmentMetadata,
  AuditVerificationResponse,
  CaseMessageDto,
  InvestigatorAccountRecord,
  InvestigatorCaseListItem,
} from '@/lib/types';

export interface DecryptedInvestigatorMessage extends CaseMessageDto {
  decryptedText: string;
  attachments?: AttachmentMetadata[];
}

export function useInvestigatorSession() {
  // Login / Unlock state
  const [password, setPassword] = useState('Correct-Horse-Battery-Staple-2026!#');
  const [username, setUsername] = useState('compliance.lead@integrity-trust.corp');
  const [isUnlocking, setIsUnlocking] = useState(false);
  const [loginError, setLoginError] = useState<string | null>(null);

  const [account, setAccount] = useState<InvestigatorAccountRecord | null>(null);
  const [privateKey, setPrivateKey] = useState<Uint8Array | null>(null);
  const privateKeyRef = useRef<Uint8Array | null>(null);

  useEffect(() => {
    privateKeyRef.current = privateKey;
  }, [privateKey]);

  // Cases List State
  const [cases, setCases] = useState<InvestigatorCaseListItem[]>([]);
  const [isLoadingCases, setIsLoadingCases] = useState(false);
  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(null);

  // Case Detail / Decrypted state
  const [decryptedReportText, setDecryptedReportText] = useState<string | null>(null);
  const [reportAttachments, setReportAttachments] = useState<AttachmentMetadata[]>([]);
  const [isDecryptingReport, setIsDecryptingReport] = useState(false);
  const [threadMessages, setThreadMessages] = useState<DecryptedInvestigatorMessage[]>([]);
  const [isLoadingThread, setIsLoadingThread] = useState(false);

  // Action state
  const [isSendingReply, setIsSendingReply] = useState(false);
  const [replySuccess, setReplySuccess] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);

  // Tamper-evident Audit Chain state
  const [auditVerification, setAuditVerification] = useState<AuditVerificationResponse | null>(null);
  const [isVerifyingAudit, setIsVerifyingAudit] = useState(false);

  // Auto wipe memory on unmount
  useEffect(() => {
    return () => {
      const key = privateKeyRef.current;
      if (key) {
        wipeMemory(key);
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

  const loadCases = useCallback(async () => {
    setIsLoadingCases(true);
    setActionError(null);
    try {
      const list = await api.listInvestigatorCases();
      setCases(list);
    } catch (err: unknown) {
      console.error(err);
      setActionError('Failed to load cases from server.');
    } finally {
      setIsLoadingCases(false);
    }
  }, []);

  const login = useCallback(
    async (overrideUsername?: string, overridePassword?: string) => {
      const u = (overrideUsername ?? username).trim();
      const p = overridePassword ?? password;
      if (!u || !p) return false;

      setIsUnlocking(true);
      setLoginError(null);

      try {
        // Fetch blind account blob from server
        const accountRecord = await api.getInvestigatorAccount(u);

        // Derive KEK via Argon2id and decrypt private key in browser memory
        const unlockedKey = await unlockInvestigatorKey(accountRecord, p);

        setAccount(accountRecord);
        setPrivateKey(unlockedKey);

        // Load cases
        const list = await api.listInvestigatorCases();
        setCases(list);
        return true;
      } catch (err: unknown) {
        console.error(err);
        const msg = err instanceof Error ? err.message : '';
        setLoginError(msg || 'Login failed: invalid password or account.');
        return false;
      } finally {
        setIsUnlocking(false);
      }
    },
    [username, password]
  );

  const selectCase = useCallback(
    async (c: InvestigatorCaseListItem) => {
      if (!account || !privateKey) return;

      setSelectedCaseId(c.id);
      setDecryptedReportText(null);
      setReportAttachments([]);
      setThreadMessages([]);
      setReplySuccess(false);
      setActionError(null);
      setIsDecryptingReport(true);
      setIsLoadingThread(true);

      // Fetch and verify BLAKE2b audit chain for this case
      fetchAuditVerification(c.id);

      try {
        // 1. Decrypt Sealed Box via crypto_box_seal_open and parse attachments
        const rawReportText = await decryptReport(
          c.encryptedReport,
          account.publicKey,
          privateKey
        );
        const parsedReport = parseMessageContent(rawReportText);
        setDecryptedReportText(parsedReport.text);
        setReportAttachments(parsedReport.attachments);

        // 2. Fetch and decrypt message thread
        const messages = await api.getCaseMessages(c.id);
        const decrypted = await Promise.all(
          messages.map(async (msg) => {
            try {
              const decText = await decryptCaseMessageForInvestigator(
                msg,
                c.reporterPublicKey,
                privateKey
              );
              const parsedMsg = parseMessageContent(decText);
              return {
                ...msg,
                decryptedText: parsedMsg.text,
                attachments: parsedMsg.attachments,
              };
            } catch {
              return {
                ...msg,
                decryptedText: '[Decryption failed: invalid key or data]',
                attachments: [],
              };
            }
          })
        );
        setThreadMessages(decrypted);
      } catch (err: unknown) {
        console.error(err);
        setActionError('Failed to decrypt report: corrupted data.');
      } finally {
        setIsDecryptingReport(false);
        setIsLoadingThread(false);
      }
    },
    [account, privateKey, fetchAuditVerification]
  );

  const sendReply = useCallback(
    async (text: string, files: File[]) => {
      if (!selectedCaseId || !text.trim() || !account || !privateKey) return false;

      const currentCase = cases.find((c) => c.id === selectedCaseId);
      if (!currentCase) return false;

      setIsSendingReply(true);
      setActionError(null);

      try {
        // 1. Encrypt and upload any investigator attachments
        const attachmentsMeta: AttachmentMetadata[] = [];
        for (const file of files) {
          const fileBuffer = await file.arrayBuffer();
          const fileBytes = new Uint8Array(fileBuffer);
          const encrypted = await encryptAttachmentFile(fileBytes, file.name, file.type);
          const uploadRes = await api.uploadAttachment(
            encrypted.fileBlob,
            selectedCaseId
          );
          encrypted.metadata.attachmentId = uploadRes.attachmentId;
          attachmentsMeta.push(encrypted.metadata);
        }

        // 2. Pack plaintext with Zero-Knowledge attachment metadata
        const packedPayload = packMessagePayload(text.trim(), attachmentsMeta);

        // 3. Authenticated encryption via crypto_box_easy (investigatorPrivKey -> reporterPubKey)
        const { encryptedResponse, nonce } = await encryptInvestigatorReply(
          packedPayload,
          currentCase.reporterPublicKey,
          privateKey
        );

        // 4. POST to backend
        const newMsg = await api.sendInvestigatorResponse(selectedCaseId, {
          caseId: selectedCaseId,
          encryptedResponse,
          nonce,
          investigatorPublicKey: account.publicKey,
        });

        setThreadMessages((prev) => [
          ...prev,
          {
            ...newMsg,
            decryptedText: text.trim(),
            attachments: attachmentsMeta,
          },
        ]);
        setReplySuccess(true);

        // Refresh cases list & audit verification
        await loadCases();
        fetchAuditVerification(selectedCaseId);
        return true;
      } catch (err: unknown) {
        console.error(err);
        const msg = err instanceof Error ? err.message : '';
        setActionError(msg || 'Failed to send reply.');
        return false;
      } finally {
        setIsSendingReply(false);
      }
    },
    [selectedCaseId, account, privateKey, cases, loadCases, fetchAuditVerification]
  );

  const logout = useCallback(() => {
    if (privateKey) {
      wipeMemory(privateKey);
    }
    setPrivateKey(null);
    setAccount(null);
    setCases([]);
    setSelectedCaseId(null);
    setDecryptedReportText(null);
    setReportAttachments([]);
    setAuditVerification(null);
    setThreadMessages([]);
    setActionError(null);
    setReplySuccess(false);
  }, [privateKey]);

  const selectedCase = cases.find((c) => c.id === selectedCaseId);

  return {
    username,
    setUsername,
    password,
    setPassword,
    isUnlocking,
    loginError,
    account,
    privateKey,
    cases,
    isLoadingCases,
    selectedCaseId,
    selectedCase,
    decryptedReportText,
    reportAttachments,
    isDecryptingReport,
    threadMessages,
    isLoadingThread,
    isSendingReply,
    replySuccess,
    setReplySuccess,
    actionError,
    auditVerification,
    isVerifyingAudit,
    login,
    loadCases,
    selectCase,
    sendReply,
    logout,
    fetchAuditVerification,
  };
}
