'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { prepareReply, deliverReply, type PendingReply } from '@/lib/replyDelivery';
import type { InvestigatorResponseDto } from '@/lib/types';
import { api, ApiError } from '@/lib/api';
import { decryptVerifiedReport, readThread, signMessage, unlockIdentity, verifyManifest, type UnlockedIdentity } from '@/lib/protocol';
import { createInvestigatorProof } from '@/lib/investigatorAuth';
import {
  decryptReport,
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
  const [password, setPassword] = useState('');
  const [accessKey, setAccessKey] = useState('');
  const [username, setUsername] = useState('');
  const [isUnlocking, setIsUnlocking] = useState(false);
  const [loginError, setLoginError] = useState<string | null>(null);

  const [account, setAccount] = useState<InvestigatorAccountRecord | null>(null);
  const [privateKey, setPrivateKey] = useState<Uint8Array | null>(null);
  const privateKeyRef = useRef<Uint8Array | null>(null);

  const identityKeys = useRef<UnlockedIdentity[]>([]);
  const [legacyMode, setLegacyMode] = useState(false);
  const generation = useRef(0);
  const sessionTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const pendingReply = useRef<PendingReply<InvestigatorResponseDto> | null>(null);
  const replyBusy = useRef(false);
  const [replyPending, setReplyPending] = useState(false);
  const transitionBusy = useRef(false);
  const pendingTransition = useRef<{ requestId: string; expectedRevision: number; targetStatus: string } | null>(null);
  const [isChangingStatus, setIsChangingStatus] = useState(false);
  const [statusPending, setStatusPending] = useState(false);

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

  const clearWorkspace = useCallback(() => {
    generation.current += 1;
    pendingReply.current = null;
    pendingTransition.current = null;
    setStatusPending(false);
    setIsChangingStatus(false);
    setReplyPending(false);
    if (sessionTimer.current) clearTimeout(sessionTimer.current);
    if (privateKeyRef.current) wipeMemory(privateKeyRef.current);
    for (const key of identityKeys.current) wipeMemory(key.privateKey, key.signingPrivateKey);
    identityKeys.current = [];
    privateKeyRef.current = null;
    setPrivateKey(null);
    setAccount(null);
    setPassword('');
    setAccessKey('');
    setCases([]);
    setSelectedCaseId(null);
    setDecryptedReportText(null);
    setReportAttachments([]);
    setThreadMessages([]);
    setAuditVerification(null);
    setActionError(null);
    setReplySuccess(false);
    setIsLoadingCases(false);
    setIsLoadingThread(false);
    setIsDecryptingReport(false);
    setIsSendingReply(false);
    setIsVerifyingAudit(false);
  }, []);

  const logout = useCallback(async () => {
    clearWorkspace();
    setIsUnlocking(true);
    try {
      await api.investigatorLogout();
      setLoginError(null);
    } catch (err) {
      setLoginError(err instanceof ApiError ? err.message : 'Server sign-out could not be confirmed. The session may remain active until it expires.');
    } finally {
      setIsUnlocking(false);
    }
  }, [clearWorkspace]);

  const handleUnauthorized = useCallback((err: unknown) => {
    if (err instanceof ApiError && err.status === 401) {
      clearWorkspace();
      setLoginError('Your investigator session expired. Sign in again.');
      return true;
    }
    return false;
  }, [clearWorkspace]);

  useEffect(() => () => {
    generation.current += 1;
    if (sessionTimer.current) clearTimeout(sessionTimer.current);
    if (privateKeyRef.current) wipeMemory(privateKeyRef.current);
    for (const key of identityKeys.current) wipeMemory(key.privateKey, key.signingPrivateKey);
  }, []);

  const fetchAuditVerification = useCallback(async (caseId: string) => {
    const operation = generation.current;
    setIsVerifyingAudit(true);
    setAuditVerification(null);
    try {
      const res = await api.verifyAuditChain(caseId);
      if (operation === generation.current) setAuditVerification(res);
    } catch (err) {
      console.error('Failed to verify audit chain:', err);
    } finally {
      if (operation === generation.current) setIsVerifyingAudit(false);
    }
  }, []);

  const loadCases = useCallback(async () => {
    const operation = generation.current;
    setIsLoadingCases(true);
    setActionError(null);
    try {
      const list = await api.listInvestigatorCases();
      if (operation === generation.current) setCases(list);
    } catch (err: unknown) {
      if (operation !== generation.current || handleUnauthorized(err)) return;
      setActionError('Failed to load cases from server.');
    } finally {
      if (operation === generation.current) setIsLoadingCases(false);
    }
  }, [handleUnauthorized]);

  const login = useCallback(async () => {
    const u = username.trim();
    const p = password;
    const key = accessKey.trim();
    if (!u || !p || !key) return false;
    const operation = ++generation.current;
    setIsUnlocking(true);
    setLoginError(null);
    setPassword('');
    setAccessKey('');
    let unlockedKey: Uint8Array | null = null;
    const unlocked: UnlockedIdentity[] = [];
    try {
      // Prove knowledge of an independent access key. Neither it nor the
      // decryption password/private key is sent to the backend.
      const challenge = await api.investigatorChallenge(u);
      const proof = await createInvestigatorProof(
        key, challenge.challengeId, challenge.nonce, u, window.location.origin,
      );
      const session = await api.investigatorLogin(u, challenge.challengeId, proof);
      const sessionExpiresAt = Date.now() + session.expiresIn * 1000;
      const accountRecord = await api.getInvestigatorAccount(u);
      if (legacyMode) {
        unlockedKey = await unlockInvestigatorKey(accountRecord, p);
      } else {
        const packets = await api.getInvestigatorIdentities();
        for (const packet of packets) {
          try { unlocked.push(await unlockIdentity(packet, p)); } catch { /* different password or unpinned archive */ }
        }
        if (!unlocked.length) throw new Error('Cannot unlock a pinned v2 identity. Check the master password and locally installed pins.');
        unlockedKey = unlocked[0].privateKey;
      }
      const list = await api.listInvestigatorCases();
      if (operation !== generation.current) {
        wipeMemory(unlockedKey);
        for (const key of unlocked) wipeMemory(key.privateKey, key.signingPrivateKey);
        await api.investigatorLogout();
        return false;
      }
      identityKeys.current = unlocked;
      privateKeyRef.current = unlockedKey;
      setPrivateKey(unlockedKey);
      setAccount({ ...accountRecord, publicKey: unlocked[0]?.packet.publicKey || accountRecord.publicKey });
      setCases(list);
      sessionTimer.current = setTimeout(() => {
        void logout();
      }, Math.max(0, sessionExpiresAt - Date.now()));
      return true;
    } catch (err: unknown) {
      if (unlockedKey) wipeMemory(unlockedKey);
      for (const key of unlocked) wipeMemory(key.privateKey, key.signingPrivateKey);
      // A wrong local unlock password must not leave a usable server session.
      let signOutFailed = false;
      try { await api.investigatorLogout(); } catch { signOutFailed = true; }
      if (operation === generation.current) {
        const message = err instanceof Error ? err.message : '';
        setLoginError((message || 'Sign-in or local key unlock failed.') + (signOutFailed
          ? ' Server sign-out could not be confirmed; the session may remain active until expiry.' : ''));
      }
      return false;
    } finally {
      if (operation === generation.current) setIsUnlocking(false);
    }
  }, [username, password, accessKey, logout, legacyMode]);

  const selectCase = useCallback(
    async (c: InvestigatorCaseListItem) => {
      if (!account || !privateKey || transitionBusy.current || pendingTransition.current) return;

      const operation = ++generation.current;
      pendingReply.current = null;
      setReplyPending(false);
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
        let caseKey = privateKey;
        if (c.protocolVersion === 2) {
          if (!c.manifest || c.manifest.caseId !== c.id || c.manifest.reporterPublicKey !== c.reporterPublicKey ||
              c.manifest.encryptedReport !== c.encryptedReport) throw new Error('Case manifest mismatch.');
          await verifyManifest(c.manifest);
          const identity = identityKeys.current.find((key) => key.packet.signingPublicKey === c.manifest!.investigatorSigningPublicKey);
          if (!identity) throw new Error('This identity is locked. Sign in with its master password.');
          caseKey = identity.privateKey;
        } else if (c.protocolVersion !== 1 || c.manifest || !legacyMode) {
          throw new Error('Open the legacy archive with its original master password to read this unverified report.');
        }
        const rawReportText = c.protocolVersion === 2
          ? await decryptVerifiedReport(c.manifest!, caseKey)
          : await decryptReport(c.encryptedReport, account.publicKey, caseKey);
        if (operation !== generation.current) return;
        const parsedReport = parseMessageContent(rawReportText);
        setDecryptedReportText(parsedReport.text);
        setReportAttachments(parsedReport.attachments);
        const messages = await api.getCaseMessages(c.id);
        if (operation !== generation.current) return;
        const decrypted = await readThread(messages, c.manifest, c.protocolVersion, 'INVESTIGATOR', caseKey, c.reporterPublicKey);
        if (operation === generation.current) setThreadMessages(decrypted);
      } catch (err: unknown) {
        if (operation !== generation.current || handleUnauthorized(err)) return;
        setActionError(err instanceof Error ? err.message : 'Failed to verify or decrypt report.');
      } finally {
        if (operation === generation.current) {
          setIsDecryptingReport(false);
          setIsLoadingThread(false);
        }
      }
    },
    [account, privateKey, fetchAuditVerification, handleUnauthorized, legacyMode]
  );

  const sendReply = useCallback(
    async (text: string, files: File[]) => {
      if (replyBusy.current || transitionBusy.current || pendingTransition.current || !selectedCaseId || !text.trim() || !account || !privateKey) return false;

      const currentCase = cases.find((c) => c.id === selectedCaseId);
      if (!currentCase || currentCase.readOnly || currentCase.protocolVersion !== 2 || !currentCase.manifest) return false;
      const identity = identityKeys.current.find((key) => key.packet.signingPublicKey === currentCase.manifest!.investigatorSigningPublicKey);
      if (!identity) return false;

      const operation = generation.current;
      replyBusy.current = true;
      setIsSendingReply(true);
      setActionError(null);

      try {
        if (!pendingReply.current) {
          const prepared = await prepareReply(text.trim(), files, (payload) => signMessage(
            currentCase.manifest!, 'INVESTIGATOR', payload, identity.privateKey, identity.signingPrivateKey));
          if (operation !== generation.current) return false;
          pendingReply.current = prepared;
        }
        if (operation !== generation.current) return false;
        setReplyPending(true);
        const pending = pendingReply.current;
        const reply = pending.dto;
        const newMsg = await deliverReply(pending, { caseId: selectedCaseId },
          (dto) => api.sendInvestigatorResponse(selectedCaseId, dto), () => api.getCaseMessages(selectedCaseId));
        const verified = await readThread([newMsg], currentCase.manifest, 2, 'INVESTIGATOR', identity.privateKey);
        if (verified[0].authentication !== 'verified' || newMsg.id !== reply.messageId) throw new Error('Server reply verification failed.');
        if (operation !== generation.current) return false;
        setThreadMessages((prev) => [
          ...prev,
          {
            ...verified[0],
            decryptedText: text.trim(),
            attachments: verified[0].attachments,
          },
        ]);
        pendingReply.current = null;
        setReplyPending(false);
        setReplySuccess(true);

        // Refresh cases list & audit verification
        await loadCases();
        if (operation !== generation.current) return true;
        fetchAuditVerification(selectedCaseId);
        return true;
      } catch (err: unknown) {
        if (operation !== generation.current || handleUnauthorized(err)) return false;
        if (err instanceof ApiError && err.status === 410) { pendingReply.current = null; setReplyPending(false); }
        const msg = err instanceof Error ? err.message : '';
        setActionError(msg || 'Failed to send reply.');
        return false;
      } finally {
        replyBusy.current = false;
        if (operation === generation.current) setIsSendingReply(false);
      }
    },
    [selectedCaseId, account, privateKey, cases, loadCases, fetchAuditVerification, handleUnauthorized]
  );

  const changeStatus = useCallback(async (targetStatus: string) => {
    const current = cases.find(c => c.id === selectedCaseId);
    if (!current || current.protocolVersion !== 2 || transitionBusy.current || replyBusy.current || pendingReply.current) return;
    const operation = generation.current;
    transitionBusy.current = true;
    setIsChangingStatus(true);
    setActionError(null);
    if (!pendingTransition.current) pendingTransition.current = {
      requestId: crypto.randomUUID(), expectedRevision: current.revision, targetStatus,
    };
    try {
      const result = await api.transitionCase(current.id, pendingTransition.current);
      if (operation !== generation.current) return;
      pendingTransition.current = null;
      setStatusPending(false);
      setCases(list => list.map(c => c.id === result.caseId ? { ...c, status: result.status, revision: result.revision,
        readOnly: result.status === 'CLOSED' } : c));
      fetchAuditVerification(current.id);
    } catch (error) {
      if (operation !== generation.current || handleUnauthorized(error)) return;
      if (error instanceof ApiError && error.status >= 400 && error.status < 500) {
        pendingTransition.current = null;
        setStatusPending(false);
        await loadCases();
        setActionError(error.message);
      } else {
        setStatusPending(true);
        setActionError('Status change is not confirmed. Retry the same change to reconcile it.');
      }
    } finally {
      transitionBusy.current = false;
      if (operation === generation.current) setIsChangingStatus(false);
    }
  }, [cases, selectedCaseId, fetchAuditVerification, handleUnauthorized, loadCases]);

  const selectedCase = cases.find((c) => c.id === selectedCaseId);
  const refresh = useCallback(async () => {
    if (replyBusy.current || pendingReply.current || transitionBusy.current || pendingTransition.current) return;
    const operation = generation.current;
    setIsLoadingCases(true);
    setActionError(null);
    try {
      const list = await api.listInvestigatorCases();
      if (operation !== generation.current) return;
      setCases(list);
      const current = list.find(c => c.id === selectedCaseId);
      if (current) await selectCase(current);
    } catch (err) {
      if (operation !== generation.current || handleUnauthorized(err)) return;
      setActionError(err instanceof ApiError ? err.message : 'Could not refresh reports. Please retry.');
    } finally {
      if (operation === generation.current) setIsLoadingCases(false);
    }
  }, [selectedCaseId, selectCase, handleUnauthorized]);

  return {
    username,
    setUsername,
    legacyMode,
    setLegacyMode,
    password,
    setPassword,
    accessKey,
    setAccessKey,
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
    replyPending,
    changeStatus,
    isChangingStatus,
    statusPending,
    setReplySuccess,
    actionError,
    auditVerification,
    isVerifyingAudit,
    login,
    loadCases: refresh,
    selectCase,
    sendReply,
    logout,
    fetchAuditVerification,
  };
}
