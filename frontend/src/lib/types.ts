export type CaseStatus = 'OPEN' | 'IN_REVIEW' | 'RESPONDED' | 'CLOSED';

export interface InvestigatorAccountRecord {
  id: string;
  username: string;
  publicKey: string;
  encryptedPrivateKey: string;
  privateKeyNonce: string;
  kdfSalt: string;
  kdfOpsLimit: number;
  kdfMemLimit: number;
  kdfAlgorithm: number;
  createdAt: string;
}

export interface CreateCaseDto {
  caseId: string;
  reporterPublicKey: string;
  caseAccessTokenHash: string;
  encryptedReport: string;
  attachmentIds?: string[];
}

export interface CaseCreatedResponse {
  caseId: string;
  status: CaseStatus;
  createdAt: string;
}

export interface CaseAccessRequestDto {
  caseAccessTokenHash: string;
}

export interface AttachmentMetadata {
  attachmentId: string;
  originalName: string;
  mimeType: string;
  keyBase64: string;
  nonceBase64: string;
  sizeBytes: number;
  bucketSize?: number;
}

export interface CaseAttachmentUploadResponse {
  attachmentId: string;
  sizeBytes: number;
  createdAt: string;
}

export interface AuditVerificationResponse {
  isValid: boolean;
  eventsCount: number;
  brokenAt: string | null;
  latestHash: string | null;
  reason: string | null;
}

export interface CaseMessageDto {
  id: string;
  caseId: string;
  encryptedResponse: string;
  nonce: string;
  investigatorPublicKey: string;
  senderType?: 'INVESTIGATOR' | 'REPORTER';
  sender: 'INVESTIGATOR' | 'REPORTER';
  createdAt: string;
  // Client-decrypted plaintext (optional in UI state)
  decryptedText?: string;
  attachments?: AttachmentMetadata[];
}

export interface ReporterReplyDto {
  caseAccessTokenHash: string;
  encryptedMessage: string;
  nonce: string;
  investigatorPublicKey?: string;
}

export interface CaseAccessResponseDto {
  caseId: string;
  status: CaseStatus;
  createdAt: string;
  reporterPublicKey: string;
  messages: CaseMessageDto[];
}

export interface InvestigatorCaseListItem {
  id: string;
  reporterPublicKey: string;
  encryptedReport: string;
  status: CaseStatus;
  createdAt: string;
  messageCount: number;
  // Client-decrypted report (optional in UI state)
  decryptedReport?: string;
}

export interface InvestigatorResponseDto {
  caseId: string;
  encryptedResponse: string;
  nonce: string;
  investigatorPublicKey: string;
}

export interface InvestigatorPublicKeyResponse {
  investigatorId: string;
  username: string;
  publicKey: string;
}
