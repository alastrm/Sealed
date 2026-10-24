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

export interface IdentityPublic {
  protocolVersion: number;
  publicKey: string;
  signingPublicKey: string;
  identitySignature: string;
}

export interface IdentityPacket extends IdentityPublic {
  encryptedPrivateKey: string;
  privateKeyNonce: string;
  kdfSalt: string;
  kdfOpsLimit: number;
  kdfMemLimit: number;
  kdfAlgorithm: number;
  active?: boolean;
}

export interface ReportManifest {
  protocolVersion: number;
  caseId: string;
  reporterPublicKey: string;
  reporterSigningPublicKey: string;
  investigatorPublicKey: string;
  investigatorSigningPublicKey: string;
  identitySignature: string;
  credentialCommitment: string;
  encryptedReport: string;
  reportSignature: string;
}

export interface CreateCaseDto {
  protocolVersion: number;
  manifest: ReportManifest;
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
  status: 'consistent' | 'inconsistent' | 'legacy' | 'unavailable';
  completenessVerified: boolean;
  historicalBaseline: boolean;
  isValid: boolean;
  eventsCount: number;
  brokenAt: string | null;
  latestHash: string | null;
  reason: string | null;
}

export interface CaseMessageDto {
  protocolVersion: number;
  signature: string | null;
  authentication?: 'verified' | 'legacy' | 'invalid';
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
  attachmentIds?: string[];
  protocolVersion: number;
  messageId: string;
  signature: string;
  caseAccessTokenHash: string;
  encryptedMessage: string;
  nonce: string;
  investigatorPublicKey?: string;
}

export interface CaseAccessResponseDto {
  protocolVersion: number;
  revision: number;
  readOnly: boolean;
  manifest: ReportManifest | null;
  caseId: string;
  status: CaseStatus;
  createdAt: string;
  reporterPublicKey: string;
  messages: CaseMessageDto[];
}

export interface InvestigatorCaseListItem {
  protocolVersion: number;
  revision: number;
  readOnly: boolean;
  manifest: ReportManifest | null;
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
  attachmentIds?: string[];
  protocolVersion: number;
  messageId: string;
  signature: string;
  caseId: string;
  encryptedResponse: string;
  nonce: string;
  investigatorPublicKey: string;
}

export interface InvestigatorPublicKeyResponse {
  protocolVersion: number;
  signingPublicKey: string | null;
  identitySignature: string | null;
  investigatorId: string;
  username: string;
  publicKey: string;
}
