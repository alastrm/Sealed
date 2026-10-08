import type {
  AuditVerificationResponse,
  CaseAccessResponseDto,
  CaseAttachmentUploadResponse,
  CaseCreatedResponse,
  CaseMessageDto,
  CreateCaseDto,
  InvestigatorAccountRecord,
  InvestigatorCaseListItem,
  InvestigatorPublicKeyResponse,
  InvestigatorResponseDto,
  ReporterReplyDto,
} from './types';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || '';

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let errorDetail = res.statusText;
    try {
      const errorJson = await res.json();
      errorDetail = errorJson.detail || JSON.stringify(errorJson);
    } catch {
      // ignore
    }
    throw new Error(errorDetail || `HTTP ${res.status}`);
  }
  return res.json();
}

export const api = {
  async getInvestigatorPublicKey(): Promise<InvestigatorPublicKeyResponse> {
    const res = await fetch(`${API_BASE}/api/v1/investigators/public-key`, {
      cache: 'no-store',
    });
    return handleResponse<InvestigatorPublicKeyResponse>(res);
  },

  async getInvestigatorAccount(username?: string): Promise<InvestigatorAccountRecord> {
    const url = username
      ? `${API_BASE}/api/v1/investigators/account?username=${encodeURIComponent(username)}`
      : `${API_BASE}/api/v1/investigators/account`;
    const res = await fetch(url, { cache: 'no-store' });
    return handleResponse<InvestigatorAccountRecord>(res);
  },

  async createCase(dto: CreateCaseDto): Promise<CaseCreatedResponse> {
    const res = await fetch(`${API_BASE}/api/v1/cases`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(dto),
    });
    return handleResponse<CaseCreatedResponse>(res);
  },

  async accessCase(
    caseId: string,
    caseAccessTokenHash: string
  ): Promise<CaseAccessResponseDto> {
    const res = await fetch(`${API_BASE}/api/v1/cases/${caseId}/access`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ caseAccessTokenHash }),
    });
    return handleResponse<CaseAccessResponseDto>(res);
  },

  async lookupCase(caseAccessTokenHash: string): Promise<CaseAccessResponseDto> {
    const res = await fetch(`${API_BASE}/api/v1/cases/lookup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ caseAccessTokenHash }),
    });
    return handleResponse<CaseAccessResponseDto>(res);
  },

  async listInvestigatorCases(): Promise<InvestigatorCaseListItem[]> {
    const res = await fetch(`${API_BASE}/api/v1/investigators/cases`, {
      cache: 'no-store',
    });
    return handleResponse<InvestigatorCaseListItem[]>(res);
  },

  async getCaseMessages(caseId: string): Promise<CaseMessageDto[]> {
    const res = await fetch(`${API_BASE}/api/v1/investigators/cases/${caseId}/messages`, {
      cache: 'no-store',
    });
    return handleResponse<CaseMessageDto[]>(res);
  },

  async sendInvestigatorResponse(
    caseId: string,
    dto: InvestigatorResponseDto
  ): Promise<CaseMessageDto> {
    const res = await fetch(`${API_BASE}/api/v1/investigators/cases/${caseId}/messages`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(dto),
    });
    return handleResponse<CaseMessageDto>(res);
  },

  async sendReporterReply(
    dto: ReporterReplyDto,
    caseId?: string
  ): Promise<CaseMessageDto> {
    const url = caseId
      ? `${API_BASE}/api/v1/cases/${caseId}/messages`
      : `${API_BASE}/api/v1/cases/messages`;
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(dto),
    });
    return handleResponse<CaseMessageDto>(res);
  },

  async uploadAttachment(
    blob: Blob | Uint8Array,
    caseId?: string,
    caseAccessTokenHash?: string
  ): Promise<CaseAttachmentUploadResponse> {
    const formData = new FormData();
    const fileBlob =
      blob instanceof Blob
        ? blob
        : new Blob([blob as Uint8Array<ArrayBuffer>], {
            type: 'application/octet-stream',
          });
    formData.append('file', fileBlob, 'evidence.enc');
    if (caseId) {
      formData.append('case_id', caseId);
    }
    if (caseAccessTokenHash) {
      formData.append('case_access_token_hash', caseAccessTokenHash);
    }

    const res = await fetch(`${API_BASE}/api/v1/cases/attachments`, {
      method: 'POST',
      body: formData,
    });
    return handleResponse<CaseAttachmentUploadResponse>(res);
  },

  async downloadAttachment(attachmentId: string): Promise<ArrayBuffer> {
    const res = await fetch(`${API_BASE}/api/v1/cases/attachments/${encodeURIComponent(attachmentId)}`, {
      cache: 'no-store',
    });
    if (!res.ok) {
      let detail = res.statusText;
      try {
        const errJson = await res.json();
        detail = errJson.detail || detail;
      } catch {
        // ignore
      }
      throw new Error(detail || `Failed to download attachment (HTTP ${res.status})`);
    }
    return res.arrayBuffer();
  },

  async verifyAuditChain(caseId: string): Promise<AuditVerificationResponse> {
    const res = await fetch(`${API_BASE}/api/v1/cases/${encodeURIComponent(caseId)}/audit-verify`, {
      cache: 'no-store',
    });
    return handleResponse<AuditVerificationResponse>(res);
  },
};

