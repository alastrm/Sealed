import type {
  CaseAccessResponseDto,
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
};

