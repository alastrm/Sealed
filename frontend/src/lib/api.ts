import type { ReporterSecrets } from './crypto';
import { requestDigest, signReporterChallenge, uploadRequestDigest, type ReporterChallenge } from './reporterAuth';
import type {
  AuditVerificationResponse,
  CaseAccessResponseDto,
  CaseAttachmentUploadResponse,
  CaseCreatedResponse,
  CaseMessageDto,
  CreateCaseDto,
  InvestigatorAccountRecord,
  IdentityPacket,
  InvestigatorCaseListItem,
  InvestigatorPublicKeyResponse,
  InvestigatorResponseDto,
  ReporterReplyDto,
} from './types';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || '';
const INVESTIGATOR_HEADERS = { 'X-Sealed-Request': '1' };

export class ApiError extends Error {
  constructor(message: string, public readonly status: number) {
    super(message);
  }
}

// A timed-out write is ambiguous: callers reconcile stable operation IDs.
async function request(url: string, options: RequestInit = {}): Promise<Response> {
  const controller = new AbortController();
  const abort = () => controller.abort();
  if (options.signal?.aborted) controller.abort();
  options.signal?.addEventListener('abort', abort, { once: true });
  const timer = setTimeout(abort, options.body instanceof FormData ? 120_000 : 20_000);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    // Keep the timeout active until the response body finishes, not just headers.
    const body = await response.arrayBuffer();
    return new Response([204, 205, 304].includes(response.status) ? null : body, {
      status: response.status, statusText: response.statusText, headers: response.headers,
    });
  }
  finally { clearTimeout(timer); options.signal?.removeEventListener('abort', abort); }
}

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let errorDetail = res.statusText;
    try {
      const errorJson = await res.json();
      errorDetail = typeof errorJson.detail === 'string' ? errorJson.detail : 'Request validation failed.';
    } catch {
      // ignore
    }
    throw new ApiError(errorDetail || `HTTP ${res.status}`, res.status);
  }
  return res.json();
}

async function reporterRequest(path: string, options: RequestInit, secrets?: ReporterSecrets,
  caseId?: string, digestOverride?: string, enroll = false): Promise<Response> {
  if (!secrets) return request(API_BASE + path, options); // Server rejects obsolete static credentials.
  const operation = (options.method || 'GET') + ' ' + path;
  const digest = digestOverride || await requestDigest(new TextEncoder().encode(typeof options.body === 'string' ? options.body : ''));
  const challenge = await handleResponse<ReporterChallenge>(await request(API_BASE + '/api/v1/reporter-auth/challenge', {
    method: 'POST', signal: options.signal, headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ authVersion: 1, locator: secrets.caseAccessTokenHashBase64,
      signingPublicKey: secrets.signingPublicKeyBase64, operation, requestDigest: digest, enroll }),
  }));
  const proof = await signReporterChallenge(challenge, secrets, { operation, requestDigest: digest, caseId });
  return request(API_BASE + path, { ...options, credentials: 'omit', headers: {
    ...options.headers, 'X-Sealed-Challenge': challenge.challengeId, 'X-Sealed-Proof': proof,
  } });
}

export const api = {
  async investigatorChallenge(username: string): Promise<{ challengeId: string; nonce: string }> {
    return handleResponse(await request(`${API_BASE}/api/v1/investigators/auth/challenge`, {
      method: 'POST', credentials: 'include', cache: 'no-store',
      headers: { ...INVESTIGATOR_HEADERS, 'Content-Type': 'application/json' },
      body: JSON.stringify({ username }),
    }));
  },

  async investigatorLogin(username: string, challengeId: string, proof: string): Promise<{ expiresIn: number }> {
    return handleResponse(await request(`${API_BASE}/api/v1/investigators/auth/session`, {
      method: 'POST', credentials: 'include', cache: 'no-store',
      headers: { ...INVESTIGATOR_HEADERS, 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, challengeId, proof }),
    }));
  },

  async investigatorLogout(): Promise<void> {
    const res = await request(`${API_BASE}/api/v1/investigators/auth/session`, {
      method: 'DELETE', credentials: 'include', headers: INVESTIGATOR_HEADERS,
    });
    if (!res.ok) throw new ApiError('Server sign-out could not be confirmed. The session may remain active until it expires.', res.status);
  },

  async getInvestigatorPublicKey(): Promise<InvestigatorPublicKeyResponse> {
    const res = await request(`${API_BASE}/api/v1/investigators/public-key`, {
      cache: 'no-store',
    });
    return handleResponse<InvestigatorPublicKeyResponse>(res);
  },

  async getInvestigatorAccount(username?: string): Promise<InvestigatorAccountRecord> {
    const url = username
      ? `${API_BASE}/api/v1/investigators/account?username=${encodeURIComponent(username)}`
      : `${API_BASE}/api/v1/investigators/account`;
    const res = await request(url, { cache: 'no-store', credentials: 'include' });
    return handleResponse<InvestigatorAccountRecord>(res);
  },

  async getInvestigatorIdentities(): Promise<IdentityPacket[]> {
    return handleResponse(await request(`${API_BASE}/api/v1/investigators/identities`, {
      cache: 'no-store', credentials: 'include',
    }));
  },

  async createCase(dto: CreateCaseDto): Promise<CaseCreatedResponse> {
    const res = await request(`${API_BASE}/api/v1/cases`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(dto),
    });
    return handleResponse<CaseCreatedResponse>(res);
  },

  async accessCase(
    caseId: string,
    caseAccessTokenHash: string,
    secrets?: ReporterSecrets
  ): Promise<CaseAccessResponseDto> {
    const res = await reporterRequest(`/api/v1/cases/${caseId}/access`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ caseAccessTokenHash }),
    }, secrets, caseId);
    return handleResponse<CaseAccessResponseDto>(res);
  },

  async lookupCase(caseAccessTokenHash: string, signal?: AbortSignal, secrets?: ReporterSecrets): Promise<CaseAccessResponseDto> {
    const res = await reporterRequest(`/api/v1/cases/lookup`, {
      signal,
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ caseAccessTokenHash }),
    }, secrets);
    return handleResponse<CaseAccessResponseDto>(res);
  },

  async listInvestigatorCases(): Promise<InvestigatorCaseListItem[]> {
    const res = await request(`${API_BASE}/api/v1/investigators/cases`, {
      cache: 'no-store',
      credentials: 'include',
    });
    return handleResponse<InvestigatorCaseListItem[]>(res);
  },

  async getCaseMessages(caseId: string): Promise<CaseMessageDto[]> {
    const res = await request(`${API_BASE}/api/v1/investigators/cases/${caseId}/messages`, {
      cache: 'no-store',
      credentials: 'include',
    });
    return handleResponse<CaseMessageDto[]>(res);
  },

  async sendInvestigatorResponse(
    caseId: string,
    dto: InvestigatorResponseDto
  ): Promise<CaseMessageDto> {
    const res = await request(`${API_BASE}/api/v1/investigators/cases/${caseId}/messages`, {
      method: 'POST',
      credentials: 'include',
      headers: { ...INVESTIGATOR_HEADERS, 'Content-Type': 'application/json' },
      body: JSON.stringify(dto),
    });
    return handleResponse<CaseMessageDto>(res);
  },

  async sendReporterReply(
    dto: ReporterReplyDto,
    caseId?: string,
    secrets?: ReporterSecrets
  ): Promise<CaseMessageDto> {
    const url = caseId
      ? `/api/v1/cases/${caseId}/messages`
      : `/api/v1/cases/messages`;
    const res = await reporterRequest(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(dto),
    }, secrets, caseId);
    return handleResponse<CaseMessageDto>(res);
  },

  async uploadAttachment(
    blob: Blob | Uint8Array,
    caseId?: string,
    caseAccessTokenHash?: string,
    attachmentId?: string,
    stagingToken?: string,
    secrets?: ReporterSecrets
  ): Promise<CaseAttachmentUploadResponse> {
    const formData = new FormData();
    const fileBlob =
      blob instanceof Blob
        ? blob
        : new Blob([blob as Uint8Array<ArrayBuffer>], {
            type: 'application/octet-stream',
          });
    formData.append('file', fileBlob, 'evidence.enc');
    if (attachmentId) formData.append('attachment_id', attachmentId);
    if (stagingToken) formData.append('staging_token', stagingToken);
    if (caseId) {
      formData.append('case_id', caseId);
    }
    if (caseAccessTokenHash) {
      formData.append('case_access_token_hash', caseAccessTokenHash);
    }

    let digest: string | undefined;
    if (secrets) {
      if (!attachmentId) throw new Error('A stable attachment ID is required.');
      const contentDigest = await requestDigest(new Uint8Array(await fileBlob.arrayBuffer()));
      formData.append('signing_public_key', secrets.signingPublicKeyBase64);
      formData.append('content_digest', contentDigest);
      digest = await uploadRequestDigest(attachmentId, caseId, contentDigest, stagingToken, caseAccessTokenHash);
    }
    const res = await reporterRequest('/api/v1/cases/attachments', {
      method: 'POST',
      credentials: caseId && !caseAccessTokenHash ? 'include' : 'omit',
      headers: caseId && !caseAccessTokenHash ? INVESTIGATOR_HEADERS : undefined,
      body: formData,
    }, secrets, caseId, digest, !!stagingToken);
    return handleResponse<CaseAttachmentUploadResponse>(res);
  },

  async downloadAttachment(attachmentId: string, secrets?: ReporterSecrets, caseId?: string): Promise<ArrayBuffer> {
    const res = await reporterRequest(`/api/v1/cases/attachments/${encodeURIComponent(attachmentId)}`, {
      cache: 'no-store', credentials: 'include',
    }, secrets, caseId);
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

  async transitionCase(caseId: string, dto: { requestId: string; expectedRevision: number; targetStatus: string }):
    Promise<{ caseId: string; status: import('./types').CaseStatus; revision: number }> {
    return handleResponse(await request(`${API_BASE}/api/v1/investigators/cases/${caseId}/status`, {
      method: 'POST', credentials: 'include', headers: { ...INVESTIGATOR_HEADERS, 'Content-Type': 'application/json' },
      body: JSON.stringify(dto),
    }));
  },

  async verifyAuditChain(caseId: string, secrets?: ReporterSecrets): Promise<AuditVerificationResponse> {
    const res = await reporterRequest(`/api/v1/cases/${encodeURIComponent(caseId)}/audit-verify`, {
      cache: 'no-store', credentials: 'include',
    }, secrets, caseId);
    return handleResponse<AuditVerificationResponse>(res);
  },
};

