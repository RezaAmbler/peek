import { apiClient } from './client';

// Triage status lifecycle for a finding (identified by fingerprint within a config).
export type TriageStatus = 'open' | 'triaged' | 'false_positive' | 'accepted_risk' | 'fixed';

export const TRIAGE_STATUSES: TriageStatus[] = [
  'open',
  'triaged',
  'false_positive',
  'accepted_risk',
  'fixed',
];

// Statuses that mean the finding is intentionally suppressed from active attention.
export const SUPPRESSED_TRIAGE_STATUSES: TriageStatus[] = ['false_positive', 'accepted_risk'];

export interface FindingState {
  id: string;
  config_id: string;
  fingerprint: string;
  status: TriageStatus;
  owner?: string | null;
  triage_notes?: string | null;
  suppressed_until?: string | null;
  updated_at?: string;
  created_at?: string;
}

export interface UpdateFindingRequest {
  status?: TriageStatus;
  owner?: string | null;
  triage_notes?: string | null;
  suppressed_until?: string | null;
}

export const findingsApi = {
  async list(configId: string): Promise<FindingState[]> {
    const { data } = await apiClient.get<FindingState[]>('/api/findings', {
      params: { config_id: configId },
    });
    return data;
  },

  async update(
    configId: string,
    fingerprint: string,
    update: UpdateFindingRequest
  ): Promise<FindingState> {
    const { data } = await apiClient.patch<FindingState>(
      `/api/findings/${configId}/${fingerprint}`,
      update
    );
    return data;
  },
};
