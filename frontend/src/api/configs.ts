import { apiClient } from './client';

export interface ScanConfig {
  id: string;
  user_id: string;
  organization_id?: string | null;
  name: string;
  description?: string;
  masscan_rate: number;
  masscan_interface?: string;
  nmap_args: string[];
  ssh_ports: number[];
  max_concurrent_hosts: number;
  max_concurrent_scans: number;
  host_timeout_seconds: number;
  masscan_timeout_percent: number;
  nmap_timeout_percent: number;
  enable_ssh_audit: boolean;
  enable_nuclei: boolean;
  nuclei_severity: string;
  nuclei_templates?: string;
  nuclei_timeout: number;
  global_tool_timeout_seconds?: number;
  parallelism_limit?: number;
  highlight_ports: number[];
  email_on_completion: boolean;
  email_on_changes_only: boolean;
  created_at: string;
  updated_at: string;
  is_default: boolean;
}

export interface ConfigListResponse {
  configs: ScanConfig[];
  total: number;
}

export interface CreateConfigRequest {
  name: string;
  description?: string;
  masscan_rate?: number;
  masscan_interface?: string;
  nmap_args?: string[];
  ssh_ports?: number[];
  max_concurrent_hosts?: number;
  max_concurrent_scans?: number;
  host_timeout_seconds?: number;
  masscan_timeout_percent?: number;
  nmap_timeout_percent?: number;
  enable_ssh_audit?: boolean;
  enable_nuclei?: boolean;
  nuclei_severity?: string;
  nuclei_templates?: string;
  nuclei_timeout?: number;
  global_tool_timeout_seconds?: number;
  parallelism_limit?: number;
  highlight_ports?: number[];
  email_on_completion?: boolean;
  email_on_changes_only?: boolean;
}

export type UpdateConfigRequest = Partial<CreateConfigRequest>;

export const configsApi = {
  async list(userId?: string): Promise<ConfigListResponse> {
    const params = userId ? `?user_id=${userId}` : '';
    const { data } = await apiClient.get<ConfigListResponse>(`/api/configs${params}`);
    return data;
  },

  async get(configId: string): Promise<ScanConfig> {
    const { data } = await apiClient.get<ScanConfig>(`/api/configs/${configId}`);
    return data;
  },

  async create(config: CreateConfigRequest): Promise<ScanConfig> {
    const { data } = await apiClient.post<ScanConfig>('/api/configs', config);
    return data;
  },

  async update(configId: string, updates: UpdateConfigRequest): Promise<ScanConfig> {
    const { data } = await apiClient.patch<ScanConfig>(`/api/configs/${configId}`, updates);
    return data;
  },

  async delete(configId: string): Promise<void> {
    await apiClient.delete(`/api/configs/${configId}`);
  },

  async setDefault(configId: string): Promise<ScanConfig> {
    const { data } = await apiClient.post<ScanConfig>(`/api/configs/${configId}/set-default`);
    return data;
  },
};
