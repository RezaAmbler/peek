import { apiClient } from './client';

export interface ScheduledScan {
  id: string;
  user_id: string;
  created_by_id: string;
  organization_id?: string;
  name: string;
  description?: string;
  cron_expression: string;
  timezone: string;
  config_id: string;
  targets: Array<{ ip_address: string; device_name?: string }>;
  auto_compare: boolean;
  baseline_scan_id?: string;
  compare_with_previous: boolean;
  email_on_completion: boolean;
  email_on_changes_only: boolean;
  email_recipients?: string[];
  alert_on_critical: boolean;
  alert_on_new_vulns: boolean;
  is_active: boolean;
  last_run_at?: string;
  last_run_scan_id?: string;
  next_run_at?: string;
  total_runs: number;
  created_at: string;
  updated_at: string;
}

export interface CreateScheduledScanRequest {
  name: string;
  description?: string;
  cron_expression: string;
  timezone?: string;
  config_id: string;
  targets: Array<{ ip_address: string; device_name?: string }>;
  auto_compare?: boolean;
  baseline_scan_id?: string;
  compare_with_previous?: boolean;
  email_on_completion?: boolean;
  email_on_changes_only?: boolean;
  email_recipients?: string[];
  alert_on_critical?: boolean;
  alert_on_new_vulns?: boolean;
  is_active?: boolean;
}

export type UpdateScheduledScanRequest = Partial<CreateScheduledScanRequest>;

export const scheduledScansApi = {
  async list(): Promise<{ scheduled_scans: ScheduledScan[]; total: number }> {
    const { data } = await apiClient.get('/api/scheduled-scans');
    return data;
  },

  async get(scheduledScanId: string): Promise<ScheduledScan> {
    const { data } = await apiClient.get(`/api/scheduled-scans/${scheduledScanId}`);
    return data;
  },

  async create(scheduledScan: CreateScheduledScanRequest): Promise<ScheduledScan> {
    const { data } = await apiClient.post('/api/scheduled-scans', scheduledScan);
    return data;
  },

  async update(scheduledScanId: string, updates: UpdateScheduledScanRequest): Promise<ScheduledScan> {
    const { data } = await apiClient.patch(`/api/scheduled-scans/${scheduledScanId}`, updates);
    return data;
  },

  async delete(scheduledScanId: string): Promise<void> {
    await apiClient.delete(`/api/scheduled-scans/${scheduledScanId}`);
  },

  async pause(scheduledScanId: string): Promise<ScheduledScan> {
    const { data } = await apiClient.post(`/api/scheduled-scans/${scheduledScanId}/pause`);
    return data;
  },

  async resume(scheduledScanId: string): Promise<ScheduledScan> {
    const { data } = await apiClient.post(`/api/scheduled-scans/${scheduledScanId}/resume`);
    return data;
  },

  async runNow(scheduledScanId: string): Promise<{ message: string; task_id: string }> {
    const { data } = await apiClient.post(`/api/scheduled-scans/${scheduledScanId}/run-now`);
    return data;
  },
};
