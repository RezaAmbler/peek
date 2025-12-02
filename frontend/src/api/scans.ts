import { apiClient } from './client';

export interface ScanTarget {
  id: string;
  device_name?: string;
  ip_address: string;
  status: string;
  error_message?: string;
  started_at?: string;
  finished_at?: string;
  duration_seconds?: number;
  sequence: number;
}

export interface Scan {
  id: string;
  user_id: string;
  created_by_id: string;
  config_id: string;
  config_name?: string;  // Denormalized for display
  run_number: number;
  name?: string;  // May be null, display as "Run #N — Date" if so
  description?: string;
  status: string;
  current_phase: string;
  created_at: string;
  started_at?: string;
  finished_at?: string;
  progress_percent: number;
  total_targets: number;
  completed_targets: number;
  failed_targets: number;
  total_open_ports: number;
  total_vulnerabilities: number;
}

export interface ScanDetail extends Scan {
  targets: ScanTarget[];
  phase_stats?: Record<string, { completed: number; total: number }>;
}

export interface ScanListResponse {
  scans: Scan[];
  total: number;
  page: number;
  pages: number;
}

export interface CreateScanRequest {
  config_id: string;  // Required - targets come from config
  name?: string;  // Optional - auto-generated as "Run #N — Date" if not provided
  description?: string;
}

export interface UpdateScanRequest {
  name?: string;
  description?: string;
}

export interface ComparableScan {
  id: string;
  name?: string;
  run_number: number;
  status: string;
  created_at: string;
  total_targets: number;
  total_open_ports: number;
  total_vulnerabilities: number;
}

export interface ComparableScansResponse {
  current_scan: {
    id: string;
    name?: string;
    run_number: number;
    config_id: string;
    config_name?: string;
    status: string;
    created_at: string;
    total_targets: number;
  };
  comparable_scans: ComparableScan[];
  total_comparable: number;
}

export interface Port {
  id: string;
  ip_address: string;
  device_name?: string;
  port: number;
  protocol: string;
  state: string;
  service_name?: string;
  product?: string;
  version?: string;
  discovered_by: string;
}

export interface SSHAudit {
  id: string;
  ip_address: string;
  device_name?: string;
  port: number;
  banner?: string;
  ssh_version?: string;
  key_exchange_algorithms?: string[];
  host_key_algorithms?: string[];
  encryption_algorithms?: string[];
  mac_algorithms?: string[];
  vulnerabilities?: Array<{
    severity: string;
    description: string;
    cve?: string;
  }>;
  recommendations?: Array<{
    action: string;
    item: string;
  }>;
  connection_failed: boolean;
  failure_reason?: string;
}

export interface Vulnerability {
  id: string;
  ip_address: string;
  device_name?: string;
  template_id: string;
  name: string;
  severity: string;
  type?: string;
  source_tool?: string;  // nuclei, nikto, zap, nse
  matched_at: string;
  host: string;
  port?: number;
  description?: string;
  reference?: string[];
  tags?: string[];
  extracted_results?: any;
  curl_command?: string;
  timestamp: string;
}

export interface NSEFinding {
  id: string;
  ip_address: string;
  device_name?: string;
  port: number;
  protocol: string;
  service_name?: string;
  script_id: string;
  profile_name?: string;
  raw_output?: string;
  elements?: Record<string, any>;
  severity?: string;
  error?: string;
}

export interface SSLScanCipher {
  status: string;
  sslversion: string;
  bits: number;
  cipher: string;
  strength: string;
  curve?: string;
  ecdhebits?: number;
}

export interface SSLScanFinding {
  severity: string;
  finding: string;
  detail: string;
}

export interface SSLScanResult {
  id: string;
  ip_address: string;
  device_name?: string;
  port: number;
  protocol: string;
  service_name?: string;
  // Protocol support
  sslv2_enabled: boolean;
  sslv3_enabled: boolean;
  tlsv10_enabled: boolean;
  tlsv11_enabled: boolean;
  tlsv12_enabled: boolean;
  tlsv13_enabled: boolean;
  // Security features
  fallback_scsv_supported?: boolean;
  secure_renegotiation?: boolean;
  compression_supported?: boolean;
  heartbleed_vulnerable: boolean;
  // Cipher suites
  ciphers?: SSLScanCipher[];
  key_exchange_groups?: Array<{ sslversion: string; bits: number; name: string }>;
  // Certificate info
  cert_subject?: string;
  cert_issuer?: string;
  cert_altnames?: string;
  cert_not_before?: string;
  cert_not_after?: string;
  cert_expired?: boolean;
  cert_self_signed?: boolean;
  cert_signature_algorithm?: string;
  cert_key_type?: string;
  cert_key_bits?: number;
  // Findings and grade
  findings?: SSLScanFinding[];
  grade?: string;
  // Connection status
  connection_failed: boolean;
  failure_reason?: string;
}

export const scansApi = {
  async list(page = 1, limit = 20, status?: string): Promise<ScanListResponse> {
    const params = new URLSearchParams({
      page: page.toString(),
      limit: limit.toString(),
    });
    if (status) params.append('status', status);

    const { data } = await apiClient.get<ScanListResponse>(`/api/scans?${params}`);
    return data;
  },

  async get(scanId: string): Promise<ScanDetail> {
    const { data } = await apiClient.get<ScanDetail>(`/api/scans/${scanId}`);
    return data;
  },

  async create(scan: CreateScanRequest): Promise<Scan> {
    const { data } = await apiClient.post<Scan>('/api/scans', scan);
    return data;
  },

  async update(scanId: string, scan: UpdateScanRequest): Promise<Scan> {
    const { data } = await apiClient.patch<Scan>(`/api/scans/${scanId}`, scan);
    return data;
  },

  async delete(scanId: string): Promise<void> {
    await apiClient.delete(`/api/scans/${scanId}`);
  },

  async cancel(scanId: string): Promise<Scan> {
    const { data } = await apiClient.post<Scan>(`/api/scans/${scanId}/cancel`);
    return data;
  },

  async start(scanId: string): Promise<Scan> {
    const { data } = await apiClient.post<Scan>(`/api/scans/${scanId}/start`);
    return data;
  },

  async restart(scanId: string): Promise<Scan> {
    const { data } = await apiClient.post<Scan>(`/api/scans/${scanId}/restart`);
    return data;
  },

  async getPorts(scanId: string): Promise<Port[]> {
    const { data } = await apiClient.get<Port[]>(`/api/scans/${scanId}/ports`);
    return data;
  },

  async getSSHAudits(scanId: string): Promise<SSHAudit[]> {
    const { data } = await apiClient.get<SSHAudit[]>(`/api/scans/${scanId}/ssh-audits`);
    return data;
  },

  async getVulnerabilities(scanId: string, severity?: string): Promise<Vulnerability[]> {
    const params = severity ? `?severity=${severity}` : '';
    const { data } = await apiClient.get<Vulnerability[]>(`/api/scans/${scanId}/vulnerabilities${params}`);
    return data;
  },

  async getNSEFindings(scanId: string): Promise<NSEFinding[]> {
    const { data } = await apiClient.get<NSEFinding[]>(`/api/scans/${scanId}/nse-findings`);
    return data;
  },

  async getSSLScanResults(scanId: string): Promise<SSLScanResult[]> {
    const { data } = await apiClient.get<SSLScanResult[]>(`/api/scans/${scanId}/sslscan-results`);
    return data;
  },

  async getComparable(scanId: string): Promise<ComparableScansResponse> {
    const { data } = await apiClient.get<ComparableScansResponse>(`/api/scans/${scanId}/comparable`);
    return data;
  },
};
