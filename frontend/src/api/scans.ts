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
  config_hash?: string;  // SHA256 of comparable config subset; identical hashes are comparable
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
  config_id: string;  // Required - scan settings come from config
  name?: string;  // Optional - auto-generated as "Run #N — Date" if not provided
  description?: string;
  targets?: string[];  // Optional - override config targets with these
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
  discovery_source?: string;  // 'port' or 'endpoint' - differentiates per-port vs endpoint scanning
  description?: string;
  reference?: string[];
  tags?: string[];
  extracted_results?: unknown;
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
  elements?: Record<string, unknown>;
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

export interface HttpxResult {
  id: string;
  port_id: string;
  ip_address: string;
  port: number;
  // HTTP Response
  status_code?: number;
  content_length?: number;
  content_type?: string;
  title?: string;
  webserver?: string;
  // Technology detection
  technologies: string[];
  // Infrastructure
  cdn?: string;
  waf?: string;
  final_url?: string;
  redirect_chain: string[];
  // Metadata
  response_time_ms?: number;
  // TLS info
  tls_version?: string;
  jarm_hash?: string;
  // Connection status
  connection_failed: boolean;
  failure_reason?: string;
}

export interface DiscoveredEndpoint {
  id: string;
  scan_id: string;
  scan_target_id?: string;
  port_id?: string;
  // URL details
  url: string;
  normalized_url?: string;
  scheme: string;
  host: string;
  port: number;
  path: string;
  query?: string;
  // HTTP details
  method: string;
  status_code?: number;
  content_type?: string;
  content_length?: number;
  // Metadata
  depth?: number;
  source_tool: string;
  content_hash?: string;
  discovered_at?: string;
}

export interface DiscoveredEndpointsResponse {
  endpoints: DiscoveredEndpoint[];
  total: number;
  page: number;
  pages: number;
  filters: {
    method?: string;
    source_tool?: string;
  };
}

export interface TestsslResult {
  id: string;
  ip_address: string;
  device_name?: string;
  host: string;
  port: number;
  service_name?: string;
  // Protocol support
  protocols?: {
    sslv2?: boolean;
    sslv3?: boolean;
    tls10?: boolean;
    tls11?: boolean;
    tls12?: boolean;
    tls13?: boolean;
  };
  // Certificate info
  certificate_info?: {
    subject?: string;
    issuer?: string;
    serial?: string;
    validity?: {
      not_before?: string;
      not_after?: string;
      days_remaining?: number;
      expired?: boolean;
    };
    fingerprint?: string;
    key_size?: number;
    key_type?: string;
    signature_algorithm?: string;
    san?: string[];
    trust_chain?: string[];
  };
  // Vulnerabilities from testssl
  vulnerabilities?: Array<{
    id: string;
    severity: string;
    finding: string;
    cve?: string;
  }>;
  // Cipher findings
  cipher_findings?: {
    strong?: string[];
    weak?: string[];
    insecure?: string[];
  };
  // Server configuration
  server_config?: {
    forward_secrecy?: boolean;
    hsts?: boolean;
    hsts_max_age?: number;
    ocsp_stapling?: boolean;
    cert_chain_issues?: string[];
  };
  // Overall grade
  overall_grade?: string;
  // Artifact path for raw output
  artifact_path?: string;
  // Connection status
  connection_failed: boolean;
  failure_reason?: string;
  // Timestamp
  created_at?: string;
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

  async getHttpxResults(scanId: string): Promise<HttpxResult[]> {
    const { data } = await apiClient.get<HttpxResult[]>(`/api/scans/${scanId}/httpx-results`);
    return data;
  },

  async getDiscoveredEndpoints(
    scanId: string,
    page = 1,
    limit = 100,
    method?: string,
    sourceTool?: string
  ): Promise<DiscoveredEndpointsResponse> {
    const params = new URLSearchParams({
      page: page.toString(),
      limit: limit.toString(),
    });
    if (method) params.append('method', method);
    if (sourceTool) params.append('source_tool', sourceTool);

    const { data } = await apiClient.get<DiscoveredEndpointsResponse>(
      `/api/scans/${scanId}/discovered-endpoints?${params}`
    );
    return data;
  },

  async getTestsslResults(scanId: string): Promise<TestsslResult[]> {
    const { data } = await apiClient.get<TestsslResult[]>(`/api/scans/${scanId}/testssl-results`);
    return data;
  },
};
