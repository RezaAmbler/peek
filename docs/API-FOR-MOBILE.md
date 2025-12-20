# PEEK API Documentation for iOS Mobile Development

**Base URL**: `http://your-server:8000/api`
**OpenAPI Spec**: See `openapi.json` in this directory

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Authentication](#authentication)
3. [Scan Lifecycle](#scan-lifecycle)
4. [Endpoints Reference](#endpoints-reference)
5. [Data Models (TypeScript)](#data-models-typescript)
6. [Example Flows](#example-flows)

---

## Quick Start

```swift
// 1. Login
POST /api/auth/login
Content-Type: application/x-www-form-urlencoded
Body: username=admin&password=admin

// 2. Use token for all subsequent requests
Authorization: Bearer <access_token>

// 3. Create a scan config (or use existing)
POST /api/configs

// 4. Create and start a scan
POST /api/scans
POST /api/scans/{id}/start

// 5. Poll for completion
GET /api/scans/{id}  (check status field)

// 6. Fetch results
GET /api/scans/{id}/ports
GET /api/scans/{id}/vulnerabilities
```

---

## Authentication

### Login

**Endpoint**: `POST /api/auth/login`

**Content-Type**: `application/x-www-form-urlencoded`

**Request Body**:
```
username=admin&password=admin
```

**Response** (200 OK):
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "user": {
    "id": "uuid",
    "email": "admin@example.com",
    "username": "admin",
    "is_admin": true,
    "is_active": true,
    "created_at": "2024-01-01T00:00:00Z"
  }
}
```

### Token Details

| Property | Value |
|----------|-------|
| Algorithm | HS256 |
| Expiration | 7 days (10,080 minutes) |
| Header Format | `Authorization: Bearer <token>` |

### Get Current User

**Endpoint**: `GET /api/auth/me`

**Headers**: `Authorization: Bearer <token>`

**Response**: Same `user` object as login response.

---

## Scan Lifecycle

### Status Values

| Status | Description |
|--------|-------------|
| `pending` | Scan created but not started |
| `queued` | Scan queued for Celery worker |
| `running` | Scan actively executing |
| `completed` | Scan finished successfully |
| `failed` | Scan encountered an error |
| `cancelled` | Scan was manually cancelled |

### Phase Values

Scans progress through these phases in order:

| Phase | Description |
|-------|-------------|
| `pending` | Waiting to start |
| `nmap_discovery` | Port discovery with nmap |
| `nmap` | Service/version detection |
| `ssh_audit` | SSH security analysis |
| `sslscan` | SSL/TLS analysis |
| `nse` | Nmap scripting engine |
| `nuclei` | Vulnerability scanning |
| `nikto` | Web server scanning (if enabled) |
| `zap` | OWASP ZAP scanning (if enabled) |
| `completed` | All phases done |
| `failed` | Error occurred |

### Scan Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│  POST /api/scans          →  status: pending                    │
│  POST /api/scans/{id}/start →  status: queued → running        │
│  GET /api/scans/{id}      →  poll until status: completed      │
│  GET /api/scans/{id}/ports →  view discovered ports            │
│  GET /api/scans/{id}/vulnerabilities →  view vulnerabilities   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Endpoints Reference

### Health Check

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/health` | No | Health check |

### Authentication

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/auth/login` | No | Login, get JWT token |
| GET | `/api/auth/me` | Yes | Get current user info |

### Users (Admin)

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/users` | Yes | List users (paginated) |
| POST | `/api/users` | Yes | Create user |
| GET | `/api/users/{id}` | Yes | Get user by ID |
| DELETE | `/api/users/{id}` | Yes | Delete user |
| POST | `/api/users/{id}/reset-password` | Yes | Reset user password |

### Scan Configurations

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/configs` | Yes | List all configs |
| POST | `/api/configs` | Yes | Create new config |
| GET | `/api/configs/{id}` | Yes | Get config by ID |
| PATCH | `/api/configs/{id}` | Yes | Update config |
| DELETE | `/api/configs/{id}` | Yes | Delete config |
| POST | `/api/configs/{id}/set-default` | Yes | Set as default config |

### Scans

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/scans` | Yes | List scans (paginated, filterable) |
| POST | `/api/scans` | Yes | Create new scan |
| GET | `/api/scans/{id}` | Yes | Get scan details |
| PATCH | `/api/scans/{id}` | Yes | Update scan metadata |
| DELETE | `/api/scans/{id}` | Yes | Delete scan |
| POST | `/api/scans/{id}/start` | Yes | Start pending scan |
| POST | `/api/scans/{id}/cancel` | Yes | Cancel running scan |
| POST | `/api/scans/{id}/restart` | Yes | Restart failed/completed scan |
| GET | `/api/scans/{id}/comparable` | Yes | Get scans for comparison |

### Scan Results

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/scans/{id}/ports` | Yes | Get discovered ports |
| GET | `/api/scans/{id}/vulnerabilities` | Yes | Get vulnerabilities |
| GET | `/api/scans/{id}/ssh-audits` | Yes | Get SSH audit results |
| GET | `/api/scans/{id}/sslscan-results` | Yes | Get SSL/TLS results |
| GET | `/api/scans/{id}/nse-findings` | Yes | Get NSE script findings |

### Scan Comparisons

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/api/comparisons/compare` | Yes | Compare two scans |
| GET | `/api/comparisons/scan/{scan_id}` | Yes | Get comparisons for a scan |
| GET | `/api/comparisons/{id}` | Yes | Get comparison details |

### Reports

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/reports/{id}/html` | Yes | Download HTML report |
| GET | `/api/reports/{id}/pdf/executive` | Yes | Download executive PDF |
| GET | `/api/reports/{id}/pdf/technical` | Yes | Download technical PDF |
| GET | `/api/reports/{id}/csv/ports` | Yes | Download ports CSV |
| GET | `/api/reports/{id}/csv/vulnerabilities` | Yes | Download vulns CSV |
| GET | `/api/reports/{id}/csv/summary` | Yes | Download summary CSV |
| GET | `/api/reports/comparison/{id}/pdf` | Yes | Download comparison PDF |

### Scheduled Scans

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/api/scheduled-scans` | Yes | List scheduled scans |
| POST | `/api/scheduled-scans` | Yes | Create scheduled scan |
| GET | `/api/scheduled-scans/{id}` | Yes | Get scheduled scan |
| DELETE | `/api/scheduled-scans/{id}` | Yes | Delete scheduled scan |
| POST | `/api/scheduled-scans/{id}/pause` | Yes | Pause schedule |
| POST | `/api/scheduled-scans/{id}/resume` | Yes | Resume schedule |
| POST | `/api/scheduled-scans/{id}/run-now` | Yes | Run immediately |

---

## Data Models (TypeScript)

### Authentication

```typescript
interface Token {
  access_token: string;
  token_type: "bearer";
  user: UserResponse;
}

interface UserResponse {
  id: string;
  email: string;
  username: string;
  is_admin: boolean;
  is_active: boolean;
  created_at: string; // ISO 8601
}
```

### Scan Configuration

```typescript
interface ScanConfig {
  id: string;
  user_id: string;
  name: string;
  description?: string;

  // Targets
  targets: string[]; // ["192.168.1.1", "10.0.0.0/24"]

  // Port Discovery
  discovery_top_ports: number; // default: 1000
  additional_ports?: string;   // "80,443,8080,8443"

  // Scanning parameters
  nmap_args: string[];         // ["-sT", "-sV", "-sC", "-T2", "-Pn"]
  ssh_ports: number[];         // [22, 830]
  scan_mode: "fast" | "deep";  // default: "deep"

  // Concurrency & Timeouts
  max_concurrent_hosts: number;   // default: 10
  max_concurrent_scans: number;   // default: 3
  host_timeout_seconds: number;   // default: 1200

  // Tool Toggles
  enable_ssh_audit: boolean;   // default: true
  enable_nuclei: boolean;      // default: true
  enable_nse: boolean;         // default: true
  enable_sslscan: boolean;     // default: true
  enable_nikto: boolean;       // default: false
  enable_zap: boolean;         // default: false

  // Nuclei Settings
  nuclei_severity: string;     // "critical,high,medium,low,info"
  nuclei_timeout: number;      // default: 300

  // Web Scanning
  zap_scan_type: "baseline" | "api";
  zap_timeout: number;
  nikto_timeout: number;
  target_urls?: string[];      // ["https://example.com/app"]

  // Scheduling (cron)
  schedule?: string;           // "0 2 * * 0" (Sunday 2am)
  schedule_enabled: boolean;

  // Reporting
  highlight_ports: number[];   // [22, 80, 443, 3389, 8443]
  email_on_completion: boolean;
  email_on_changes_only: boolean;

  // Metadata
  is_default: boolean;
  is_preset: boolean;
  created_at: string;
  updated_at: string;
}
```

### Scan

```typescript
type ScanStatus = "pending" | "queued" | "running" | "completed" | "failed" | "cancelled";

type ScanPhase =
  | "pending"
  | "nmap_discovery"
  | "nmap"
  | "ssh_audit"
  | "sslscan"
  | "nse"
  | "nuclei"
  | "nikto"
  | "zap"
  | "completed"
  | "failed";

interface Scan {
  id: string;
  user_id: string;
  created_by_id: string;
  config_id: string;
  config_name?: string;

  // Run tracking
  run_number: number;
  name?: string;         // Auto: "Run #1 — Jan 15, 2024 14:30"
  description?: string;

  // Status
  status: ScanStatus;
  current_phase: ScanPhase;

  // Timing
  created_at: string;    // ISO 8601
  started_at?: string;
  finished_at?: string;

  // Progress (for polling)
  progress_percent: number;  // 0.0 to 100.0

  // Statistics
  total_targets: number;
  completed_targets: number;
  failed_targets: number;
  total_open_ports: number;
  total_vulnerabilities: number;
}

interface ScanDetail extends Scan {
  targets: ScanTarget[];
}

interface ScanTarget {
  id: string;
  scan_id: string;
  device_name?: string;
  ip_address: string;
  status: TargetStatus;
  error_message?: string;
  started_at?: string;
  finished_at?: string;
  duration_seconds?: number;
  sequence: number;
}

type TargetStatus = "pending" | "scanning" | "completed" | "failed" | "timeout" | "skipped";
```

### Port

```typescript
interface Port {
  id: string;
  ip_address: string;
  device_name?: string;
  port: number;
  protocol: "tcp" | "udp";
  state: "open" | "closed" | "filtered";
  service_name?: string;
  product?: string;
  version?: string;
  discovered_by: "nmap" | "masscan";
}
```

### Vulnerability

```typescript
type Severity = "critical" | "high" | "medium" | "low" | "info";
type SourceTool = "nuclei" | "nikto" | "zap" | "nse";

interface Vulnerability {
  id: string;
  ip_address: string;
  device_name?: string;

  // Identification
  template_id: string;   // e.g., "CVE-2023-12345"
  name: string;          // Human-readable name

  // Classification
  severity: Severity;
  type?: string;         // "cve", "exposure", "misconfiguration"
  source_tool: SourceTool;

  // Location
  matched_at: string;    // URL where found
  host: string;
  port?: number;

  // Details
  description?: string;
  reference?: string[];  // CVE links, etc.
  tags?: string[];
  extracted_results?: any;
  curl_command?: string;

  timestamp: string;     // ISO 8601
}
```

### SSH Audit Result

```typescript
interface SSHAuditResult {
  id: string;
  ip_address: string;
  device_name?: string;
  port: number;

  // SSH Info
  banner?: string;       // "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
  ssh_version?: string;  // "2.0"

  // Algorithms
  key_exchange_algorithms?: string[];
  host_key_algorithms?: string[];
  encryption_algorithms?: string[];
  mac_algorithms?: string[];

  // Findings
  vulnerabilities?: SSHVulnerability[];
  recommendations?: SSHRecommendation[];

  // Status
  connection_failed: boolean;
  failure_reason?: string;
}

interface SSHVulnerability {
  severity: Severity;
  description: string;
}

interface SSHRecommendation {
  action: "remove" | "add" | "update";
  item: string;
}
```

### SSL Scan Result

```typescript
interface SslScanResult {
  id: string;
  ip_address: string;
  device_name?: string;
  port: number;
  protocol: string;
  service_name?: string;

  // Protocol Support
  sslv2_enabled: boolean;
  sslv3_enabled: boolean;
  tlsv10_enabled: boolean;
  tlsv11_enabled: boolean;
  tlsv12_enabled: boolean;
  tlsv13_enabled: boolean;

  // Security Features
  fallback_scsv_supported?: boolean;
  secure_renegotiation?: boolean;
  compression_supported?: boolean;
  heartbleed_vulnerable: boolean;

  // Ciphers
  ciphers?: SslCipher[];
  key_exchange_groups?: string[];

  // Certificate
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

  // Analysis
  findings?: SslFinding[];
  grade?: string;  // "A", "B", "C", "D", "F"

  // Status
  connection_failed: boolean;
  failure_reason?: string;
}

interface SslCipher {
  status: "preferred" | "accepted";
  sslversion: string;
  bits: number;
  cipher: string;
  strength: "strong" | "acceptable" | "weak";
}

interface SslFinding {
  severity: Severity;
  finding: string;
  detail?: string;
}
```

### NSE Finding

```typescript
interface NseFinding {
  id: string;
  ip_address: string;
  device_name?: string;
  port: number;
  protocol: string;
  service_name?: string;

  script_id: string;      // e.g., "rdp-enum-encryption"
  profile_name?: string;
  raw_output?: string;
  elements?: any;         // Parsed script output
  severity: Severity;
  error?: string;
}
```

### Scan Comparison

```typescript
interface ScanComparison {
  id: string;
  baseline_scan_id: string;
  comparison_scan_id: string;
  created_at: string;

  summary: ComparisonSummary;
  port_changes: PortChange[];
  vulnerability_changes: VulnerabilityChange[];
}

interface ComparisonSummary {
  new_ports: number;
  closed_ports: number;
  new_vulnerabilities: number;
  resolved_vulnerabilities: number;
}

interface PortChange {
  ip_address: string;
  port: number;
  protocol: string;
  change_type: "new" | "closed" | "changed";
  baseline_state?: string;
  comparison_state?: string;
  service_name?: string;
}

interface VulnerabilityChange {
  ip_address: string;
  template_id: string;
  name: string;
  severity: Severity;
  change_type: "new" | "resolved";
}
```

### Pagination

```typescript
interface PaginatedResponse<T> {
  items: T[];    // or scan-specific key like "scans"
  total: number;
  page: number;
  pages: number;
}
```

---

## Example Flows

### 1. Complete Scan Flow

```bash
# 1. Login
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin"

# Response:
# {"access_token":"eyJ...", "token_type":"bearer", "user":{...}}

# 2. Create a configuration
curl -X POST http://localhost:8000/api/configs \
  -H "Authorization: Bearer eyJ..." \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production Servers",
    "targets": ["10.0.0.1", "10.0.0.2"],
    "scan_mode": "deep",
    "enable_nuclei": true,
    "enable_ssh_audit": true
  }'

# Response:
# {"id":"config-uuid", "name":"Production Servers", ...}

# 3. Create a scan from the config
curl -X POST http://localhost:8000/api/scans \
  -H "Authorization: Bearer eyJ..." \
  -H "Content-Type: application/json" \
  -d '{"config_id": "config-uuid"}'

# Response:
# {"id":"scan-uuid", "status":"pending", ...}

# 4. Start the scan
curl -X POST http://localhost:8000/api/scans/scan-uuid/start \
  -H "Authorization: Bearer eyJ..."

# Response:
# {"id":"scan-uuid", "status":"queued", ...}

# 5. Poll for completion (repeat until status is "completed")
curl http://localhost:8000/api/scans/scan-uuid \
  -H "Authorization: Bearer eyJ..."

# Response:
# {"status":"running", "current_phase":"nuclei", "progress_percent":75.0, ...}

# 6. Fetch ports when done
curl http://localhost:8000/api/scans/scan-uuid/ports \
  -H "Authorization: Bearer eyJ..."

# 7. Fetch vulnerabilities
curl http://localhost:8000/api/scans/scan-uuid/vulnerabilities \
  -H "Authorization: Bearer eyJ..."
```

### 2. iOS Swift Example

```swift
import Foundation

struct PEEKClient {
    let baseURL = "http://your-server:8000/api"
    var token: String?

    // Login
    mutating func login(username: String, password: String) async throws -> Token {
        var request = URLRequest(url: URL(string: "\(baseURL)/auth/login")!)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = "username=\(username)&password=\(password)".data(using: .utf8)

        let (data, _) = try await URLSession.shared.data(for: request)
        let token = try JSONDecoder().decode(Token.self, from: data)
        self.token = token.access_token
        return token
    }

    // List scans
    func listScans(page: Int = 1, status: String? = nil) async throws -> ScanListResponse {
        var urlComponents = URLComponents(string: "\(baseURL)/scans")!
        urlComponents.queryItems = [
            URLQueryItem(name: "page", value: String(page))
        ]
        if let status = status {
            urlComponents.queryItems?.append(URLQueryItem(name: "status", value: status))
        }

        var request = URLRequest(url: urlComponents.url!)
        request.setValue("Bearer \(token!)", forHTTPHeaderField: "Authorization")

        let (data, _) = try await URLSession.shared.data(for: request)
        return try JSONDecoder().decode(ScanListResponse.self, from: data)
    }

    // Get scan details
    func getScan(id: String) async throws -> Scan {
        var request = URLRequest(url: URL(string: "\(baseURL)/scans/\(id)")!)
        request.setValue("Bearer \(token!)", forHTTPHeaderField: "Authorization")

        let (data, _) = try await URLSession.shared.data(for: request)
        return try JSONDecoder().decode(Scan.self, from: data)
    }

    // Start scan
    func startScan(id: String) async throws -> Scan {
        var request = URLRequest(url: URL(string: "\(baseURL)/scans/\(id)/start")!)
        request.httpMethod = "POST"
        request.setValue("Bearer \(token!)", forHTTPHeaderField: "Authorization")

        let (data, _) = try await URLSession.shared.data(for: request)
        return try JSONDecoder().decode(Scan.self, from: data)
    }

    // Get ports
    func getPorts(scanId: String, state: String = "open") async throws -> [Port] {
        var urlComponents = URLComponents(string: "\(baseURL)/scans/\(scanId)/ports")!
        urlComponents.queryItems = [URLQueryItem(name: "state", value: state)]

        var request = URLRequest(url: urlComponents.url!)
        request.setValue("Bearer \(token!)", forHTTPHeaderField: "Authorization")

        let (data, _) = try await URLSession.shared.data(for: request)
        return try JSONDecoder().decode([Port].self, from: data)
    }

    // Get vulnerabilities
    func getVulnerabilities(scanId: String, severity: String? = nil) async throws -> [Vulnerability] {
        var urlComponents = URLComponents(string: "\(baseURL)/scans/\(scanId)/vulnerabilities")!
        if let severity = severity {
            urlComponents.queryItems = [URLQueryItem(name: "severity", value: severity)]
        }

        var request = URLRequest(url: urlComponents.url!)
        request.setValue("Bearer \(token!)", forHTTPHeaderField: "Authorization")

        let (data, _) = try await URLSession.shared.data(for: request)
        return try JSONDecoder().decode([Vulnerability].self, from: data)
    }
}
```

### 3. Polling for Scan Completion

```swift
func waitForScanCompletion(scanId: String) async throws -> Scan {
    var scan = try await client.getScan(id: scanId)

    while scan.status == "queued" || scan.status == "running" {
        try await Task.sleep(nanoseconds: 3_000_000_000) // 3 seconds
        scan = try await client.getScan(id: scanId)

        // Update UI with progress
        print("Progress: \(scan.progress_percent)% - Phase: \(scan.current_phase)")
    }

    return scan
}
```

---

## Error Handling

All errors return standard HTTP status codes with JSON error body:

```json
{
  "detail": "Error message here"
}
```

| Status | Description |
|--------|-------------|
| 400 | Bad Request (validation error, invalid state) |
| 401 | Unauthorized (missing/invalid token) |
| 403 | Forbidden (no access to resource) |
| 404 | Not Found |
| 422 | Validation Error (request body parsing) |
| 500 | Server Error |

---

## Rate Limits

No rate limits are currently enforced. However, for polling:
- Recommended poll interval: **3 seconds**
- Maximum practical poll rate: 1 request per second

---

## Notes for iOS Development

1. **Token Storage**: Store JWT token in Keychain, not UserDefaults
2. **Date Parsing**: All dates are ISO 8601 format (`yyyy-MM-dd'T'HH:mm:ss.SSSSSS`)
3. **Background Refresh**: Use background fetch to poll running scans
4. **Push Notifications**: Not currently supported (use polling)
5. **Offline Mode**: Cache scan results locally for offline viewing
