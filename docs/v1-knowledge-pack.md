KNOCK KNOCK V1 CODEBASE KNOWLEDGE PACK
1. SCANNER PIPELINE INVENTORY
1.1 MASSCAN
Invocation Points:
Function: run_masscan() in scanner.py:85-218
Called by: scan_host() and scan_hosts_parallel() (Phase 1 of batched pipeline)
CLI Arguments & Configuration:
cmd = [
    'sudo', masscan_binary,  # Requires sudo for raw socket access
    ip,                       # Target IP
    '-p0-65535',             # Scan ALL ports (0-65535)
    f'--rate={rate}',        # Packet rate (PPS)
    '--output-format', 'json',
    '--output-filename', str(output_path)
]
# Optional:
['--interface', interface]  # Network interface if specified
Arguments Breakdown:
masscan_binary: From config, default 'masscan'
rate: From config.masscan_rate, default 1000 PPS
interface: From config.masscan_interface, optional (e.g., 'en0', 'eth0')
Timeout: 20% of host_timeout_seconds (default: 240s out of 1200s)
Expected Output Format:
JSON array format
Each entry: {"ip": "...", "ports": [{"port": 22, "status": "open"}]}
Empty array [] if no open ports
Output file: masscan-<ip>.json
Error Handling:
Checks if output file exists post-execution
Parses JSON to extract port numbers with status='open'
Returns (success: bool, open_ports: List[int], error_message: Optional[str])
Timeout handled via subprocess.run(timeout=...)
No retry logic - single execution
Key Assumptions:
masscan may return non-zero even on success (checks file existence instead)
Automatically prepends sudo (assumes passwordless sudo configured)
Scan always scans full port range 0-65535
1.2 NMAP
Invocation Points:
Function: run_nmap_scan() in scanner.py:221-322
Called by: scan_host() and scan_hosts_parallel() (Phase 2 of batched pipeline)
CLI Arguments & Configuration:
# Base args from config (filtered to remove existing -p flags)
filtered_args = ['-sS', '-sV', '-sC', '-T2', '-Pn']  # Default from config

# Port specification (automatically added)
port_args = ['-p', '22,80,443,8080']  # Ports discovered by masscan

# Output
['-oX', str(output_path)]  # XML output

# Final command
cmd = ['sudo', nmap_binary] + filtered_args + port_args + ['-oX', output_path, ip]
# or without sudo if -sS not present
cmd = [nmap_binary] + filtered_args + port_args + ['-oX', output_path, ip]
Arguments Breakdown:
nmap_binary: From config, default 'nmap'
nmap_args: From config.nmap_args, default ['-sS', '-sV', '-sC', '-T2', '-Pn']
-sS: SYN scan (requires sudo)
-sV: Service version detection
-sC: Default scripts
-T2: Polite timing (could be -T4 for aggressive)
-Pn: Skip host discovery
ports: List of ports from masscan discovery (dynamically generated)
Timeout: 70% of host_timeout_seconds (default: 840s out of 1200s)
Expected Output Format:
XML format (nmap's -oX output)
Output file: nmap-<ip>.xml
Parsed via ElementTree in parse_nmap_xml()
Parsing Logic (parse_nmap_xml() in scanner.py:325-397):
Extracts <port> elements with state="open"
Fields extracted:
portid: Port number
protocol: tcp/udp
state: open/closed/filtered
service/@name: Service name
service/@product + service/@version: Combined as version string
script/@output: NSE script output (truncated to 100 chars), stored in notes
Returns: List[Port] dataclass objects
Error Handling:
Checks return code (non-zero = failure)
Verifies XML file exists after execution
Timeout handled via subprocess.run(timeout=...)
No retry logic
Key Assumptions:
Always scans ONLY ports discovered by masscan (not full range)
Requires sudo if -sS flag present
Script output truncated to avoid bloat
1.3 SSH-AUDIT
Invocation Points:
Function: run_ssh_audit() in scanner.py:400-544
Called by: scan_host() and scan_hosts_parallel() (Phase 3 of batched pipeline)
CLI Arguments & Configuration:
cmd = [ssh_audit_binary, '-j', f'{ip}:{port}']
Arguments Breakdown:
ssh_audit_binary: From config, default 'ssh-audit'
-j: JSON output mode
<ip>:<port>: Target in IP:PORT format
Timeout: Fixed 60 seconds (hardcoded, not configurable)
Expected Output Format:
JSON object on stdout
Structure:
{
  "banner": {"raw": "SSH-2.0-OpenSSH_8.2", "protocol": "2.0"},
  "kex": [{"algorithm": "...", "notes": {"warn": [...], "fail": [...]}}],
  "enc": [{"algorithm": "...", "notes": {...}}],
  "key": [{"algorithm": "...", "notes": {...}}],
  "mac": [{"algorithm": "...", "notes": {...}}]
}
Parsing Logic (inline in run_ssh_audit()):
Checks for [exception] cannot connect in stdout → sets connection_failed=True
Extracts:
banner.raw → SSHAuditResult.banner
banner.protocol → SSHAuditResult.ssh_version
Algorithm names from kex, enc, key, mac arrays
Warnings/failures from notes.warn and notes.fail nested in each algorithm
Aggregates warnings and failures into sets (deduplicated)
Returns: SSHAuditResult dataclass
Error Handling:
Connection timeouts/refusals detected via output parsing
JSON parsing errors caught and logged
Timeout: 60 seconds hardcoded
No retry logic
Errors stored in SSHAuditResult.error field, does not fail scan
Key Assumptions:
Only scans ports [22, 830] by default (configurable via config.ssh_ports)
Only attempts SSH audit on ports that nmap confirmed as open
Failure of ssh-audit does not fail overall host scan
1.4 NUCLEI
Invocation Points:
Function: run_nuclei() in nuclei_runner.py:16-105
Called by: _run_nuclei_for_target() wrapper (Phase 4 of batched pipeline) in scanner.py:667-700
Enabled when: config.nuclei_enabled == True
CLI Arguments & Configuration:
cmd = [
    nuclei_binary,
    '-target', target,        # URL or IP
    '-jsonl',                 # JSONL output format
    '-silent',                # Suppress banner
    '-o', str(output_path)    # Output file
]
# Optional additions:
if severity_filter:
    cmd.extend(['-severity', severity_filter])  # e.g., "critical,high,medium"
if templates:
    cmd.extend(['-t', templates])  # Custom templates path
Arguments Breakdown:
nuclei_binary: From config, default 'nuclei'
target: Either IP address or URL (http://ip:port or https://ip:port)
Mode controlled by config.nuclei_scan_mode:
'ips' mode: Scans IP directly
'urls' mode: Constructs URLs from http/https ports (80, 443, 8080, 8443)
severity_filter: From config.nuclei_severity, default "critical,high,medium"
templates: From config.nuclei_templates, optional custom templates path
Timeout: From config.nuclei_timeout, default 300 seconds
Expected Output Format:
JSONL (JSON Lines) format - one JSON object per line
Each finding:
{
  "template-id": "CVE-2021-12345",
  "info": {"name": "...", "severity": "high", "type": "http"},
  "matched-at": "https://example.com/path",
  "host": "example.com",
  "port": "443",
  "extracted-results": ["result1", "result2"],
  "timestamp": "2025-01-20T12:34:56Z"
}
Output file: nuclei-<ip>-<hash>.jsonl
Parsing Logic (parse_nuclei_jsonl() in nuclei_parser.py:38-137):
Reads JSONL file line-by-line
For each line:
Parses JSON
Extracts fields into NucleiFinding dataclass:
template_id: From template-id or templateID
name: From info.name
severity: From info.severity (normalized to lowercase)
type: From info.type or top-level type
host, matched_at, port, extracted_results, timestamp
Stores raw JSON in raw_json field
Returns: List[NucleiFinding]
Error Handling:
Non-zero return code logged as error
Empty output file (0 bytes) = no vulnerabilities found (success)
JSON decode errors on individual lines logged and skipped
Timeout handled via subprocess.run(timeout=...)
No retry logic
Findings stored in HostScanResult.nuclei_findings
Key Assumptions:
Nuclei templates must be pre-installed or path specified
In 'urls' mode, protocol guessed based on port (443/8443=https, else http)
Enabled globally via config, not per-target
2. PARSED-RESULT / DOMAIN MODELS
2.1 Core Scanner Dataclasses (in scanner.py)
Port (scanner.py:20-28)
@dataclass
class Port:
    port: int
    protocol: str       # 'tcp' or 'udp'
    state: str          # 'open', 'closed', 'filtered'
    service: str = ""   # Service name from nmap
    version: str = ""   # Product + version from nmap
    notes: str = ""     # NSE script output (truncated)
Created: By parse_nmap_xml() after nmap execution Consumed:
HTML report generation (_html_ports_table() in report.py)
Database storage (record_run() in storage.py → ports table)
Web API responses (via HostScanResult)
SSHAuditResult (scanner.py:31-43)
@dataclass
class SSHAuditResult:
    port: int
    ssh_version: str = ""
    banner: str = ""
    key_exchange: List[str] = field(default_factory=list)
    ciphers: List[str] = field(default_factory=list)
    macs: List[str] = field(default_factory=list)
    critical_issues: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    connection_failed: bool = False
    error: Optional[str] = None
Created: By run_ssh_audit() parsing JSON output Consumed:
HTML report generation (_html_ssh_audit() in report.py)
Database storage (→ ssh_audit table with JSON serialization)
Transformations:
Raw ssh-audit JSON → Parsed into algorithm lists + warnings/failures extracted from nested notes objects
Warnings/failures aggregated across all algorithm types (kex, enc, key, mac)
HostScanResult (scanner.py:46-55)
@dataclass
class HostScanResult:
    ip: str
    status: str  # 'success', 'error', 'timeout'
    open_ports: List[Port] = field(default_factory=list)
    ssh_results: List[SSHAuditResult] = field(default_factory=list)
    nuclei_findings: List = field(default_factory=list)  # List[NucleiFinding]
    error_message: Optional[str] = None
    nmap_xml_path: Optional[Path] = None
Created:
By scan_host() (per-host sequential scanning)
By scan_hosts_parallel() (batched parallel scanning - current approach)
Consumed:
HTML report generation (all report functions)
Database storage (record_run())
Web API scan results
Email report generation
Population Flow:
Initialized with IP and status='success'
Masscan fills open_ports with basic Port objects (port + protocol only)
Nmap refines open_ports with service/version details
SSH-audit fills ssh_results for applicable ports
Nuclei fills nuclei_findings if enabled
2.2 Nuclei Dataclasses (in nuclei_parser.py)
NucleiFinding (nuclei_parser.py:17-36)
@dataclass
class NucleiFinding:
    template_id: str
    name: str
    severity: str  # Normalized to lowercase in __post_init__
    type: str
    host: str
    matched_at: Optional[str] = None
    port: Optional[str] = None
    extracted_results: Optional[List[str]] = field(default_factory=list)
    timestamp: Optional[str] = None
    raw_json: Optional[str] = None
Created: By parse_nuclei_jsonl() reading JSONL output Consumed:
HTML report generation (_html_nuclei_findings() in report.py)
Database storage (→ nuclei_results table)
Aggregated by severity in reports
Transformations:
JSONL line → JSON object → NucleiFinding dataclass
Severity normalized to lowercase
Multiple field name variations handled (template-id vs templateID, etc.)
2.3 Storage Dataclasses (in storage.py)
RunMetadata (storage.py:22-29)
@dataclass
class RunMetadata:
    started_at: str  # ISO-8601 UTC
    finished_at: str  # ISO-8601 UTC
    config_hash: Optional[str] = None
    targets_hash: Optional[str] = None
    cli_args: Optional[str] = None
Created: In knock_knock.py:main() after scan completes Consumed: By record_run() to insert into runs table Hash Computation:
config_hash: SHA-256 of sorted config dict (masscan_rate, nmap_args, ssh_ports, concurrency, timeout)
targets_hash: SHA-256 of CSV file contents
Purpose: Detect configuration/target changes between runs
PortSummaryRow (storage.py:33-43)
@dataclass
class PortSummaryRow:
    device_name: str
    ip: str
    port: int
    protocol: str
    first_seen_at: str  # ISO-8601 UTC
    last_seen_at: str   # ISO-8601 UTC
    runs_count: int
    last_product: Optional[str] = None
    last_version: Optional[str] = None
Created: By query_ports_summary() SQL query Consumed: By CLI report mode (--report ports) Purpose: Historical port tracking showing when ports first/last appeared
SSHAuditSummaryRow (storage.py:46-56)
@dataclass
class SSHAuditSummaryRow:
    device_name: str
    ip: str
    port: int
    scan_date: str  # ISO-8601 UTC
    banner: Optional[str] = None
    issues_count: Optional[int] = None
    warnings: Optional[str] = None  # Comma-separated (limited to first 3)
    failures: Optional[str] = None  # Comma-separated (limited to first 3)
Created: By query_ssh_audit_summary() SQL query (parses raw_json from DB) Consumed: By CLI report mode (--report ssh-audit) Purpose: Historical SSH security posture tracking
3. DATABASE SCHEMA AND PERSISTENCE MODEL
3.1 Database Technology
SQLite - Single-file database
Default path: /var/lib/knockknock/knockknock.db (configurable)
Two separate databases:
CLI/legacy DB (storage.py schema) - Scan results, append-only
Web DB (web/database.py models) - Users, schedules, scan run tracking
3.2 CLI Database Schema (storage.py)
Table: runs
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    config_hash TEXT,
    targets_hash TEXT,
    cli_args TEXT
);
CREATE INDEX idx_runs_finished_at ON runs(finished_at);
Purpose: Track each scan run execution Key columns:
started_at, finished_at: ISO-8601 timestamps
config_hash: SHA-256 of config dict (detects config changes)
targets_hash: SHA-256 of targets CSV (detects target changes)
cli_args: Command-line arguments used
Table: hosts
CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES runs(id),
    device_name TEXT,
    ip TEXT NOT NULL,
    status TEXT NOT NULL,
    error_message TEXT,
    scan_duration_seconds REAL
);
CREATE INDEX idx_hosts_run_id ON hosts(run_id);
CREATE INDEX idx_hosts_ip ON hosts(ip);
Purpose: Per-host scan results within a run Key columns:
run_id: FK to runs table
device_name: From CSV (e.g., "DAL1-FW1")
status: 'success', 'error', 'timeout'
error_message: Populated on failure
Table: ports
CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id),
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    state TEXT NOT NULL,
    service_name TEXT,
    product TEXT,
    version TEXT,
    nmap_extra TEXT
);
CREATE INDEX idx_ports_host_id ON ports(host_id);
CREATE INDEX idx_ports_port ON ports(port);
Purpose: Individual port scan results Key columns:
host_id: FK to hosts table
service_name: From nmap service detection
product/version: From nmap (currently product not populated, only version)
nmap_extra: JSON field storing {"notes": "..."} from NSE scripts
Table: ssh_audit
CREATE TABLE IF NOT EXISTS ssh_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    port_id INTEGER NOT NULL REFERENCES ports(id),
    banner TEXT,
    kex_algos TEXT,
    ciphers TEXT,
    macs TEXT,
    issues_count INTEGER,
    raw_json TEXT
);
CREATE INDEX idx_ssh_audit_port_id ON ssh_audit(port_id);
Purpose: SSH security audit results Key columns:
port_id: FK to ports table (one ssh_audit per SSH port)
kex_algos, ciphers, macs: JSON arrays of algorithm names
issues_count: Total count of warnings + critical issues
raw_json: Complete SSHAuditResult serialized as JSON
Table: nuclei_results
CREATE TABLE IF NOT EXISTS nuclei_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id),
    template_id TEXT NOT NULL,
    name TEXT,
    severity TEXT,
    type TEXT,
    host TEXT,
    port TEXT,
    matched_at TEXT,
    extracted_results TEXT,
    timestamp TEXT,
    raw_json TEXT
);
CREATE INDEX idx_nuclei_host_id ON nuclei_results(host_id);
CREATE INDEX idx_nuclei_severity ON nuclei_results(severity);
Purpose: Nuclei vulnerability findings Key columns:
host_id: FK to hosts table
template_id: Nuclei template ID (e.g., "CVE-2021-12345")
severity: critical/high/medium/low/info
extracted_results: JSON array of extracted data
raw_json: Full NucleiFinding JSON
3.3 Web Database Schema (web/models/)
Table: users
id: Integer (PK)
email: String(unique, indexed)
username: String(unique, indexed)
hashed_password: String
is_active: Boolean
is_superuser: Boolean
created_at: DateTime
Purpose: User authentication for web UI Relationships:
scan_runs ← One-to-many
schedules ← One-to-many
Table: targets
id: Integer (PK)
ip_address: String(45, nullable, indexed)  # IPv4/IPv6
dns_name: String(255, nullable, indexed)
friendly_name: String(200, nullable)
description: Text
tags: Text  # JSON array
is_valid: Boolean
last_validated_at: DateTime
validation_error: String(500)
created_at: DateTime
updated_at: DateTime
Purpose: Target inventory for web-based scanning Validation: At least one of ip_address or dns_name required Relationships: Many-to-many with target_lists via target_list_items
Table: target_lists
id: Integer (PK)
name: String(200, unique)
description: Text
created_at: DateTime
updated_at: DateTime
created_by_id: Integer (FK → users.id)
Relationships:
items ← One-to-many (TargetListItem)
schedules ← One-to-many
Table: schedules
id: Integer (PK)
name: String(200)
description: Text
type: Enum(CRON, INTERVAL)
cron_expression: String(100)  # "0 2 * * 0"
interval_seconds: Integer
timezone: String(50, default="UTC")
target_list_id: Integer (FK → target_lists.id)

# Scan overrides
masscan_rate_override: Integer(nullable)
max_concurrent_override: Integer(nullable)
host_timeout_override: Integer(nullable)
nuclei_enabled: Boolean
nuclei_severity: String(50)
nuclei_templates_path: String(500)

# Email overrides
send_email: Boolean
email_recipients_override: Text
email_from_override: String(200)

# Metadata
enabled: Boolean
next_run_utc: DateTime
last_run_utc: DateTime
created_at: DateTime
updated_at: DateTime
created_by_id: Integer (FK → users.id)
Purpose: Recurring scan schedules (cron or interval-based) Relationships:
target_list → Many-to-one
scan_runs ← One-to-many
Table: scan_runs
id: Integer (PK)
run_uuid: String(36, unique, indexed)  # UUID v4
schedule_id: Integer (FK → schedules.id, nullable)  # NULL = ad-hoc
initiated_by_id: Integer (FK → users.id)
status: Enum(QUEUED, RUNNING, SUCCESS, ERROR, CANCELLED)
started_at: DateTime(nullable)
finished_at: DateTime(nullable)
error_message: Text(nullable)
config_snapshot: Text  # JSON snapshot of config
output_dir: String(500)
html_report_path: String(500)
log_path: String(500)
legacy_run_id: Integer(nullable)  # FK to storage.py runs.id
created_at: DateTime
Purpose: Track web-initiated scan executions Link to CLI DB: legacy_run_id references runs.id in storage.py schema Relationships:
artifacts ← One-to-many
schedule → Many-to-one (nullable)
initiated_by_user → Many-to-one
Table: artifacts
id: Integer (PK)
scan_run_id: Integer (FK → scan_runs.id)
kind: Enum(HTML, MASSCAN_JSON, NMAP_XML, NUCLEI_JSONL, LOG, SSH_AUDIT_JSON)
path: String(500)
size_bytes: BigInteger(nullable)
Purpose: Track scan output files (masscan JSON, nmap XML, reports, etc.) Cascade: Deleted when parent scan_run deleted
3.4 Data Flow into Database
CLI Scan Flow (knock_knock.py → storage.py)
Pre-scan:
Load targets from CSV
Compute targets_hash (SHA-256 of CSV contents)
Compute config_hash (SHA-256 of sorted config dict)
Record started_at timestamp
Scan execution:
scan_hosts_parallel() returns List[HostScanResult]
Each HostScanResult contains:
IP, status, error_message
List[Port]
List[SSHAuditResult]
List[NucleiFinding]
Post-scan storage (record_run()):
INSERT INTO runs (started_at, finished_at, config_hash, targets_hash, cli_args)
→ Get run_id

FOR EACH HostScanResult:
    INSERT INTO hosts (run_id, device_name, ip, status, error_message)
    → Get host_id
    
    FOR EACH Port:
        INSERT INTO ports (host_id, port, protocol, state, service_name, version, nmap_extra)
        → Get port_id
        
        IF port has matching SSHAuditResult:
            Serialize SSHAuditResult → raw_json
            INSERT INTO ssh_audit (port_id, banner, kex_algos, ciphers, macs, issues_count, raw_json)
    
    FOR EACH NucleiFinding:
        INSERT INTO nuclei_results (host_id, template_id, name, severity, ...)
Error handling:
DB errors logged as warnings, never fail the scan
All inserts wrapped in try/except with logger.warning()
Web Scan Flow (tasks.py → scanner_wrapper.py → storage.py + web DB)
User initiates scan (web UI or API):
Creates ScanRun record with status=QUEUED
Enqueues Celery task execute_scan.delay(scan_run_id)
Celery worker executes:
Update ScanRun to status=RUNNING
Load targets from schedule.target_list or ad-hoc config
Call run_scan_job() which:
Calls scan_hosts_parallel() (same as CLI)
Generates HTML report
Calls record_run() → writes to CLI DB
Returns ScanJobResult with:
output_dir, html_report_path
legacy_run_id (from CLI DB)
artifacts list
Post-execution:
Update ScanRun:
status=SUCCESS or ERROR
legacy_run_id = link to CLI DB run
output_dir, html_report_path
Insert Artifact records for each output file
3.5 Schema Support for Historical Comparisons
Current Capabilities:
Port history tracking: query_ports_summary() aggregates:
first_seen_at: MIN(runs.finished_at) for a (ip, port, protocol) tuple
last_seen_at: MAX(runs.finished_at)
runs_count: COUNT(DISTINCT run_id)
last_product, last_version: From most recent run
SSH audit tracking: query_ssh_audit_summary() shows most recent SSH audit per host:port
Missing for Full Diff Capability:
❌ No explicit "baseline" or "snapshot" concept
❌ No direct "scan A vs scan B" diff queries
❌ No port change detection (new ports, closed ports)
❌ No vulnerability change tracking (new/resolved findings)
❌ No service version change tracking (version upgrades/downgrades)
Schema IS Sufficient For Diffs:
✅ All runs are timestamped with finished_at
✅ All data linked via foreign keys (runs → hosts → ports)
✅ Nuclei findings linked to host_id with timestamps
✅ Config/target hashes allow detecting what changed between runs
To Build Diff Feature, You Would:
Query two runs by run_id or time range
Compare sets of (ip, port, protocol) tuples to find added/removed ports
Compare nuclei_results to find new/resolved vulnerabilities
Compare ssh_audit to find security posture changes
Compare version fields to detect version changes
4. REPORT GENERATION AND EXPORT FORMATS
4.1 HTML Reports
Generator: HTMLReportGenerator class in report.py:20-814 Inputs:
def generate(
    device_ip_mapping: Dict[str, List[str]],  # {device_name: [ip1, ip2, ...]}
    scan_results: List[HostScanResult],
    start_time: datetime,
    end_time: datetime
) -> str
Output:
Returns: HTML string (complete standalone document)
File written by caller to disk (e.g., knock-knock-20250123-143052.html)
Location: output_dir / html_report_path
Structure:
Header (_html_header()):
Embedded CSS (no external dependencies)
Responsive design
Color-coded severity levels (critical=red, high=orange, etc.)
Summary Section (_html_summary()):
Scan timestamps and duration
Device count, unique IPs, successful/errored/timed-out scans
Total open ports (TCP/UDP breakdown)
Nuclei findings summary (if any) with severity breakdown
Timeout Section (_html_timeout_section()):
Lists hosts that timed out
Only shown if timeouts occurred
Device Sections (_html_device_sections()):
One section per device (sorted alphabetically)
Shows all IPs for that device
Per-IP sections (_html_ip_section()):
Status indicator (✓ success, ⏱ timeout, ✗ error)
Ports table (_html_ports_table())
SSH audit results (_html_ssh_audit())
Nuclei findings (_html_nuclei_findings())
Footer (_html_footer()):
Generation timestamp
Special Features:
Ports of interest highlighting: Ports in config.ports_of_interest get yellow background
CVE hyperlinks: CVE template IDs in Nuclei findings automatically linked to NVD
Severity color coding: Critical=red, High=orange, Medium=yellow, Low=green, Info=blue
Algorithm truncation: SSH algorithms limited to first 5 per category
Fixed Filenames/Layouts:
Default: knock-knock-YYYYMMDD-HHMMSS.html
Directory: /tmp/knockknock-YYYYMMDD-HHMMSS/ (default) or custom via --output-dir
4.2 JSON Exports
Status: ❌ NOT IMPLEMENTED Evidence:
No json_report.py module found
No JSON serialization of scan results
HostScanResult is a dataclass but not serialized to JSON
Web API returns JSON but only for scan run metadata, not full results
What Would Be Needed:
Serialize HostScanResult, Port, SSHAuditResult, NucleiFinding to JSON
Could use dataclasses.asdict() + json.dumps()
Add CLI flag like --json-report scan-results.json
4.3 CSV Exports
Status: ✅ PARTIALLY IMPLEMENTED (CLI report mode only) Where Implemented:
Ports CSV (print_ports_csv() in knock_knock.py:493-511):
Command: --report ports --output csv
Format:
device_name,ip,port,protocol,first_seen_at,last_seen_at,runs_count,last_product,last_version
DAL1-FW1,64.255.192.53,22,tcp,2025-01-20T12:00:00Z,2025-01-23T14:00:00Z,3,OpenSSH,8.2
SSH Audit CSV (print_ssh_audit_csv() in knock_knock.py:577-598):
Command: --report ssh-audit --output csv
Format:
device_name,ip,port,scan_date,banner,issues_count,warnings,failures
DAL1-FW1,64.255.192.53,22,2025-01-23T14:00:00Z,SSH-2.0-OpenSSH_8.2,5,"KEX algo: weak","Cipher: deprecated"
NOT Implemented:
❌ CSV export of per-run scan results (hosts + ports)
❌ CSV export of Nuclei findings
❌ Web UI CSV download
4.4 Email Reports
Sender: EmailSender class in emailer.py:20-155 Inputs:
def send_report(
    html_content: str,       # HTML string from HTMLReportGenerator
    html_file_path: Path     # Path to HTML file (for attachment)
) -> bool
Email Structure:
Subject: {subject_prefix} - YYYY-MM-DD
Body:
Multipart/alternative:
Plain text version (generic message directing to HTML)
HTML version (embedded report)
Attachment: HTML file attached as application/html
SMTP Configuration:
Host, port, TLS, from/to addresses from config
Authentication: NOW SUPPORTED (username/password)
smtp_username and smtp_password from config or env vars
SMTP_USERNAME and SMTP_PASSWORD env vars take precedence
Error Handling:
Returns bool: True = sent, False = failed
Logs SMTP errors but does not crash scan
Email failure does not affect scan success status
5. CONFIGURATION KNOBS RELEVANT TO SCANNING
5.1 Masscan Configuration
Source: config.yaml → Config class (config.py:48-61)
Option	Config Key	Default	Purpose
Binary path	masscan.binary	'masscan'	Path or command name
Packet rate	masscan.rate	1000	Packets per second (PPS) per host
Interface	masscan.interface	null	Network interface (e.g., 'en0', 'eth0')
Consumed:
run_masscan() builds command: ['sudo', masscan_binary, ip, '-p0-65535', f'--rate={rate}', ...]
Interface added only if not null
Impact:
Rate: Higher = faster but more network impact
100 pps = ~11 min for all ports
1000 pps = ~75 sec for all ports
5000 pps = ~15 sec for all ports
Total PPS: max_concurrent_hosts × masscan_rate
Recommendation: Keep total < 10,000 PPS
5.2 Nmap Configuration
Source: config.yaml → Config class (config.py:64-72)
Option	Config Key	Default	Purpose
Binary path	nmap.binary	'nmap'	Path or command name
Arguments	nmap.args	['-sS', '-sV', '-sC', '-T2', '-Pn']	CLI flags (except -p and -oX)
Argument Breakdown:
-sS: SYN scan (requires sudo)
-sV: Service/version detection
-sC: Run default NSE scripts
-T2: Polite timing (alternatives: -T4=aggressive, -T3=normal, -T5=insane)
-Pn: Skip host discovery (assume host is up)
Consumed:
run_nmap_scan() filters out existing -p flags, adds ports from masscan, appends -oX
Note: Port specification (-p) is ALWAYS dynamically generated from masscan results
5.3 SSH-Audit Configuration
Source: config.yaml → Config class (config.py:75-83)
Option	Config Key	Default	Purpose
Binary path	ssh_audit.binary	'ssh-audit'	Path or command name
Ports	ssh_audit.ports	[22, 830]	Ports to scan with ssh-audit
Consumed:
scan_host() and scan_hosts_parallel() only run ssh-audit on ports that:
Are in ssh_ports list
Were confirmed open by nmap
Hardcoded: 60-second timeout (not configurable)
5.4 Nuclei Configuration
Source: config.yaml → Config class (config.py:86-115)
Option	Config Key	Default	Purpose
Enabled	nuclei.enabled	False	Enable/disable Nuclei scanning
Binary path	nuclei.binary	'nuclei'	Path or command name
Severity filter	nuclei.severity	'critical,high,medium'	Comma-separated severities
Timeout	nuclei.timeout	300	Per-host timeout in seconds
Templates path	nuclei.templates	''	Custom templates directory
Scan mode	nuclei.scan_mode	'ips'	'ips' or 'urls'
Scan Mode Details:
'ips' mode: Scan IP addresses directly (nuclei -target 192.0.2.1)
'urls' mode: Build URLs from http/https ports:
Port 80, 8080 → http://ip:port
Port 443, 8443 → https://ip:port
Service name 'http' → http://ip:port
Service name 'https' → https://ip:port
Consumed:
run_nuclei() builds command with these options
scan_hosts_parallel() Phase 4 only runs if nuclei_enabled=True
5.5 Concurrency and Timeout Settings
Source: config.yaml → Config class (config.py:118-126)
Option	Config Key	Default	Purpose
Max workers	concurrency.max_concurrent_hosts	10	ProcessPoolExecutor workers
Host timeout	concurrency.host_timeout_seconds	600	Total timeout per host (old default: 1200)
Timeout Allocation (in scan_host()):
Masscan: 20% of host_timeout (e.g., 240s for 1200s total)
Nmap: 70% of host_timeout (e.g., 840s)
SSH-audit: 10% of host_timeout (e.g., 120s) - BUT hardcoded to 60s in code
Consumed:
scan_hosts_parallel() creates ProcessPoolExecutor(max_workers=...)
Each phase timeout calculated based on percentages
Retry Logic: ❌ None - each tool executes once
5.6 Email / SMTP Configuration
Source: config.yaml → Config class (config.py:129-175)
Option	Config Key	Default	Env Var Override	Purpose
Host	email.smtp_host	-	-	SMTP server hostname
Port	email.smtp_port	25	-	SMTP port (25, 587, 465)
Use TLS	email.smtp_use_tls	False	-	STARTTLS encryption
Username	email.smtp_username	-	SMTP_USERNAME	Auth username
Password	email.smtp_password	-	SMTP_PASSWORD	Auth password
From	email.from_address	-	-	Sender address
To	email.to_addresses	[]	-	Recipient list
Subject prefix	email.subject_prefix	'Knock Knock Security Scan'	-	Email subject line
Validation:
validate_email_config() checks smtp_host, from_address, to_addresses not empty
Required when --send-email flag used
Environment Variable Precedence:
SMTP_USERNAME env var > email.smtp_username in config
SMTP_PASSWORD env var > email.smtp_password in config
5.7 Database Configuration
Source: config.yaml → Config class (config.py:178-186)
Option	Config Key	Default	Purpose
Enabled	database.enabled	False	Enable SQLite logging
Path	database.path	/var/lib/knockknock/knockknock.db	SQLite file path
CLI Override Precedence:
--no-db → Disable logging (highest priority)
--db-path PATH → Enable logging to PATH
config.database.enabled=true → Use config.database.path
Consumed:
record_run() writes to SQLite after scan completes
Errors logged as warnings, never fail the scan
5.8 Reporting Configuration
Source: config.yaml → Config class (config.py:189-197)
Option	Config Key	Default	Purpose
Ports of interest	reporting.ports_of_interest	[22, 80, 443, 8443, 3389]	Highlighted in HTML
Report title	reporting.report_title	'Knock Knock Security Scan Report'	HTML report title
Consumed:
HTMLReportGenerator highlights ports in ports_of_interest with yellow background
Report title used in HTML <title> and <h1>
6. HISTORICAL COMPARISONS / DIFFS
Status: ❌ NOT IMPLEMENTED Evidence:
Grep search for "diff", "compare", "baseline", "previous" found ONLY:
test_storage.py (test file)
React UI files (unrelated to backend diff logic)
README/docs mentioning potential use cases
No Existing Code For:
Comparing two scan runs
Detecting new/removed ports
Detecting new/resolved vulnerabilities
Detecting service version changes
Baseline/snapshot concept
Alerting on changes
Database Schema DOES Support Building This:
All runs timestamped
All data linked via FKs (runs → hosts → ports)
Config/target hashes track what changed
Can query two runs and diff their results
What You Would Build:
Query two run_ids or time ranges
Compare sets of (ip, port, protocol) tuples
Compare nuclei_results by template_id
Compare version strings for service changes
Generate diff report showing:
New ports opened
Ports closed
New vulnerabilities
Resolved vulnerabilities
Version upgrades/downgrades
7. CONSTRAINTS, ASSUMPTIONS, AND IMPLICIT DESIGN DECISIONS
7.1 Network Assumptions
IPv4 only: validate_ip() uses ipaddress.IPv4Address - no IPv6 support
Single subnet/VLAN: No multi-network routing support
Masscan in PATH: Assumes masscan binary available and sudoers configured
Nmap in PATH: Assumes nmap binary available
SSH-audit in PATH: Assumes ssh-audit binary available
Nuclei optional: Can run without Nuclei if disabled
7.2 Tool Availability Assumptions
Pre-flight check: check_tools() verifies masscan, nmap, ssh-audit via which command Nuclei: No pre-flight check for Nuclei binary
If enabled but missing, scan will fail at execution time
check_nuclei_installed() exists but not called automatically
Sudoers Requirement:
masscan: Always requires sudo for raw socket access
nmap: Requires sudo if -sS flag present (SYN scan)
Example sudoers configuration:
youruser ALL=(root) NOPASSWD: /usr/bin/masscan
youruser ALL=(root) NOPASSWD: /usr/bin/nmap
7.3 Concurrency Model
ProcessPoolExecutor (not threading):
Uses multiprocessing for true parallelism
Each worker is a separate Python process
No shared memory between workers
Workers timeout independently
Batched Phase Approach:
Phase 1: ALL hosts run masscan in parallel
Phase 2: ALL hosts with open ports run nmap in parallel
Phase 3: ALL SSH endpoints run ssh-audit in parallel
Phase 4: ALL targets run nuclei in parallel (if enabled)
Why batched vs per-host sequential:
Faster: Fast masscan scans don't wait for slow nmap scans
Better resource utilization: Maximum parallelism in each phase
7.4 Filesystem Assumptions
Output Directory Layout:
Default: /tmp/knockknock-YYYYMMDD-HHMMSS/
Contains:
knock-knock-YYYYMMDD-HHMMSS.html
masscan-<ip>.json (one per host)
nmap-<ip>.xml (one per host)
nuclei-<ip>-<hash>.jsonl (if Nuclei enabled)
Web Stack:
Reports dir: ./data/reports/<run_uuid>/
Database: ./data/db/knockknock.db (SQLite)
Scanner config: conf/config.yaml
Hardcoded Paths:
CLI debug logs: tmp/debug-YYYYMMDD-HHMMSS.log
Web default reports: settings.REPORTS_DIR = "./data/reports"
7.5 Security Assumptions
CLI:
No authentication
Assumes single-user/cron execution
Runs with user's privileges (requires sudo for masscan/nmap)
Web:
JWT authentication required
User model with is_superuser flag (not fully utilized)
No role-based access control (RBAC)
Password hashing via bcrypt
Network Security:
Scanning can trigger IDS/IPS alerts
No evasion techniques
Aggressive timing (-T4) may be noisy
Masscan raw socket access requires root
7.6 Data Model Assumptions
Single-tenant (CLI):
No user/org isolation
All scans visible to anyone with DB access
Multi-tenant (Web):
User authentication exists
No org/team concept
All users can see all scans (no filtering by initiated_by_id in list API)
Future: Would need per-user or per-org isolation
Device-to-IP Mapping:
CSV format: device_name, wan_ip
One device can have multiple IPs
One IP can only belong to one device (no sharing)
7.7 Error Handling Philosophy
Graceful Degradation:
Per-host errors don't abort entire scan
DB errors logged as warnings, don't fail scan
Email errors don't affect scan success
SSH-audit errors stored in result, don't fail host scan
Timeout Behavior:
Host timeout → status='timeout', partial results preserved
Tool timeout → error logged, move to next tool
Exit Codes (CLI):
0: Success (even if some hosts errored)
1: Fatal error (missing tools, invalid CSV, bad SMTP config)
130: User interruption (Ctrl+C)
7.8 Magic Constants
Hardcoded Values:
SSH-audit timeout: 60 seconds (not configurable)
Masscan timeout allocation: 20% of host timeout
Nmap timeout allocation: 70% of host timeout
SSH-audit timeout allocation: 10% (but hardcoded to 60s)
Nuclei timeout: 60s buffer added in scan_hosts_parallel() (line 991)
Script output truncation: 100 characters
SSH algorithm display limit: First 5 algorithms per category
Web concurrent scan limit: 3 (hardcoded in scans.py:39)
PPS warning thresholds:
≤5000 PPS: Green (Safe)
≤10000 PPS: Cyan (Safe - Moderate)
≤20000 PPS: Yellow (Caution)
20000 PPS: Red (Warning)
7.9 Logging
CLI Logging:
Default level: INFO
--quiet: WARNING level
--debug: DEBUG level + file logging to tmp/debug-*.log
Format: YYYY-MM-DD HH:MM:SS - module - LEVEL - message
Web Logging:
Celery task logging via logger = logging.getLogger(__name__)
No centralized logging configuration visible
Progress file: output_dir / progress.jsonl (intended for real-time updates, not fully implemented)
7.10 External Dependencies
Python Packages:
pyyaml: Config parsing
sqlalchemy: Web DB ORM
fastapi: Web framework
celery: Task queue
redis: Celery broker/backend
pydantic: Settings/schema validation
bcrypt: Password hashing
python-jose: JWT tokens
System Tools:
masscan: Port discovery (requires sudo)
nmap: Service detection (may require sudo)
ssh-audit: SSH security auditing
nuclei: Vulnerability scanning (optional)
Infrastructure:
SQLite: Data storage
Redis: Celery broker (web stack only)
SMTP server: Email delivery (optional)
SUMMARY
This knowledge pack documents the current Knock Knock v1 codebase's scanner pipeline, data models, database schema, reporting capabilities, configuration knobs, and design constraints. Key takeaways:
Four-tool pipeline: masscan → nmap → ssh-audit → nuclei (optional)
Batched parallel execution: Process all hosts in phases for maximum efficiency
Two database schemas: CLI SQLite (scan results) + Web SQLite (users/schedules)
HTML-only reporting: CSV/JSON exports limited to CLI historical reports
No diff capability: Schema supports it, but no implementation exists
Graceful degradation: Errors don't cascade, partial results preserved
Web stack partial: Celery/FastAPI framework exists but limited integration
This provides the foundation for designing a clean, web-first v2 architecture.
