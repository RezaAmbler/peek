# Strategic Integration Plan: ProjectDiscovery httpx

## Executive Summary

This document outlines a comprehensive plan to integrate ProjectDiscovery's **httpx** HTTP probing tool into PEEK's scan pipeline. httpx provides fast, multi-purpose HTTP probing with technology fingerprinting capabilities that will significantly enhance PEEK's HTTP reconnaissance and vulnerability scanning accuracy.

**Key Value Proposition:**
- Rich HTTP metadata collection before vulnerability scanning
- Technology fingerprinting to enhance nuclei template selection
- Validation of actual HTTP services vs. port-based assumptions
- CDN/WAF detection for context in reports

---

## 1. What is httpx?

httpx is a fast, multi-purpose HTTP toolkit from ProjectDiscovery (same team as nuclei) that:

- Probes HTTP endpoints for status codes, titles, headers
- Detects technologies using Wappalyzer fingerprints
- Identifies CDNs, WAFs, and load balancers
- Captures TLS/SSL information and JARM fingerprints
- Follows redirects and maps redirect chains
- Optionally captures screenshots
- Outputs structured JSON for easy parsing

**Installation:**
```bash
# Go install
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# Or download binary from releases
# https://github.com/projectdiscovery/httpx/releases
```

---

## 2. Pipeline Placement

### Current Pipeline (8 phases)

```
1. Port Discovery (nmap-discovery)     0% -> 10%
2. Nmap Service Detection             10% -> 80%
3. SSH-Audit                          80% -> 90%
4. Nuclei                             85% -> 90%
5. NSE Scripts                        90% -> 95%
6. SSLScan                            95% -> 97%
7. Nikto                              97% -> 98%
8. ZAP                                98% -> 100%
```

### Proposed Pipeline (9 phases)

```
1. Port Discovery (nmap-discovery)     0% -> 10%
2. Nmap Service Detection             10% -> 75%
3. httpx HTTP Probing        [NEW]    75% -> 80%
4. SSH-Audit                          80% -> 85%
5. Nuclei                             85% -> 92%
6. NSE Scripts                        92% -> 95%
7. SSLScan                            95% -> 97%
8. Nikto                              97% -> 98%
9. ZAP                                98% -> 100%
```

### Rationale for Placement

httpx runs **after nmap service detection** and **before nuclei** because:

1. **Technology Enhancement**: httpx technology detection can add targeted tags to nuclei scanning
2. **HTTP Validation**: Confirms which ports actually serve HTTP (vs. nmap guessing from port numbers)
3. **Minimal Latency**: httpx is very fast (seconds per host), adding minimal overhead
4. **Report Enrichment**: Provides HTTP metadata even if no vulnerabilities are found

---

## 3. Data Model

### New Model: HttpxResult

Create `backend/app/models/httpx_result.py`:

```python
from sqlalchemy import Column, String, Integer, Boolean, ForeignKey, JSON
from sqlalchemy.orm import relationship
from ..database import Base

class HttpxResult(Base):
    __tablename__ = "httpx_results"

    id = Column(String(36), primary_key=True)
    port_id = Column(String(36), ForeignKey("ports.id", ondelete="CASCADE"), nullable=False, index=True)
    tool_execution_id = Column(String(36), ForeignKey("tool_executions.id", ondelete="CASCADE"), nullable=True)

    # HTTP Response
    status_code = Column(Integer, nullable=True)
    content_length = Column(Integer, nullable=True)
    content_type = Column(String, nullable=True)
    title = Column(String, nullable=True)
    webserver = Column(String, nullable=True)
    method = Column(String, nullable=True)  # GET, POST, etc.

    # Technology Fingerprinting
    technologies = Column(JSON, nullable=True)  # ["WordPress", "PHP", "nginx"]

    # Infrastructure
    cdn = Column(String, nullable=True)  # "cloudflare", "akamai", etc.
    waf = Column(String, nullable=True)  # Detected WAF
    redirect_chain = Column(JSON, nullable=True)  # [url1, url2, final_url]
    final_url = Column(String, nullable=True)

    # Response Metadata
    response_time_ms = Column(Integer, nullable=True)
    body_hash = Column(String, nullable=True)  # MD5 for content comparison

    # TLS Information
    tls_version = Column(String, nullable=True)
    tls_cipher = Column(String, nullable=True)
    jarm_hash = Column(String, nullable=True)  # JARM TLS fingerprint

    # Virtual Hosts
    virtual_hosts = Column(JSON, nullable=True)

    # Screenshot (optional feature)
    screenshot_path = Column(String, nullable=True)

    # Connection Status
    connection_failed = Column(Boolean, default=False, nullable=False)
    failure_reason = Column(String, nullable=True)

    # Relationships
    port_record = relationship("Port", back_populates="httpx_results")
    tool_execution = relationship("ToolExecution")
```

### Port Model Update

Add relationship to `backend/app/models/port.py`:

```python
# In Port class
httpx_results = relationship("HttpxResult", back_populates="port_record", cascade="all, delete-orphan")
```

---

## 4. Tool Wrapper

Create `backend/app/tools/httpx.py`:

```python
"""httpx HTTP prober integration."""
import subprocess
import json
import logging
import tempfile
from pathlib import Path
from typing import Tuple, Optional, List
from ..core.config import settings

logger = logging.getLogger(__name__)


def run_httpx(
    target: str,
    timeout: int = 30,
    follow_redirects: bool = True,
    tech_detect: bool = True,
    tls_probe: bool = True,
    jarm: bool = True,
    screenshot: bool = False,
    screenshot_path: Optional[str] = None
) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Execute httpx HTTP prober.

    Args:
        target: URL or host:port to probe (e.g., "http://192.168.1.1:8080")
        timeout: HTTP request timeout in seconds
        follow_redirects: Follow HTTP redirects
        tech_detect: Enable technology detection
        tls_probe: Enable TLS probing
        jarm: Enable JARM fingerprinting
        screenshot: Capture screenshot
        screenshot_path: Path to store screenshots

    Returns:
        Tuple of (success, json_output, error_message)
    """
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        output_path = f.name

    try:
        # Build command
        cmd = [
            settings.HTTPX_PATH or 'httpx',
            '-u', target,
            '-json',
            '-silent',
            '-nc',  # No color
            '-timeout', str(timeout),
            '-sc',   # Status code
            '-cl',   # Content length
            '-ct',   # Content type
            '-title',
            '-server',
            '-hash', 'md5',
            '-o', output_path,
        ]

        if follow_redirects:
            cmd.extend(['-fr', '-maxr', '10'])

        if tech_detect:
            cmd.append('-td')

        if tls_probe:
            cmd.append('-tls-probe')

        if jarm:
            cmd.append('-jarm')

        # CDN detection
        cmd.append('-cdn')

        if screenshot and screenshot_path:
            cmd.extend(['-screenshot', '-ss-path', screenshot_path])

        cmd_str = ' '.join(cmd)
        logger.info(f"Running httpx: {cmd_str}")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 30  # Buffer beyond HTTP timeout
        )

        # Read output file
        output_file = Path(output_path)
        if output_file.exists():
            raw_json = output_file.read_text()
            if raw_json.strip():
                logger.info(f"httpx completed for {target}")
                return True, raw_json, None
            else:
                # Empty output = no HTTP response (connection failed)
                logger.warning(f"httpx produced empty output for {target}")
                return False, None, "No HTTP response"
        else:
            stderr_preview = result.stderr[:500] if result.stderr else "no stderr"
            logger.warning(f"httpx did not produce output for {target}: {stderr_preview}")
            return False, None, f"No output file. stderr: {stderr_preview}"

    except subprocess.TimeoutExpired:
        logger.warning(f"httpx timed out after {timeout}s for {target}")
        return False, None, f"Timeout after {timeout} seconds"
    except FileNotFoundError:
        logger.error("httpx not found. Install from: https://github.com/projectdiscovery/httpx")
        return False, None, "httpx not found"
    except Exception as e:
        logger.error(f"httpx error for {target}: {e}")
        return False, None, str(e)
    finally:
        # Cleanup
        Path(output_path).unlink(missing_ok=True)


def parse_httpx_output(raw_json: str) -> Optional[dict]:
    """
    Parse httpx JSON output into structured data.

    Args:
        raw_json: Raw JSON string from httpx

    Returns:
        Parsed dictionary or None if parsing fails
    """
    if not raw_json or not raw_json.strip():
        return None

    try:
        # httpx outputs one JSON object per line
        data = json.loads(raw_json.strip().split('\n')[0])

        return {
            'url': data.get('url'),
            'input': data.get('input'),
            'status_code': data.get('status_code') or data.get('status-code'),
            'content_length': data.get('content_length') or data.get('content-length'),
            'content_type': data.get('content_type') or data.get('content-type'),
            'title': data.get('title'),
            'webserver': data.get('webserver'),
            'method': data.get('method', 'GET'),
            'technologies': data.get('tech') or data.get('technologies') or [],
            'cdn': data.get('cdn'),
            'waf': data.get('waf'),
            'final_url': data.get('final_url') or data.get('final-url'),
            'redirect_chain': data.get('chain') or [],
            'response_time_ms': _parse_response_time(data.get('time') or data.get('response_time')),
            'body_hash': _extract_hash(data.get('hash') or data.get('hashes')),
            'tls_version': _extract_tls_version(data.get('tls') or data.get('tls-grab')),
            'tls_cipher': _extract_tls_cipher(data.get('tls') or data.get('tls-grab')),
            'jarm_hash': data.get('jarm'),
            'failed': data.get('failed', False),
        }
    except json.JSONDecodeError as e:
        logger.warning(f"Failed to parse httpx JSON: {e}")
        return None
    except Exception as e:
        logger.error(f"Error parsing httpx output: {e}")
        return None


def _parse_response_time(time_str: Optional[str]) -> Optional[int]:
    """Parse response time string to milliseconds."""
    if not time_str:
        return None
    try:
        if isinstance(time_str, (int, float)):
            return int(time_str)
        # Handle formats like "245ms", "1.2s"
        time_str = str(time_str).lower()
        if 'ms' in time_str:
            return int(float(time_str.replace('ms', '')))
        elif 's' in time_str:
            return int(float(time_str.replace('s', '')) * 1000)
        return int(float(time_str))
    except (ValueError, TypeError):
        return None


def _extract_hash(hash_data) -> Optional[str]:
    """Extract MD5 hash from hash data."""
    if not hash_data:
        return None
    if isinstance(hash_data, str):
        return hash_data
    if isinstance(hash_data, dict):
        return hash_data.get('body_md5') or hash_data.get('md5')
    return None


def _extract_tls_version(tls_data) -> Optional[str]:
    """Extract TLS version from TLS data."""
    if not tls_data:
        return None
    if isinstance(tls_data, dict):
        return tls_data.get('version') or tls_data.get('tls_version')
    return None


def _extract_tls_cipher(tls_data) -> Optional[str]:
    """Extract TLS cipher from TLS data."""
    if not tls_data:
        return None
    if isinstance(tls_data, dict):
        return tls_data.get('cipher')
    return None


def check_httpx_available() -> bool:
    """Check if httpx is available."""
    try:
        result = subprocess.run(
            [settings.HTTPX_PATH or 'httpx', '-version'],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False
```

---

## 5. Parser

Create `backend/app/parsers/httpx_parser.py`:

```python
"""Parser for httpx output."""
from typing import Optional
from sqlalchemy.orm import Session
import uuid

from ..models import ToolExecution, ScanTarget, Port
from ..models.httpx_result import HttpxResult
from ..tools.httpx import parse_httpx_output


def create_httpx_result_from_output(
    db: Session,
    tool_execution: ToolExecution,
    target: ScanTarget,
    port_rec: Port
) -> Optional[HttpxResult]:
    """
    Parse httpx output and create HttpxResult record.

    Args:
        db: Database session
        tool_execution: The ToolExecution record for this httpx run
        target: The ScanTarget being scanned
        port_rec: The Port record being probed

    Returns:
        Created HttpxResult or None if parsing fails
    """
    if not tool_execution.raw_output:
        return None

    try:
        parsed = parse_httpx_output(tool_execution.raw_output)
        if not parsed:
            return None

        # Check for existing result (prevent duplicates)
        existing = db.query(HttpxResult).filter(
            HttpxResult.port_id == str(port_rec.id)
        ).first()

        if existing:
            # Update existing record
            existing.status_code = parsed.get('status_code')
            existing.content_length = parsed.get('content_length')
            existing.content_type = parsed.get('content_type')
            existing.title = parsed.get('title')
            existing.webserver = parsed.get('webserver')
            existing.method = parsed.get('method')
            existing.technologies = parsed.get('technologies')
            existing.cdn = parsed.get('cdn')
            existing.waf = parsed.get('waf')
            existing.final_url = parsed.get('final_url')
            existing.redirect_chain = parsed.get('redirect_chain')
            existing.response_time_ms = parsed.get('response_time_ms')
            existing.body_hash = parsed.get('body_hash')
            existing.tls_version = parsed.get('tls_version')
            existing.tls_cipher = parsed.get('tls_cipher')
            existing.jarm_hash = parsed.get('jarm_hash')
            existing.connection_failed = parsed.get('failed', False)
            db.flush()
            return existing

        # Create new record
        result = HttpxResult(
            id=str(uuid.uuid4()),
            port_id=str(port_rec.id),
            tool_execution_id=str(tool_execution.id),
            status_code=parsed.get('status_code'),
            content_length=parsed.get('content_length'),
            content_type=parsed.get('content_type'),
            title=parsed.get('title'),
            webserver=parsed.get('webserver'),
            method=parsed.get('method'),
            technologies=parsed.get('technologies'),
            cdn=parsed.get('cdn'),
            waf=parsed.get('waf'),
            final_url=parsed.get('final_url'),
            redirect_chain=parsed.get('redirect_chain'),
            response_time_ms=parsed.get('response_time_ms'),
            body_hash=parsed.get('body_hash'),
            tls_version=parsed.get('tls_version'),
            tls_cipher=parsed.get('tls_cipher'),
            jarm_hash=parsed.get('jarm_hash'),
            connection_failed=parsed.get('failed', False),
        )

        db.add(result)
        db.flush()
        return result

    except Exception as e:
        tool_execution.error_message = f"Failed to parse httpx output: {str(e)}"
        db.flush()
        return None
```

---

## 6. Pipeline Integration

### Add to scan_tasks.py

```python
# Add imports
from ..tools.httpx import run_httpx, check_httpx_available
from ..parsers.httpx_parser import create_httpx_result_from_output
from ..models.httpx_result import HttpxResult

# In run_scan() function, add after nmap phase:

            # Phase 3: httpx HTTP Probing (75% -> 80%)
            if config.enable_httpx:
                scan.current_phase = ScanPhase.HTTPX.value
                db.commit()
                self.update_state(state='PROGRESS', meta={'phase': 'httpx', 'progress': 0.75})
                run_httpx_phase(db, scan, targets, config)


def run_httpx_phase(db, scan: Scan, targets: List[ScanTarget], config):
    """
    Run httpx HTTP probing on discovered HTTP/HTTPS ports.

    This phase:
    1. Probes HTTP ports to gather rich metadata
    2. Detects technologies for enhanced nuclei scanning
    3. Validates which ports are actually serving HTTP
    """
    logger.info(f"Starting httpx phase for scan {scan.id}")

    # Check if httpx is available
    if not check_httpx_available():
        logger.warning("httpx not available, skipping phase")
        return

    # HTTP services and common HTTP ports
    http_services = ['http', 'https', 'ssl/http', 'http-proxy', 'http-alt']
    http_port_numbers = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000]

    # Get HTTP-like ports
    http_ports = db.query(Port).join(ScanTarget).filter(
        ScanTarget.scan_id == str(scan.id),
        Port.state == 'open'
    ).filter(
        (Port.service_name.in_(http_services)) |
        (Port.port.in_(http_port_numbers))
    ).all()

    if not http_ports:
        logger.info("No HTTP ports found for httpx probing")
        return

    logger.info(f"httpx: {len(http_ports)} HTTP port(s) to probe")

    total = len(http_ports)
    completed = 0

    for port_rec in http_ports:
        # Get target for this port
        target = db.query(ScanTarget).filter(
            ScanTarget.id == port_rec.scan_target_id
        ).first()

        if not target:
            completed += 1
            continue

        ip = target.ip_address
        port = port_rec.port

        # Determine protocol based on service or port
        is_ssl = (
            port_rec.service_name in ['https', 'ssl/http'] or
            port in [443, 8443]
        )
        scheme = "https" if is_ssl else "http"
        target_url = f"{scheme}://{ip}:{port}"

        logger.info(f"httpx: Probing {target_url}")

        # Create tool execution record
        tool_exec = ToolExecution(
            id=str(uuid.uuid4()),
            scan_target_id=str(target.id),
            port_id=str(port_rec.id),
            tool_name="httpx",
            command_line=f"httpx -u {target_url} -json -td",
            started_at=datetime.utcnow()
        )
        db.add(tool_exec)
        db.flush()

        try:
            # Run httpx
            timeout = config.httpx_timeout or 30
            success, raw_json, error = run_httpx(
                target=target_url,
                timeout=timeout,
                tech_detect=config.httpx_tech_detect,
                screenshot=config.httpx_screenshot
            )

            tool_exec.finished_at = datetime.utcnow()
            tool_exec.duration_ms = int((tool_exec.finished_at - tool_exec.started_at).total_seconds() * 1000)
            tool_exec.raw_output = raw_json[:50000] if raw_json else None
            tool_exec.raw_format = "json"
            tool_exec.error_message = error
            tool_exec.exit_code = 0 if success else 1

            if success and raw_json:
                # Parse and create HttpxResult
                result = create_httpx_result_from_output(db, tool_exec, target, port_rec)
                if result:
                    logger.info(f"httpx: {target_url} -> {result.status_code} {result.title or ''} techs={result.technologies}")
            else:
                # Create failed result
                failed_result = HttpxResult(
                    id=str(uuid.uuid4()),
                    port_id=str(port_rec.id),
                    tool_execution_id=str(tool_exec.id),
                    connection_failed=True,
                    failure_reason=error or "Unknown error"
                )
                db.add(failed_result)

            db.commit()

        except Exception as e:
            logger.error(f"httpx error for {target_url}: {e}")
            tool_exec.finished_at = datetime.utcnow()
            tool_exec.error_message = str(e)
            tool_exec.exit_code = 1
            db.commit()

        completed += 1

        # Update progress (httpx is 5% of total, from 75% to 80%)
        progress = 0.75 + (0.05 * completed / total)
        scan.progress_percent = progress
        scan.progress_updated_at = datetime.utcnow()
        db.commit()

    logger.info(f"httpx complete: {completed} ports probed")
```

### Add ScanPhase

In `backend/app/models/scan.py`:

```python
class ScanPhase(str, Enum):
    PENDING = "pending"
    NMAP_DISCOVERY = "nmap_discovery"
    NMAP = "nmap"
    HTTPX = "httpx"  # NEW
    SSH_AUDIT = "ssh_audit"
    NUCLEI = "nuclei"
    NSE = "nse"
    SSLSCAN = "sslscan"
    NIKTO = "nikto"
    ZAP = "zap"
    COMPLETED = "completed"
    FAILED = "failed"
```

### Add ScanConfig Fields

In `backend/app/models/scan_config.py`:

```python
# httpx options
enable_httpx = Column(Boolean, default=True, nullable=False)
httpx_timeout = Column(Integer, default=30, nullable=False)  # seconds
httpx_tech_detect = Column(Boolean, default=True, nullable=False)
httpx_screenshot = Column(Boolean, default=False, nullable=False)
```

---

## 7. Nuclei Enhancement

### Technology-to-Tag Mapping

Add to `backend/config/nuclei_profiles.yaml`:

```yaml
# ============================================
# Technology Tags (from httpx detection)
# ============================================
# Maps httpx technology fingerprints to nuclei tags
# These enhance base service profiles with more specific templates

technology_tags:
  # CMS
  wordpress: [wordpress, wp]
  drupal: [drupal]
  joomla: [joomla]
  magento: [magento]
  ghost: [ghost]
  strapi: [strapi]

  # Frameworks
  laravel: [laravel, php]
  symfony: [symfony, php]
  django: [django, python]
  flask: [flask, python]
  rails: [rails, ruby]
  spring: [spring, java]
  express: [express, node]

  # Frontend
  react: [react]
  angular: [angular]
  vue: [vue]
  next.js: [nextjs]
  nuxt: [nuxt]

  # Servers
  nginx: [nginx]
  apache: [apache]
  iis: [iis]
  tomcat: [tomcat]
  caddy: [caddy]

  # Databases
  mysql: [mysql]
  postgresql: [postgres]
  mongodb: [mongodb]
  redis: [redis]

  # Panels
  phpmyadmin: [phpmyadmin]
  cpanel: [cpanel]
  plesk: [plesk]
  webmin: [webmin]

  # DevOps
  jenkins: [jenkins]
  gitlab: [gitlab]
  grafana: [grafana]
  kibana: [kibana]
```

### Update service_profile.py

Add technology parameter to `get_nuclei_profile()`:

```python
def get_nuclei_profile(
    service_name: Optional[str],
    product: Optional[str] = None,
    version: Optional[str] = None,
    extra_info: Optional[dict] = None,
    port: Optional[int] = None,
    scan_mode: str = "deep",
    technologies: Optional[List[str]] = None  # NEW: from httpx
) -> NucleiProfile:
    """
    Get Nuclei scanning profile for a detected service.

    Args:
        ...
        technologies: List of technologies detected by httpx
    """
    # ... existing code ...

    # Add technology-specific tags from httpx detection
    if technologies and tags:  # Only if not in comprehensive mode
        tech_tags_config = config.get('technology_tags', {})
        for tech in technologies:
            tech_lower = tech.lower()
            for key, extra_tags in tech_tags_config.items():
                if key in tech_lower:
                    tags.extend(t for t in extra_tags if t not in tags)
                    break

    # ... rest of function
```

---

## 8. API Endpoints

### Add to routers/scans.py

```python
from ..models.httpx_result import HttpxResult
from ..schemas.httpx import HttpxResultResponse

@router.get("/{scan_id}/httpx-results", response_model=List[HttpxResultResponse])
async def get_httpx_results(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all httpx probe results for a scan."""
    # Verify scan access
    scan = await db.get(Scan, scan_id)
    if not scan or scan.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Get httpx results with port and target info
    query = select(HttpxResult, Port, ScanTarget).join(
        Port, HttpxResult.port_id == Port.id
    ).join(
        ScanTarget, Port.scan_target_id == ScanTarget.id
    ).where(
        ScanTarget.scan_id == scan_id
    )

    result = await db.execute(query)
    rows = result.all()

    return [
        HttpxResultResponse(
            id=str(httpx.id),
            port_id=str(httpx.port_id),
            ip_address=target.ip_address,
            port=port.port,
            status_code=httpx.status_code,
            content_length=httpx.content_length,
            content_type=httpx.content_type,
            title=httpx.title,
            webserver=httpx.webserver,
            technologies=httpx.technologies or [],
            cdn=httpx.cdn,
            final_url=httpx.final_url,
            redirect_chain=httpx.redirect_chain or [],
            response_time_ms=httpx.response_time_ms,
            tls_version=httpx.tls_version,
            jarm_hash=httpx.jarm_hash,
            connection_failed=httpx.connection_failed,
            failure_reason=httpx.failure_reason
        )
        for httpx, port, target in rows
    ]
```

### Schema (schemas/httpx.py)

```python
from pydantic import BaseModel
from typing import List, Optional


class HttpxResultResponse(BaseModel):
    id: str
    port_id: str
    ip_address: str
    port: int

    status_code: Optional[int] = None
    content_length: Optional[int] = None
    content_type: Optional[str] = None
    title: Optional[str] = None
    webserver: Optional[str] = None
    technologies: List[str] = []
    cdn: Optional[str] = None
    final_url: Optional[str] = None
    redirect_chain: List[str] = []
    response_time_ms: Optional[int] = None
    tls_version: Optional[str] = None
    jarm_hash: Optional[str] = None

    connection_failed: bool = False
    failure_reason: Optional[str] = None

    class Config:
        from_attributes = True
```

---

## 9. Frontend Integration

### API Client Update (frontend/src/api/scans.ts)

```typescript
export interface HttpxResult {
  id: string;
  port_id: string;
  ip_address: string;
  port: number;
  status_code?: number;
  content_length?: number;
  content_type?: string;
  title?: string;
  webserver?: string;
  technologies: string[];
  cdn?: string;
  final_url?: string;
  redirect_chain: string[];
  response_time_ms?: number;
  tls_version?: string;
  jarm_hash?: string;
  connection_failed: boolean;
  failure_reason?: string;
}

export const scansApi = {
  // ... existing methods ...

  async getHttpxResults(scanId: string): Promise<HttpxResult[]> {
    const { data } = await apiClient.get<HttpxResult[]>(`/api/scans/${scanId}/httpx-results`);
    return data;
  },
};
```

### Component (frontend/src/components/HttpxResultsSection.tsx)

```tsx
import { useQuery } from '@tanstack/react-query';
import { scansApi, HttpxResult } from '../api/scans';

interface Props {
  scanId: string;
}

export function HttpxResultsSection({ scanId }: Props) {
  const { data: results, isLoading } = useQuery({
    queryKey: ['httpx-results', scanId],
    queryFn: () => scansApi.getHttpxResults(scanId),
  });

  if (isLoading) return <div>Loading HTTP probes...</div>;
  if (!results?.length) return null;

  return (
    <div className="bg-white shadow rounded-lg overflow-hidden">
      <div className="px-4 py-5 sm:px-6">
        <h3 className="text-lg font-medium text-gray-900">HTTP Probes</h3>
        <p className="mt-1 text-sm text-gray-500">
          HTTP endpoint analysis via httpx
        </p>
      </div>
      <div className="border-t border-gray-200">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Target</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Title</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Server</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Technologies</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">CDN</th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {results.map((result) => (
              <tr key={result.id}>
                <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                  {result.ip_address}:{result.port}
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  {result.connection_failed ? (
                    <span className="text-red-600">Failed</span>
                  ) : (
                    <span className={`px-2 py-1 rounded text-xs font-medium ${
                      result.status_code === 200 ? 'bg-green-100 text-green-800' :
                      result.status_code && result.status_code < 400 ? 'bg-blue-100 text-blue-800' :
                      'bg-yellow-100 text-yellow-800'
                    }`}>
                      {result.status_code}
                    </span>
                  )}
                </td>
                <td className="px-6 py-4 text-sm text-gray-500 max-w-xs truncate">
                  {result.title || '-'}
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                  {result.webserver || '-'}
                </td>
                <td className="px-6 py-4">
                  <div className="flex flex-wrap gap-1">
                    {result.technologies.slice(0, 4).map((tech) => (
                      <span key={tech} className="px-2 py-0.5 rounded-full text-xs bg-indigo-100 text-indigo-800">
                        {tech}
                      </span>
                    ))}
                    {result.technologies.length > 4 && (
                      <span className="text-xs text-gray-500">+{result.technologies.length - 4}</span>
                    )}
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                  {result.cdn || '-'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
```

---

## 10. Docker Configuration

### Install httpx in Dockerfile.celery

```dockerfile
# Install httpx
RUN curl -L https://github.com/projectdiscovery/httpx/releases/download/v1.6.0/httpx_1.6.0_linux_amd64.zip -o /tmp/httpx.zip \
    && unzip /tmp/httpx.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/httpx \
    && rm /tmp/httpx.zip
```

### Settings (core/config.py)

```python
HTTPX_PATH: str = Field(default="httpx", env="HTTPX_PATH")
```

---

## 11. Implementation Checklist

### Phase 1: Core Infrastructure
- [ ] Create `backend/app/models/httpx_result.py`
- [ ] Update `backend/app/models/__init__.py`
- [ ] Update `backend/app/models/port.py` with relationship
- [ ] Create database migration
- [ ] Create `backend/app/tools/httpx.py`
- [ ] Create `backend/app/parsers/httpx_parser.py`

### Phase 2: Pipeline Integration
- [ ] Update `backend/app/models/scan.py` (ScanPhase.HTTPX)
- [ ] Update `backend/app/models/scan_config.py` (enable_httpx, etc.)
- [ ] Update `backend/app/tasks/scan_tasks.py` (run_httpx_phase)
- [ ] Update progress percentages for all phases

### Phase 3: Nuclei Enhancement
- [ ] Update `backend/config/nuclei_profiles.yaml` (technology_tags)
- [ ] Update `backend/app/services/service_profile.py` (technologies param)
- [ ] Update nuclei phase to pass technologies from httpx

### Phase 4: API Layer
- [ ] Create `backend/app/schemas/httpx.py`
- [ ] Update `backend/app/routers/scans.py` (new endpoint)

### Phase 5: Frontend
- [ ] Update `frontend/src/api/scans.ts` (types, API method)
- [ ] Create `frontend/src/components/HttpxResultsSection.tsx`
- [ ] Update `frontend/src/pages/ScanDetail.tsx`

### Phase 6: Reports
- [ ] Update `backend/app/services/report_service.py` (HTTP Probes section)

### Phase 7: Docker
- [ ] Update `backend/Dockerfile.celery` (install httpx)
- [ ] Update `backend/app/core/config.py` (HTTPX_PATH)

---

## 12. Success Criteria

1. **Functional**: httpx phase runs after nmap, before nuclei
2. **Data**: HttpxResult records created with technology detection
3. **Enhancement**: Detected technologies enhance nuclei tag selection
4. **UI**: HTTP probes displayed in scan detail page
5. **Reports**: HTTP probe section in PDF/HTML reports
6. **Graceful Degradation**: If httpx unavailable, phase skips without failing scan

---

## 13. Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| httpx not installed | Check availability, skip phase gracefully |
| Rate limiting by CDN/WAF | Use configurable timeout and respect rate limits |
| Large scan delays | Process sequentially (SQLite constraint), httpx is fast |
| Screenshot storage | Store in data/ with cleanup policy |
| Technology detection false positives | Technologies are additive hints, not authoritative |

---

## 14. Future Enhancements

1. **Virtual Host Discovery**: Use httpx vhost brute-forcing
2. **Screenshot Gallery**: Visual evidence in reports
3. **Technology Trend Analysis**: Track tech changes across runs
4. **WAF Detection Enhancement**: Inform scanning strategy based on WAF presence
5. **Batch Mode**: Use httpx's list input for better performance on large scans
