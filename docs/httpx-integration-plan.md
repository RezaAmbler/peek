# Strategic Integration Plan: ProjectDiscovery httpx

> **Status**: Implemented
> **Completed**: December 2024
> **Branch**: diffy (commit `16189a9`)

## Executive Summary

This document outlines the comprehensive integration of ProjectDiscovery's **httpx** HTTP probing tool into PEEK's scan pipeline. httpx provides fast, multi-purpose HTTP probing with technology fingerprinting capabilities that significantly enhances PEEK's HTTP reconnaissance and vulnerability scanning accuracy.

**Key Value Proposition:**
- Rich HTTP metadata collection before vulnerability scanning
- Technology fingerprinting to enhance nuclei template selection
- Validation of actual HTTP services vs. port-based assumptions
- CDN/WAF detection for context in reports

---

## Implementation Notes

The httpx integration was completed in December 2024 with the following outcomes:

| Aspect | Details |
|--------|---------|
| **httpx Version** | v1.6.0 installed in celery container |
| **Pipeline Position** | Phase 3 of 9 (after nmap service detection, before SSH-audit) |
| **Progress Range** | 75% → 80% |
| **Technology Mappings** | 62 technology-to-nuclei-tag mappings added |
| **Config Options** | `enable_httpx`, `httpx_timeout`, `httpx_tech_detect` |
| **Frontend** | HttpxSection component with collapsible cards |
| **Reports** | HTML, Technical PDF, and Executive PDF all include HTTP Probes |

**Files Created:**
- `backend/app/models/httpx_result.py` - Data model
- `backend/app/tools/httpx.py` - Tool wrapper
- `backend/app/parsers/httpx_parser.py` - Output parser
- `backend/app/schemas/httpx.py` - Pydantic response schema
- `frontend/src/components/HttpxSection.tsx` - UI component

**Files Modified:**
- `backend/app/tasks/scan_tasks.py` - Pipeline integration
- `backend/config/nuclei_profiles.yaml` - Technology tag mappings
- `backend/app/services/service_profile.py` - Technology parameter
- `backend/app/services/report_service.py` - Report sections
- `backend/Dockerfile.celery` - httpx installation

---

## 1. What is httpx?

httpx is a fast, multi-purpose HTTP toolkit from ProjectDiscovery (same team as nuclei) that:

- Probes HTTP endpoints for status codes, titles, headers
- Detects technologies using Wappalyzer fingerprints
- Identifies CDNs, WAFs, and load balancers
- Captures TLS/SSL information and JARM fingerprints
- Follows redirects and maps redirect chains
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

### Previous Pipeline (8 phases)

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

### Current Pipeline (9 phases)

```
1. Port Discovery (nmap-discovery)     0% -> 10%
2. Nmap Service Detection             10% -> 75%
3. httpx HTTP Probing                 75% -> 80%
4. SSH-Audit                          80% -> 85%
5. Nuclei                             85% -> 92%
6. NSE Scripts                        92% -> 95%
7. SSLScan                            95% -> 97%
8. Nikto                              97% -> 98%
9. ZAP                                98% -> 100%
```

### Rationale for Placement

httpx runs **after nmap service detection** and **before nuclei** because:

1. **Technology Enhancement**: httpx technology detection adds targeted tags to nuclei scanning
2. **HTTP Validation**: Confirms which ports actually serve HTTP (vs. nmap guessing from port numbers)
3. **Minimal Latency**: httpx is very fast (seconds per host), adding minimal overhead
4. **Report Enrichment**: Provides HTTP metadata even if no vulnerabilities are found

---

## 3. Data Model

### Model: HttpxResult

Located at `backend/app/models/httpx_result.py`:

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

    # Connection Status
    connection_failed = Column(Boolean, default=False, nullable=False)
    failure_reason = Column(String, nullable=True)

    # Relationships
    port_record = relationship("Port", back_populates="httpx_results")
    tool_execution = relationship("ToolExecution")
```

### Port Model Update

Relationship added to `backend/app/models/port.py`:

```python
# In Port class
httpx_results = relationship("HttpxResult", back_populates="port_record", cascade="all, delete-orphan")
```

---

## 4. Tool Wrapper

Located at `backend/app/tools/httpx.py`:

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
    jarm: bool = True
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

Located at `backend/app/parsers/httpx_parser.py`:

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

### Added to scan_tasks.py

```python
# Imports added
from ..tools.httpx import run_httpx, check_httpx_available
from ..parsers.httpx_parser import create_httpx_result_from_output
from ..models.httpx_result import HttpxResult

# In run_scan() function, after nmap phase:

            # Phase 3: httpx HTTP Probing (75% -> 80%)
            if config.enable_httpx:
                scan.current_phase = ScanPhase.HTTPX.value
                db.commit()
                self.update_state(state='PROGRESS', meta={'phase': 'httpx', 'progress': 0.75})
                run_httpx_phase(db, scan, targets, config)
```

### ScanPhase Enum

Updated in `backend/app/models/scan.py`:

```python
class ScanPhase(str, Enum):
    PENDING = "pending"
    NMAP_DISCOVERY = "nmap_discovery"
    NMAP = "nmap"
    HTTPX = "httpx"  # Added
    SSH_AUDIT = "ssh_audit"
    NUCLEI = "nuclei"
    NSE = "nse"
    SSLSCAN = "sslscan"
    NIKTO = "nikto"
    ZAP = "zap"
    COMPLETED = "completed"
    FAILED = "failed"
```

### ScanConfig Fields

Added to `backend/app/models/scan_config.py`:

```python
# httpx options
enable_httpx = Column(Boolean, default=True, nullable=False)
httpx_timeout = Column(Integer, default=30, nullable=False)  # seconds
httpx_tech_detect = Column(Boolean, default=True, nullable=False)
```

---

## 7. Nuclei Enhancement

### Technology-to-Tag Mapping

Added to `backend/config/nuclei_profiles.yaml` (62 mappings):

```yaml
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

  # And 40+ more...
```

### service_profile.py Update

Added technology parameter to `get_nuclei_profile()`:

```python
def get_nuclei_profile(
    service_name: Optional[str],
    product: Optional[str] = None,
    version: Optional[str] = None,
    extra_info: Optional[dict] = None,
    port: Optional[int] = None,
    scan_mode: str = "deep",
    technologies: Optional[List[str]] = None  # From httpx
) -> NucleiProfile:
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
```

---

## 8. API Endpoints

### Endpoint Added to routers/scans.py

```python
@router.get("/{scan_id}/httpx-results", response_model=List[HttpxResultResponse])
async def get_httpx_results(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get all httpx probe results for a scan."""
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

### API Client (frontend/src/api/scans.ts)

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

### Component (frontend/src/components/HttpxSection.tsx)

A collapsible section component that displays:
- Status code with color coding (2xx green, 3xx blue, 4xx orange, 5xx red)
- Page title and web server
- Detected technologies as badges
- CDN/WAF/TLS information
- Response time
- Expandable details with redirect chains and JARM hash

---

## 10. Docker Configuration

### Dockerfile.celery

httpx v1.6.0 installed via:

```dockerfile
# Install httpx (HTTP prober from ProjectDiscovery)
ARG HTTPX_VERSION=1.6.0
RUN wget -q https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_amd64.zip -O /tmp/httpx.zip && \
    unzip -o /tmp/httpx.zip -d /tmp/httpx_extract && \
    mv /tmp/httpx_extract/httpx /usr/local/bin/ && \
    chmod +x /usr/local/bin/httpx && \
    rm -rf /tmp/httpx.zip /tmp/httpx_extract
```

### Settings (core/config.py)

```python
HTTPX_PATH: str = Field(default="httpx", env="HTTPX_PATH")
```

---

## 11. Implementation Checklist

### Phase 1: Core Infrastructure
- [x] Create `backend/app/models/httpx_result.py`
- [x] Update `backend/app/models/__init__.py`
- [x] Update `backend/app/models/port.py` with relationship
- [x] Create database table (via SQLite ALTER TABLE)
- [x] Create `backend/app/tools/httpx.py`
- [x] Create `backend/app/parsers/httpx_parser.py`

### Phase 2: Pipeline Integration
- [x] Update `backend/app/models/scan.py` (ScanPhase.HTTPX)
- [x] Update `backend/app/models/scan_config.py` (enable_httpx, etc.)
- [x] Update `backend/app/tasks/scan_tasks.py` (run_httpx_phase)
- [x] Update progress percentages for all phases

### Phase 3: Nuclei Enhancement
- [x] Update `backend/config/nuclei_profiles.yaml` (technology_tags)
- [x] Update `backend/app/services/service_profile.py` (technologies param)
- [x] Update nuclei phase to pass technologies from httpx

### Phase 4: API Layer
- [x] Create `backend/app/schemas/httpx.py`
- [x] Update `backend/app/routers/scans.py` (new endpoint)

### Phase 5: Frontend
- [x] Update `frontend/src/api/scans.ts` (types, API method)
- [x] Create `frontend/src/components/HttpxSection.tsx`
- [x] Update `frontend/src/pages/ScanDetail.tsx`

### Phase 6: Reports
- [x] Update `backend/app/services/report_service.py` (HTTP Probes section)

### Phase 7: Docker
- [x] Update `backend/Dockerfile.celery` (install httpx)
- [x] Update `backend/app/core/config.py` (HTTPX_PATH)

---

## 12. Success Criteria

All criteria met:

1. **Functional**: httpx phase runs after nmap, before nuclei
2. **Data**: HttpxResult records created with technology detection
3. **Enhancement**: Detected technologies enhance nuclei tag selection
4. **UI**: HTTP probes displayed in scan detail page
5. **Reports**: HTTP probe section in PDF/HTML reports
6. **Graceful Degradation**: If httpx unavailable, phase skips without failing scan

---

## 13. Risks and Mitigations

| Risk | Mitigation | Status |
|------|------------|--------|
| httpx not installed | Check availability, skip phase gracefully | Implemented |
| Rate limiting by CDN/WAF | Use configurable timeout and respect rate limits | Configurable |
| Large scan delays | Process sequentially (SQLite constraint), httpx is fast | Acceptable |
| Technology detection false positives | Technologies are additive hints, not authoritative | By design |

---

## 14. Future Enhancements

1. **Screenshot Capture**: Add screenshot support with `-screenshot` flag and gallery view in reports
2. **Virtual Host Discovery**: Use httpx vhost brute-forcing
3. **Technology Trend Analysis**: Track tech changes across runs
4. **WAF Detection Enhancement**: Inform scanning strategy based on WAF presence
5. **Batch Mode**: Use httpx's list input for better performance on large scans

---

## Validation Results

End-to-end validation performed December 2024:

| Test | Result |
|------|--------|
| httpx version | v1.6.0 installed |
| Database schema | httpx_results table exists, scan_configs has httpx columns |
| Test scan | Completed successfully against internal Docker service |
| HttpxResult records | 1 record created (status=404, tech=[Python, Uvicorn]) |
| API endpoint | GET /api/scans/{id}/httpx-results returns results |
| Frontend | HTTP Probes section displays correctly |
| HTML report | Contains "HTTP Probes" section with table |
| Technical PDF | Valid PDF generated (5,906 bytes) |
| Executive PDF | Valid PDF generated (3,133 bytes) |
| Config toggle | enable_httpx=false results in 0 httpx results |

**Test Target**: peek-backend-1:8000 (FastAPI backend inside Docker network)

**Technologies Detected**: Python, Uvicorn

**Celery Log Output**:
```
Running httpx: httpx -u http://peek-backend-1:8000 -json -silent -nc -timeout 30 ...
httpx completed for http://peek-backend-1:8000
Created HttpxResult for port 8000: status=404, techs=['Python', 'Uvicorn']
httpx complete: 1 ports probed
```
