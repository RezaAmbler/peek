# Tool Documentation

PEEK v2.2.1 integrates 11 external security tools. Each tool has a wrapper in `backend/app/tools/` and a parser in `backend/app/parsers/`.

## Tool Index

| Tool | Purpose | Phase | Config Toggle | Documentation |
|------|---------|-------|---------------|---------------|
| [Nmap](nmap.md) | Port discovery & service detection | 1, 2 | Always on | [nmap.md](nmap.md) |
| [httpx](httpx.md) | HTTP probing & tech detection | 3 | `enable_httpx` | [httpx.md](httpx.md) |
| [Katana](katana.md) | Web endpoint discovery | 3.5 | `enable_katana` | [katana.md](katana.md) |
| [ssh-audit](ssh-audit.md) | SSH security analysis | 4 | `enable_ssh_audit` | [ssh-audit.md](ssh-audit.md) |
| [Nuclei](nuclei.md) | Vulnerability scanning | 5, 5.5 | `enable_nuclei`, `enable_nuclei_endpoints` | [nuclei.md](nuclei.md) |
| [Nmap NSE](nmap-nse.md) | Service-specific scripts | 6 | `enable_nse` | [nmap-nse.md](nmap-nse.md) |
| [sslscan](sslscan.md) | Quick TLS analysis | 7 | `enable_sslscan` | [sslscan.md](sslscan.md) |
| [testssl.sh](testssl.md) | Deep TLS analysis | 7.5 | `enable_testssl` | [testssl.md](testssl.md) |
| [Nikto](nikto.md) | Web server scanning | 8 | `enable_nikto` | [nikto.md](nikto.md) |
| [OWASP ZAP](zap.md) | Web application security | 9 | `enable_zap` | [zap.md](zap.md) |
| [masscan](masscan.md) | Fast port discovery (legacy) | - | Replaced by Nmap | [masscan.md](masscan.md) |

## Tool Categories

### Discovery Tools
- **Nmap**: Port and service discovery
- **httpx**: HTTP service probing
- **Katana**: Web endpoint crawling

### Vulnerability Scanners
- **Nuclei**: Template-based vulnerability detection
- **Nikto**: Web server vulnerabilities
- **OWASP ZAP**: Web application security testing

### Protocol Analyzers
- **ssh-audit**: SSH protocol security
- **sslscan**: SSL/TLS quick scan
- **testssl.sh**: Comprehensive TLS analysis
- **Nmap NSE**: Service-specific scripting

## Installation

All tools must be installed in the Celery worker environment. The Docker setup includes all tools.

For local development:

```bash
# Nmap
apt-get install nmap

# ProjectDiscovery tools (httpx, nuclei, katana)
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

# SSH audit
pip install ssh-audit

# SSL tools
apt-get install sslscan
git clone https://github.com/drwetter/testssl.sh.git

# Web scanners
apt-get install nikto
# ZAP runs as Docker container
```

## Common Patterns

All tool wrappers follow these patterns:

1. **Input validation**: Validate IPs/hostnames before subprocess execution
2. **Temp file output**: Write tool output to temp files, parse, then cleanup
3. **Timeout handling**: Respect configured timeouts with subprocess.run
4. **Return tuple**: `(success: bool, raw_output: str, error: Optional[str])`
5. **ToolExecution recording**: Create database records with command line and output

## Related Documentation

- [Scan Lifecycle](../scan-lifecycle.md) - How tools fit into the 12-phase pipeline
- [Backend Architecture](../backend.md) - Tool wrapper and parser organization
- [Extending Scanners](../extending-scanners.md) - Adding new tools
