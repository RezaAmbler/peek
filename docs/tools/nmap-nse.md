# Nmap NSE

Nmap Scripting Engine (NSE) provides service-specific security checks in Phase 6.

## Phase

| Phase | Purpose |
|-------|---------|
| 6 | Run targeted NSE scripts against specific services |

## Wrapper Location

`backend/app/tools/nmap_nse.py`

## Parser Location

Parsing included in `nmap_nse.py`

## Functions

### run_nmap_nse()

Runs NSE scripts against a single port.

```python
def run_nmap_nse(
    ip: str,
    port: int,
    scripts: List[str],
    protocol: str = "tcp",
    timeout: int = 300
) -> Tuple[bool, str, Optional[str]]
```

### run_nmap_nse_batch()

Runs NSE scripts across multiple ports in one invocation.

```python
def run_nmap_nse_batch(
    ip: str,
    ports_scripts: List[Dict],
    timeout: int = 600
) -> Tuple[bool, str, Optional[str]]
```

## Command Pattern

```bash
nmap -Pn -sV -sT -p<port> --script=<scripts> -oX output.xml <ip>
```

For batch mode with mixed TCP/UDP:
```bash
nmap -Pn -sV -sT -sU -p T:22,80,U:53 --script=<scripts> -oX output.xml <ip>
```

## Configuration Options

| Setting | Description | Default |
|---------|-------------|---------|
| `enable_nse` | Enable NSE scripts | true |

## Script Selection

Scripts are selected based on service type from `nse_profiles.yaml`:

```yaml
service_profiles:
  rdp:
    scripts:
      - rdp-enum-encryption
      - rdp-ntlm-info
  smtp:
    scripts:
      - smtp-commands
      - smtp-ntlm-info
      - smtp-enum-users
  ftp:
    scripts:
      - ftp-anon
      - ftp-bounce
```

## Output Format

NSE scripts output XML with script elements:

```xml
<port protocol="tcp" portid="3389">
    <script id="rdp-enum-encryption" output="Security layer\n  CredSSP (NLA): SUCCESS">
        <elem key="Security layer">CredSSP (NLA): SUCCESS</elem>
        <table key="RDP Encryption level">
            <elem>High</elem>
        </table>
    </script>
</port>
```

Parsed into:

```python
{
    "port": 3389,
    "protocol": "tcp",
    "script_id": "rdp-enum-encryption",
    "output": "Security layer\n  CredSSP (NLA): SUCCESS",
    "elements": {
        "Security layer": "CredSSP (NLA): SUCCESS",
        "RDP Encryption level": ["High"]
    }
}
```

## Severity Determination

The `determine_nse_severity()` function infers severity from output:

| Severity | Patterns |
|----------|----------|
| Critical | NTP monlist vulnerable, anonymous access, Heartbleed |
| High | No encryption, DNS recursion enabled |
| Medium | SMTP user enumeration, weak settings |
| Low | NTLM info disclosure |
| Info | Default for informational output |

## Database Model

Results stored in `NseFinding`:

| Field | Type | Description |
|-------|------|-------------|
| `port` | Integer | Port number |
| `protocol` | String | tcp/udp |
| `script_id` | String | NSE script name |
| `output` | Text | Raw script output |
| `elements` | JSON | Parsed key-value data |
| `severity` | String | Inferred severity |

## Common Scripts by Service

### RDP (3389)
- `rdp-enum-encryption`: Check encryption levels
- `rdp-ntlm-info`: Extract domain/hostname info

### SMB (445)
- `smb-security-mode`: Check signing requirements
- `smb-enum-shares`: List accessible shares
- `smb2-security-mode`: SMB2 security settings

### SMTP (25, 587)
- `smtp-commands`: Supported commands
- `smtp-enum-users`: User enumeration
- `smtp-ntlm-info`: Domain info disclosure

### DNS (53)
- `dns-recursion`: Check open resolver
- `dns-zone-transfer`: Zone transfer attempt

### FTP (21)
- `ftp-anon`: Anonymous access
- `ftp-bounce`: FTP bounce attack

### NTP (123)
- `ntp-monlist`: Amplification vulnerability

## Element Parsing

The `_parse_script_elements()` function handles:

1. **Simple elements**: `<elem key="name">value</elem>`
2. **Anonymous elements**: `<elem>value</elem>`
3. **Tables with values**: `<table><elem>v1</elem><elem>v2</elem></table>`
4. **Tables with keys**: `<table><elem key="k">v</elem></table>`

## Batch Efficiency

`run_nmap_nse_batch()` combines multiple ports into one scan:
- Collects all unique scripts
- Builds port spec: `T:22,80,443,U:53`
- Single Nmap invocation
- Parses results by port

## Security Notes

- Uses `-sT` (TCP connect) for Docker compatibility
- `-sV` enables version detection (helps script targeting)
- No raw socket requirements
- Timeout per-scan, not per-script

## Related

- [Nmap](nmap.md) - Port discovery and service detection
- [Scan Lifecycle](../scan-lifecycle.md) - Phase 6 details
