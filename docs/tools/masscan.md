# masscan

masscan is a fast port scanner. **Note: This tool is legacy and has been replaced by Nmap discovery.**

## Status

**DEPRECATED** - PEEK v2.2.0+ uses Nmap for port discovery instead of masscan.

## Why Replaced

| Issue | Description |
|-------|-------------|
| Raw socket requirement | Needs `cap_net_raw` (file capability in the worker image; no root/sudo) |
| Docker compatibility | Needs host networking or special capabilities |
| Interface detection | Often fails to detect correct interface |
| Accuracy | Faster but less accurate than Nmap |

## Wrapper Location

`backend/app/tools/masscan.py`

## Parser Location

`backend/app/parsers/masscan_parser.py`

## Function

```python
def run_masscan(
    ip: str,
    rate: int = 1000,
    interface: Optional[str] = None,
    timeout: int = 240
) -> Tuple[bool, str, Optional[str]]
```

## Command Pattern

```bash
masscan <ip> -p0-65535 --rate=1000 \
     --output-format json --output-filename output.json \
     [--interface <iface>]
```

## Configuration Options (Legacy)

| Setting | Description | Default |
|---------|-------------|---------|
| `masscan_rate` | Packets per second | 1000 |
| `masscan_interface` | Network interface | Auto-detect |
| `masscan_timeout_percent` | Timeout multiplier | 100 |

## Output Format

```json
[
    {
        "ip": "192.168.1.1",
        "timestamp": "1234567890",
        "ports": [
            {"port": 22, "proto": "tcp", "status": "open"},
            {"port": 80, "proto": "tcp", "status": "open"}
        ]
    }
]
```

Parsed into:
```python
[
    {"port": 22, "protocol": "tcp", "state": "open"},
    {"port": 80, "protocol": "tcp", "state": "open"}
]
```

## Migration to Nmap

The current port discovery uses `run_nmap_discovery()`:

```python
# Old (masscan)
success, raw_json, error = run_masscan(ip, rate=1000)
ports = parse_masscan_output(raw_json)

# New (nmap)
success, raw_xml, error = run_nmap_discovery(ip, timing_template="T4")
ports = parse_nmap_discovery(raw_xml)
```

## When masscan Might Still Be Useful

- Scanning large IP ranges (Class B/C networks)
- Initial reconnaissance of many hosts
- When speed is critical and accuracy is less important

## Related

- [Nmap](nmap.md) - Current port discovery tool
- [Scan Lifecycle](../scan-lifecycle.md) - Phase 1 (Port Discovery)
