# Nmap

Nmap (Network Mapper) is used for port discovery and service detection in Phases 1 and 2.

## Phases

| Phase | Purpose | Function |
|-------|---------|----------|
| 1 | Port Discovery | `run_nmap_discovery()` - Find open ports |
| 2 | Service Detection | `run_nmap()` - Identify services on open ports |

## Wrapper Location

`backend/app/tools/nmap.py`

## Parser Location

- `backend/app/parsers/nmap_discovery_parser.py` - Phase 1 parsing
- `backend/app/parsers/nmap_parser.py` - Phase 2 parsing

## Functions

### run_nmap_discovery()

Discovers open ports on a target using TCP connect scan.

```python
def run_nmap_discovery(
    ip: str,
    timing_template: str = "T4",
    timeout: int = 600,
    top_ports: Optional[int] = None,  # Deprecated
    additional_ports: Optional[str] = None,
    full_scan: bool = False
) -> Tuple[bool, str, Optional[str]]
```

**Default Behavior**: Scans top 100 TCP ports from `NMAP_TOP_100_PORTS` list.

**Command Pattern**:
```bash
nmap -Pn -sT -T4 --open --max-retries 2 --host-timeout 600s -p <ports> -oX output.xml <target>
```

### run_nmap()

Runs service version detection on discovered ports.

```python
def run_nmap(
    ip: str,
    ports: List[int],
    nmap_args: List[str],
    timeout: int = 600
) -> Tuple[bool, str, Optional[str]]
```

**Command Pattern**:
```bash
nmap -sT -sV -sC -T2 -Pn -p <ports> -oX output.xml <target>
```

## Configuration Options

| Setting | Description | Default |
|---------|-------------|---------|
| `nmap_args` | Custom nmap arguments | `["-sT", "-sV", "-sC", "-T2", "-Pn"]` |
| `discovery_top_ports` | Number of top ports (deprecated) | 100 |
| `additional_ports` | Extra ports to scan | None |

## Output Format

Nmap outputs XML which is parsed into Port records:

```python
{
    "port": 22,
    "protocol": "tcp",
    "state": "open",
    "service_name": "ssh",
    "product": "OpenSSH",
    "version": "8.2p1 Ubuntu 4ubuntu0.5",
    "extra_info": {"scripts": {...}}
}
```

## Top 100 Ports

The discovery phase scans these ports by default:

```
7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465,
513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995,
1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900,
2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899,
5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800,
5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443,
8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156
```

## Security Notes

- Input validation prevents command injection via `validate_target()` and `validate_port_list()`
- Uses `-sT` (TCP connect) instead of `-sS` (SYN scan) for Docker compatibility
- Sudo required for raw socket operations

## Related

- [Nmap NSE](nmap-nse.md) - Nmap Scripting Engine for advanced checks
- [Scan Lifecycle](../scan-lifecycle.md) - Phases 1 and 2 details

## Privileges and failure handling

- nmap is never run through `sudo`. The worker runs as the unprivileged `peek` user;
  the image grants `/usr/local/bin/nmap` the `cap_net_raw` file capability.
- Connect scans (`-sT`, used by discovery and NSE) need no privileges. For raw-socket
  scan types in `nmap_args` (`-sS`, `-sU`, `-O`, ...) the runner adds `--privileged` so
  nmap uses the capability. If the capability is missing (e.g. `cap_drop: [ALL]`),
  nmap exits non-zero and the run is recorded as failed.
- Any non-zero exit, timeout or empty XML is a failed `ToolExecution` with the stderr
  excerpt in `error_message`; the target is marked `failed` when discovery fails, never
  "0 open ports".

## Allowed `nmap_args`

`nmap_args` comes from a user-editable scan config and is passed to nmap's command line,
so it is checked against an allow-list (`validate_nmap_args` in
`backend/app/core/validators.py`) both by the API (create and update) and again by the
runner:

- Flags: `-sS -sT -sU -sA -sW -sM -sN -sF -sX`, `-sV -sC -O -A`, `--version-light`,
  `--version-all`, `--osscan-limit`, `--osscan-guess`, `-Pn -n -R -6`, `-T0`…`-T5`,
  `-v -vv -d`, `--open`, `--reason`, `--defeat-rst-ratelimit`
- Options with a numeric/time value: `--version-intensity`, `--max-retries`,
  `--min-rate`, `--max-rate`, `--min/max-parallelism`, `--min/max-hostgroup`,
  `--host-timeout`, `--script-timeout`, `--scan-delay`, `--max-scan-delay`,
  `--min/max/initial-rtt-timeout`

Everything else is rejected, in particular options that read or write files or load
code: `-oN/-oX/-oG/-oA`, `-iL`, `--script*`, `--datadir`, `--resume`, `--stylesheet`,
`--excludefile`. Use `-sC` and the NSE profiles in `backend/config/nse_profiles.yaml`
for scripts. `-p…` is ignored because PEEK sets the port list itself. A stored config
with a disallowed argument makes the nmap run fail with a validation error on its
`ToolExecution`; edit the config to fix it.
