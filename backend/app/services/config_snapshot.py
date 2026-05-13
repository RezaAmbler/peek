"""Capture a deterministic snapshot+hash of a ScanConfig at scan-creation time.

A scan's `config_snapshot` records the full set of comparable fields from the
ScanConfig at the moment the scan was created. The `config_hash` is a SHA256
of the canonical JSON serialization of that snapshot. Two scans are
comparable in the UI only if their config_hashes match — this is what makes
"compare with another scan" meaningful even when the underlying ScanConfig
is later edited.

Fields are partitioned into:

- COMPARABLE_CONFIG_FIELDS: affect what the scan does. Included in the hash.
- Everything else on ScanConfig (id, user_id, created_at, name, description,
  scheduling, reporting, notification toggles): metadata or out-of-band
  concerns. Excluded.

The full set of comparable fields is also written to `Scan.config_snapshot`
as a JSON dict, so the diagnostic question "what config did this scan
actually run with?" is answerable from the scan row alone.
"""
import hashlib
import json
from typing import Any, Tuple

from ..models.scan_config import ScanConfig

# Fields that affect scan behavior. Order doesn't matter for hashing
# (sort_keys=True) but is alphabetical for readability.
COMPARABLE_CONFIG_FIELDS: tuple[str, ...] = (
    "additional_ports",
    "discovery_top_ports",
    "enable_httpx",
    "enable_katana",
    "enable_nikto",
    "enable_nse",
    "enable_nuclei",
    "enable_nuclei_endpoints",
    "enable_ssh_audit",
    "enable_sslscan",
    "enable_testssl",
    "enable_zap",
    "global_tool_timeout_seconds",
    "host_timeout_seconds",
    "httpx_screenshot_timeout",
    "httpx_screenshots",
    "httpx_tech_detect",
    "httpx_timeout",
    "httpx_vhost_discovery",
    "katana_concurrency",
    "katana_max_depth",
    "katana_timeout",
    "masscan_interface",
    "masscan_rate",
    "masscan_timeout_percent",
    "max_concurrent_hosts",
    "max_concurrent_scans",
    "nikto_timeout",
    "nmap_args",
    "nmap_timeout_percent",
    "nuclei_endpoint_severity",
    "nuclei_endpoint_timeout",
    "nuclei_severity",
    "nuclei_templates",
    "nuclei_timeout",
    "parallelism_limit",
    "scan_mode",
    "ssh_ports",
    "target_urls",
    "targets",
    "testssl_timeout",
    "zap_scan_type",
    "zap_timeout",
)


def make_snapshot(config: ScanConfig) -> dict[str, Any]:
    """Extract the comparable fields from a ScanConfig as a plain dict.

    Lists are returned as-is (JSON-serializable). The dict can be stored on
    Scan.config_snapshot directly.
    """
    return {field: getattr(config, field) for field in COMPARABLE_CONFIG_FIELDS}


def canonical_json(snapshot: dict[str, Any]) -> str:
    """Serialize a snapshot deterministically for hashing.

    sort_keys=True is the load-bearing guarantee. separators removes optional
    whitespace. default=str defends against unexpected non-JSON-native types
    (none expected in the comparable subset, but cheap insurance).
    """
    return json.dumps(snapshot, sort_keys=True, separators=(",", ":"), default=str)


def compute_hash(snapshot: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(snapshot).encode("utf-8")).hexdigest()


def snapshot_config(config: ScanConfig) -> Tuple[dict[str, Any], str]:
    """One-shot helper: returns (snapshot_dict, hash_hex). Use from scan creation."""
    snapshot = make_snapshot(config)
    return snapshot, compute_hash(snapshot)
