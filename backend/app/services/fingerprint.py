"""
Stable Finding Fingerprints for SOC-grade Comparison.

Scan tooling (ZAP/Nuclei/Nikto) is non-deterministic: crawlers hit different
surfaces run-to-run, RPC services (mountd, nlockmgr, ...) register on random high
ports that change every reboot, and URLs carry volatile query params / session
tokens. A naive "ip:template_id:port" key therefore makes the SAME logical finding
look new+fixed across runs, which misleads the flagship comparison feature.

This module derives a *stable* sha256 fingerprint for a finding that survives that
noise, by:
  - lowercasing the host,
  - keying on the CVE / template id (the actual vulnerability identity),
  - collapsing ephemeral / RPC ports to a stable sentinel (see normalize_port),
  - reducing the matched-at URL to just its normalized path (dropping the volatile
    query string, fragment, scheme and port).
"""

import hashlib
from typing import Optional

from .url_normalizer import normalize_url


# --- Ephemeral port ranges ---------------------------------------------------
# Named constants (not magic numbers) so the churn policy is auditable.
#
# Linux default local port range (net.ipv4.ip_local_port_range). Outbound sockets
# and dynamically-registered RPC services land here and rotate on every reboot.
LINUX_EPHEMERAL_PORT_MIN = 32768
LINUX_EPHEMERAL_PORT_MAX = 60999

# IANA / RFC 6335 dynamic (a.k.a. private/ephemeral) port range. Windows and many
# other stacks allocate transient ports from here.
IANA_EPHEMERAL_PORT_MIN = 49152
IANA_EPHEMERAL_PORT_MAX = 65535

# First non-well-known port. RPC-ish services below this (e.g. rpcbind on 111) are
# stable and must NOT be collapsed.
REGISTERED_PORT_MIN = 1024

# SunRPC-registered services that bind to random high ports assigned by rpcbind.
# These are the classic churn generators seen in QA (mountd:49163, nlockmgr:44971).
EPHEMERAL_RPC_SERVICES = frozenset({
    "mountd",
    "nlockmgr",
    "status",
    "rpcbind",  # only collapsed when it appears on a dynamic port (see below)
})


def _in_ephemeral_range(port: int) -> bool:
    """True if the raw port sits in a known ephemeral/dynamic allocation range."""
    if LINUX_EPHEMERAL_PORT_MIN <= port <= LINUX_EPHEMERAL_PORT_MAX:
        return True
    if IANA_EPHEMERAL_PORT_MIN <= port <= IANA_EPHEMERAL_PORT_MAX:
        return True
    return False


def normalize_port(port: Optional[int], service_name: Optional[str] = None) -> str:
    """
    Collapse ephemeral / RPC ports to a stable sentinel so reboots don't churn diffs.

    - RPC-ish services (mountd, nlockmgr, status, rpcbind) on a non-well-known port
      collapse to ``ephemeral:<service_name>`` regardless of the exact number, since
      the RPC portmapper hands them a fresh random port each reboot.
    - Any port inside the Linux (32768-60999) or IANA (49152-65535) dynamic ranges
      collapses to ``ephemeral:<service_name or 'dyn'>``.
    - Every other (well-known / registered) port passes through unchanged as its
      string form.

    Returns a string so callers can use it directly in a composite key.
    """
    if port is None:
        return "none"

    svc = (service_name or "").strip().lower()

    # RPC services register on random high ports; collapse them by service identity
    # (but leave e.g. rpcbind on its fixed 111 alone).
    if svc in EPHEMERAL_RPC_SERVICES and port >= REGISTERED_PORT_MIN:
        return f"ephemeral:{svc}"

    if _in_ephemeral_range(port):
        return f"ephemeral:{svc or 'dyn'}"

    return str(port)


def _normalize_path(matched_at: Optional[str]) -> str:
    """
    Reduce a matched-at URL to a stable, comparable path.

    Drops volatile bits (scheme, host:port, query string with random params /
    session tokens, and fragment) and keeps only the normalized path. Uses the
    shared url_normalizer so behaviour matches endpoint dedup elsewhere.
    """
    if not matched_at:
        return "/"
    try:
        _, components = normalize_url(matched_at)
    except Exception:
        # Never let a malformed URL break fingerprinting.
        return matched_at.strip().lower()
    return components.get("path") or "/"


def _normalize_host(host: Optional[str]) -> str:
    """Lowercase/strip the host or IP."""
    return (host or "").strip().lower()


def finding_fingerprint(
    host: Optional[str],
    template_id: Optional[str] = None,
    port: Optional[int] = None,
    matched_at: Optional[str] = None,
    cve_id: Optional[str] = None,
    service_name: Optional[str] = None,
) -> str:
    """
    Compute a stable sha256 hex fingerprint for a finding.

    Formula (pipe-delimited, then sha256):
        normalized_host | (cve_id or template_id) | normalized_port | normalized_path

    Volatile inputs are deliberately EXCLUDED: timestamps, session tokens, random
    query params (dropped with the query string), and ephemeral/RPC ports
    (collapsed via normalize_port). The result is identical across re-detections of
    the same logical finding even when the crawler hits a different URL or the RPC
    port rotates after a reboot.
    """
    identity = (cve_id or template_id or "").strip().lower()
    parts = [
        _normalize_host(host),
        identity,
        normalize_port(port, service_name),
        _normalize_path(matched_at),
    ]
    raw = "|".join(parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
