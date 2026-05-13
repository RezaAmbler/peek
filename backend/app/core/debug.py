"""
Debug utilities for saving raw tool output during development.

When DEBUG=True, saves raw output from scanning tools to files for inspection.
Files are saved to DEBUG_OUTPUT_DIR (default: /app/data/debug inside container).
"""
import os
from pathlib import Path
from datetime import datetime
from typing import Optional
from .config import settings


def save_debug_output(
    tool_name: str,
    target: str,
    output: str,
    scan_id: Optional[str] = None,
    port: Optional[int] = None,
    suffix: str = ""
) -> Optional[str]:
    """
    Save raw tool output to a debug file when DEBUG mode is enabled.

    Args:
        tool_name: Name of the tool (nmap, nuclei, ssh-audit)
        target: Target IP or hostname
        output: Raw output from the tool
        scan_id: Optional scan ID for grouping
        port: Optional port number
        suffix: Optional suffix for filename (e.g., "discovery", "service")

    Returns:
        Path to saved file if DEBUG is True, None otherwise
    """
    if not settings.DEBUG:
        return None

    if not output or not output.strip():
        return None

    try:
        # Create debug directory structure
        debug_dir = Path(settings.DEBUG_OUTPUT_DIR)
        debug_dir.mkdir(parents=True, exist_ok=True)

        # Generate timestamp
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

        # Sanitize target for filename (replace dots and colons)
        safe_target = target.replace(".", "_").replace(":", "_").replace("/", "_")

        # Build filename
        parts = [tool_name, safe_target]
        if port:
            parts.append(f"port{port}")
        if suffix:
            parts.append(suffix)
        parts.append(timestamp)

        # Determine extension based on content
        if output.strip().startswith("<?xml") or output.strip().startswith("<"):
            ext = ".xml"
        elif output.strip().startswith("{") or output.strip().startswith("["):
            ext = ".json"
        else:
            ext = ".txt"

        filename = "_".join(parts) + ext

        # If scan_id provided, create subdirectory for it
        if scan_id:
            scan_dir = debug_dir / scan_id[:8]  # Use first 8 chars of scan ID
            scan_dir.mkdir(parents=True, exist_ok=True)
            filepath = scan_dir / filename
        else:
            filepath = debug_dir / filename

        # Write output
        filepath.write_text(output)

        return str(filepath)

    except Exception as e:
        # Don't let debug failures affect actual scanning
        print(f"[DEBUG] Failed to save debug output: {e}")
        return None


def save_nmap_debug(
    target: str,
    raw_xml: str,
    scan_id: Optional[str] = None,
    phase: str = "scan"
) -> Optional[str]:
    """Save nmap XML output for debugging."""
    return save_debug_output(
        tool_name="nmap",
        target=target,
        output=raw_xml,
        scan_id=scan_id,
        suffix=phase
    )


def save_nuclei_debug(
    target: str,
    raw_jsonl: str,
    scan_id: Optional[str] = None,
    port: Optional[int] = None
) -> Optional[str]:
    """Save nuclei JSONL output for debugging."""
    return save_debug_output(
        tool_name="nuclei",
        target=target,
        output=raw_jsonl,
        scan_id=scan_id,
        port=port
    )


def save_ssh_audit_debug(
    target: str,
    raw_json: str,
    scan_id: Optional[str] = None,
    port: int = 22
) -> Optional[str]:
    """Save ssh-audit JSON output for debugging."""
    return save_debug_output(
        tool_name="ssh-audit",
        target=target,
        output=raw_json,
        scan_id=scan_id,
        port=port
    )
