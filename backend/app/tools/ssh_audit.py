import subprocess
import json
from typing import Tuple, Optional
from ..core.config import settings

def run_ssh_audit(
    ip: str,
    port: int = 22,
    timeout: int = 60
) -> Tuple[bool, str, Optional[str]]:
    """
    Execute ssh-audit for SSH security assessment.

    Args:
        ip: Target IP address
        port: SSH port (default 22)
        timeout: Max execution time in seconds

    Returns:
        (success: bool, raw_json: str, error: Optional[str])
    """
    try:
        # Build command
        cmd = [
            settings.SSH_AUDIT_PATH or 'ssh-audit',
            '-j',  # JSON output
            '-p', str(port),
            ip
        ]

        # Execute
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        # ssh-audit returns non-zero if issues found, but output is still valid
        raw_json = result.stdout

        if not raw_json.strip():
            # Empty output or connection failed
            error_msg = result.stderr or "No output from ssh-audit"
            return False, "", error_msg

        # Try to parse to verify it's valid JSON
        try:
            json.loads(raw_json)
        except json.JSONDecodeError:
            return False, raw_json, "Invalid JSON output from ssh-audit"

        return True, raw_json, None

    except subprocess.TimeoutExpired:
        return False, "", f"ssh-audit timed out after {timeout} seconds"
    except FileNotFoundError:
        return False, "", "ssh-audit not found. Install with: pip install ssh-audit"
    except Exception as e:
        return False, "", f"ssh-audit execution failed: {str(e)}"

def parse_ssh_audit_output(raw_json: str) -> dict:
    """
    Parse ssh-audit JSON output into structured data.

    Returns:
    {
        "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
        "ssh_version": "2.0",
        "key_exchange": ["diffie-hellman-group14-sha256", ...],
        "host_keys": ["ssh-rsa", "ssh-ed25519"],
        "encryption": ["aes128-ctr", "aes256-gcm@openssh.com"],
        "mac": ["hmac-sha2-256", "hmac-sha2-512"],
        "compression": ["none"],
        "vulnerabilities": [
            {"severity": "critical", "description": "CVE-2023-XXXX", "cve": "CVE-2023-XXXX"}
        ],
        "recommendations": [
            {"action": "remove", "item": "weak-cipher", "reason": "Uses CBC mode"}
        ]
    }
    """
    try:
        data = json.loads(raw_json)

        result = {
            "banner": data.get("banner", {}).get("raw"),
            "ssh_version": data.get("banner", {}).get("protocol"),
            "key_exchange": [],
            "host_keys": [],
            "encryption": [],
            "mac": [],
            "compression": [],
            "vulnerabilities": [],
            "recommendations": []
        }

        # Extract algorithms (each is an array of objects with "algorithm" and "notes")
        # Key exchange algorithms
        kex_list = data.get("kex", [])
        result["key_exchange"] = [item.get("algorithm") for item in kex_list if isinstance(item, dict)]

        # Host key algorithms
        key_list = data.get("key", [])
        result["host_keys"] = [item.get("algorithm") for item in key_list if isinstance(item, dict)]

        # Encryption algorithms
        enc_list = data.get("enc", [])
        result["encryption"] = [item.get("algorithm") for item in enc_list if isinstance(item, dict)]

        # MAC algorithms
        mac_list = data.get("mac", [])
        result["mac"] = [item.get("algorithm") for item in mac_list if isinstance(item, dict)]

        # Compression (simple list of strings)
        result["compression"] = data.get("compression", [])

        # Extract vulnerabilities/CVEs
        cves = data.get("cves", [])
        for cve in cves:
            result["vulnerabilities"].append({
                "severity": "critical",  # ssh-audit marks CVEs as critical
                "description": cve.get("description", "Unknown CVE"),
                "cve": cve.get("name", "")
            })

        # Extract recommendations from nested structure
        # Format: {severity: {action: {category: [{name, notes}]}}}
        recommendations = data.get("recommendations", {})
        for severity, actions in recommendations.items():  # 'critical', 'warning'
            if not isinstance(actions, dict):
                continue
            for action, categories in actions.items():  # 'del', 'chg', 'add'
                if not isinstance(categories, dict):
                    continue
                for category, items in categories.items():  # 'kex', 'enc', 'key', 'mac'
                    if not isinstance(items, list):
                        continue
                    for item in items:
                        if isinstance(item, dict):
                            result["recommendations"].append({
                                "action": action,
                                "item": f"{category}: {item.get('name', 'unknown')}"
                            })

        # Also extract algorithm warnings from notes (vulnerabilities without CVEs)
        for algo_list, algo_type in [
            (enc_list, "encryption"),
            (kex_list, "key-exchange"),
            (mac_list, "mac"),
            (key_list, "host-key")
        ]:
            for algo in algo_list:
                if not isinstance(algo, dict):
                    continue
                notes = algo.get("notes", {})
                if isinstance(notes, dict):
                    # Check for fail/warn messages
                    fail_notes = notes.get("fail", [])
                    warn_notes = notes.get("warn", [])

                    for note in fail_notes:
                        result["vulnerabilities"].append({
                            "severity": "critical",
                            "description": note,
                            "cve": None
                        })

                    for note in warn_notes:
                        result["vulnerabilities"].append({
                            "severity": "warning",
                            "description": note,
                            "cve": None
                        })

        return result

    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON from ssh-audit: {str(e)}")
    except Exception as e:
        raise ValueError(f"Failed to parse ssh-audit output: {str(e)}")
