"""OWASP ZAP integration for web application scanning."""
import requests
import time
import json
import logging
from typing import Tuple, Optional, List, Dict, Any

logger = logging.getLogger(__name__)

# ZAP API base URL - use Docker service name
ZAP_API_BASE = "http://zap:8080"


def wait_for_zap(timeout: int = 60) -> bool:
    """Wait for ZAP to be ready."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            resp = requests.get(f"{ZAP_API_BASE}/JSON/core/view/version/", timeout=5)
            if resp.status_code == 200:
                version = resp.json().get('version', 'unknown')
                logger.info(f"ZAP ready, version: {version}")
                return True
        except requests.RequestException:
            pass
        time.sleep(2)
    logger.warning(f"ZAP not ready after {timeout}s")
    return False


def run_zap_baseline(
    target_url: str,
    timeout: int = 300,
    spider_timeout: int = 60
) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Run ZAP baseline scan (spider + passive scan).

    Args:
        target_url: Full URL to scan (e.g., http://44.211.84.221:80)
        timeout: Total scan timeout in seconds
        spider_timeout: Spider phase timeout

    Returns:
        Tuple of (success, alerts_json, error_message)
    """
    try:
        # Check ZAP is ready
        if not wait_for_zap(timeout=30):
            return False, None, "ZAP not available"

        logger.info(f"Starting ZAP baseline scan of {target_url}")

        # Start spider
        try:
            spider_resp = requests.get(
                f"{ZAP_API_BASE}/JSON/spider/action/scan/",
                params={"url": target_url, "maxChildren": 10},
                timeout=30
            )
            spider_data = spider_resp.json()
            spider_id = spider_data.get("scan")
            logger.info(f"Spider started: {spider_id}")
        except Exception as e:
            logger.warning(f"Spider start failed: {e}, continuing with alerts")
            spider_id = None

        # Wait for spider to complete (if started)
        if spider_id:
            spider_start = time.time()
            while time.time() - spider_start < spider_timeout:
                try:
                    status_resp = requests.get(
                        f"{ZAP_API_BASE}/JSON/spider/view/status/",
                        params={"scanId": spider_id},
                        timeout=10
                    )
                    status = int(status_resp.json().get("status", 0))
                    if status >= 100:
                        logger.info("Spider complete")
                        break
                except Exception:
                    pass
                time.sleep(2)

        # Wait for passive scan to process
        logger.info("Waiting for passive scan...")
        time.sleep(5)

        # Get alerts
        alerts_resp = requests.get(
            f"{ZAP_API_BASE}/JSON/core/view/alerts/",
            params={"baseurl": target_url},
            timeout=30
        )

        alerts_json = alerts_resp.text
        alerts_data = alerts_resp.json()
        alert_count = len(alerts_data.get("alerts", []))
        logger.info(f"ZAP found {alert_count} alerts for {target_url}")

        return True, alerts_json, None

    except requests.RequestException as e:
        logger.error(f"ZAP API error: {e}")
        return False, None, str(e)
    except Exception as e:
        logger.error(f"ZAP scan error: {e}")
        return False, None, str(e)


def parse_zap_alerts(alerts_json: str) -> List[Dict[str, Any]]:
    """
    Parse ZAP alerts JSON into normalized findings.

    Args:
        alerts_json: Raw JSON string from ZAP alerts API

    Returns:
        List of normalized finding dictionaries
    """
    if not alerts_json:
        return []

    try:
        data = json.loads(alerts_json)
        alerts = data.get("alerts", [])
    except json.JSONDecodeError as e:
        logger.warning(f"Failed to parse ZAP alerts: {e}")
        return []

    findings = []
    for alert in alerts:
        # Map ZAP risk to severity
        risk = alert.get("risk", "Informational")
        severity_map = {
            "High": "high",
            "Medium": "medium",
            "Low": "low",
            "Informational": "info"
        }
        severity = severity_map.get(risk, "info")

        finding = {
            "alert_id": alert.get("pluginId", "unknown"),
            "name": alert.get("alert", alert.get("name", "Unknown")),
            "severity": severity,
            "confidence": alert.get("confidence", "Medium"),
            "url": alert.get("url", ""),
            "method": alert.get("method", "GET"),
            "param": alert.get("param", ""),
            "attack": alert.get("attack", ""),
            "evidence": alert.get("evidence", ""),
            "description": alert.get("description", ""),
            "solution": alert.get("solution", ""),
            "reference": alert.get("reference", ""),
            "cwe": alert.get("cweid", ""),
            "wasc": alert.get("wascid", ""),
            "tags": alert.get("tags", {}),
        }
        findings.append(finding)

    logger.info(f"Parsed {len(findings)} ZAP findings")
    return findings


def check_zap_available() -> bool:
    """Check if ZAP container is available and responding."""
    try:
        resp = requests.get(f"{ZAP_API_BASE}/JSON/core/view/version/", timeout=5)
        return resp.status_code == 200
    except Exception:
        return False
