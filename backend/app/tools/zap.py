"""OWASP ZAP integration for web application scanning."""
import requests
import time
import json
import logging
from typing import List, Dict, Any

from .base import EXIT_NOT_RUN, EXIT_TIMEOUT, ToolResult

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
) -> ToolResult:
    """
    Run ZAP baseline scan (spider + passive scan).

    Args:
        target_url: Full URL to scan (e.g., http://203.0.113.10:80)
        timeout: Total scan timeout in seconds (caps the spider wait)
        spider_timeout: Spider phase timeout

    Returns:
        ToolResult, unpackable as (success, alerts_json, error_message).
        A spider that never started, a ZAP API error or a non-200 alerts
        response is a failure - never an empty "clean" alert list. A spider
        that did not finish in time is reported as success with a warning in
        ``error`` so the partial coverage is visible on the ToolExecution.
    """
    command_line = f"ZAP API {ZAP_API_BASE}: spider/action/scan url={target_url} maxChildren=10; core/view/alerts baseurl={target_url}"

    def result(success, alerts, error, timed_out=False):
        if success:
            exit_code = 0
        else:
            exit_code = EXIT_TIMEOUT if timed_out else EXIT_NOT_RUN
        return ToolResult(success, alerts, error, command_line=command_line,
                          exit_code=exit_code, timed_out=timed_out)

    try:
        # Check ZAP is ready
        if not wait_for_zap(timeout=30):
            return result(False, None, "ZAP not available")

        logger.info(f"Starting ZAP baseline scan of {target_url}")

        # Start spider
        try:
            spider_resp = requests.get(
                f"{ZAP_API_BASE}/JSON/spider/action/scan/",
                params={"url": target_url, "maxChildren": 10},
                timeout=30
            )
            spider_resp.raise_for_status()
            spider_data = spider_resp.json()
            spider_id = spider_data.get("scan")
        except Exception as e:
            logger.error(f"ZAP spider start failed: {e}")
            return result(False, None, f"ZAP spider failed to start: {e}")

        if spider_id is None:
            # ZAP answers 200 with an error object when it refuses the URL
            return result(False, None, f"ZAP spider did not start: {str(spider_data)[:300]}")

        logger.info(f"Spider started: {spider_id}")

        # Wait for spider to complete
        warning = None
        spider_done = False
        spider_start = time.time()
        status_check_failures = 0
        max_status_failures = 5
        spider_budget = min(spider_timeout, timeout) if timeout else spider_timeout
        while time.time() - spider_start < spider_budget:
            try:
                status_resp = requests.get(
                    f"{ZAP_API_BASE}/JSON/spider/view/status/",
                    params={"scanId": spider_id},
                    timeout=10
                )
                status = int(status_resp.json().get("status", 0))
                status_check_failures = 0  # Reset on success
                if status >= 100:
                    logger.info("Spider complete")
                    spider_done = True
                    break
            except Exception as e:
                status_check_failures += 1
                logger.warning(f"ZAP spider status check failed ({status_check_failures}/{max_status_failures}): {e}")
                if status_check_failures >= max_status_failures:
                    logger.error(f"ZAP spider status check failed {max_status_failures} times, aborting spider wait")
                    return result(False, None, f"ZAP spider status could not be read: {e}")
            time.sleep(2)

        if not spider_done:
            warning = f"ZAP spider did not finish within {spider_budget}s; alerts may be incomplete"
            logger.warning(warning)

        # Wait for passive scan to process
        logger.info("Waiting for passive scan...")
        time.sleep(5)

        # Get alerts
        alerts_resp = requests.get(
            f"{ZAP_API_BASE}/JSON/core/view/alerts/",
            params={"baseurl": target_url},
            timeout=30
        )
        alerts_resp.raise_for_status()

        alerts_json = alerts_resp.text
        alerts_data = alerts_resp.json()
        if not isinstance(alerts_data, dict) or "alerts" not in alerts_data:
            return result(False, alerts_json, f"Unexpected ZAP alerts response: {alerts_json[:300]}")

        alert_count = len(alerts_data.get("alerts", []))
        logger.info(f"ZAP found {alert_count} alerts for {target_url}")

        return result(True, alerts_json, warning)

    except requests.Timeout as e:
        logger.error(f"ZAP API timeout: {e}")
        return result(False, None, f"ZAP API timed out: {e}", timed_out=True)
    except requests.RequestException as e:
        logger.error(f"ZAP API error: {e}")
        return result(False, None, str(e))
    except Exception as e:
        logger.error(f"ZAP scan error: {e}")
        return result(False, None, str(e))


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
