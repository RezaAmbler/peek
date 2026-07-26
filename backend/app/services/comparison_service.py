from typing import List, Dict, Any
import logging
from sqlalchemy.orm import Session
from sqlalchemy import select, text
from ..models import Scan, ScanTarget, Port, Vulnerability, ScanComparison, SSHAudit, FindingState
from ..models.finding_state import SUPPRESSED_STATUSES
from .fingerprint import finding_fingerprint, normalize_port
import uuid
from datetime import datetime

logger = logging.getLogger(__name__)

class ComparisonService:
    """Service for comparing two scans and generating change reports"""

    def __init__(self, db: Session):
        self.db = db

    def compare_scans(
        self,
        baseline_scan_id: str,
        current_scan_id: str,
        user_id: str
    ) -> ScanComparison:
        """
        Compare two scans and generate a comparison report.

        Returns ScanComparison object with detailed changes.
        """
        # Load scans
        baseline = self.db.query(Scan).filter(Scan.id == baseline_scan_id).first()
        current = self.db.query(Scan).filter(Scan.id == current_scan_id).first()

        if not baseline or not current:
            raise ValueError("One or both scans not found")

        # Initialize comparison with explicit defaults
        comparison = ScanComparison(
            id=str(uuid.uuid4()),
            baseline_scan_id=baseline_scan_id,
            current_scan_id=current_scan_id,
            created_by_id=user_id,
            changes=[],
            total_changes=0,
            new_ports=0,
            closed_ports=0,
            version_changes=0,
            new_vulnerabilities=0,
            fixed_vulnerabilities=0,
            critical_changes=0,
            high_changes=0,
            medium_changes=0,
            low_changes=0,
            positive_changes=0
        )

        changes = []

        # Get baseline vulnerabilities first (needed for associated_vulnerabilities in closed ports)
        baseline_vulns = self._get_vulnerabilities_by_scan(baseline_scan_id)

        # 1. Compare ports (pass baseline_vulns for associated_vulnerabilities)
        port_changes = self._compare_ports(baseline_scan_id, current_scan_id, baseline_vulns)
        changes.extend(port_changes)

        # 2. Compare vulnerabilities.
        # Thread the CURRENT scan's config_id through so new findings can be
        # checked against persistent triage state (FindingState is keyed by
        # (config_id, fingerprint)). config_id is always present on a scan.
        vuln_changes = self._compare_vulnerabilities(
            baseline_scan_id, current_scan_id, baseline_vulns,
            current_config_id=current.config_id,
        )
        changes.extend(vuln_changes)

        # 3. Compare SSH audits (if applicable)
        ssh_changes = self._compare_ssh_audits(baseline_scan_id, current_scan_id)
        changes.extend(ssh_changes)

        # Store changes
        comparison.changes = changes

        # Calculate statistics
        self._calculate_statistics(comparison, changes)

        # Generate summary
        comparison.summary = self._generate_summary(comparison, baseline, current)

        # Save comparison
        self.db.add(comparison)
        self.db.commit()
        self.db.refresh(comparison)

        return comparison

    def _compare_ports(self, baseline_scan_id: str, current_scan_id: str, baseline_vulns: List[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Compare ports between two scans"""
        changes = []

        # Get all ports from both scans (grouped by IP + port + protocol)
        baseline_ports = self._get_ports_by_scan(baseline_scan_id)
        current_ports = self._get_ports_by_scan(current_scan_id)

        # Create lookup keys: "ip:normalized_port:protocol" (ephemeral/RPC ports
        # collapsed to a stable sentinel — see _port_key).
        baseline_keys = {self._port_key(p): p for p in baseline_ports}
        current_keys = {self._port_key(p): p for p in current_ports}

        # Annotate (but do not count) ephemeral-port churn that normalization
        # suppressed, so it stays visible in logs without polluting the diff.
        self._log_suppressed_port_churn(baseline_ports, current_ports, baseline_keys, current_keys)

        # Create a lookup of baseline vulnerabilities by IP:port for associated_vulnerabilities
        baseline_vulns_by_ip_port: Dict[str, List[Dict[str, Any]]] = {}
        if baseline_vulns:
            for vuln in baseline_vulns:
                ip_port_key = f"{vuln['ip_address']}:{vuln['port']}"
                if ip_port_key not in baseline_vulns_by_ip_port:
                    baseline_vulns_by_ip_port[ip_port_key] = []
                baseline_vulns_by_ip_port[ip_port_key].append(vuln)

        # Find new ports (in current but not in baseline)
        for key in current_keys:
            if key not in baseline_keys:
                port = current_keys[key]
                changes.append({
                    'type': 'NEW_PORT',
                    'severity': 'HIGH',
                    'category': 'port',
                    'ip_address': port['ip_address'],
                    'device_name': port['device_name'],
                    'port': port['port'],
                    'protocol': port['protocol'],
                    'service_name': port['service_name'],
                    'version': port['version'],
                    'product': port.get('product'),
                    'description': f"New open port: {port['port']}/{port['protocol']}"
                })

        # Find closed ports (in baseline but not in current)
        for key in baseline_keys:
            if key not in current_keys:
                port = baseline_keys[key]
                # Find associated vulnerabilities from baseline that were on this IP:port
                ip_port_key = f"{port['ip_address']}:{port['port']}"
                associated_vulns = baseline_vulns_by_ip_port.get(ip_port_key, [])
                associated_vulnerabilities = [
                    {
                        'name': v['name'],
                        'severity': v['severity'],
                        'template_id': v['template_id'],
                        'matched_at': v['matched_at']
                    }
                    for v in associated_vulns
                ]

                changes.append({
                    'type': 'CLOSED_PORT',
                    'severity': 'POSITIVE',
                    'category': 'port',
                    'ip_address': port['ip_address'],
                    'device_name': port['device_name'],
                    'port': port['port'],
                    'protocol': port['protocol'],
                    'service_name': port['service_name'],
                    'version': port['version'],
                    'product': port.get('product'),
                    'description': f"Port closed: {port['port']}/{port['protocol']}",
                    'associated_vulnerabilities': associated_vulnerabilities if associated_vulnerabilities else None
                })

        # Find version changes (same port, different version)
        for key in baseline_keys:
            if key in current_keys:
                baseline_port = baseline_keys[key]
                current_port = current_keys[key]

                # Check if version changed
                baseline_version = baseline_port.get('version') or ''
                current_version = current_port.get('version') or ''

                if baseline_version and current_version and baseline_version != current_version:
                    changes.append({
                        'type': 'VERSION_UPDATE',
                        'severity': 'MEDIUM',
                        'category': 'service',
                        'ip_address': current_port['ip_address'],
                        'device_name': current_port['device_name'],
                        'port': current_port['port'],
                        'protocol': current_port['protocol'],
                        'service_name': current_port['service_name'],
                        'old_version': baseline_version,
                        'new_version': current_version,
                        'description': f"Service updated: {current_port['service_name']} {baseline_version} → {current_version}"
                    })

        return changes

    def _compare_vulnerabilities(self, baseline_scan_id: str, current_scan_id: str, baseline_vulns: List[Dict[str, Any]] = None, current_config_id: str = None) -> List[Dict[str, Any]]:
        """Compare vulnerabilities between two scans"""
        changes = []

        # Get all vulnerabilities from both scans
        if baseline_vulns is None:
            baseline_vulns = self._get_vulnerabilities_by_scan(baseline_scan_id)
        current_vulns = self._get_vulnerabilities_by_scan(current_scan_id)

        # Create lookup keys: "ip:template_id:port"
        baseline_keys = {self._vuln_key(v): v for v in baseline_vulns}
        current_keys = {self._vuln_key(v): v for v in current_vulns}

        # Find new vulnerabilities
        for key in current_keys:
            if key not in baseline_keys:
                vuln = current_keys[key]

                # Map vuln severity to change severity
                change_severity = {
                    'critical': 'CRITICAL',
                    'high': 'HIGH',
                    'medium': 'MEDIUM',
                    'low': 'LOW',
                    'info': 'INFO'
                }.get(vuln['severity'], 'MEDIUM')

                # Cross-scan triage memory: a finding a human already dispositioned
                # as false_positive / accepted_risk (or time-boxed via
                # suppressed_until) must NOT be re-surfaced as a new vulnerability
                # every scan. If (and only if) a suppressing FindingState row
                # exists for this (config_id, fingerprint), mark the change
                # SUPPRESSED so _calculate_statistics does not count it as new.
                # When no state row exists behavior is UNCHANGED (GENUINELY_NEW,
                # counted) — this guards the existing de-noising tests.
                classification = 'GENUINELY_NEW'
                if self._is_suppressed(current_config_id, vuln.get('fingerprint')):
                    classification = 'SUPPRESSED'

                changes.append({
                    'type': 'NEW_VULNERABILITY',
                    'severity': change_severity,
                    'category': 'vulnerability',
                    # Fingerprint keying + port normalization already suppressed
                    # scan-noise churn, so anything surfacing here is genuinely new
                    # UNLESS a human triage decision suppresses it (see above).
                    'classification': classification,
                    'ip_address': vuln['ip_address'],
                    'device_name': vuln['device_name'],
                    'port': vuln['port'],
                    'fingerprint': vuln['fingerprint'],
                    'template_id': vuln['template_id'],
                    'name': vuln['name'],
                    'vuln_severity': vuln['severity'],
                    'matched_at': vuln['matched_at'],
                    'vuln_description': vuln.get('description'),
                    'reference': vuln.get('reference'),
                    'description': f"New {vuln['severity']} vulnerability: {vuln['name']}"
                })

        # Find fixed vulnerabilities
        for key in baseline_keys:
            if key not in current_keys:
                vuln = baseline_keys[key]
                changes.append({
                    'type': 'FIXED_VULNERABILITY',
                    'severity': 'POSITIVE',
                    'category': 'vulnerability',
                    'ip_address': vuln['ip_address'],
                    'device_name': vuln['device_name'],
                    'port': vuln['port'],
                    'template_id': vuln['template_id'],
                    'name': vuln['name'],
                    'vuln_severity': vuln['severity'],
                    'matched_at': vuln['matched_at'],
                    'vuln_description': vuln.get('description'),
                    'reference': vuln.get('reference'),
                    'description': f"Fixed {vuln['severity']} vulnerability: {vuln['name']}"
                })

        return changes

    def _compare_ssh_audits(self, baseline_scan_id: str, current_scan_id: str) -> List[Dict[str, Any]]:
        """Compare SSH audit results between two scans"""
        changes = []

        # Get SSH audits from both scans
        baseline_audits = self._get_ssh_audits_by_scan(baseline_scan_id)
        current_audits = self._get_ssh_audits_by_scan(current_scan_id)

        # Create lookup by IP:port
        baseline_keys = {f"{a['ip_address']}:{a['port']}": a for a in baseline_audits}
        current_keys = {f"{a['ip_address']}:{a['port']}": a for a in current_audits}

        # Compare common SSH servers
        for key in baseline_keys:
            if key in current_keys:
                baseline_audit = baseline_keys[key]
                current_audit = current_keys[key]

                baseline_vuln_count = len(baseline_audit.get('vulnerabilities') or [])
                current_vuln_count = len(current_audit.get('vulnerabilities') or [])

                if baseline_vuln_count != current_vuln_count:
                    if current_vuln_count < baseline_vuln_count:
                        # Security improved
                        changes.append({
                            'type': 'SSH_SECURITY_IMPROVED',
                            'severity': 'POSITIVE',
                            'category': 'ssh',
                            'ip_address': current_audit['ip_address'],
                            'device_name': current_audit['device_name'],
                            'port': current_audit['port'],
                            'old_vuln_count': baseline_vuln_count,
                            'new_vuln_count': current_vuln_count,
                            'description': f"SSH security improved: {baseline_vuln_count} → {current_vuln_count} issues"
                        })
                    else:
                        # Security degraded
                        changes.append({
                            'type': 'SSH_SECURITY_DEGRADED',
                            'severity': 'HIGH',
                            'category': 'ssh',
                            'ip_address': current_audit['ip_address'],
                            'device_name': current_audit['device_name'],
                            'port': current_audit['port'],
                            'old_vuln_count': baseline_vuln_count,
                            'new_vuln_count': current_vuln_count,
                            'description': f"SSH security degraded: {baseline_vuln_count} → {current_vuln_count} issues"
                        })

        return changes

    def _is_suppressed(self, config_id: str, fingerprint: str) -> bool:
        """True if a persistent triage decision suppresses this finding.

        Looks up FindingState by (config_id, fingerprint). Suppression applies
        when status is false_positive / accepted_risk, OR suppressed_until is set
        to a future time. Returns False (behavior unchanged) whenever config_id or
        fingerprint is missing, or no state row exists — this is the guard that
        keeps the default de-noising comparison path untouched.
        """
        if not config_id or not fingerprint:
            return False
        state = (
            self.db.query(FindingState)
            .filter(
                FindingState.config_id == config_id,
                FindingState.fingerprint == fingerprint,
            )
            .first()
        )
        if state is None:
            return False
        if state.status in SUPPRESSED_STATUSES:
            return True
        if state.suppressed_until and state.suppressed_until > datetime.utcnow():
            return True
        return False

    def _calculate_statistics(self, comparison: ScanComparison, changes: List[Dict[str, Any]]):
        """Calculate summary statistics from changes"""
        comparison.total_changes = len(changes)

        for change in changes:
            change_type = change['type']
            severity = change['severity']

            # A NEW_VULNERABILITY suppressed by persistent triage state is kept in
            # the changes list (so the UI can show it) but is NOT counted as a new
            # vulnerability or a severity change.
            if change.get('classification') == 'SUPPRESSED':
                continue

            # Count by type
            if change_type == 'NEW_PORT':
                comparison.new_ports += 1
            elif change_type == 'CLOSED_PORT':
                comparison.closed_ports += 1
            elif change_type == 'VERSION_UPDATE':
                comparison.version_changes += 1
            elif change_type == 'NEW_VULNERABILITY':
                comparison.new_vulnerabilities += 1
            elif change_type == 'FIXED_VULNERABILITY':
                comparison.fixed_vulnerabilities += 1

            # Count by severity
            if severity == 'CRITICAL':
                comparison.critical_changes += 1
            elif severity == 'HIGH':
                comparison.high_changes += 1
            elif severity == 'MEDIUM':
                comparison.medium_changes += 1
            elif severity == 'LOW':
                comparison.low_changes += 1
            elif severity == 'POSITIVE':
                comparison.positive_changes += 1

    def _generate_summary(self, comparison: ScanComparison, baseline: Scan, current: Scan) -> str:
        """Generate human-readable summary"""
        lines = []

        lines.append(f"Comparison: {baseline.name} → {current.name}")
        lines.append(f"Baseline: {baseline.created_at.strftime('%Y-%m-%d %H:%M')}")
        lines.append(f"Current: {current.created_at.strftime('%Y-%m-%d %H:%M')}")
        lines.append("")

        if comparison.total_changes == 0:
            lines.append("✅ No changes detected")
            return "\n".join(lines)

        lines.append(f"📊 Total Changes: {comparison.total_changes}")
        lines.append("")

        if comparison.new_ports > 0:
            lines.append(f"🔴 New Ports: {comparison.new_ports}")
        if comparison.closed_ports > 0:
            lines.append(f"🟢 Closed Ports: {comparison.closed_ports}")
        if comparison.version_changes > 0:
            lines.append(f"🟡 Version Updates: {comparison.version_changes}")
        if comparison.new_vulnerabilities > 0:
            lines.append(f"🔴 New Vulnerabilities: {comparison.new_vulnerabilities}")
        if comparison.fixed_vulnerabilities > 0:
            lines.append(f"🟢 Fixed Vulnerabilities: {comparison.fixed_vulnerabilities}")

        lines.append("")
        lines.append("Severity Breakdown:")
        if comparison.critical_changes > 0:
            lines.append(f"  🔥 Critical: {comparison.critical_changes}")
        if comparison.high_changes > 0:
            lines.append(f"  🔴 High: {comparison.high_changes}")
        if comparison.medium_changes > 0:
            lines.append(f"  🟡 Medium: {comparison.medium_changes}")
        if comparison.positive_changes > 0:
            lines.append(f"  ✅ Improvements: {comparison.positive_changes}")

        return "\n".join(lines)

    # Helper methods for data retrieval

    def _get_ports_by_scan(self, scan_id: str) -> List[Dict[str, Any]]:
        """Get all ports for a scan with target info"""
        query = text("""
            SELECT
                st.ip_address,
                st.device_name,
                p.port,
                p.protocol,
                p.state,
                p.service_name,
                p.version,
                p.product
            FROM ports p
            JOIN scan_targets st ON p.scan_target_id = st.id
            WHERE st.scan_id = :scan_id
            AND p.state = 'open'
        """)

        result = self.db.execute(query, {'scan_id': scan_id})

        ports = []
        for row in result:
            ports.append({
                'ip_address': row[0],
                'device_name': row[1],
                'port': row[2],
                'protocol': row[3],
                'state': row[4],
                'service_name': row[5],
                'version': row[6],
                'product': row[7]
            })

        return ports

    def _get_vulnerabilities_by_scan(self, scan_id: str) -> List[Dict[str, Any]]:
        """Get all vulnerabilities for a scan with target info"""
        query = text("""
            SELECT
                st.ip_address,
                st.device_name,
                v.template_id,
                v.name,
                v.severity,
                v.port,
                v.matched_at,
                v.description,
                v.reference,
                v.fingerprint
            FROM vulnerabilities v
            JOIN scan_targets st ON v.scan_target_id = st.id
            WHERE st.scan_id = :scan_id
        """)

        result = self.db.execute(query, {'scan_id': scan_id})

        vulns = []
        for row in result:
            fingerprint = row[9]
            # Backward-compat: rows ingested before the fingerprint column existed
            # (or backfilled lazily) may be NULL — compute the same stable value
            # on the fly so comparison stays fingerprint-keyed.
            if not fingerprint:
                fingerprint = finding_fingerprint(
                    host=row[0],
                    template_id=row[2],
                    port=row[5],
                    matched_at=row[6],
                )
            vulns.append({
                'ip_address': row[0],
                'device_name': row[1],
                'template_id': row[2],
                'name': row[3],
                'severity': row[4],
                'port': row[5],
                'matched_at': row[6],
                'description': row[7],
                'reference': row[8],
                'fingerprint': fingerprint
            })

        return vulns

    def _get_ssh_audits_by_scan(self, scan_id: str) -> List[Dict[str, Any]]:
        """Get all SSH audits for a scan with target info"""
        query = text("""
            SELECT
                st.ip_address,
                st.device_name,
                p.port,
                sa.vulnerabilities
            FROM ssh_audits sa
            JOIN ports p ON sa.port_id = p.id
            JOIN scan_targets st ON p.scan_target_id = st.id
            WHERE st.scan_id = :scan_id
        """)

        result = self.db.execute(query, {'scan_id': scan_id})

        audits = []
        for row in result:
            audits.append({
                'ip_address': row[0],
                'device_name': row[1],
                'port': row[2],
                'vulnerabilities': row[3]  # JSON field
            })

        return audits

    def _port_key(self, port: Dict[str, Any]) -> str:
        """Generate unique key for port comparison.

        Ephemeral/RPC ports (mountd, nlockmgr, ... on random high ports) are
        collapsed to a stable sentinel so reboot-driven port churn does NOT
        surface as NEW_PORT/CLOSED_PORT noise.
        """
        norm_port = normalize_port(port['port'], port.get('service_name'))
        return f"{port['ip_address']}:{norm_port}:{port['protocol']}"

    def _log_suppressed_port_churn(
        self,
        baseline_ports: List[Dict[str, Any]],
        current_ports: List[Dict[str, Any]],
        baseline_keys: Dict[str, Any],
        current_keys: Dict[str, Any],
    ) -> None:
        """Log ephemeral-port churn that normalization collapsed.

        A raw port present in only one scan but whose *normalized* key exists in
        both scans is reboot noise (e.g. mountd:49163 vs mountd:50011). We report
        it at info level so operators can see it was suppressed, but it is never
        counted as NEW_PORT / CLOSED_PORT.
        """
        def raw_key(p: Dict[str, Any]) -> str:
            return f"{p['ip_address']}:{p['port']}:{p['protocol']}"

        baseline_raw = {raw_key(p) for p in baseline_ports}
        current_raw = {raw_key(p) for p in current_ports}
        raw_only = baseline_raw.symmetric_difference(current_raw)
        if not raw_only:
            return

        # Of the raw-differing ports, how many resolved to a shared normalized key?
        suppressed = 0
        for ports in (baseline_ports, current_ports):
            for p in ports:
                if raw_key(p) in raw_only:
                    k = self._port_key(p)
                    if k in baseline_keys and k in current_keys:
                        suppressed += 1
        if suppressed:
            logger.info(
                "Comparison suppressed %d ephemeral/RPC port change(s) as reboot "
                "noise (collapsed via normalize_port)", suppressed
            )

    def _vuln_key(self, vuln: Dict[str, Any]) -> str:
        """Generate unique key for vulnerability comparison.

        Uses the stable finding fingerprint (host + template_id/cve + normalized
        port + normalized URL path) so the same logical finding is not reported as
        both new and fixed when the crawler hits a different URL or an RPC port
        rotates between runs.
        """
        return vuln['fingerprint']
