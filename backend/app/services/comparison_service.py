from typing import List, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import select, text
from ..models import Scan, ScanTarget, Port, Vulnerability, ScanComparison, SSHAudit
import uuid
from datetime import datetime

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

        # 1. Compare ports
        port_changes = self._compare_ports(baseline_scan_id, current_scan_id)
        changes.extend(port_changes)

        # 2. Compare vulnerabilities
        vuln_changes = self._compare_vulnerabilities(baseline_scan_id, current_scan_id)
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

    def _compare_ports(self, baseline_scan_id: str, current_scan_id: str) -> List[Dict[str, Any]]:
        """Compare ports between two scans"""
        changes = []

        # Get all ports from both scans (grouped by IP + port + protocol)
        baseline_ports = self._get_ports_by_scan(baseline_scan_id)
        current_ports = self._get_ports_by_scan(current_scan_id)

        # Create lookup keys: "ip:port:protocol"
        baseline_keys = {self._port_key(p): p for p in baseline_ports}
        current_keys = {self._port_key(p): p for p in current_ports}

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
                    'description': f"New open port: {port['port']}/{port['protocol']}"
                })

        # Find closed ports (in baseline but not in current)
        for key in baseline_keys:
            if key not in current_keys:
                port = baseline_keys[key]
                changes.append({
                    'type': 'CLOSED_PORT',
                    'severity': 'POSITIVE',
                    'category': 'port',
                    'ip_address': port['ip_address'],
                    'device_name': port['device_name'],
                    'port': port['port'],
                    'protocol': port['protocol'],
                    'service_name': port['service_name'],
                    'description': f"Port closed: {port['port']}/{port['protocol']}"
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

    def _compare_vulnerabilities(self, baseline_scan_id: str, current_scan_id: str) -> List[Dict[str, Any]]:
        """Compare vulnerabilities between two scans"""
        changes = []

        # Get all vulnerabilities from both scans
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

                changes.append({
                    'type': 'NEW_VULNERABILITY',
                    'severity': change_severity,
                    'category': 'vulnerability',
                    'ip_address': vuln['ip_address'],
                    'device_name': vuln['device_name'],
                    'port': vuln['port'],
                    'template_id': vuln['template_id'],
                    'name': vuln['name'],
                    'vuln_severity': vuln['severity'],
                    'matched_at': vuln['matched_at'],
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

    def _calculate_statistics(self, comparison: ScanComparison, changes: List[Dict[str, Any]]):
        """Calculate summary statistics from changes"""
        comparison.total_changes = len(changes)

        for change in changes:
            change_type = change['type']
            severity = change['severity']

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
                p.version
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
                'version': row[6]
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
                v.matched_at
            FROM vulnerabilities v
            JOIN scan_targets st ON v.scan_target_id = st.id
            WHERE st.scan_id = :scan_id
        """)

        result = self.db.execute(query, {'scan_id': scan_id})

        vulns = []
        for row in result:
            vulns.append({
                'ip_address': row[0],
                'device_name': row[1],
                'template_id': row[2],
                'name': row[3],
                'severity': row[4],
                'port': row[5],
                'matched_at': row[6]
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
        """Generate unique key for port comparison"""
        return f"{port['ip_address']}:{port['port']}:{port['protocol']}"

    def _vuln_key(self, vuln: Dict[str, Any]) -> str:
        """Generate unique key for vulnerability comparison"""
        # Key: IP + template_id + port
        # Note: Ignore matched_at to allow for same vuln on different URLs
        return f"{vuln['ip_address']}:{vuln['template_id']}:{vuln['port']}"
