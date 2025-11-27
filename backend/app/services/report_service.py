from typing import List, Dict, Any, Optional
from datetime import datetime
from io import BytesIO
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
import pandas as pd
from jinja2 import Template
from sqlalchemy.orm import Session
from sqlalchemy import text
from ..models import Scan, ScanTarget, Port, Vulnerability, SSHAudit, ScanComparison

class ReportService:
    """Service for generating scan reports in various formats"""

    def __init__(self, db: Session):
        self.db = db
        self.styles = getSampleStyleSheet()
        self._add_custom_styles()

    def _add_custom_styles(self):
        """Add custom paragraph styles"""
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a202c'),
            spaceAfter=30,
            alignment=TA_CENTER
        ))

        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#2d3748'),
            spaceAfter=12,
            spaceBefore=12
        ))

    # ==================== PDF REPORTS ====================

    def generate_executive_summary_pdf(self, scan_id: str) -> BytesIO:
        """Generate executive summary PDF (1-2 pages)"""
        scan = self._load_scan(scan_id)

        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        story = []

        # Title
        story.append(Paragraph(f"Security Scan Executive Summary", self.styles['CustomTitle']))
        story.append(Paragraph(f"{scan.name}", self.styles['Heading2']))
        story.append(Spacer(1, 0.2*inch))

        # Scan metadata
        story.append(Paragraph(f"<b>Date:</b> {scan.created_at.strftime('%Y-%m-%d %H:%M')}", self.styles['Normal']))
        story.append(Paragraph(f"<b>Status:</b> {scan.status.upper()}", self.styles['Normal']))
        story.append(Paragraph(f"<b>Targets Scanned:</b> {scan.total_targets}", self.styles['Normal']))
        story.append(Spacer(1, 0.3*inch))

        # Key Metrics
        story.append(Paragraph("Key Findings", self.styles['SectionHeader']))

        metrics_data = [
            ['Metric', 'Count', 'Status'],
            ['Open Ports', str(scan.total_open_ports), self._get_status_indicator(scan.total_open_ports, 'ports')],
            ['Vulnerabilities', str(scan.total_vulnerabilities), self._get_status_indicator(scan.total_vulnerabilities, 'vulns')],
            ['Critical Findings', str(self._count_critical_vulns(scan_id)), 'High Priority' if self._count_critical_vulns(scan_id) > 0 else 'Good'],
        ]

        metrics_table = Table(metrics_data, colWidths=[2.5*inch, 1.5*inch, 2*inch])
        metrics_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4a5568')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(metrics_table)
        story.append(Spacer(1, 0.3*inch))

        # Top vulnerabilities
        story.append(Paragraph("Critical Vulnerabilities", self.styles['SectionHeader']))
        critical_vulns = self._get_critical_vulnerabilities(scan_id, limit=5)

        if critical_vulns:
            vuln_data = [['Severity', 'Vulnerability', 'Target']]
            for vuln in critical_vulns:
                vuln_data.append([
                    vuln['severity'].upper(),
                    vuln['name'][:50] + '...' if len(vuln['name']) > 50 else vuln['name'],
                    vuln['ip_address']
                ])

            vuln_table = Table(vuln_data, colWidths=[1*inch, 3.5*inch, 1.5*inch])
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4a5568')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(vuln_table)
        else:
            story.append(Paragraph("No critical vulnerabilities detected", self.styles['Normal']))

        story.append(Spacer(1, 0.3*inch))

        # Recommendations
        story.append(Paragraph("Recommendations", self.styles['SectionHeader']))
        recommendations = self._generate_recommendations(scan_id)
        for i, rec in enumerate(recommendations[:5], 1):
            story.append(Paragraph(f"{i}. {rec}", self.styles['Normal']))
            story.append(Spacer(1, 0.1*inch))

        # Build PDF
        doc.build(story)
        buffer.seek(0)
        return buffer

    def generate_technical_report_pdf(self, scan_id: str) -> BytesIO:
        """Generate detailed technical report PDF"""
        scan = self._load_scan(scan_id)

        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        story = []

        # Title page
        story.append(Paragraph("Technical Security Report", self.styles['CustomTitle']))
        story.append(Paragraph(f"{scan.name}", self.styles['Heading2']))
        story.append(Spacer(1, 0.5*inch))

        # Metadata
        story.append(Paragraph("Scan Information", self.styles['SectionHeader']))
        info_data = [
            ['Scan Name', scan.name],
            ['Description', scan.description or 'N/A'],
            ['Start Time', scan.started_at.strftime('%Y-%m-%d %H:%M:%S') if scan.started_at else 'N/A'],
            ['End Time', scan.finished_at.strftime('%Y-%m-%d %H:%M:%S') if scan.finished_at else 'N/A'],
            ['Duration', self._format_duration(scan)],
            ['Status', scan.status.upper()],
            ['Total Targets', str(scan.total_targets)],
        ]

        info_table = Table(info_data, colWidths=[2*inch, 4*inch])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e2e8f0')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey)
        ]))
        story.append(info_table)
        story.append(PageBreak())

        # Targets and ports
        story.append(Paragraph("Discovered Services", self.styles['SectionHeader']))
        targets = self._load_targets(scan_id)

        for target in targets[:5]:  # Limit for PDF size
            story.append(Paragraph(f"<b>{target.device_name or target.ip_address}</b> ({target.ip_address})",
                                 self.styles['Heading3']))

            ports = self._load_ports(str(target.id))
            if ports:
                port_data = [['Port', 'Protocol', 'State', 'Service', 'Version']]
                for port in ports[:20]:  # Limit ports per target
                    port_data.append([
                        str(port.port),
                        port.protocol,
                        port.state,
                        port.service_name or '-',
                        port.version[:30] if port.version else '-'
                    ])

                port_table = Table(port_data, colWidths=[0.7*inch, 0.8*inch, 0.8*inch, 1.5*inch, 2.2*inch])
                port_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4a5568')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey)
                ]))
                story.append(port_table)
            else:
                story.append(Paragraph("No open ports detected", self.styles['Normal']))

            story.append(Spacer(1, 0.2*inch))

        story.append(PageBreak())

        # Vulnerabilities
        story.append(Paragraph("Vulnerability Details", self.styles['SectionHeader']))
        vulns = self._load_vulnerabilities(scan_id)

        if vulns:
            for vuln in vulns[:20]:  # Limit to first 20 for PDF size
                severity_color = self._get_severity_color(vuln['severity'])
                story.append(Paragraph(
                    f"<font color='{severity_color}'><b>[{vuln['severity'].upper()}]</b></font> {vuln['name']}",
                    self.styles['Heading4']
                ))
                story.append(Paragraph(f"<b>Target:</b> {vuln['ip_address']}:{vuln['port']}", self.styles['Normal']))
                story.append(Paragraph(f"<b>Template:</b> {vuln['template_id']}", self.styles['Normal']))
                story.append(Spacer(1, 0.15*inch))
        else:
            story.append(Paragraph("No vulnerabilities detected", self.styles['Normal']))

        # Build PDF
        doc.build(story)
        buffer.seek(0)
        return buffer

    def generate_comparison_report_pdf(self, comparison_id: str) -> BytesIO:
        """Generate comparison report PDF"""
        comparison = self.db.query(ScanComparison).filter(
            ScanComparison.id == comparison_id
        ).first()

        if not comparison:
            raise ValueError("Comparison not found")

        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        story = []

        # Title
        story.append(Paragraph("Scan Comparison Report", self.styles['CustomTitle']))
        story.append(Spacer(1, 0.3*inch))

        # Summary
        story.append(Paragraph("Change Summary", self.styles['SectionHeader']))

        summary_data = [
            ['Metric', 'Count'],
            ['Total Changes', str(comparison.total_changes)],
            ['New Ports', str(comparison.new_ports)],
            ['Closed Ports', str(comparison.closed_ports)],
            ['Version Updates', str(comparison.version_changes)],
            ['New Vulnerabilities', str(comparison.new_vulnerabilities)],
            ['Fixed Vulnerabilities', str(comparison.fixed_vulnerabilities)],
            ['Critical Changes', str(comparison.critical_changes)],
            ['High Severity Changes', str(comparison.high_changes)],
            ['Positive Changes', str(comparison.positive_changes)],
        ]

        summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4a5568')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 0.3*inch))

        # Detailed changes
        story.append(Paragraph("Detailed Changes", self.styles['SectionHeader']))

        for change in comparison.changes[:30]:  # Limit for PDF size
            story.append(Paragraph(
                f"<b>{change['type'].replace('_', ' ').title()}:</b> {change['description']}",
                self.styles['Normal']
            ))
            story.append(Spacer(1, 0.1*inch))

        # Build PDF
        doc.build(story)
        buffer.seek(0)
        return buffer

    # ==================== HTML REPORTS ====================

    def generate_html_report(self, scan_id: str) -> str:
        """Generate HTML report"""
        scan = self._load_scan(scan_id)
        targets = self._load_targets(scan_id)
        vulns = self._load_vulnerabilities(scan_id)

        template = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Security Scan Report - {{ scan.name }}</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f7fafc;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 30px;
        }
        .header h1 { margin: 0 0 10px 0; }
        .section {
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .section h2 {
            color: #2d3748;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        th {
            background: #4a5568;
            color: white;
            padding: 12px;
            text-align: left;
        }
        td {
            padding: 10px;
            border-bottom: 1px solid #e2e8f0;
        }
        tr:hover { background: #f7fafc; }
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
        }
        .badge-critical { background: #f56565; color: white; }
        .badge-high { background: #ed8936; color: white; }
        .badge-medium { background: #ecc94b; color: white; }
        .badge-low { background: #4299e1; color: white; }
        .badge-info { background: #a0aec0; color: white; }
        .metrics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .metric-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        .metric-card .value {
            font-size: 36px;
            font-weight: bold;
            margin: 10px 0;
        }
        .metric-card .label {
            font-size: 14px;
            opacity: 0.9;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{ scan.name }}</h1>
        <p>{{ scan.description or 'Security Scan Report' }}</p>
        <p><strong>Date:</strong> {{ scan.created_at.strftime('%Y-%m-%d %H:%M') }}</p>
    </div>

    <div class="section">
        <h2>Scan Metrics</h2>
        <div class="metrics">
            <div class="metric-card">
                <div class="label">Targets Scanned</div>
                <div class="value">{{ scan.total_targets }}</div>
            </div>
            <div class="metric-card">
                <div class="label">Open Ports</div>
                <div class="value">{{ scan.total_open_ports }}</div>
            </div>
            <div class="metric-card">
                <div class="label">Vulnerabilities</div>
                <div class="value">{{ scan.total_vulnerabilities }}</div>
            </div>
        </div>
    </div>

    <div class="section">
        <h2>Discovered Services</h2>
        {% for target in targets %}
        <h3>{{ target.device_name or target.ip_address }} ({{ target.ip_address }})</h3>
        <table>
            <thead>
                <tr>
                    <th>Port</th>
                    <th>Protocol</th>
                    <th>State</th>
                    <th>Service</th>
                    <th>Version</th>
                </tr>
            </thead>
            <tbody>
                {% for port in target.ports %}
                <tr>
                    <td>{{ port.port }}</td>
                    <td>{{ port.protocol }}</td>
                    <td>{{ port.state }}</td>
                    <td>{{ port.service_name or '-' }}</td>
                    <td>{{ port.version or '-' }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% endfor %}
    </div>

    <div class="section">
        <h2>Vulnerabilities</h2>
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Vulnerability</th>
                    <th>Target</th>
                    <th>Template ID</th>
                </tr>
            </thead>
            <tbody>
                {% for vuln in vulns %}
                <tr>
                    <td><span class="badge badge-{{ vuln.severity }}">{{ vuln.severity.upper() }}</span></td>
                    <td>{{ vuln.name }}</td>
                    <td>{{ vuln.ip_address }}:{{ vuln.port }}</td>
                    <td><code>{{ vuln.template_id }}</code></td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% if not vulns %}
        <p>No vulnerabilities detected</p>
        {% endif %}
    </div>
</body>
</html>
        """

        tmpl = Template(template)

        # Load ports for each target
        for target in targets:
            target.ports = self._load_ports(str(target.id))

        return tmpl.render(
            scan=scan,
            targets=targets,
            vulns=vulns
        )

    # ==================== CSV EXPORT ====================

    def export_vulnerabilities_csv(self, scan_id: str) -> BytesIO:
        """Export vulnerabilities to CSV"""
        vulns = self._load_vulnerabilities(scan_id)

        df = pd.DataFrame(vulns)

        # Reorder columns
        if len(vulns) > 0:
            columns = ['ip_address', 'device_name', 'port', 'severity', 'name',
                      'template_id', 'type', 'matched_at']
            df = df[[col for col in columns if col in df.columns]]

        buffer = BytesIO()
        df.to_csv(buffer, index=False, encoding='utf-8')
        buffer.seek(0)
        return buffer

    def export_ports_csv(self, scan_id: str) -> BytesIO:
        """Export ports to CSV"""
        targets = self._load_targets(scan_id)

        data = []
        for target in targets:
            ports = self._load_ports(str(target.id))
            for port in ports:
                data.append({
                    'ip_address': target.ip_address,
                    'device_name': target.device_name,
                    'port': port.port,
                    'protocol': port.protocol,
                    'state': port.state,
                    'service_name': port.service_name,
                    'version': port.version,
                    'discovered_by': port.discovered_by
                })

        df = pd.DataFrame(data)

        buffer = BytesIO()
        df.to_csv(buffer, index=False, encoding='utf-8')
        buffer.seek(0)
        return buffer

    def export_scan_summary_csv(self, scan_id: str) -> BytesIO:
        """Export scan summary to CSV"""
        scan = self._load_scan(scan_id)

        data = {
            'Scan Name': [scan.name],
            'Description': [scan.description or 'N/A'],
            'Status': [scan.status],
            'Start Time': [scan.started_at.strftime('%Y-%m-%d %H:%M:%S') if scan.started_at else 'N/A'],
            'End Time': [scan.finished_at.strftime('%Y-%m-%d %H:%M:%S') if scan.finished_at else 'N/A'],
            'Total Targets': [scan.total_targets],
            'Completed Targets': [scan.completed_targets],
            'Failed Targets': [scan.failed_targets],
            'Total Open Ports': [scan.total_open_ports],
            'Total Vulnerabilities': [scan.total_vulnerabilities]
        }

        df = pd.DataFrame(data)

        buffer = BytesIO()
        df.to_csv(buffer, index=False, encoding='utf-8')
        buffer.seek(0)
        return buffer

    # ==================== HELPER METHODS ====================

    def _load_scan(self, scan_id: str) -> Scan:
        """Load scan from database"""
        scan = self.db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            raise ValueError("Scan not found")
        return scan

    def _load_targets(self, scan_id: str) -> List[ScanTarget]:
        """Load targets for scan"""
        return self.db.query(ScanTarget).filter(
            ScanTarget.scan_id == scan_id
        ).all()

    def _load_ports(self, target_id: str) -> List[Port]:
        """Load ports for target"""
        return self.db.query(Port).filter(
            Port.scan_target_id == target_id
        ).all()

    def _load_vulnerabilities(self, scan_id: str) -> List[Dict[str, Any]]:
        """Load vulnerabilities for scan"""
        query = text("""
            SELECT
                v.severity,
                v.name,
                v.template_id,
                v.vuln_type as type,
                v.matched_at,
                v.port,
                st.ip_address,
                st.device_name
            FROM vulnerabilities v
            JOIN scan_targets st ON v.scan_target_id = st.id
            WHERE st.scan_id = :scan_id
            ORDER BY
                CASE v.severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END
        """)

        result = self.db.execute(query, {'scan_id': scan_id})

        vulns = []
        for row in result:
            vulns.append({
                'severity': row[0],
                'name': row[1],
                'template_id': row[2],
                'type': row[3],
                'matched_at': row[4],
                'port': row[5],
                'ip_address': row[6],
                'device_name': row[7]
            })

        return vulns

    def _get_critical_vulnerabilities(self, scan_id: str, limit: int = 10) -> List[Dict]:
        """Get critical and high severity vulnerabilities"""
        vulns = self._load_vulnerabilities(scan_id)
        return [v for v in vulns if v['severity'] in ['critical', 'high']][:limit]

    def _count_critical_vulns(self, scan_id: str) -> int:
        """Count critical vulnerabilities"""
        vulns = self._load_vulnerabilities(scan_id)
        return len([v for v in vulns if v['severity'] == 'critical'])

    def _get_status_indicator(self, count: int, metric_type: str) -> str:
        """Get status indicator"""
        if metric_type == 'vulns':
            if count == 0:
                return 'Good'
            elif count < 5:
                return 'Monitor'
            else:
                return 'Action Needed'
        elif metric_type == 'ports':
            if count < 10:
                return 'Normal'
            elif count < 50:
                return 'Review'
            else:
                return 'High Exposure'
        return 'N/A'

    def _get_severity_color(self, severity: str) -> str:
        """Get color hex for severity"""
        colors_map = {
            'critical': '#f56565',
            'high': '#ed8936',
            'medium': '#ecc94b',
            'low': '#4299e1',
            'info': '#a0aec0'
        }
        return colors_map.get(severity, '#718096')

    def _format_duration(self, scan: Scan) -> str:
        """Format scan duration"""
        if not scan.started_at or not scan.finished_at:
            return 'N/A'

        duration = scan.finished_at - scan.started_at
        seconds = int(duration.total_seconds())

        if seconds < 60:
            return f"{seconds}s"
        elif seconds < 3600:
            return f"{seconds // 60}m {seconds % 60}s"
        else:
            hours = seconds // 3600
            minutes = (seconds % 3600) // 60
            return f"{hours}h {minutes}m"

    def _generate_recommendations(self, scan_id: str) -> List[str]:
        """Generate security recommendations"""
        recommendations = []

        vulns = self._load_vulnerabilities(scan_id)
        critical_count = len([v for v in vulns if v['severity'] == 'critical'])
        high_count = len([v for v in vulns if v['severity'] == 'high'])

        if critical_count > 0:
            recommendations.append(
                f"Address {critical_count} critical vulnerabilities immediately. "
                "These pose the highest security risk."
            )

        if high_count > 0:
            recommendations.append(
                f"Review and remediate {high_count} high severity vulnerabilities "
                "within the next maintenance window."
            )

        if not recommendations:
            recommendations.append(
                "No critical security issues detected. Continue regular security monitoring "
                "and keep systems updated with latest security patches."
            )

        return recommendations
