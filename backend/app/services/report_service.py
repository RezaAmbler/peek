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
        """Generate HTML report matching the UI structure"""
        scan = self._load_scan(scan_id)
        targets = self._load_targets(scan_id)
        all_vulns = self._load_vulnerabilities(scan_id)
        ssh_audits = self._load_ssh_audits(scan_id)
        sslscan_results = self._load_sslscan_results(scan_id)

        # Separate vulnerabilities from informational findings
        vulns = [v for v in all_vulns if v['severity'].lower() in ['critical', 'high', 'medium', 'low']]
        info_findings = [v for v in all_vulns
                        if v['severity'].lower() == 'info'
                        and v['name']
                        and 'unknown' not in v['name'].lower()]

        # Count by severity
        severity_counts = {
            'critical': len([v for v in all_vulns if v['severity'].lower() == 'critical']),
            'high': len([v for v in all_vulns if v['severity'].lower() == 'high']),
            'medium': len([v for v in all_vulns if v['severity'].lower() == 'medium']),
            'low': len([v for v in all_vulns if v['severity'].lower() == 'low']),
            'info': len(info_findings)
        }

        template = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Security Scan Report - {{ scan.name }}</title>
    <style>
        * { box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f7fafc;
            color: #1a202c;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 30px;
        }
        .header h1 { margin: 0 0 10px 0; font-size: 28px; }
        .header p { margin: 5px 0; opacity: 0.9; }
        .section {
            background: white;
            padding: 24px;
            border-radius: 8px;
            margin-bottom: 24px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .section h2 {
            color: #2d3748;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
            margin-top: 0;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .section h3 { color: #4a5568; margin-top: 20px; }
        .section-count {
            font-size: 14px;
            font-weight: normal;
            color: #718096;
        }

        /* Severity Summary */
        .severity-summary {
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
            margin: 20px 0;
        }
        .severity-badge {
            padding: 8px 16px;
            border-radius: 6px;
            font-weight: bold;
            font-size: 14px;
        }
        .severity-critical { background: #fed7d7; color: #c53030; }
        .severity-high { background: #feebc8; color: #c05621; }
        .severity-medium { background: #fefcbf; color: #b7791f; }
        .severity-low { background: #bee3f8; color: #2b6cb0; }
        .severity-info { background: #e2e8f0; color: #4a5568; }

        /* Metrics Grid */
        .metrics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin: 20px 0;
        }
        .metric-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        .metric-card .value { font-size: 32px; font-weight: bold; margin: 8px 0; }
        .metric-card .label { font-size: 13px; opacity: 0.9; }

        /* Tables */
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
            font-size: 14px;
        }
        th {
            background: #4a5568;
            color: white;
            padding: 12px 10px;
            text-align: left;
            font-weight: 600;
        }
        td {
            padding: 10px;
            border-bottom: 1px solid #e2e8f0;
            vertical-align: top;
        }
        tr:hover { background: #f7fafc; }
        code {
            background: #edf2f7;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 12px;
        }

        /* Badges */
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
            text-transform: uppercase;
        }
        .badge-critical { background: #c53030; color: white; }
        .badge-high { background: #dd6b20; color: white; }
        .badge-medium { background: #d69e2e; color: white; }
        .badge-low { background: #3182ce; color: white; }
        .badge-info { background: #718096; color: white; }

        /* Tool badges */
        .tool-badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 10px;
            font-weight: bold;
        }
        .tool-nuclei { background: #9f7aea; color: white; }
        .tool-zap { background: #ed8936; color: white; }
        .tool-nikto { background: #4299e1; color: white; }
        .tool-nse { background: #48bb78; color: white; }
        .tool-sslscan { background: #38b2ac; color: white; }
        .tool-unknown { background: #a0aec0; color: white; }

        /* Grade badges */
        .grade {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 16px;
            font-weight: bold;
        }
        .grade-a { background: #c6f6d5; color: #276749; }
        .grade-b { background: #c6f6d5; color: #276749; }
        .grade-c { background: #fefcbf; color: #b7791f; }
        .grade-d { background: #fed7d7; color: #c53030; }
        .grade-f { background: #fed7d7; color: #c53030; }

        /* SSH Audit card */
        .ssh-audit-card {
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 16px;
        }
        .ssh-audit-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
        }
        .ssh-issues { color: #c53030; }
        .ssh-recs { color: #2b6cb0; }

        /* SSL card */
        .ssl-card {
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 16px;
        }
        .ssl-protocols {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            margin: 10px 0;
        }
        .protocol-badge {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 500;
        }
        .protocol-good { background: #c6f6d5; color: #276749; }
        .protocol-bad { background: #fed7d7; color: #c53030; }
        .protocol-disabled { background: #e2e8f0; color: #a0aec0; }

        /* Info finding */
        .info-finding {
            border: 1px solid #e2e8f0;
            border-radius: 6px;
            padding: 12px;
            margin-bottom: 8px;
            background: #f7fafc;
        }

        /* Scan info grid */
        .scan-info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
        }
        .scan-info-item label {
            font-size: 12px;
            color: #718096;
            display: block;
        }
        .scan-info-item span {
            font-weight: 500;
        }

        @media print {
            body { background: white; }
            .section { box-shadow: none; border: 1px solid #e2e8f0; }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{ scan.name }}</h1>
        <p>{{ scan.description or 'Security Scan Report' }}</p>
        <p><strong>Generated:</strong> {{ now.strftime('%Y-%m-%d %H:%M') }}</p>
    </div>

    <!-- Scan Information -->
    <div class="section">
        <h2>Scan Information</h2>
        <div class="scan-info-grid">
            <div class="scan-info-item">
                <label>Status</label>
                <span>{{ scan.status.upper() }}</span>
            </div>
            <div class="scan-info-item">
                <label>Created</label>
                <span>{{ scan.created_at.strftime('%Y-%m-%d %H:%M') }}</span>
            </div>
            {% if scan.started_at %}
            <div class="scan-info-item">
                <label>Started</label>
                <span>{{ scan.started_at.strftime('%Y-%m-%d %H:%M') }}</span>
            </div>
            {% endif %}
            {% if scan.finished_at %}
            <div class="scan-info-item">
                <label>Finished</label>
                <span>{{ scan.finished_at.strftime('%Y-%m-%d %H:%M') }}</span>
            </div>
            {% endif %}
            {% if duration %}
            <div class="scan-info-item">
                <label>Duration</label>
                <span>{{ duration }}</span>
            </div>
            {% endif %}
        </div>
    </div>

    <!-- Executive Summary -->
    <div class="section">
        <h2>Executive Summary</h2>
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
                <div class="value">{{ vulns|length }}</div>
            </div>
            <div class="metric-card">
                <div class="label">Info Findings</div>
                <div class="value">{{ info_findings|length }}</div>
            </div>
        </div>
        <div class="severity-summary">
            {% if severity_counts.critical > 0 %}
            <span class="severity-badge severity-critical">CRITICAL: {{ severity_counts.critical }}</span>
            {% endif %}
            {% if severity_counts.high > 0 %}
            <span class="severity-badge severity-high">HIGH: {{ severity_counts.high }}</span>
            {% endif %}
            {% if severity_counts.medium > 0 %}
            <span class="severity-badge severity-medium">MEDIUM: {{ severity_counts.medium }}</span>
            {% endif %}
            {% if severity_counts.low > 0 %}
            <span class="severity-badge severity-low">LOW: {{ severity_counts.low }}</span>
            {% endif %}
            {% if severity_counts.info > 0 %}
            <span class="severity-badge severity-info">INFO: {{ severity_counts.info }}</span>
            {% endif %}
        </div>
    </div>

    <!-- Discovered Ports -->
    <div class="section">
        <h2>Discovered Ports <span class="section-count">({{ total_ports }})</span></h2>
        {% for target in targets %}
        <h3>{{ target.device_name or target.ip_address }} ({{ target.ip_address }})</h3>
        {% if target.ports %}
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
                    <td><strong>{{ port.port }}</strong></td>
                    <td>{{ port.protocol }}</td>
                    <td>{{ port.state }}</td>
                    <td>{{ port.service_name or '-' }}</td>
                    <td>{{ port.version or '-' }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% else %}
        <p>No open ports detected</p>
        {% endif %}
        {% endfor %}
    </div>

    <!-- SSH Security Audits -->
    {% if ssh_audits %}
    <div class="section">
        <h2>SSH Security Audits <span class="section-count">({{ ssh_audits|length }})</span></h2>
        {% for audit in ssh_audits %}
        <div class="ssh-audit-card">
            <div class="ssh-audit-header">
                <div>
                    <strong>{{ audit.ip_address }}:{{ audit.port }}</strong>
                    {% if audit.device_name %}<span style="color: #718096;"> - {{ audit.device_name }}</span>{% endif %}
                </div>
                <div>
                    {% if audit.vulnerabilities|length > 0 %}
                    <span class="ssh-issues">{{ audit.vulnerabilities|length }} issues</span>
                    {% endif %}
                    {% if audit.recommendations|length > 0 %}
                    <span class="ssh-recs">{{ audit.recommendations|length }} recommendations</span>
                    {% endif %}
                </div>
            </div>
            {% if audit.ssh_version %}
            <p style="margin: 8px 0; font-size: 13px; color: #4a5568;">Version: {{ audit.ssh_version }}</p>
            {% endif %}
            {% if audit.vulnerabilities %}
            <table style="margin-top: 10px;">
                <thead>
                    <tr><th>Severity</th><th>Issue</th></tr>
                </thead>
                <tbody>
                    {% for issue in audit.vulnerabilities %}
                    <tr>
                        <td><span class="badge badge-{{ issue.severity|lower }}">{{ issue.severity }}</span></td>
                        <td>{{ issue.description }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% endif %}
        </div>
        {% endfor %}
    </div>
    {% endif %}

    <!-- SSL/TLS Analysis -->
    {% if sslscan_results %}
    <div class="section">
        <h2>SSL/TLS Analysis <span class="section-count">({{ sslscan_results|length }})</span></h2>
        {% for ssl in sslscan_results %}
        <div class="ssl-card">
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div>
                    <strong>{{ ssl.ip_address }}:{{ ssl.port }}</strong>
                    <span style="color: #718096;"> ({{ ssl.service_name or 'SSL/TLS' }})</span>
                </div>
                {% if ssl.grade %}
                <span class="grade grade-{{ ssl.grade|lower }}">{{ ssl.grade }}</span>
                {% endif %}
            </div>
            <div class="ssl-protocols">
                <span class="protocol-badge {% if ssl.tlsv13_enabled %}protocol-good{% else %}protocol-disabled{% endif %}">TLS 1.3</span>
                <span class="protocol-badge {% if ssl.tlsv12_enabled %}protocol-good{% else %}protocol-disabled{% endif %}">TLS 1.2</span>
                <span class="protocol-badge {% if ssl.tlsv11_enabled %}protocol-bad{% else %}protocol-disabled{% endif %}">TLS 1.1</span>
                <span class="protocol-badge {% if ssl.tlsv10_enabled %}protocol-bad{% else %}protocol-disabled{% endif %}">TLS 1.0</span>
                <span class="protocol-badge {% if ssl.sslv3_enabled %}protocol-bad{% else %}protocol-disabled{% endif %}">SSLv3</span>
            </div>
            {% if ssl.cert_subject %}
            <p style="font-size: 13px; margin: 8px 0;">
                <strong>Certificate:</strong> {{ ssl.cert_subject }}
                {% if ssl.cert_self_signed %}<span style="color: #dd6b20;">(Self-signed)</span>{% endif %}
                {% if ssl.cert_expired %}<span style="color: #c53030;">(EXPIRED)</span>{% endif %}
            </p>
            {% endif %}
            {% if ssl.findings %}
            <div style="margin-top: 10px;">
                {% for finding in ssl.findings %}
                <span class="badge badge-{{ finding.severity|lower }}" style="margin: 2px;">{{ finding.finding }}</span>
                {% endfor %}
            </div>
            {% endif %}
        </div>
        {% endfor %}
    </div>
    {% endif %}

    <!-- Vulnerabilities (non-INFO) -->
    <div class="section">
        <h2>Vulnerabilities <span class="section-count">({{ vulns|length }})</span></h2>
        {% if vulns %}
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Source</th>
                    <th>Vulnerability</th>
                    <th>Target</th>
                    <th>Template ID</th>
                </tr>
            </thead>
            <tbody>
                {% for vuln in vulns %}
                <tr>
                    <td><span class="badge badge-{{ vuln.severity|lower }}">{{ vuln.severity|upper }}</span></td>
                    <td><span class="tool-badge tool-{{ vuln.source_tool|lower }}">{{ vuln.source_tool|upper }}</span></td>
                    <td>{{ vuln.name }}</td>
                    <td>{{ vuln.ip_address }}{% if vuln.port %}:{{ vuln.port }}{% endif %}</td>
                    <td><code>{{ vuln.template_id }}</code></td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% else %}
        <div style="background: #c6f6d5; padding: 16px; border-radius: 8px; color: #276749;">
            <strong>No vulnerabilities found</strong>
            <p style="margin: 8px 0 0 0;">No critical, high, medium, or low severity vulnerabilities were detected.</p>
        </div>
        {% endif %}
    </div>

    <!-- Informational Findings -->
    {% if info_findings %}
    <div class="section" style="border: 1px solid #e2e8f0;">
        <h2 style="color: #718096;">Informational Findings <span class="section-count">({{ info_findings|length }})</span></h2>
        <p style="color: #718096; margin-bottom: 16px;">Discovery and detection information</p>
        {% for finding in info_findings %}
        <div class="info-finding">
            <div style="display: flex; align-items: center; gap: 8px;">
                <span class="badge badge-info">INFO</span>
                {% if finding.source_tool %}
                <span class="tool-badge tool-{{ finding.source_tool|lower }}">{{ finding.source_tool|upper }}</span>
                {% endif %}
                <strong>{{ finding.name }}</strong>
            </div>
            {% if finding.matched_at %}
            <p style="font-size: 12px; color: #718096; margin: 6px 0 0 0; font-family: monospace;">{{ finding.matched_at }}</p>
            {% endif %}
        </div>
        {% endfor %}
    </div>
    {% endif %}

    <div style="text-align: center; color: #a0aec0; margin-top: 40px; font-size: 12px;">
        <p>Generated by PEEK Security Scanner</p>
    </div>
</body>
</html>
        """

        tmpl = Template(template)

        # Load ports for each target
        total_ports = 0
        for target in targets:
            target.ports = self._load_ports(str(target.id))
            total_ports += len(target.ports)

        return tmpl.render(
            scan=scan,
            targets=targets,
            vulns=vulns,
            info_findings=info_findings,
            ssh_audits=ssh_audits,
            sslscan_results=sslscan_results,
            severity_counts=severity_counts,
            total_ports=total_ports,
            duration=self._format_duration(scan),
            now=datetime.now()
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
                v.source_tool,
                v.description,
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
                'source_tool': row[6] or 'unknown',
                'description': row[7],
                'ip_address': row[8],
                'device_name': row[9]
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

    def _load_ssh_audits(self, scan_id: str) -> List[Dict[str, Any]]:
        """Load SSH audit results for scan"""
        query = text("""
            SELECT
                sa.id,
                p.port as port_number,
                sa.banner,
                sa.ssh_version,
                sa.vulnerabilities,
                sa.recommendations,
                sa.connection_failed,
                sa.failure_reason,
                st.ip_address,
                st.device_name
            FROM ssh_audits sa
            JOIN ports p ON sa.port_id = p.id
            JOIN scan_targets st ON p.scan_target_id = st.id
            WHERE st.scan_id = :scan_id
            ORDER BY st.ip_address, p.port
        """)

        result = self.db.execute(query, {'scan_id': scan_id})

        audits = []
        for row in result:
            import json
            vulns = row[4]
            recs = row[5]
            # Parse JSON if stored as string
            if isinstance(vulns, str):
                try:
                    vulns = json.loads(vulns)
                except:
                    vulns = []
            if isinstance(recs, str):
                try:
                    recs = json.loads(recs)
                except:
                    recs = []

            audits.append({
                'id': row[0],
                'port': row[1],
                'banner': row[2],
                'ssh_version': row[3],
                'vulnerabilities': vulns or [],
                'recommendations': recs or [],
                'connection_failed': row[6],
                'failure_reason': row[7],
                'ip_address': row[8],
                'device_name': row[9]
            })

        return audits

    def _load_sslscan_results(self, scan_id: str) -> List[Dict[str, Any]]:
        """Load SSLScan results for scan"""
        query = text("""
            SELECT
                ss.id,
                ss.sslv2_enabled,
                ss.sslv3_enabled,
                ss.tlsv10_enabled,
                ss.tlsv11_enabled,
                ss.tlsv12_enabled,
                ss.tlsv13_enabled,
                ss.heartbleed_vulnerable,
                ss.cert_subject,
                ss.cert_issuer,
                ss.cert_not_before,
                ss.cert_not_after,
                ss.cert_expired,
                ss.cert_self_signed,
                ss.cert_key_type,
                ss.cert_key_bits,
                ss.findings,
                ss.grade,
                ss.connection_failed,
                p.port,
                p.service_name,
                st.ip_address,
                st.device_name
            FROM sslscan_results ss
            JOIN ports p ON ss.port_id = p.id
            JOIN scan_targets st ON p.scan_target_id = st.id
            WHERE st.scan_id = :scan_id
            ORDER BY st.ip_address, p.port
        """)

        result = self.db.execute(query, {'scan_id': scan_id})

        results = []
        for row in result:
            import json
            findings = row[16]
            if isinstance(findings, str):
                try:
                    findings = json.loads(findings)
                except:
                    findings = []

            results.append({
                'id': row[0],
                'sslv2_enabled': row[1],
                'sslv3_enabled': row[2],
                'tlsv10_enabled': row[3],
                'tlsv11_enabled': row[4],
                'tlsv12_enabled': row[5],
                'tlsv13_enabled': row[6],
                'heartbleed_vulnerable': row[7],
                'cert_subject': row[8],
                'cert_issuer': row[9],
                'cert_not_before': row[10],
                'cert_not_after': row[11],
                'cert_expired': row[12],
                'cert_self_signed': row[13],
                'cert_key_type': row[14],
                'cert_key_bits': row[15],
                'findings': findings or [],
                'grade': row[17],
                'connection_failed': row[18],
                'port': row[19],
                'service_name': row[20],
                'ip_address': row[21],
                'device_name': row[22]
            })

        return results

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
