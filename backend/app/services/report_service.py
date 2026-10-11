from typing import List, Dict, Any, Optional
from datetime import datetime
from io import BytesIO
from xml.sax.saxutils import escape
import json
import logging
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, ListFlowable, ListItem
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
import pandas as pd
from jinja2 import Template
from sqlalchemy.orm import Session
from sqlalchemy import text
from ..models import Scan, ScanTarget, Port, Vulnerability, SSHAudit, ScanComparison, ScanConfig
from ..core.timeutil import utcnow

# Stored timestamps are naive UTC; reports say so explicitly because the reader's
# timezone is unknown when a PDF/HTML/CSV file is generated.
REPORT_TIMEZONE_LABEL = "UTC"

# Comparison PDF: rows listed per section before the rest is summarised as a count,
# and the longest title printed in a row.
COMPARISON_MAX_ROWS_PER_SECTION = 200
COMPARISON_TITLE_MAX_CHARS = 160
# The executive PDF keeps only the most severe rows of each section; the HTML
# report is a single scrolling page, so it can afford far more than the PDF.
COMPARISON_EXECUTIVE_MAX_ROWS_PER_SECTION = 10
COMPARISON_HTML_MAX_ROWS_PER_SECTION = 2000

# Columns of the comparison changes CSV, in order (keys of a stored change).
COMPARISON_CSV_COLUMNS = [
    'type', 'category', 'severity', 'classification', 'ip_address', 'device_name',
    'port', 'protocol', 'service_name', 'product', 'version', 'old_version',
    'new_version', 'name', 'template_id', 'vuln_severity', 'matched_at', 'description',
]
COMPARISON_CSV_CATEGORIES = ('port', 'service', 'vulnerability', 'ssh')
# A cell starting with one of these is run as a formula by spreadsheet apps.
CSV_FORMULA_PREFIXES = ('=', '+', '-', '@', '\t', '\r')

# Stylesheet shared by every HTML report (scan report, comparison report).
REPORT_HTML_STYLES = """
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
        .severity-positive { background: #c6f6d5; color: #276749; }

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
        .badge-positive { background: #38a169; color: white; }

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

        /* Vulnerability card */
        .vuln-card {
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 16px;
            background: white;
        }
        .vuln-card-header {
            display: flex;
            align-items: flex-start;
            gap: 12px;
            margin-bottom: 12px;
        }
        .vuln-card-title {
            font-weight: 600;
            color: #2d3748;
            flex: 1;
        }
        .vuln-card-meta {
            font-size: 12px;
            color: #718096;
            margin-bottom: 8px;
        }
        .vuln-description {
            color: #4a5568;
            margin: 8px 0;
            font-size: 14px;
        }
        .vuln-tags {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
            margin-top: 8px;
        }
        .vuln-tag {
            background: #edf2f7;
            color: #4a5568;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 11px;
        }
        .vuln-refs {
            font-size: 12px;
            color: #667eea;
            margin-top: 8px;
        }
        .vuln-refs a {
            color: #667eea;
            text-decoration: none;
        }
        .vuln-refs a:hover {
            text-decoration: underline;
        }
        .extracted-data {
            background: #f7fafc;
            border-radius: 4px;
            padding: 10px;
            margin-top: 10px;
            font-size: 12px;
        }
        .extracted-data dt {
            font-weight: 600;
            color: #4a5568;
        }
        .extracted-data dd {
            margin: 0 0 6px 0;
            color: #718096;
        }

        /* NSE card */
        .nse-card {
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 16px;
        }
        .nse-script {
            border-left: 3px solid #48bb78;
            padding-left: 12px;
            margin: 10px 0;
        }
        .nse-output {
            background: #1a202c;
            color: #e2e8f0;
            padding: 12px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 12px;
            white-space: pre-wrap;
            max-height: 200px;
            overflow-y: auto;
            margin-top: 8px;
        }

        /* Algorithm list */
        .algo-list {
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
            margin: 6px 0;
        }
        .algo-item {
            background: #edf2f7;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 11px;
            font-family: monospace;
        }
        .algo-item.weak { background: #fed7d7; color: #c53030; }

        /* Recommendations list */
        .rec-list {
            list-style: none;
            padding: 0;
            margin: 10px 0;
        }
        .rec-list li {
            padding: 6px 0 6px 20px;
            position: relative;
            font-size: 13px;
            border-bottom: 1px solid #f0f0f0;
        }
        .rec-list li:before {
            content: "→";
            position: absolute;
            left: 0;
            color: #667eea;
        }

        @media print {
            body { background: white; }
            .section { box-shadow: none; border: 1px solid #e2e8f0; }
        }
"""

logger = logging.getLogger(__name__)


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
            spaceAfter=10,
            alignment=TA_CENTER
        ))

        self.styles.add(ParagraphStyle(
            name='Subtitle',
            parent=self.styles['Normal'],
            fontSize=12,
            textColor=colors.HexColor('#718096'),
            spaceAfter=20,
            alignment=TA_CENTER
        ))

        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#2d3748'),
            spaceAfter=12,
            spaceBefore=16
        ))

        self.styles.add(ParagraphStyle(
            name='SubSection',
            parent=self.styles['Heading3'],
            fontSize=12,
            textColor=colors.HexColor('#4a5568'),
            spaceAfter=8,
            spaceBefore=10
        ))

        self.styles.add(ParagraphStyle(
            name='SmallText',
            parent=self.styles['Normal'],
            fontSize=8,
            textColor=colors.HexColor('#718096')
        ))

        self.styles.add(ParagraphStyle(
            name='ComparisonCell',
            parent=self.styles['Normal'],
            fontSize=8,
            leading=10
        ))

        self.styles.add(ParagraphStyle(
            name='RecommendationItem',
            parent=self.styles['Normal'],
            fontSize=10,
            leftIndent=20,
            spaceBefore=4,
            spaceAfter=4
        ))

    # ==================== PDF REPORTS ====================

    def generate_executive_summary_pdf(self, scan_id: str) -> BytesIO:
        """Generate executive summary PDF (2-3 pages max)"""
        scan = self._load_scan(scan_id)
        title, subtitle = self._get_report_title(scan)

        # Load all data
        vulns = self._load_vulnerabilities(scan_id)
        ssh_audits = self._load_ssh_audits(scan_id)
        ssl_results = self._load_sslscan_results(scan_id)
        severity_counts = self._get_severity_counts(vulns)

        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)
        story = []

        # Title with config name as primary identifier
        story.append(Paragraph(title, self.styles['CustomTitle']))
        story.append(Paragraph(f"Executive Security Summary", self.styles['Subtitle']))
        story.append(Paragraph(subtitle, self.styles['SmallText']))
        story.append(Spacer(1, 0.2*inch))

        # ============ QUICK STATS BOX ============
        story.append(Paragraph("Scan Overview", self.styles['SectionHeader']))

        non_info = len([v for v in vulns if (v['severity'] or '').lower() != 'info'])
        stats_data = [
            ['Scan Duration', 'Open Ports', 'Vulnerabilities', 'Critical / High'],
            [
                self._format_duration(scan),
                str(scan.total_open_ports),
                f"{non_info} (+{len(vulns) - non_info} info)",
                f"{severity_counts['critical']} CRIT / {severity_counts['high']} HIGH"
            ]
        ]

        stats_table = Table(stats_data, colWidths=[1.5*inch, 1.5*inch, 1.5*inch, 1.5*inch])
        stats_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('FONTSIZE', (0, 1), (-1, 1), 11),
            ('FONTNAME', (0, 1), (-1, 1), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('TOPPADDING', (0, 1), (-1, 1), 10),
            ('BOTTOMPADDING', (0, 1), (-1, 1), 10),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f7fafc')),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#667eea'))
        ]))
        story.append(stats_table)
        story.append(Spacer(1, 0.2*inch))

        # ============ SEVERITY BREAKDOWN ============
        story.append(Paragraph("Vulnerability Severity Breakdown", self.styles['SectionHeader']))

        severity_data = [
            ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
            [
                str(severity_counts['critical']),
                str(severity_counts['high']),
                str(severity_counts['medium']),
                str(severity_counts['low']),
                str(severity_counts['info'])
            ]
        ]

        severity_table = Table(severity_data, colWidths=[1.2*inch, 1.2*inch, 1.2*inch, 1.2*inch, 1.2*inch])
        severity_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, 0), colors.HexColor('#c53030')),  # Critical
            ('BACKGROUND', (1, 0), (1, 0), colors.HexColor('#dd6b20')),  # High
            ('BACKGROUND', (2, 0), (2, 0), colors.HexColor('#d69e2e')),  # Medium
            ('BACKGROUND', (3, 0), (3, 0), colors.HexColor('#3182ce')),  # Low
            ('BACKGROUND', (4, 0), (4, 0), colors.HexColor('#718096')),  # Info
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('FONTSIZE', (0, 1), (-1, 1), 14),
            ('FONTNAME', (0, 1), (-1, 1), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
            ('TOPPADDING', (0, 1), (-1, 1), 8),
            ('BOTTOMPADDING', (0, 1), (-1, 1), 8),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#edf2f7')),
            ('BOX', (0, 0), (-1, -1), 1, colors.grey)
        ]))
        story.append(severity_table)
        story.append(Spacer(1, 0.2*inch))

        # ============ SECURITY POSTURE ============
        story.append(Paragraph("Security Posture Indicators", self.styles['SectionHeader']))

        posture_items = []

        # SSH Security
        total_ssh_issues = sum(len(a.get('vulnerabilities', [])) for a in ssh_audits)
        total_ssh_recs = sum(len(a.get('recommendations', [])) for a in ssh_audits)
        if ssh_audits:
            posture_items.append(f"<b>SSH Security:</b> {total_ssh_issues} issues, {total_ssh_recs} recommendations")

        # SSL/TLS
        if ssl_results:
            grades = [s.get('grade', 'N/A') for s in ssl_results if s.get('grade')]
            if grades:
                grade_summary = ', '.join([f"Port {s['port']}: {s.get('grade', 'N/A')}" for s in ssl_results[:3]])
                posture_items.append(f"<b>SSL/TLS Grades:</b> {grade_summary}")

        # Unauthenticated services
        unauth_vulns = [v for v in vulns if 'unauth' in v['name'].lower() or 'no auth' in v['name'].lower()]
        if unauth_vulns:
            posture_items.append(f"<b>Unauthenticated Services:</b> {len(unauth_vulns)} found requiring immediate attention")

        if posture_items:
            for item in posture_items:
                story.append(Paragraph(f"• {item}", self.styles['Normal']))
                story.append(Spacer(1, 0.05*inch))
        else:
            story.append(Paragraph("No significant security posture concerns identified.", self.styles['Normal']))

        story.append(Spacer(1, 0.15*inch))

        # ============ CRITICAL FINDINGS ============
        story.append(Paragraph("Critical & High Severity Findings", self.styles['SectionHeader']))
        critical_vulns = self._get_critical_vulnerabilities(scan_id, limit=8)

        if critical_vulns:
            vuln_data = [['Severity', 'Finding', 'Target', 'Port']]
            for vuln in critical_vulns:
                name = vuln['name'][:40] + '...' if len(vuln['name']) > 40 else vuln['name']
                vuln_data.append([
                    vuln['severity'].upper(),
                    name,
                    vuln['ip_address'],
                    str(vuln['port']) if vuln['port'] else '-'
                ])

            vuln_table = Table(vuln_data, colWidths=[0.8*inch, 3*inch, 1.3*inch, 0.6*inch])
            vuln_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4a5568')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('ALIGN', (3, 0), (3, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f7fafc')]),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0'))
            ]))
            story.append(vuln_table)
        else:
            story.append(Paragraph(
                "<font color='#276749'>✓ No critical or high severity vulnerabilities detected.</font>",
                self.styles['Normal']
            ))

        story.append(Spacer(1, 0.2*inch))

        # ============ RECOMMENDATIONS ============
        story.append(Paragraph("Priority Recommendations", self.styles['SectionHeader']))
        recommendations = self._generate_recommendations(scan_id)

        for i, rec in enumerate(recommendations[:7], 1):
            # Color-code based on severity indicator in recommendation
            if rec.startswith('CRITICAL:'):
                rec_text = f"<font color='#c53030'><b>{i}.</b></font> {rec}"
            elif rec.startswith('HIGH:'):
                rec_text = f"<font color='#dd6b20'><b>{i}.</b></font> {rec}"
            else:
                rec_text = f"<b>{i}.</b> {rec}"
            story.append(Paragraph(rec_text, self.styles['RecommendationItem']))

        story.append(Spacer(1, 0.3*inch))

        # Footer
        story.append(Paragraph(
            f"<font color='#a0aec0'>Generated by PEEK Security Scanner • {self._format_timestamp(utcnow())}</font>",
            self.styles['SmallText']
        ))

        # Build PDF
        doc.build(story)
        buffer.seek(0)
        return buffer

    def generate_technical_report_pdf(self, scan_id: str) -> BytesIO:
        """Generate detailed technical report PDF with all security findings"""
        scan = self._load_scan(scan_id)
        title, subtitle = self._get_report_title(scan)

        # Load all data
        vulns = self._load_vulnerabilities(scan_id)
        ssh_audits = self._load_ssh_audits(scan_id)
        ssl_results = self._load_sslscan_results(scan_id)
        nse_findings = self._load_nse_findings(scan_id)
        severity_counts = self._get_severity_counts(vulns)

        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch)
        story = []

        # ============ TITLE PAGE ============
        story.append(Paragraph(title, self.styles['CustomTitle']))
        story.append(Paragraph("Technical Security Report", self.styles['Subtitle']))
        story.append(Paragraph(subtitle, self.styles['SmallText']))
        story.append(Spacer(1, 0.3*inch))

        # ============ SCAN INFORMATION ============
        story.append(Paragraph("1. Scan Information", self.styles['SectionHeader']))
        info_data = [
            ['Configuration', title],
            ['Run Number', str(scan.run_number)],
            ['Description', scan.description or 'N/A'],
            ['Start Time (UTC)', self._format_timestamp(scan.started_at, seconds=True)],
            ['End Time (UTC)', self._format_timestamp(scan.finished_at, seconds=True)],
            ['Duration', self._format_duration(scan)],
            ['Status', scan.status.upper()],
            ['Total Targets', str(scan.total_targets)],
            ['Open Ports Found', str(scan.total_open_ports)],
        ]

        info_table = Table(info_data, colWidths=[1.8*inch, 4.2*inch])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e2e8f0')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        story.append(info_table)
        story.append(Spacer(1, 0.2*inch))

        # ============ EXECUTIVE SUMMARY ============
        story.append(Paragraph("2. Executive Summary", self.styles['SectionHeader']))

        summary_data = [
            ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
            [str(severity_counts['critical']), str(severity_counts['high']),
             str(severity_counts['medium']), str(severity_counts['low']), str(severity_counts['info'])]
        ]
        summary_table = Table(summary_data, colWidths=[1.2*inch]*5)
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, 0), colors.HexColor('#c53030')),
            ('BACKGROUND', (1, 0), (1, 0), colors.HexColor('#dd6b20')),
            ('BACKGROUND', (2, 0), (2, 0), colors.HexColor('#d69e2e')),
            ('BACKGROUND', (3, 0), (3, 0), colors.HexColor('#3182ce')),
            ('BACKGROUND', (4, 0), (4, 0), colors.HexColor('#718096')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('FONTSIZE', (0, 1), (-1, 1), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f7fafc')),
            ('BOX', (0, 0), (-1, -1), 1, colors.grey)
        ]))
        story.append(summary_table)
        story.append(PageBreak())

        # ============ DISCOVERED SERVICES ============
        story.append(Paragraph("3. Discovered Services", self.styles['SectionHeader']))
        targets = self._load_targets(scan_id)

        for target in targets[:10]:  # Limit for PDF size
            story.append(Paragraph(
                f"<b>{target.device_name or target.ip_address}</b> ({target.ip_address})",
                self.styles['SubSection']
            ))

            ports = self._load_ports(str(target.id))
            if ports:
                port_data = [['Port', 'Proto', 'State', 'Service', 'Version']]
                for port in ports[:25]:
                    version = (port.version[:25] + '...') if port.version and len(port.version) > 25 else (port.version or '-')
                    port_data.append([
                        str(port.port),
                        port.protocol,
                        port.state,
                        port.service_name or '-',
                        version
                    ])

                port_table = Table(port_data, colWidths=[0.6*inch, 0.5*inch, 0.6*inch, 1.3*inch, 3*inch])
                port_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4a5568')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 8),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f7fafc')])
                ]))
                story.append(port_table)
            else:
                story.append(Paragraph("No open ports detected", self.styles['Normal']))

            story.append(Spacer(1, 0.15*inch))

        story.append(PageBreak())

        # ============ VULNERABILITY DETAILS ============
        story.append(Paragraph("4. Vulnerability Details", self.styles['SectionHeader']))
        non_info_vulns = [v for v in vulns if v['severity'].lower() != 'info']

        if non_info_vulns:
            for vuln in non_info_vulns[:30]:
                severity_color = self._get_severity_color(vuln['severity'])
                story.append(Paragraph(
                    f"<font color='{severity_color}'><b>[{vuln['severity'].upper()}]</b></font> {vuln['name']}",
                    self.styles['SubSection']
                ))
                story.append(Paragraph(
                    f"<b>Target:</b> {vuln['ip_address']}:{vuln['port'] or 'N/A'} | "
                    f"<b>Template:</b> {vuln['template_id']} | "
                    f"<b>Source:</b> {vuln['source_tool'].upper()}",
                    self.styles['SmallText']
                ))

                # Description
                if vuln.get('description'):
                    desc = vuln['description'][:200] + '...' if len(vuln['description']) > 200 else vuln['description']
                    story.append(Paragraph(desc, self.styles['Normal']))

                # References
                if vuln.get('references'):
                    refs = vuln['references'][:3]  # Limit to 3 refs
                    ref_text = ' | '.join(refs) if isinstance(refs, list) else str(refs)
                    if len(ref_text) > 100:
                        ref_text = ref_text[:100] + '...'
                    story.append(Paragraph(f"<b>References:</b> {ref_text}", self.styles['SmallText']))

                story.append(Spacer(1, 0.1*inch))
        else:
            story.append(Paragraph(
                "<font color='#276749'>No critical, high, medium, or low severity vulnerabilities detected.</font>",
                self.styles['Normal']
            ))

        story.append(PageBreak())

        # ============ SSH SECURITY AUDITS ============
        if ssh_audits:
            story.append(Paragraph("5. SSH Security Audits", self.styles['SectionHeader']))

            for audit in ssh_audits[:10]:
                story.append(Paragraph(
                    f"<b>{audit['ip_address']}:{audit['port']}</b>",
                    self.styles['SubSection']
                ))

                if audit.get('ssh_version'):
                    story.append(Paragraph(f"SSH Version: {audit['ssh_version']}", self.styles['SmallText']))
                if audit.get('banner'):
                    banner = audit['banner'][:80] + '...' if len(audit['banner']) > 80 else audit['banner']
                    story.append(Paragraph(f"Banner: {banner}", self.styles['SmallText']))

                # Issues table
                issues = audit.get('vulnerabilities', [])
                if issues:
                    issue_data = [['Severity', 'Issue']]
                    for issue in issues[:10]:
                        sev = issue.get('severity', 'info')
                        desc = issue.get('description', str(issue))[:60]
                        issue_data.append([sev.upper(), desc])

                    issue_table = Table(issue_data, colWidths=[1*inch, 5*inch])
                    issue_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4a5568')),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, -1), 8),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0'))
                    ]))
                    story.append(issue_table)

                # Recommendations
                recs = audit.get('recommendations', [])
                if recs:
                    story.append(Paragraph(f"<b>Recommendations ({len(recs)}):</b>", self.styles['SmallText']))
                    for rec in recs[:5]:
                        rec_text = rec.get('description', str(rec)) if isinstance(rec, dict) else str(rec)
                        if len(rec_text) > 80:
                            rec_text = rec_text[:80] + '...'
                        story.append(Paragraph(f"• {rec_text}", self.styles['SmallText']))

                story.append(Spacer(1, 0.15*inch))

            story.append(PageBreak())

        # ============ SSL/TLS ANALYSIS ============
        if ssl_results:
            story.append(Paragraph("6. SSL/TLS Analysis", self.styles['SectionHeader']))

            for ssl in ssl_results[:10]:
                grade = ssl.get('grade', 'N/A')
                grade_color = '#276749' if grade in ['A', 'A+', 'B'] else '#c53030' if grade in ['D', 'F'] else '#d69e2e'

                story.append(Paragraph(
                    f"<b>{ssl['ip_address']}:{ssl['port']}</b> ({ssl.get('service_name', 'SSL/TLS')}) - "
                    f"<font color='{grade_color}'><b>Grade: {grade}</b></font>",
                    self.styles['SubSection']
                ))

                # Protocols
                protocols = []
                if ssl.get('tlsv13_enabled'): protocols.append('TLS 1.3 ✓')
                if ssl.get('tlsv12_enabled'): protocols.append('TLS 1.2 ✓')
                if ssl.get('tlsv11_enabled'): protocols.append('TLS 1.1 ⚠')
                if ssl.get('tlsv10_enabled'): protocols.append('TLS 1.0 ⚠')
                if ssl.get('sslv3_enabled'): protocols.append('SSLv3 ✗')
                story.append(Paragraph(f"Protocols: {', '.join(protocols)}", self.styles['SmallText']))

                # Certificate
                if ssl.get('cert_subject'):
                    cert_info = f"CN: {ssl['cert_subject']}"
                    if ssl.get('cert_self_signed'):
                        cert_info += " (SELF-SIGNED)"
                    if ssl.get('cert_expired'):
                        cert_info += " (EXPIRED)"
                    story.append(Paragraph(f"Certificate: {cert_info}", self.styles['SmallText']))

                # Findings
                findings = ssl.get('findings', [])
                if findings:
                    for finding in findings[:3]:
                        f_text = finding.get('finding', str(finding)) if isinstance(finding, dict) else str(finding)
                        story.append(Paragraph(f"• {f_text}", self.styles['SmallText']))

                story.append(Spacer(1, 0.1*inch))

            story.append(PageBreak())

        # ============ NSE SCRIPT RESULTS ============
        if nse_findings:
            story.append(Paragraph("7. NSE Script Results", self.styles['SectionHeader']))

            grouped = self._group_nse_by_target(nse_findings)
            for target_key, findings in list(grouped.items())[:15]:
                story.append(Paragraph(
                    f"<b>{target_key}</b> ({len(findings)} scripts)",
                    self.styles['SubSection']
                ))

                for finding in findings[:5]:
                    sev_color = self._get_severity_color(finding.get('severity', 'info'))
                    story.append(Paragraph(
                        f"<font color='{sev_color}'>[{finding['severity'].upper()}]</font> "
                        f"<b>{finding['script_id']}</b> ({finding['profile_name']})",
                        self.styles['SmallText']
                    ))

                    # Show extracted elements if available
                    elements = finding.get('elements', {})
                    if elements and isinstance(elements, dict):
                        for k, v in list(elements.items())[:3]:
                            v_str = str(v)[:50] + '...' if len(str(v)) > 50 else str(v)
                            story.append(Paragraph(f"  {k}: {v_str}", self.styles['SmallText']))

                story.append(Spacer(1, 0.1*inch))

        # ============ FOOTER ============
        story.append(Spacer(1, 0.3*inch))
        story.append(Paragraph(
            f"<font color='#a0aec0'>Generated by PEEK Security Scanner • {self._format_timestamp(utcnow())}</font>",
            self.styles['SmallText']
        ))

        # Build PDF
        doc.build(story)
        buffer.seek(0)
        return buffer

    def generate_comparison_report_pdf(self, comparison_id: str, executive: bool = False) -> BytesIO:
        """
        Generate comparison report PDF.

        The detailed report lists the changes of every section (capped at
        COMPARISON_MAX_ROWS_PER_SECTION); the executive summary keeps the same
        layout but only the few most severe changes of each section.
        """
        comparison = self._load_comparison(comparison_id)
        max_rows = (COMPARISON_EXECUTIVE_MAX_ROWS_PER_SECTION if executive
                    else COMPARISON_MAX_ROWS_PER_SECTION)

        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        story = []

        # Title
        story.append(Paragraph(
            "Scan Comparison Executive Summary" if executive else "Scan Comparison Report",
            self.styles['CustomTitle']
        ))
        story.append(Paragraph(
            f"Compared {self._format_timestamp(comparison.created_at)}",
            self.styles['Subtitle']
        ))

        # Scans compared
        story.append(Paragraph("Scans Compared", self.styles['SectionHeader']))
        scan_data = [['', 'Scan', f'Started ({REPORT_TIMEZONE_LABEL})', f'Finished ({REPORT_TIMEZONE_LABEL})']]
        for label, scan in self._comparison_scans(comparison):
            scan_data.append([
                label,
                self._comparison_cell(self._comparison_scan_label(scan)),
                self._format_timestamp(scan.started_at if scan else None),
                self._format_timestamp(scan.finished_at if scan else None),
            ])
        scan_table = Table(scan_data, colWidths=[0.9*inch, 2.6*inch, 1.5*inch, 1.5*inch])
        scan_table.setStyle(self._comparison_table_style())
        story.append(scan_table)
        story.append(Spacer(1, 0.2*inch))

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

        # Changes, one table per kind of change
        for section in self._comparison_sections(comparison.changes or [], max_rows=max_rows):
            story.append(Paragraph(
                f"{section['title']} ({section['total']})", self.styles['SectionHeader']
            ))
            for note in section['notes']:
                story.append(Paragraph(escape(note), self.styles['SmallText']))
            if not section['rows']:
                story.append(Paragraph("None.", self.styles['Normal']))
                continue

            table_data = [['Severity', 'Host:Port', section['detail_header']]]
            for row in section['rows']:
                sev_color = self._get_severity_color(row['severity'])
                table_data.append([
                    Paragraph(
                        f"<font color='{sev_color}'><b>{escape(row['severity'].upper())}</b></font>",
                        self.styles['SmallText']
                    ),
                    self._comparison_cell(row['location']),
                    self._comparison_cell(row['title']),
                ])
            # repeatRows keeps the header on every page a long table spills onto
            change_table = Table(table_data, colWidths=[0.9*inch, 2.1*inch, 3.5*inch], repeatRows=1)
            change_table.setStyle(self._comparison_table_style())
            story.append(change_table)

        # Footer
        story.append(Spacer(1, 0.3*inch))
        story.append(Paragraph(
            f"<font color='#a0aec0'>Generated by PEEK Security Scanner • {self._format_timestamp(utcnow())}</font>",
            self.styles['SmallText']
        ))

        # Build PDF
        doc.build(story)
        buffer.seek(0)
        return buffer

    def _load_comparison(self, comparison_id: str) -> ScanComparison:
        comparison = self.db.query(ScanComparison).filter(
            ScanComparison.id == comparison_id
        ).first()
        if not comparison:
            raise ValueError("Comparison not found")
        return comparison

    def _comparison_scans(self, comparison: ScanComparison) -> List[tuple]:
        """``(label, scan)`` for both sides; the scan is None once it has been deleted."""
        return [
            (label, self.db.query(Scan).filter(Scan.id == scan_id).first())
            for label, scan_id in (('Baseline', comparison.baseline_scan_id),
                                   ('Current', comparison.current_scan_id))
        ]

    def _comparison_cell(self, text_value: str) -> Paragraph:
        """Wrapping table cell; scan data is escaped because Paragraph parses markup."""
        return Paragraph(escape(text_value), self.styles['ComparisonCell'])

    @staticmethod
    def _comparison_table_style() -> TableStyle:
        return TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4a5568')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f7fafc')]),
        ])

    @staticmethod
    def _comparison_scan_label(scan: Optional[Scan]) -> str:
        if not scan:
            return "Scan no longer available"
        if scan.run_number:
            return f"{scan.name} (Run #{scan.run_number})"
        return scan.name

    @staticmethod
    def _comparison_location(change: Dict[str, Any]) -> str:
        """host:port[/protocol], with the device name when one is known."""
        location = str(change.get('ip_address') or 'unknown host')
        if change.get('port'):
            location += f":{change['port']}"
            if change.get('protocol'):
                location += f"/{change['protocol']}"
        if change.get('device_name'):
            location += f" ({change['device_name']})"
        return location

    @staticmethod
    def _truncate(value: str, limit: int = COMPARISON_TITLE_MAX_CHARS) -> str:
        return value if len(value) <= limit else value[:limit - 3] + '...'

    def _comparison_sections(
        self, changes: List[Dict[str, Any]], max_rows: int = COMPARISON_MAX_ROWS_PER_SECTION
    ) -> List[Dict[str, Any]]:
        """
        Group comparison changes into the report's sections.

        Each section lists the most severe changes first and is capped at
        ``max_rows`` so a comparison with thousands of changes still produces a
        PDF of bounded size; ``total`` keeps the real count.
        """
        def service_title(change):
            parts = [change.get('service_name'), change.get('product'), change.get('version')]
            return ' '.join(str(p) for p in parts if p) or 'unknown service'

        def closed_port_title(change):
            title = service_title(change)
            associated = change.get('associated_vulnerabilities') or []
            if associated:
                noun = 'vulnerability' if len(associated) == 1 else 'vulnerabilities'
                title += f" - {len(associated)} associated {noun} no longer exposed"
            return title

        def version_title(change):
            return (f"{change.get('service_name') or 'unknown service'}: "
                    f"{change.get('old_version')} → {change.get('new_version')}")

        def vuln_title(change):
            title = str(change.get('name') or change.get('template_id') or 'Unnamed finding')
            if change.get('template_id') and change.get('name'):
                title += f" [{change['template_id']}]"
            if change.get('classification') == 'SUPPRESSED':
                title += " (suppressed)"
            return title

        def change_severity(change):
            return str(change.get('severity') or 'info').lower()

        def vuln_severity(change):
            return str(change.get('vuln_severity') or 'info').lower()

        layout = [
            ('New Ports', 'Service', ('NEW_PORT',), change_severity, service_title),
            ('Closed Ports', 'Service', ('CLOSED_PORT',), change_severity, closed_port_title),
            ('Version Changes', 'Change', ('VERSION_UPDATE',), change_severity, version_title),
            ('New Vulnerabilities', 'Title', ('NEW_VULNERABILITY',), vuln_severity, vuln_title),
            ('Fixed Vulnerabilities', 'Title', ('FIXED_VULNERABILITY',), vuln_severity, vuln_title),
        ]
        known_types = {t for _, _, types, _, _ in layout for t in types}
        other = [c for c in changes if c.get('type') not in known_types]

        severity_rank = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4, 'positive': 5}

        def build(title, detail_header, items, severity_of, title_of):
            def sort_key(change):
                try:
                    port = int(change.get('port') or 0)
                except (TypeError, ValueError):
                    port = 0
                return (
                    change.get('classification') == 'SUPPRESSED',
                    severity_rank.get(severity_of(change), len(severity_rank)),
                    str(change.get('ip_address') or ''),
                    port,
                )

            ordered = sorted(items, key=sort_key)
            notes = []
            suppressed = sum(1 for c in items if c.get('classification') == 'SUPPRESSED')
            if suppressed:
                notes.append(
                    f"{suppressed} suppressed by triage (listed last, not counted in the summary)."
                )
            if len(ordered) > max_rows:
                notes.append(
                    f"Showing the {max_rows} most severe of {len(ordered)}; "
                    f"{len(ordered) - max_rows} more are available in the PEEK comparison view."
                )
            return {
                'title': title,
                'detail_header': detail_header,
                'total': len(ordered),
                'notes': notes,
                'rows': [
                    {
                        'severity': severity_of(c),
                        'location': self._comparison_location(c),
                        'title': self._truncate(title_of(c)),
                    }
                    for c in ordered[:max_rows]
                ],
            }

        sections = [
            build(title, header, [c for c in changes if c.get('type') in types], severity_of, title_of)
            for title, header, types, severity_of, title_of in layout
        ]
        if other:
            # e.g. SSH audit changes: no dedicated section, but never dropped silently
            sections.append(build(
                'Other Changes', 'Change', other, change_severity,
                lambda c: str(c.get('description') or c.get('type') or 'Change'),
            ))
        return sections

    # ==================== HTML REPORTS ====================

    def generate_html_report(self, scan_id: str) -> str:
        """Generate comprehensive HTML report with all security findings"""
        scan = self._load_scan(scan_id)
        title, subtitle = self._get_report_title(scan)
        targets = self._load_targets(scan_id)
        all_vulns = self._load_vulnerabilities(scan_id)
        ssh_audits = self._load_ssh_audits(scan_id)
        sslscan_results = self._load_sslscan_results(scan_id)
        nse_findings = self._load_nse_findings(scan_id)
        nse_grouped = self._group_nse_by_target(nse_findings)

        # Separate vulnerabilities from informational findings
        vulns = [v for v in all_vulns if v['severity'].lower() in ['critical', 'high', 'medium', 'low']]
        info_findings = [v for v in all_vulns
                        if v['severity'].lower() == 'info'
                        and v['name']
                        and 'unknown' not in v['name'].lower()]

        # Count by severity
        severity_counts = self._get_severity_counts(all_vulns)

        template = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Security Scan Report - {{ title }}</title>
    <style>
{{ report_styles|safe }}    </style>
</head>
<body>
    <div class="header">
        <h1>{{ title }}</h1>
        <p style="font-size: 16px; margin: 5px 0;">{{ subtitle }}</p>
        <p>{{ scan.description or 'Security Scan Report' }}</p>
        <p><strong>Generated:</strong> {{ format_ts(now) }}</p>
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
                <span>{{ format_ts(scan.created_at) }}</span>
            </div>
            {% if scan.started_at %}
            <div class="scan-info-item">
                <label>Started</label>
                <span>{{ format_ts(scan.started_at) }}</span>
            </div>
            {% endif %}
            {% if scan.finished_at %}
            <div class="scan-info-item">
                <label>Finished</label>
                <span>{{ format_ts(scan.finished_at) }}</span>
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
            <p style="margin: 8px 0; font-size: 13px; color: #4a5568;">
                <strong>Version:</strong> {{ audit.ssh_version }}
                {% if audit.banner %}<br><strong>Banner:</strong> <code>{{ audit.banner[:80] }}{% if audit.banner|length > 80 %}...{% endif %}</code>{% endif %}
            </p>
            {% endif %}

            {% if audit.vulnerabilities %}
            <h4 style="color: #c53030; margin: 12px 0 8px;">Security Issues</h4>
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

            {% if audit.recommendations %}
            <h4 style="color: #2b6cb0; margin: 16px 0 8px;">Recommendations ({{ audit.recommendations|length }})</h4>
            <ul class="rec-list">
                {% for rec in audit.recommendations %}
                <li>{{ rec.description if rec.description is defined else rec }}</li>
                {% endfor %}
            </ul>
            {% endif %}

            {% if audit.key_exchange_algorithms or audit.encryption_algorithms or audit.mac_algorithms %}
            <details style="margin-top: 12px;">
                <summary style="cursor: pointer; color: #667eea; font-weight: 500;">Algorithm Details</summary>
                <div style="padding: 12px 0;">
                    {% if audit.key_exchange_algorithms %}
                    <p style="font-size: 12px; margin: 6px 0;"><strong>Key Exchange:</strong></p>
                    <div class="algo-list">
                        {% for algo in audit.key_exchange_algorithms %}
                        <span class="algo-item {% if 'sha1' in algo or 'diffie-hellman-group1' in algo %}weak{% endif %}">{{ algo }}</span>
                        {% endfor %}
                    </div>
                    {% endif %}
                    {% if audit.encryption_algorithms %}
                    <p style="font-size: 12px; margin: 6px 0;"><strong>Encryption:</strong></p>
                    <div class="algo-list">
                        {% for algo in audit.encryption_algorithms %}
                        <span class="algo-item {% if 'cbc' in algo or '3des' in algo or 'arcfour' in algo %}weak{% endif %}">{{ algo }}</span>
                        {% endfor %}
                    </div>
                    {% endif %}
                    {% if audit.mac_algorithms %}
                    <p style="font-size: 12px; margin: 6px 0;"><strong>MAC:</strong></p>
                    <div class="algo-list">
                        {% for algo in audit.mac_algorithms %}
                        <span class="algo-item {% if 'md5' in algo or 'sha1' in algo and 'sha1-96' in algo %}weak{% endif %}">{{ algo }}</span>
                        {% endfor %}
                    </div>
                    {% endif %}
                </div>
            </details>
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

    <!-- NSE Script Results -->
    {% if nse_grouped %}
    <div class="section">
        <h2>NSE Script Results <span class="section-count">({{ nse_findings|length }} scripts)</span></h2>
        {% for target_key, findings in nse_grouped.items() %}
        <div class="nse-card">
            <h3 style="margin: 0 0 12px 0; color: #2d3748;">{{ target_key }} <span class="section-count">({{ findings|length }} scripts)</span></h3>
            {% for finding in findings %}
            <div class="nse-script">
                <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 6px;">
                    <span class="badge badge-{{ finding.severity|lower }}">{{ finding.severity|upper }}</span>
                    <strong>{{ finding.script_id }}</strong>
                    <span class="tool-badge tool-nse">{{ finding.profile_name }}</span>
                </div>
                {% if finding.elements and finding.elements|length > 0 %}
                <div class="extracted-data" style="margin: 8px 0;">
                    <dl style="margin: 0;">
                    {% for key, value in finding.elements.items() %}
                        <dt>{{ key }}</dt>
                        <dd>{{ value }}</dd>
                    {% endfor %}
                    </dl>
                </div>
                {% endif %}
                {% if finding.raw_output %}
                <details style="margin-top: 8px;">
                    <summary style="cursor: pointer; color: #667eea; font-size: 12px;">View Raw Output</summary>
                    <div class="nse-output">{{ finding.raw_output }}</div>
                </details>
                {% endif %}
            </div>
            {% endfor %}
        </div>
        {% endfor %}
    </div>
    {% endif %}

    <!-- Vulnerabilities (non-INFO) -->
    <div class="section">
        <h2>Vulnerabilities <span class="section-count">({{ vulns|length }})</span></h2>
        {% if vulns %}
        {% for vuln in vulns %}
        <div class="vuln-card">
            <div class="vuln-card-header">
                <span class="badge badge-{{ vuln.severity|lower }}">{{ vuln.severity|upper }}</span>
                <span class="tool-badge tool-{{ vuln.source_tool|lower }}">{{ vuln.source_tool|upper }}</span>
                <div class="vuln-card-title">{{ vuln.name }}</div>
            </div>
            <div class="vuln-card-meta">
                <strong>Target:</strong> {{ vuln.ip_address }}{% if vuln.port %}:{{ vuln.port }}{% endif %} |
                <strong>Template:</strong> <code>{{ vuln.template_id }}</code>
                {% if vuln.timestamp %} | <strong>Discovered:</strong> {{ vuln.timestamp }}{% endif %}
            </div>
            {% if vuln.description %}
            <div class="vuln-description">{{ vuln.description }}</div>
            {% endif %}
            {% if vuln.tags and vuln.tags|length > 0 %}
            <div class="vuln-tags">
                {% for tag in vuln.tags %}
                <span class="vuln-tag">{{ tag }}</span>
                {% endfor %}
            </div>
            {% endif %}
            {% if vuln.references and vuln.references|length > 0 %}
            <div class="vuln-refs">
                <strong>References:</strong>
                {% for ref in vuln.references[:5] %}
                <a href="{{ ref }}" target="_blank">{{ ref[:50] }}{% if ref|length > 50 %}...{% endif %}</a>{% if not loop.last %}, {% endif %}
                {% endfor %}
            </div>
            {% endif %}
            {% if vuln.extracted_results %}
            <div class="extracted-data">
                <strong>Extracted Data:</strong>
                <dl style="margin: 6px 0 0 0;">
                {% for key, value in vuln.extracted_results %}
                    {% if key %}<dt>{{ key }}</dt>{% endif %}
                    <dd>{{ value }}</dd>
                {% endfor %}
                </dl>
            </div>
            {% endif %}
        </div>
        {% endfor %}
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

        # Scan data (banners, finding names, extracted values) is attacker-influenced
        tmpl = Template(template, autoescape=True)

        # Load ports for each target
        total_ports = 0
        for target in targets:
            target.ports = self._load_ports(str(target.id))
            total_ports += len(target.ports)

        return tmpl.render(
            report_styles=REPORT_HTML_STYLES,
            scan=scan,
            title=title,
            subtitle=subtitle,
            targets=targets,
            vulns=vulns,
            info_findings=info_findings,
            ssh_audits=ssh_audits,
            sslscan_results=sslscan_results,
            nse_findings=nse_findings,
            nse_grouped=nse_grouped,
            severity_counts=severity_counts,
            total_ports=total_ports,
            duration=self._format_duration(scan),
            now=utcnow(),
            format_ts=self._format_timestamp,
        )

    def generate_comparison_html_report(self, comparison_id: str) -> str:
        """Generate the comparison report as a standalone HTML page"""
        comparison = self._load_comparison(comparison_id)
        sections = self._comparison_sections(
            comparison.changes or [], max_rows=COMPARISON_HTML_MAX_ROWS_PER_SECTION
        )

        template = """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Scan Comparison Report</title>
    <style>
{{ report_styles|safe }}    </style>
</head>
<body>
    <div class="header">
        <h1>Scan Comparison Report</h1>
        <p style="font-size: 16px; margin: 5px 0;">{{ scans[0].name }} → {{ scans[1].name }}</p>
        <p><strong>Compared:</strong> {{ format_ts(comparison.created_at) }}</p>
        <p><strong>Generated:</strong> {{ format_ts(now) }}</p>
    </div>

    <div class="section">
        <h2>Scans Compared</h2>
        <table>
            <tr><th></th><th>Scan</th><th>Started ({{ tz }})</th><th>Finished ({{ tz }})</th></tr>
            {% for scan in scans %}
            <tr>
                <td><strong>{{ scan.label }}</strong></td>
                <td>{{ scan.name }}</td>
                <td>{{ scan.started }}</td>
                <td>{{ scan.finished }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>

    <div class="section">
        <h2>Change Summary</h2>
        <div class="metrics">
            {% for label, value in metrics %}
            <div class="metric-card">
                <div class="label">{{ label }}</div>
                <div class="value">{{ value }}</div>
            </div>
            {% endfor %}
        </div>
        <div class="severity-summary">
            {% if comparison.critical_changes %}
            <span class="severity-badge severity-critical">CRITICAL: {{ comparison.critical_changes }}</span>
            {% endif %}
            {% if comparison.high_changes %}
            <span class="severity-badge severity-high">HIGH: {{ comparison.high_changes }}</span>
            {% endif %}
            {% if comparison.medium_changes %}
            <span class="severity-badge severity-medium">MEDIUM: {{ comparison.medium_changes }}</span>
            {% endif %}
            {% if comparison.positive_changes %}
            <span class="severity-badge severity-positive">IMPROVEMENTS: {{ comparison.positive_changes }}</span>
            {% endif %}
        </div>
    </div>

    {% for section in sections %}
    <div class="section">
        <h2>{{ section.title }} <span class="section-count">({{ section.total }})</span></h2>
        {% for note in section.notes %}
        <p style="color: #718096; font-size: 13px;">{{ note }}</p>
        {% endfor %}
        {% if section.rows %}
        <table>
            <tr><th style="width: 110px;">Severity</th><th style="width: 30%;">Host:Port</th><th>{{ section.detail_header }}</th></tr>
            {% for row in section.rows %}
            <tr>
                <td><span class="badge badge-{{ row.severity if row.severity in badge_severities else 'info' }}">{{ row.severity }}</span></td>
                <td><code>{{ row.location }}</code></td>
                <td>{{ row.title }}</td>
            </tr>
            {% endfor %}
        </table>
        {% else %}
        <p style="color: #718096;">None.</p>
        {% endif %}
    </div>
    {% endfor %}

    <div style="text-align: center; color: #a0aec0; margin-top: 40px; font-size: 12px;">
        <p>Generated by PEEK Security Scanner</p>
    </div>
</body>
</html>
        """

        # Change data (banners, finding names, versions) is attacker-influenced
        tmpl = Template(template, autoescape=True)

        return tmpl.render(
            report_styles=REPORT_HTML_STYLES,
            comparison=comparison,
            scans=[
                {
                    'label': label,
                    'name': self._comparison_scan_label(scan),
                    'started': self._format_timestamp(scan.started_at if scan else None),
                    'finished': self._format_timestamp(scan.finished_at if scan else None),
                }
                for label, scan in self._comparison_scans(comparison)
            ],
            metrics=[
                ('Total Changes', comparison.total_changes),
                ('New Ports', comparison.new_ports),
                ('Closed Ports', comparison.closed_ports),
                ('Version Changes', comparison.version_changes),
                ('New Vulnerabilities', comparison.new_vulnerabilities),
                ('Fixed Vulnerabilities', comparison.fixed_vulnerabilities),
            ],
            sections=sections,
            badge_severities=('critical', 'high', 'medium', 'low', 'info', 'positive'),
            tz=REPORT_TIMEZONE_LABEL,
            now=utcnow(),
            format_ts=self._format_timestamp,
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
            'Start Time (UTC)': [self._format_timestamp(scan.started_at, seconds=True)],
            'End Time (UTC)': [self._format_timestamp(scan.finished_at, seconds=True)],
            'Total Targets': [scan.total_targets],
            'Completed Targets': [scan.completed_targets],
            'Failed Targets': [scan.failed_targets],
            'Total Open Ports': [scan.total_open_ports],
            'Total Findings (incl. info)': [scan.total_vulnerabilities]
        }

        df = pd.DataFrame(data)

        buffer = BytesIO()
        df.to_csv(buffer, index=False, encoding='utf-8')
        buffer.seek(0)
        return buffer

    def export_comparison_changes_csv(self, comparison_id: str, category: Optional[str] = None) -> BytesIO:
        """Export every change of a comparison (optionally one category) to CSV"""
        comparison = self._load_comparison(comparison_id)
        changes = [
            c for c in (comparison.changes or [])
            if category is None or c.get('category') == category
        ]

        df = pd.DataFrame(
            [[self._csv_cell(c.get(col)) for col in COMPARISON_CSV_COLUMNS] for c in changes],
            columns=COMPARISON_CSV_COLUMNS,
        )

        buffer = BytesIO()
        df.to_csv(buffer, index=False, encoding='utf-8')
        buffer.seek(0)
        return buffer

    def export_comparison_summary_csv(self, comparison_id: str) -> BytesIO:
        """Export comparison summary to CSV"""
        comparison = self._load_comparison(comparison_id)

        data = {'Compared At (UTC)': [self._format_timestamp(comparison.created_at, seconds=True)]}
        for label, scan in self._comparison_scans(comparison):
            data[f'{label} Scan'] = [self._csv_cell(self._comparison_scan_label(scan))]
            data[f'{label} Start Time (UTC)'] = [
                self._format_timestamp(scan.started_at if scan else None, seconds=True)]
            data[f'{label} End Time (UTC)'] = [
                self._format_timestamp(scan.finished_at if scan else None, seconds=True)]
        data.update({
            'Total Changes': [comparison.total_changes],
            'New Ports': [comparison.new_ports],
            'Closed Ports': [comparison.closed_ports],
            'Version Changes': [comparison.version_changes],
            'New Vulnerabilities': [comparison.new_vulnerabilities],
            'Fixed Vulnerabilities': [comparison.fixed_vulnerabilities],
            'Critical Changes': [comparison.critical_changes],
            'High Severity Changes': [comparison.high_changes],
            'Medium Severity Changes': [comparison.medium_changes],
            'Positive Changes': [comparison.positive_changes],
        })

        df = pd.DataFrame(data)

        buffer = BytesIO()
        df.to_csv(buffer, index=False, encoding='utf-8')
        buffer.seek(0)
        return buffer

    # ==================== HELPER METHODS ====================

    @staticmethod
    def _csv_cell(value: Any) -> Any:
        """
        CSV value for attacker-influenced scan data: text that a spreadsheet
        would evaluate as a formula is prefixed with a quote so it stays text.
        """
        if value is None:
            return ''
        if isinstance(value, str) and value.startswith(CSV_FORMULA_PREFIXES):
            return "'" + value
        return value

    @staticmethod
    def _format_timestamp(value: Optional[datetime], seconds: bool = False) -> str:
        """Render a stored (naive UTC) timestamp with an explicit timezone label."""
        if not value:
            return 'N/A'
        fmt = '%Y-%m-%d %H:%M:%S' if seconds else '%Y-%m-%d %H:%M'
        return f"{value.strftime(fmt)} {REPORT_TIMEZONE_LABEL}"

    @staticmethod
    def _extracted_pairs(extracted: Any) -> List[tuple]:
        """Normalize ``extracted_results`` to ``(label, value)`` pairs.

        Nuclei stores a plain list of extracted strings while other tools
        store a mapping; templates iterate the pairs either way (the label is
        empty for list items).
        """
        if not extracted:
            return []
        if isinstance(extracted, dict):
            return [(str(k), v) for k, v in extracted.items()]
        if isinstance(extracted, (list, tuple, set)):
            return [('', v) for v in extracted]
        return [('', extracted)]

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
        """Load vulnerabilities for scan with all available details"""
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
                st.device_name,
                v.extracted_results,
                v.reference,
                v.tags,
                v.timestamp
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
            # Parse JSON fields
            extracted = row[10]
            refs = row[11]
            tags = row[12]

            if isinstance(extracted, str):
                try:
                    extracted = json.loads(extracted)
                except json.JSONDecodeError:
                    logger.warning(f"Failed to parse extracted_results JSON for vulnerability")
                    extracted = None
            if isinstance(refs, str):
                try:
                    refs = json.loads(refs)
                except json.JSONDecodeError:
                    logger.warning(f"Failed to parse references JSON for vulnerability")
                    refs = None
            if isinstance(tags, str):
                try:
                    tags = json.loads(tags)
                except json.JSONDecodeError:
                    logger.warning(f"Failed to parse tags JSON for vulnerability")
                    tags = None

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
                'device_name': row[9],
                'extracted_results': self._extracted_pairs(extracted),
                'references': refs or [],
                'tags': tags or [],
                'timestamp': row[13]
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
            'info': '#a0aec0',
            'positive': '#276749'
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
        """Generate detailed security recommendations based on findings"""
        recommendations = []
        scan = self._load_scan(scan_id)

        vulns = self._load_vulnerabilities(scan_id)
        ssh_audits = self._load_ssh_audits(scan_id)
        ssl_results = self._load_sslscan_results(scan_id)

        critical_vulns = [v for v in vulns if v['severity'] == 'critical']
        high_vulns = [v for v in vulns if v['severity'] == 'high']

        # Critical vulnerability recommendations
        for vuln in critical_vulns[:3]:  # Top 3 critical
            recommendations.append(
                f"CRITICAL: Immediately address '{vuln['name']}' on {vuln['ip_address']}"
                f"{':' + str(vuln['port']) if vuln['port'] else ''}"
            )

        # High vulnerability recommendations
        for vuln in high_vulns[:3]:  # Top 3 high
            recommendations.append(
                f"HIGH: Remediate '{vuln['name']}' on {vuln['ip_address']}"
                f"{':' + str(vuln['port']) if vuln['port'] else ''}"
            )

        # SSH recommendations
        total_ssh_issues = sum(len(a.get('vulnerabilities', [])) for a in ssh_audits)
        if total_ssh_issues > 0:
            recommendations.append(
                f"Harden SSH configuration - {total_ssh_issues} security issues identified "
                "including deprecated algorithms and weak ciphers."
            )

        # SSL/TLS recommendations
        weak_ssl = [s for s in ssl_results if s.get('tlsv10_enabled') or s.get('tlsv11_enabled')]
        if weak_ssl:
            ports = ', '.join([str(s['port']) for s in weak_ssl[:3]])
            recommendations.append(
                f"Disable TLSv1.0 and TLSv1.1 on services (ports: {ports}). "
                "These protocols have known vulnerabilities."
            )

        # Self-signed certs
        self_signed = [s for s in ssl_results if s.get('cert_self_signed')]
        if self_signed:
            recommendations.append(
                f"Replace self-signed certificates on {len(self_signed)} endpoint(s) "
                "with certificates from a trusted CA."
            )

        if not recommendations:
            recommendations.append(
                "No critical security issues detected. Continue regular security monitoring "
                "and keep systems updated with latest security patches."
            )

        return recommendations

    def _get_report_title(self, scan: Scan) -> tuple:
        """Get report title and subtitle using config name as primary identifier"""
        config = self.db.query(ScanConfig).filter(ScanConfig.id == scan.config_id).first()

        if config and config.name:
            title = config.name
            subtitle = f"Run #{scan.run_number} • {scan.created_at.strftime('%b %d, %Y %H:%M')} {REPORT_TIMEZONE_LABEL}"
        else:
            # Fallback to scan name
            title = scan.name or "Security Scan"
            subtitle = f"{scan.created_at.strftime('%b %d, %Y %H:%M')} {REPORT_TIMEZONE_LABEL}"

        return title, subtitle

    def _load_nse_findings(self, scan_id: str) -> List[Dict[str, Any]]:
        """Load NSE script results for scan"""
        query = text("""
            SELECT
                nf.id,
                nf.script_id,
                nf.profile_name,
                nf.raw_output,
                nf.elements,
                nf.severity,
                nf.error,
                p.port,
                p.protocol,
                p.service_name,
                st.ip_address,
                st.device_name
            FROM nse_findings nf
            JOIN ports p ON nf.port_id = p.id
            JOIN scan_targets st ON p.scan_target_id = st.id
            WHERE st.scan_id = :scan_id
            ORDER BY st.ip_address, p.port, nf.script_id
        """)

        result = self.db.execute(query, {'scan_id': scan_id})

        findings = []
        for row in result:
            elements = row[4]
            if isinstance(elements, str):
                try:
                    elements = json.loads(elements)
                except:
                    elements = {}

            findings.append({
                'id': row[0],
                'script_id': row[1],
                'profile_name': row[2] or 'default',
                'raw_output': row[3],
                'elements': elements or {},
                'severity': row[5] or 'info',
                'error': row[6],
                'port': row[7],
                'protocol': row[8],
                'service_name': row[9],
                'ip_address': row[10],
                'device_name': row[11]
            })

        return findings

    def _get_severity_counts(self, vulns: List[Dict]) -> Dict[str, int]:
        """Count vulnerabilities by severity"""
        return {
            'critical': len([v for v in vulns if v['severity'].lower() == 'critical']),
            'high': len([v for v in vulns if v['severity'].lower() == 'high']),
            'medium': len([v for v in vulns if v['severity'].lower() == 'medium']),
            'low': len([v for v in vulns if v['severity'].lower() == 'low']),
            'info': len([v for v in vulns if v['severity'].lower() == 'info'])
        }

    def _group_nse_by_target(self, nse_findings: List[Dict]) -> Dict[str, List[Dict]]:
        """Group NSE findings by target (ip:port/protocol)"""
        grouped = {}
        for finding in nse_findings:
            key = f"{finding['ip_address']}:{finding['port']}/{finding['protocol']} {finding['service_name'] or ''}"
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(finding)
        return grouped
