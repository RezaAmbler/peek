import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from typing import List, Optional
from io import BytesIO
from ..core.config import settings
import logging

logger = logging.getLogger(__name__)

class EmailService:
    """Service for sending emails with optional attachments"""

    @staticmethod
    def send_email(
        to_emails: List[str],
        subject: str,
        body_text: str,
        body_html: Optional[str] = None,
        attachments: Optional[List[tuple]] = None  # List of (filename, BytesIO, mimetype)
    ) -> bool:
        """
        Send email via SMTP

        Args:
            to_emails: List of recipient email addresses
            subject: Email subject line
            body_text: Plain text email body
            body_html: HTML email body (optional)
            attachments: List of (filename, file_buffer, mimetype) tuples

        Returns:
            True if sent successfully, False otherwise
        """
        if not settings.SMTP_ENABLED:
            logger.info(f"SMTP disabled. Would send email to {to_emails}: {subject}")
            logger.info(f"Body preview: {body_text[:200]}...")
            return False

        if not settings.SMTP_USER or not settings.SMTP_PASSWORD:
            logger.error("SMTP credentials not configured (SMTP_USER or SMTP_PASSWORD missing)")
            return False

        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['From'] = f"{settings.SMTP_FROM_NAME} <{settings.SMTP_FROM_EMAIL}>"
            msg['To'] = ', '.join(to_emails)
            msg['Subject'] = subject

            # Add plain text body
            msg.attach(MIMEText(body_text, 'plain'))

            # Add HTML body if provided
            if body_html:
                msg.attach(MIMEText(body_html, 'html'))

            # Add attachments if provided
            if attachments:
                for filename, file_buffer, mimetype in attachments:
                    attachment = MIMEBase('application', 'octet-stream')
                    file_buffer.seek(0)  # Reset buffer position
                    attachment.set_payload(file_buffer.read())
                    encoders.encode_base64(attachment)
                    attachment.add_header(
                        'Content-Disposition',
                        f'attachment; filename={filename}'
                    )
                    msg.attach(attachment)
                    logger.info(f"Attached: {filename}")

            # Send email
            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=30) as server:
                if settings.SMTP_USE_TLS:
                    server.starttls()
                server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
                server.send_message(msg)

            logger.info(f"✅ Email sent successfully to {to_emails}: {subject}")
            return True

        except smtplib.SMTPAuthenticationError:
            logger.error("❌ SMTP authentication failed. Check SMTP_USER and SMTP_PASSWORD.")
            return False
        except smtplib.SMTPException as e:
            logger.error(f"❌ SMTP error: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"❌ Failed to send email: {str(e)}")
            return False

    @staticmethod
    def send_scan_completion_email(
        recipients: List[str],
        scan_name: str,
        scan_id: str,
        summary_stats: dict,
        comparison_summary: Optional[str] = None,
        attach_reports: bool = True
    ) -> bool:
        """
        Send scan completion notification with optional reports attached

        Args:
            recipients: Email addresses
            scan_name: Name of the scan
            scan_id: Scan ID for generating reports
            summary_stats: Dictionary with scan statistics
            comparison_summary: Optional comparison summary text
            attach_reports: Whether to attach PDF reports

        Returns:
            True if sent successfully
        """
        # Build subject
        has_vulns = summary_stats.get('total_vulnerabilities', 0) > 0
        subject = f"[PEEK] {'⚠️ ' if has_vulns else '✅ '}Scan Complete: {scan_name}"

        # Build plain text body
        body_lines = [
            f"Security scan '{scan_name}' has completed.",
            "",
            "=== SCAN SUMMARY ===",
            f"Status: {summary_stats.get('status', 'Unknown').upper()}",
            f"Targets Scanned: {summary_stats.get('total_targets', 0)}",
            f"Open Ports Discovered: {summary_stats.get('total_open_ports', 0)}",
            f"Vulnerabilities Found: {summary_stats.get('total_vulnerabilities', 0)}",
            "",
        ]

        if comparison_summary:
            body_lines.append("=== CHANGES DETECTED ===")
            body_lines.append(comparison_summary)
            body_lines.append("")

        body_lines.append(f"View full results: {settings.FRONTEND_URL}/scans/{scan_id}")
        body_lines.append("")
        if attach_reports:
            body_lines.append("Executive summary PDF is attached.")
            body_lines.append("")
        body_lines.append("---")
        body_lines.append("PEEK Security Scanner")

        body_text = "\n".join(body_lines)

        # Build HTML body
        vuln_badge = ""
        if summary_stats.get('total_vulnerabilities', 0) > 0:
            vuln_badge = f'<span style="background: #f56565; color: white; padding: 5px 10px; border-radius: 5px; font-weight: bold;">⚠️ {summary_stats["total_vulnerabilities"]} Vulnerabilities</span>'
        else:
            vuln_badge = '<span style="background: #48bb78; color: white; padding: 5px 10px; border-radius: 5px; font-weight: bold;">✅ No Vulnerabilities</span>'

        body_html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }}
                .container {{ max-width: 600px; margin: 0 auto; }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px 20px; text-align: center; }}
                .header h1 {{ margin: 0 0 10px 0; font-size: 24px; }}
                .content {{ padding: 20px; background: #f7fafc; }}
                .stats {{ background: white; padding: 20px; border-radius: 8px; margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .stat-row {{ display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px solid #e2e8f0; }}
                .stat-row:last-child {{ border-bottom: none; }}
                .stat-label {{ font-weight: 600; color: #4a5568; }}
                .stat-value {{ color: #2d3748; }}
                .changes {{ background: #fff3cd; padding: 20px; border-radius: 8px; border-left: 4px solid #ffc107; margin: 20px 0; }}
                .changes pre {{ margin: 0; font-family: monospace; font-size: 13px; white-space: pre-wrap; }}
                .button {{ display: inline-block; padding: 12px 30px; background: #667eea; color: white; text-decoration: none; border-radius: 6px; margin: 20px 0; font-weight: bold; }}
                .button:hover {{ background: #5568d3; }}
                .footer {{ margin-top: 20px; padding: 20px; text-align: center; font-size: 12px; color: #718096; border-top: 1px solid #e2e8f0; }}
                .badge-container {{ text-align: center; margin: 20px 0; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔒 Security Scan Complete</h1>
                    <p style="margin: 0; font-size: 16px;">{scan_name}</p>
                </div>

                <div class="content">
                    <div class="badge-container">
                        {vuln_badge}
                    </div>

                    <div class="stats">
                        <h2 style="margin-top: 0; color: #2d3748;">Scan Summary</h2>
                        <div class="stat-row">
                            <span class="stat-label">Status</span>
                            <span class="stat-value">{summary_stats.get('status', 'Unknown').upper()}</span>
                        </div>
                        <div class="stat-row">
                            <span class="stat-label">Targets Scanned</span>
                            <span class="stat-value">{summary_stats.get('total_targets', 0)}</span>
                        </div>
                        <div class="stat-row">
                            <span class="stat-label">Open Ports</span>
                            <span class="stat-value">{summary_stats.get('total_open_ports', 0)}</span>
                        </div>
                        <div class="stat-row">
                            <span class="stat-label">Vulnerabilities</span>
                            <span class="stat-value" style="font-weight: bold; color: {'#e53e3e' if summary_stats.get('total_vulnerabilities', 0) > 0 else '#38a169'};">
                                {summary_stats.get('total_vulnerabilities', 0)}
                            </span>
                        </div>
                    </div>

                    {f'''
                    <div class="changes">
                        <h3 style="margin-top: 0; color: #744210;">⚠️ Changes Detected</h3>
                        <pre>{comparison_summary}</pre>
                    </div>
                    ''' if comparison_summary else ''}

                    <div style="text-align: center;">
                        <a href="{settings.FRONTEND_URL}/scans/{scan_id}" class="button">
                            View Full Report →
                        </a>
                    </div>

                    {'''
                    <p style="text-align: center; color: #4a5568; margin-top: 20px;">
                        📎 Executive summary PDF is attached
                    </p>
                    ''' if attach_reports else ''}
                </div>

                <div class="footer">
                    <p style="margin: 0 0 5px 0;">PEEK Security Scanner</p>
                    <p style="margin: 0;">Automated Network Security Assessment</p>
                </div>
            </div>
        </body>
        </html>
        """

        # Prepare attachments
        attachments = []
        if attach_reports and settings.SMTP_ENABLED:
            try:
                # Generate and attach executive summary PDF
                from ..services.report_service import ReportService
                from ..db.sync_session import get_sync_db

                with get_sync_db() as db:
                    report_service = ReportService(db)
                    pdf_buffer = report_service.generate_executive_summary_pdf(scan_id)
                    filename = f"executive_summary_{scan_name.replace(' ', '_')[:30]}.pdf"
                    attachments.append((
                        filename,
                        pdf_buffer,
                        "application/pdf"
                    ))
                    logger.info(f"Generated PDF attachment: {filename}")
            except Exception as e:
                logger.error(f"Failed to generate/attach report: {str(e)}")

        # Send email
        return EmailService.send_email(
            to_emails=recipients,
            subject=subject,
            body_text=body_text,
            body_html=body_html,
            attachments=attachments if attachments else None
        )
