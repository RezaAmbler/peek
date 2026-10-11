"""
Report exports: every format renders for a scan whose findings carry the data
shapes the scanners really store (nuclei: list of extracted values, others: a
mapping), and every timestamp names its timezone.
"""
import base64
import re
import uuid
import zlib
from datetime import datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
import app.models  # noqa: F401
from app.models import Port, Scan, ScanConfig, ScanTarget, Vulnerability
from app.services.report_service import ReportService


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _vuln(target, port, severity, name, extracted=None):
    return Vulnerability(
        id=str(uuid.uuid4()), scan_target_id=target.id, port_id=port.id, port=port.port,
        template_id=f"tmpl-{severity}", name=name, severity=severity, vuln_type="http",
        matched_at="http://10.0.0.5:80/", host="10.0.0.5", source_tool="nuclei",
        extracted_results=extracted,
    )


@pytest.fixture
def scan(db):
    db.add(ScanConfig(id="config-1", user_id="user-1", name="office-network"))
    scan = Scan(
        id=str(uuid.uuid4()), user_id="user-1", created_by_id="user-1", config_id="config-1",
        name="run", status="completed", run_number=3, total_targets=1, total_open_ports=1,
        total_vulnerabilities=4,
        created_at=datetime(2026, 10, 10, 19, 1, 49),
        started_at=datetime(2026, 10, 10, 19, 1, 50),
        finished_at=datetime(2026, 10, 10, 19, 55, 38),
    )
    db.add(scan)
    target = ScanTarget(id=str(uuid.uuid4()), scan_id=scan.id, ip_address="10.0.0.5")
    db.add(target)
    port = Port(id=str(uuid.uuid4()), scan_target_id=target.id, port=80, protocol="tcp",
                state="open", service_name="http", discovered_by="nmap")
    db.add(port)
    db.flush()
    db.add_all([
        # nuclei stores extracted values as a list: this shape caused the HTML 500
        _vuln(target, port, "high", "List extraction", extracted=["nginx/1.18.0", "PHP/7.4"]),
        _vuln(target, port, "medium", "Mapping extraction", extracted={"server": "Apache"}),
        _vuln(target, port, "low", "<script>alert(1)</script>", extracted=None),
        _vuln(target, port, "info", "Tech detected", extracted=["jquery"]),
    ])
    db.commit()
    return scan


def test_html_report_renders_list_and_mapping_extracted_results(db, scan):
    html = ReportService(db).generate_html_report(scan.id)

    assert "nginx/1.18.0" in html and "PHP/7.4" in html
    assert "<dt>server</dt>" in html and "Apache" in html
    assert "office-network" in html


def test_html_report_escapes_scan_data(db, scan):
    html = ReportService(db).generate_html_report(scan.id)

    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_html_report_labels_timestamps_as_utc(db, scan):
    html = ReportService(db).generate_html_report(scan.id)

    assert "2026-10-10 19:01 UTC" in html  # created / started
    assert "2026-10-10 19:55 UTC" in html  # finished
    assert "Oct 10, 2026 19:01 UTC" in html  # subtitle


@pytest.mark.parametrize("extracted, expected", [
    (None, []),
    ([], []),
    (["a", "b"], [("", "a"), ("", "b")]),
    ({"k": "v"}, [("k", "v")]),
    ("plain", [("", "plain")]),
])
def test_extracted_pairs_normalizes_every_stored_shape(extracted, expected):
    assert ReportService._extracted_pairs(extracted) == expected


def test_format_timestamp_names_the_timezone():
    stamp = datetime(2026, 10, 10, 19, 1, 49)
    assert ReportService._format_timestamp(stamp) == "2026-10-10 19:01 UTC"
    assert ReportService._format_timestamp(stamp, seconds=True) == "2026-10-10 19:01:49 UTC"
    assert ReportService._format_timestamp(None) == "N/A"


@pytest.mark.parametrize("method", ["generate_executive_summary_pdf", "generate_technical_report_pdf"])
def test_pdf_reports_render(db, scan, method):
    data = getattr(ReportService(db), method)(scan.id).read()

    assert data.startswith(b"%PDF") and len(data) > 1000


def _pdf_page_text(data: bytes) -> bytes:
    """Concatenated, decoded page content streams of a reportlab PDF."""
    pages = []
    for stream in re.findall(rb"stream\r?\n(.*?)endstream", data, re.DOTALL):
        try:
            pages.append(zlib.decompress(base64.a85decode(stream.strip(), adobe=True)))
        except (ValueError, zlib.error):
            continue
    return b"\n".join(pages)


def test_html_report_credits_nmap_with_link(db, scan):
    html = ReportService(db).generate_html_report(scan.id)

    assert '<a href="https://nmap.org/"' in html
    assert re.search(r'<a href="https://nmap\.org/"[^>]*>This system uses the Nmap Security Scanner</a>', html)


@pytest.mark.parametrize("method", ["generate_executive_summary_pdf", "generate_technical_report_pdf"])
def test_pdf_reports_credit_nmap_with_link(db, scan, method):
    data = getattr(ReportService(db), method)(scan.id).read()

    assert b"This system uses the Nmap Security Scanner" in _pdf_page_text(data)
    assert b"/URI (https://nmap.org/)" in data


def test_csv_exports_render_and_label_utc(db, scan):
    service = ReportService(db)

    vulns = service.export_vulnerabilities_csv(scan.id).read().decode()
    ports = service.export_ports_csv(scan.id).read().decode()
    summary = service.export_scan_summary_csv(scan.id).read().decode()

    assert vulns.splitlines()[0].startswith("ip_address,") and len(vulns.splitlines()) == 5
    assert "10.0.0.5" in ports and ",80," in ports
    assert "Start Time (UTC)" in summary and "2026-10-10 19:01:50 UTC" in summary
