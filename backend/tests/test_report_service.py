"""
Report exports: every format renders for a scan whose findings carry the data
shapes the scanners really store (nuclei: list of extracted values, others: a
mapping), and every timestamp names its timezone. The comparison PDF lists the
actual changes, capped per section.
"""
import re
import uuid
from datetime import datetime

import pytest
from reportlab import rl_config
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
import app.models  # noqa: F401
from app.models import Port, Scan, ScanComparison, ScanConfig, ScanTarget, Vulnerability
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


def test_csv_exports_render_and_label_utc(db, scan):
    service = ReportService(db)

    vulns = service.export_vulnerabilities_csv(scan.id).read().decode()
    ports = service.export_ports_csv(scan.id).read().decode()
    summary = service.export_scan_summary_csv(scan.id).read().decode()

    assert vulns.splitlines()[0].startswith("ip_address,") and len(vulns.splitlines()) == 5
    assert "10.0.0.5" in ports and ",80," in ports
    assert "Start Time (UTC)" in summary and "2026-10-10 19:01:50 UTC" in summary


# ---------------------------------------------------------------- comparison PDF

def _change(change_type, **fields):
    base = {"type": change_type, "severity": "MEDIUM", "category": "port",
            "ip_address": "10.0.0.5", "device_name": None, "description": change_type}
    base.update(fields)
    return base


COMPARISON_CHANGES = [
    _change("NEW_PORT", severity="HIGH", port=8443, protocol="tcp", service_name="https",
            product="nginx", version="1.25.3"),
    _change("CLOSED_PORT", severity="POSITIVE", port=23, protocol="tcp", service_name="telnet",
            product=None, version=None, device_name="core-sw",
            associated_vulnerabilities=[{"name": "Telnet cleartext", "severity": "high",
                                         "template_id": "telnet-detect", "matched_at": "10.0.0.5:23"}]),
    _change("VERSION_UPDATE", category="service", port=22, protocol="tcp", service_name="ssh",
            old_version="8.2p1", new_version="9.6p1"),
    _change("NEW_VULNERABILITY", severity="MEDIUM", category="vulnerability", port=80,
            name="Low one", template_id="low-one", vuln_severity="low", classification="GENUINELY_NEW"),
    _change("NEW_VULNERABILITY", severity="CRITICAL", category="vulnerability", port=443,
            name="<b>RCE</b> & more", template_id="CVE-2026-0001", vuln_severity="critical",
            classification="GENUINELY_NEW"),
    _change("NEW_VULNERABILITY", severity="CRITICAL", category="vulnerability", port=8080,
            name="Accepted risk", template_id="accepted", vuln_severity="critical",
            classification="SUPPRESSED"),
    _change("FIXED_VULNERABILITY", severity="POSITIVE", category="vulnerability", port=80,
            name="Old jQuery", template_id="jquery-old", vuln_severity="medium"),
    _change("SSH_SECURITY_DEGRADED", severity="HIGH", category="ssh", port=22,
            description="SSH security degraded: 1 → 3 issues"),
]


@pytest.fixture
def comparison(db, scan):
    baseline = Scan(
        id=str(uuid.uuid4()), user_id="user-1", created_by_id="user-1", config_id="config-1",
        name="run", status="completed", run_number=2,
        created_at=datetime(2026, 10, 3, 8, 0, 0),
        started_at=datetime(2026, 10, 3, 8, 0, 5),
        finished_at=datetime(2026, 10, 3, 8, 42, 10),
    )
    comparison = ScanComparison(
        id=str(uuid.uuid4()), baseline_scan_id=baseline.id, current_scan_id=scan.id,
        created_by_id="user-1", created_at=datetime(2026, 10, 10, 20, 15, 0),
        total_changes=7, new_ports=1, closed_ports=1, version_changes=1,
        new_vulnerabilities=2, fixed_vulnerabilities=1, changes=COMPARISON_CHANGES,
    )
    db.add_all([baseline, comparison])
    db.commit()
    return comparison


def _sections(changes, **kwargs):
    return {s["title"]: s for s in ReportService(None)._comparison_sections(changes, **kwargs)}


def test_comparison_sections_list_each_kind_of_change():
    sections = _sections(COMPARISON_CHANGES)

    assert list(sections) == ["New Ports", "Closed Ports", "Version Changes",
                              "New Vulnerabilities", "Fixed Vulnerabilities", "Other Changes"]
    assert sections["New Ports"]["rows"] == [
        {"severity": "high", "location": "10.0.0.5:8443/tcp", "title": "https nginx 1.25.3"}]
    assert sections["Closed Ports"]["rows"] == [
        {"severity": "positive", "location": "10.0.0.5:23/tcp (core-sw)",
         "title": "telnet - 1 associated vulnerability no longer exposed"}]
    assert sections["Version Changes"]["rows"] == [
        {"severity": "medium", "location": "10.0.0.5:22/tcp", "title": "ssh: 8.2p1 → 9.6p1"}]
    assert sections["Fixed Vulnerabilities"]["rows"] == [
        {"severity": "medium", "location": "10.0.0.5:80", "title": "Old jQuery [jquery-old]"}]
    assert sections["Other Changes"]["rows"][0]["title"] == "SSH security degraded: 1 → 3 issues"


def test_comparison_new_vulnerabilities_sorted_by_severity_with_suppressed_last():
    section = _sections(COMPARISON_CHANGES)["New Vulnerabilities"]

    assert [(r["severity"], r["location"]) for r in section["rows"]] == [
        ("critical", "10.0.0.5:443"), ("low", "10.0.0.5:80"), ("critical", "10.0.0.5:8080")]
    assert section["rows"][-1]["title"] == "Accepted risk [accepted] (suppressed)"
    assert section["total"] == 3
    assert section["notes"] == ["1 suppressed by triage (listed last, not counted in the summary)."]


def test_comparison_sections_are_capped_and_say_how_many_were_left_out():
    changes = [
        _change("NEW_VULNERABILITY", category="vulnerability", port=1000 + i, name=f"Finding {i}",
                template_id=f"t-{i}", vuln_severity="critical" if i == 249 else "info")
        for i in range(250)
    ]
    section = _sections(changes, max_rows=100)["New Vulnerabilities"]

    assert section["total"] == 250 and len(section["rows"]) == 100
    assert section["rows"][0]["title"] == "Finding 249 [t-249]"  # most severe survives the cap
    assert section["notes"] == [
        "Showing the 100 most severe of 250; 150 more are available in the PEEK comparison view."]


def test_comparison_sections_empty_and_long_titles():
    sections = _sections([_change("NEW_VULNERABILITY", name="x" * 500, vuln_severity="high")])

    assert sections["New Ports"] == {"title": "New Ports", "detail_header": "Service",
                                     "total": 0, "notes": [], "rows": []}
    assert "Other Changes" not in sections
    title = sections["New Vulnerabilities"]["rows"][0]["title"]
    assert len(title) == 160 and title.endswith("...")


def _pdf_text(pdf: bytes) -> str:
    """Text drawn by an uncompressed reportlab PDF, in drawing order."""
    return " ".join(m.decode("latin-1") for m in re.findall(rb"\((.*?)\) Tj", pdf))


def test_comparison_pdf_lists_changes_and_labels_timestamps(db, comparison, monkeypatch):
    monkeypatch.setattr(rl_config, "pageCompression", 0)

    data = ReportService(db).generate_comparison_report_pdf(comparison.id).read()
    text = _pdf_text(data)

    assert data.startswith(b"%PDF")
    for heading in ("New Ports \\(1\\)", "Closed Ports \\(1\\)", "Version Changes \\(1\\)",
                    "New Vulnerabilities \\(3\\)", "Fixed Vulnerabilities \\(1\\)"):
        assert heading in text
    assert "10.0.0.5:8443/tcp" in text and "https nginx 1.25.3" in text
    assert "ssh: 8.2p1" in text and "9.6p1" in text
    # scan data is escaped: the tags are printed, not interpreted as markup
    assert "CRITICAL" in text and "< b > RCE < /b > & more [CVE-2026-0001]" in text
    assert "Old jQuery [jquery-old]" in text
    # baseline / current scans and the comparison itself, each naming the timezone
    assert "run \\(Run #2\\)" in text and "run \\(Run #3\\)" in text
    assert "2026-10-03 08:42 UTC" in text and "2026-10-10 19:55 UTC" in text
    assert "Compared 2026-10-10 20:15 UTC" in text


def test_comparison_pdf_paginates_large_change_lists(db, comparison):
    comparison.changes = [
        _change("NEW_VULNERABILITY", category="vulnerability", port=i % 65535 + 1,
                name=f"Finding {i} " + "detail " * 20, template_id=f"t-{i}", vuln_severity="high")
        for i in range(1500)
    ]
    db.commit()

    data = ReportService(db).generate_comparison_report_pdf(comparison.id).read()

    pages = len(re.findall(rb"/Type /Page\b", data))
    assert data.startswith(b"%PDF") and 3 < pages < 20  # 200 of 1500 rows, over several pages


def test_comparison_pdf_unknown_comparison(db):
    with pytest.raises(ValueError):
        ReportService(db).generate_comparison_report_pdf("missing")
