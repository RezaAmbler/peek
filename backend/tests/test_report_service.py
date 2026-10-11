"""
Report exports: every format renders for a scan whose findings carry the data
shapes the scanners really store (nuclei: list of extracted values, others: a
mapping), and every timestamp names its timezone. The comparison reports (PDF
executive/detailed, HTML, CSV) list the actual changes, capped per section where
the format needs it.
"""
import csv
import io
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


def test_comparison_executive_pdf_keeps_only_the_most_severe_changes(db, comparison, monkeypatch):
    monkeypatch.setattr(rl_config, "pageCompression", 0)
    comparison.changes = [
        _change("NEW_VULNERABILITY", category="vulnerability", port=1000 + i, name=f"Finding {i}",
                template_id=f"t-{i}", vuln_severity="critical" if i == 39 else "low")
        for i in range(40)
    ]
    db.commit()
    service = ReportService(db)

    executive = _pdf_text(service.generate_comparison_report_pdf(comparison.id, executive=True).read())
    detailed = _pdf_text(service.generate_comparison_report_pdf(comparison.id).read())

    assert "Scan Comparison Executive Summary" in executive
    assert "Scan Comparison Report" in detailed
    assert "Compared 2026-10-10 20:15 UTC" in executive and "2026-10-03 08:42 UTC" in executive
    assert "New Vulnerabilities \\(40\\)" in executive  # the real count, not the listed rows
    assert "Finding 39 [t-39]" in executive and "Showing the 10 most severe of 40" in executive
    assert executive.count("10.0.0.5:10") == 10 and detailed.count("10.0.0.5:10") == 40


# ---------------------------------------------------------------- comparison HTML

def test_comparison_html_lists_changes_with_report_styling(db, comparison):
    html = ReportService(db).generate_comparison_html_report(comparison.id)

    for heading in ("New Ports", "Closed Ports", "Version Changes", "New Vulnerabilities",
                    "Fixed Vulnerabilities", "Other Changes"):
        assert f"<h2>{heading} <span" in html
    assert "10.0.0.5:8443/tcp" in html and "https nginx 1.25.3" in html
    assert "ssh: 8.2p1 → 9.6p1" in html
    assert "Accepted risk [accepted] (suppressed)" in html
    assert '<span class="badge badge-critical">critical</span>' in html
    assert '<span class="badge badge-positive">positive</span>' in html
    assert "CRITICAL: " not in html  # severity counts of zero are left out
    # same stylesheet as the scan HTML report
    assert ".metric-card {" in html and ".badge-critical {" in html
    assert "{{" not in html and "{%" not in html


def test_scan_and_comparison_html_share_one_stylesheet(db, scan, comparison):
    from app.services.report_service import REPORT_HTML_STYLES

    service = ReportService(db)

    assert REPORT_HTML_STYLES in service.generate_html_report(scan.id)
    assert REPORT_HTML_STYLES in service.generate_comparison_html_report(comparison.id)


def test_comparison_html_escapes_change_data_and_labels_timestamps(db, comparison):
    html = ReportService(db).generate_comparison_html_report(comparison.id)

    assert "<b>RCE</b>" not in html
    assert "&lt;b&gt;RCE&lt;/b&gt; &amp; more [CVE-2026-0001]" in html
    assert "run (Run #2)" in html and "run (Run #3)" in html
    assert "2026-10-03 08:42 UTC" in html and "2026-10-10 19:55 UTC" in html
    assert "<strong>Compared:</strong> 2026-10-10 20:15 UTC" in html
    assert "Started (UTC)" in html and "Finished (UTC)" in html


def test_comparison_html_without_changes_or_scans(db, comparison):
    comparison.changes = []
    comparison.baseline_scan_id = "deleted-scan"
    db.commit()

    html = ReportService(db).generate_comparison_html_report(comparison.id)

    assert "Scan no longer available" in html and "N/A" in html
    assert html.count("None.") == 5


# ---------------------------------------------------------------- comparison CSV

def _csv_rows(buffer):
    return list(csv.DictReader(io.StringIO(buffer.read().decode())))


def test_comparison_changes_csv_has_one_row_per_change(db, comparison):
    rows = _csv_rows(ReportService(db).export_comparison_changes_csv(comparison.id))

    assert len(rows) == len(COMPARISON_CHANGES)  # every change, suppressed ones included
    assert list(rows[0]) == ["type", "category", "severity", "classification", "ip_address",
                             "device_name", "port", "protocol", "service_name", "product",
                             "version", "old_version", "new_version", "name", "template_id",
                             "vuln_severity", "matched_at", "description"]
    assert rows[0]["type"] == "NEW_PORT" and rows[0]["port"] == "8443"
    assert rows[0]["product"] == "nginx" and rows[0]["name"] == ""
    assert (rows[2]["old_version"], rows[2]["new_version"]) == ("8.2p1", "9.6p1")
    assert rows[4]["name"] == "<b>RCE</b> & more" and rows[4]["vuln_severity"] == "critical"
    assert rows[5]["classification"] == "SUPPRESSED"


def test_comparison_changes_csv_filters_by_category(db, comparison):
    service = ReportService(db)

    vulns = _csv_rows(service.export_comparison_changes_csv(comparison.id, "vulnerability"))
    ports = _csv_rows(service.export_comparison_changes_csv(comparison.id, "port"))

    assert [r["type"] for r in vulns] == ["NEW_VULNERABILITY"] * 3 + ["FIXED_VULNERABILITY"]
    assert [r["type"] for r in ports] == ["NEW_PORT", "CLOSED_PORT"]


def test_comparison_changes_csv_without_changes_still_has_the_header(db, comparison):
    comparison.changes = []
    db.commit()

    text = ReportService(db).export_comparison_changes_csv(comparison.id).read().decode()

    assert text.splitlines() == [",".join([
        "type", "category", "severity", "classification", "ip_address", "device_name", "port",
        "protocol", "service_name", "product", "version", "old_version", "new_version", "name",
        "template_id", "vuln_severity", "matched_at", "description"])]


def test_comparison_changes_csv_neutralizes_spreadsheet_formulas(db, comparison):
    comparison.changes = [
        _change("NEW_VULNERABILITY", category="vulnerability", port=80,
                name='=HYPERLINK("http://evil.example","click")', template_id="@SUM(1+1)",
                vuln_severity="high", description="-2+3"),
    ]
    db.commit()

    row = _csv_rows(ReportService(db).export_comparison_changes_csv(comparison.id))[0]

    assert row["name"] == "'=HYPERLINK(\"http://evil.example\",\"click\")"
    assert row["template_id"] == "'@SUM(1+1)" and row["description"] == "'-2+3"
    assert row["port"] == "80"  # numbers are left alone


def test_comparison_summary_csv_labels_timestamps_as_utc(db, comparison):
    rows = _csv_rows(ReportService(db).export_comparison_summary_csv(comparison.id))

    assert len(rows) == 1
    assert rows[0]["Compared At (UTC)"] == "2026-10-10 20:15:00 UTC"
    assert rows[0]["Baseline Scan"] == "run (Run #2)" and rows[0]["Current Scan"] == "run (Run #3)"
    assert rows[0]["Baseline Start Time (UTC)"] == "2026-10-03 08:00:05 UTC"
    assert rows[0]["Current End Time (UTC)"] == "2026-10-10 19:55:38 UTC"
    assert rows[0]["Total Changes"] == "7" and rows[0]["New Vulnerabilities"] == "2"


@pytest.mark.parametrize("method", [
    "generate_comparison_html_report", "export_comparison_changes_csv", "export_comparison_summary_csv"])
def test_comparison_exports_unknown_comparison(db, method):
    with pytest.raises(ValueError):
        getattr(ReportService(db), method)("missing")
