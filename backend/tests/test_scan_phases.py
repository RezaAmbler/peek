"""
Phase-level tests: ToolExecution bookkeeping, rollback on errors, result
linkage and monotonic progress. Runners are mocked; the DB is in-memory SQLite.
"""
import json
import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import PendingRollbackError
from sqlalchemy.orm import sessionmaker

from app.database import Base
import app.models  # noqa: F401
from app.models import Port, Scan, ScanTarget, ToolExecution, Vulnerability
from app.services.service_profile import NucleiProfile
from app.tasks import scan_tasks
from app.tasks.scan_tasks import (
    PHASE_PROGRESS,
    RAW_OUTPUT_LIMIT,
    fail_tool_exec,
    fail_unfinished_tool_execs,
    phase_progress,
    record_tool_result,
    set_phase_progress,
    start_tool_exec,
)
from app.tools.base import EXIT_TIMEOUT, ToolResult
from app.tools.nikto import run_nikto  # noqa: F401  (import check)

NUCLEI_EVENT = {
    "template-id": "CVE-2021-41773",
    "info": {"name": "Apache Path Traversal", "severity": "high", "tags": ["cve"]},
    "type": "http",
    "host": "http://10.0.0.5:80",
    "matched-at": "http://10.0.0.5:80/cgi-bin/x",
}
NMAP_XML = ('<?xml version="1.0"?><nmaprun><host><ports>'
            '<port protocol="tcp" portid="80"><state state="open"/></port>'
            '</ports></host></nmaprun>')


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


@pytest.fixture
def scan_env(db):
    scan = Scan(id=str(uuid.uuid4()), user_id="user-1", created_by_id="user-1",
                config_id="config-1", name="t", status="running", total_vulnerabilities=0)
    db.add(scan)
    db.flush()
    target = ScanTarget(id=str(uuid.uuid4()), scan_id=scan.id, ip_address="10.0.0.5")
    db.add(target)
    db.flush()
    port = Port(id=str(uuid.uuid4()), scan_target_id=target.id, port=80, protocol="tcp",
                state="open", service_name="http", discovered_by="nmap")
    db.add(port)
    db.commit()
    return SimpleNamespace(scan=scan, target=target, port=port)


@pytest.fixture
def config():
    return SimpleNamespace(
        scan_mode="fast", nuclei_timeout=300, global_tool_timeout_seconds=None,
        nuclei_severity="critical,high", nuclei_templates=None, nikto_timeout=60,
        host_timeout_seconds=600, masscan_timeout_percent=0.2, nmap_timeout_percent=0.7,
        nmap_args=["-sT", "-sV"], discovery_top_ports=100, additional_ports=None,
    )


@pytest.fixture
def nuclei_phase(monkeypatch):
    """Stub everything around run_nuclei so only the phase logic is exercised."""
    profile = NucleiProfile(should_scan=True, target_format="url", protocol="http", tags=["http"])
    monkeypatch.setattr(scan_tasks, "get_excluded_templates", lambda: [])
    monkeypatch.setattr(scan_tasks, "get_nuclei_profile", lambda **kwargs: profile)
    monkeypatch.setattr(scan_tasks, "validate_tags", lambda tags: (True, 5))
    monkeypatch.setattr(scan_tasks, "build_nuclei_target", lambda ip, port, *a, **k: f"http://{ip}:{port}")
    monkeypatch.setattr(scan_tasks, "save_nuclei_debug", lambda **kwargs: None)

    def set_result(result):
        calls = []

        def fake_run_nuclei(**kwargs):
            calls.append(kwargs)
            if isinstance(result, Exception):
                raise result
            return result
        monkeypatch.setattr(scan_tasks, "run_nuclei", fake_run_nuclei)
        return calls
    return set_result


def only_exec(db, tool_name):
    execs = db.query(ToolExecution).filter(ToolExecution.tool_name == tool_name).all()
    assert len(execs) == 1
    return execs[0]


# --------------------------------------------------------------------------- nuclei phase

class TestNucleiPhase:
    def test_failed_run_is_recorded_as_failed_not_as_clean(self, db, scan_env, config, nuclei_phase):
        nuclei_phase(ToolResult(False, "", "Nuclei exited with code 1: [FTL] no templates provided",
                                command_line="nuclei -severity critical,high -target http://10.0.0.5:80",
                                exit_code=1))

        scan_tasks.run_nuclei_phase(db, scan_env.scan, [scan_env.target], config)

        tool_exec = only_exec(db, "nuclei")
        assert tool_exec.exit_code == 1
        assert "no templates provided" in tool_exec.error_message
        assert tool_exec.finished_at is not None and tool_exec.duration_ms is not None
        assert tool_exec.command_line == "nuclei -severity critical,high -target http://10.0.0.5:80"
        assert tool_exec.raw_format == "jsonl"
        assert db.query(Vulnerability).count() == 0
        assert scan_env.scan.total_vulnerabilities == 0

    def test_timeout_is_distinguishable(self, db, scan_env, config, nuclei_phase):
        nuclei_phase(ToolResult(False, "", "Nuclei timed out after 300 seconds",
                                command_line="nuclei ...", exit_code=EXIT_TIMEOUT, timed_out=True))

        scan_tasks.run_nuclei_phase(db, scan_env.scan, [scan_env.target], config)

        tool_exec = only_exec(db, "nuclei")
        assert tool_exec.exit_code == EXIT_TIMEOUT and "timed out" in tool_exec.error_message

    def test_success_links_execution_port_and_vulnerability(self, db, scan_env, config, nuclei_phase):
        calls = nuclei_phase(ToolResult(True, json.dumps(NUCLEI_EVENT) + "\n", None,
                                        command_line="nuclei -target http://10.0.0.5:80", exit_code=0))

        scan_tasks.run_nuclei_phase(db, scan_env.scan, [scan_env.target], config)

        tool_exec = only_exec(db, "nuclei")
        assert tool_exec.exit_code == 0 and tool_exec.error_message is None
        assert tool_exec.scan_target_id == scan_env.target.id and tool_exec.port_id == scan_env.port.id
        vuln = db.query(Vulnerability).one()
        assert vuln.tool_execution_id == tool_exec.id and vuln.port_id == scan_env.port.id
        assert vuln.template_id == "CVE-2021-41773" and vuln.severity == "high"
        assert scan_env.scan.total_vulnerabilities == 1
        assert calls[0]["target"] == "http://10.0.0.5:80" and calls[0]["tags"] == ["http"]

    def test_clean_run_has_no_error(self, db, scan_env, config, nuclei_phase):
        nuclei_phase(ToolResult(True, "", None, command_line="nuclei ...", exit_code=0))

        scan_tasks.run_nuclei_phase(db, scan_env.scan, [scan_env.target], config)

        tool_exec = only_exec(db, "nuclei")
        assert (tool_exec.exit_code, tool_exec.error_message, tool_exec.raw_output) == (0, None, None)

    def test_raw_output_is_parsed_in_full_then_truncated(self, db, scan_env, config, nuclei_phase):
        events = []
        for i in range(400):
            event = dict(NUCLEI_EVENT, **{"template-id": f"tpl-{i}", "matched-at": f"http://10.0.0.5:80/{i}"})
            events.append(json.dumps(event))
        raw = "\n".join(events)
        assert len(raw) > RAW_OUTPUT_LIMIT
        nuclei_phase(ToolResult(True, raw, None, command_line="nuclei ...", exit_code=0))

        scan_tasks.run_nuclei_phase(db, scan_env.scan, [scan_env.target], config)

        assert db.query(Vulnerability).count() == 400
        assert len(only_exec(db, "nuclei").raw_output) == RAW_OUTPUT_LIMIT

    def test_runner_exception_finalizes_the_execution(self, db, scan_env, config, nuclei_phase):
        nuclei_phase(RuntimeError("boom"))

        scan_tasks.run_nuclei_phase(db, scan_env.scan, [scan_env.target], config)

        tool_exec = only_exec(db, "nuclei")
        assert tool_exec.exit_code == 1 and tool_exec.error_message == "RuntimeError: boom"
        assert tool_exec.finished_at is not None and tool_exec.duration_ms is not None

    def test_failed_flush_is_rolled_back_and_scan_continues(self, db, scan_env, config, nuclei_phase, monkeypatch):
        """A DB error inside the phase must not poison the session for the rest of the scan."""
        raw = json.dumps(NUCLEI_EVENT)
        nuclei_phase(ToolResult(True, raw, None, command_line="nuclei -target x", exit_code=0))

        def broken_parser(db_session, tool_exec, target, port_rec, discovery_source="port"):
            # NOT NULL violation -> IntegrityError on flush -> session needs rollback
            db_session.add(Port(id=str(uuid.uuid4()), scan_target_id=target.id, port=None,
                                protocol="tcp", state="open", discovered_by="x"))
            db_session.flush()
        monkeypatch.setattr(scan_tasks, "create_vulnerabilities_from_nuclei", broken_parser)

        scan_tasks.run_nuclei_phase(db, scan_env.scan, [scan_env.target], config)

        # Session is usable again and the execution is finalized with what was captured
        tool_exec = only_exec(db, "nuclei")
        assert tool_exec.exit_code == 1 and "IntegrityError" in tool_exec.error_message
        assert tool_exec.finished_at is not None
        assert tool_exec.raw_output == raw and tool_exec.command_line == "nuclei -target x"
        assert db.query(Port).count() == 1
        scan_env.scan.status = "completed"
        db.commit()  # would raise PendingRollbackError without the rollback

    def test_skips_when_no_templates_match(self, db, scan_env, config, nuclei_phase, monkeypatch):
        calls = nuclei_phase(ToolResult(True, "", None))
        monkeypatch.setattr(scan_tasks, "validate_tags", lambda tags: (False, 0))

        scan_tasks.run_nuclei_phase(db, scan_env.scan, [scan_env.target], config)

        assert calls == [] and db.query(ToolExecution).count() == 0
        assert scan_env.scan.progress_percent == phase_progress("nuclei", 1.0)


# --------------------------------------------------------------------------- discovery / nmap / nikto phases

class TestOtherPhases:
    def test_discovery_failure_marks_target_failed(self, db, scan_env, config, monkeypatch):
        monkeypatch.setattr(scan_tasks, "save_nmap_debug", lambda **kwargs: None)
        monkeypatch.setattr(scan_tasks, "run_nmap_discovery", lambda **kwargs: ToolResult(
            False, "", "Nmap discovery exited with code 1: QUITTING!", command_line="nmap -Pn ...", exit_code=1))

        scan_tasks.run_masscan_phase(db, scan_env.scan, [scan_env.target], config)

        tool_exec = only_exec(db, "nmap-discovery")
        assert tool_exec.exit_code == 1 and "QUITTING" in tool_exec.error_message
        assert tool_exec.command_line == "nmap -Pn ..."
        assert scan_env.target.status == "failed" and "QUITTING" in scan_env.target.error_message
        assert scan_env.scan.progress_percent == phase_progress("nmap_discovery", 1.0)

    def test_discovery_unparseable_output_is_not_zero_ports(self, db, scan_env, config, monkeypatch):
        monkeypatch.setattr(scan_tasks, "save_nmap_debug", lambda **kwargs: None)
        monkeypatch.setattr(scan_tasks, "run_nmap_discovery", lambda **kwargs: ToolResult(
            True, "<nmaprun><host>", None, command_line="nmap ...", exit_code=0))

        scan_tasks.run_masscan_phase(db, scan_env.scan, [scan_env.target], config)

        assert scan_env.target.status == "failed"
        assert "Failed to parse" in only_exec(db, "nmap-discovery").error_message

    def test_discovery_success_creates_ports(self, db, scan_env, config, monkeypatch):
        db.delete(scan_env.port)
        db.commit()
        monkeypatch.setattr(scan_tasks, "save_nmap_debug", lambda **kwargs: None)
        monkeypatch.setattr(scan_tasks, "run_nmap_discovery", lambda **kwargs: ToolResult(
            True, NMAP_XML, None, command_line="nmap ...", exit_code=0))

        scan_tasks.run_masscan_phase(db, scan_env.scan, [scan_env.target], config)

        tool_exec = only_exec(db, "nmap-discovery")
        port = db.query(Port).one()
        assert port.port == 80 and port.tool_execution_id == tool_exec.id
        assert scan_env.target.status == "completed" and tool_exec.error_message is None

    def test_discovery_exception_rolls_back_and_closes_open_execution(self, db, scan_env, config, monkeypatch):
        def explode(**kwargs):
            raise RuntimeError("runner crashed")
        monkeypatch.setattr(scan_tasks, "run_nmap_discovery", explode)

        scan_tasks.run_masscan_phase(db, scan_env.scan, [scan_env.target], config)

        tool_exec = only_exec(db, "nmap-discovery")
        assert tool_exec.finished_at is not None and "runner crashed" in tool_exec.error_message
        assert scan_env.target.status == "failed"

    def test_nmap_failure_is_recorded(self, db, scan_env, config, monkeypatch):
        monkeypatch.setattr(scan_tasks, "run_nmap", lambda **kwargs: ToolResult(
            False, "", "Nmap timed out after 420 seconds", command_line="nmap -sT ...",
            exit_code=EXIT_TIMEOUT, timed_out=True))

        scan_tasks.run_nmap_phase(db, scan_env.scan, [scan_env.target], config)

        tool_exec = only_exec(db, "nmap")
        assert tool_exec.exit_code == EXIT_TIMEOUT and "timed out" in tool_exec.error_message
        assert "Nmap failed" in scan_env.target.error_message
        assert scan_env.scan.progress_percent == phase_progress("nmap", 1.0)

    def test_nikto_failure_creates_no_findings(self, db, scan_env, config, monkeypatch):
        monkeypatch.setattr(scan_tasks, "determine_http_protocol", lambda **kwargs: "http")
        monkeypatch.setattr(scan_tasks, "run_nikto", lambda **kwargs: ToolResult(
            False, None, "Nikto exited with code 1: + ERROR", command_line="nikto -h 10.0.0.5 -p 80",
            exit_code=1))

        scan_tasks.run_nikto_phase(db, scan_env.scan, [scan_env.target], config)

        tool_exec = only_exec(db, "nikto")
        assert tool_exec.exit_code == 1 and "ERROR" in tool_exec.error_message
        assert tool_exec.port_id == scan_env.port.id
        assert db.query(Vulnerability).count() == 0

    def test_nikto_success_links_findings(self, db, scan_env, config, monkeypatch):
        report = json.dumps([{"host": "10.0.0.5", "ip": "10.0.0.5", "port": "80", "vulnerabilities": [
            {"id": "000366", "method": "GET", "url": "/backup.sql", "msg": "Database backup file found."}]}])
        monkeypatch.setattr(scan_tasks, "determine_http_protocol", lambda **kwargs: "http")
        monkeypatch.setattr(scan_tasks, "run_nikto", lambda **kwargs: ToolResult(
            True, report, None, command_line="nikto -h 10.0.0.5 -p 80", exit_code=0))

        scan_tasks.run_nikto_phase(db, scan_env.scan, [scan_env.target], config)

        tool_exec = only_exec(db, "nikto")
        vuln = db.query(Vulnerability).one()
        assert vuln.tool_execution_id == tool_exec.id and vuln.port_id == scan_env.port.id
        assert vuln.source_tool == "nikto"
        assert scan_env.scan.total_vulnerabilities == 1


# --------------------------------------------------------------------------- helpers

class TestToolExecHelpers:
    def test_record_tool_result_defaults_error_for_silent_failure(self, db, scan_env):
        tool_exec = start_tool_exec(db, scan_env.target, "nmap", command_line="placeholder")
        record_tool_result(tool_exec, ToolResult(False, "", None), raw_format="xml")
        assert tool_exec.exit_code == 1 and tool_exec.error_message == "nmap failed (exit code 1)"
        assert tool_exec.command_line == "placeholder"  # runner gave none: keep the placeholder

    def test_record_tool_result_accepts_output_dataclasses(self, db, scan_env):
        from app.tools.httpx import HttpxOutput
        tool_exec = start_tool_exec(db, scan_env.target, "httpx", scan_env.port)
        output = HttpxOutput(success=False, error="No HTTP response", command_line="httpx -u x", exit_code=0)
        record_tool_result(tool_exec, output, raw_format="json")
        assert (tool_exec.exit_code, tool_exec.error_message, tool_exec.command_line) == (
            0, "No HTTP response", "httpx -u x")

    def test_fail_tool_exec_recovers_a_session_in_failed_flush_state(self, db, scan_env):
        tool_exec = start_tool_exec(db, scan_env.target, "katana", scan_env.port)
        record_tool_result(tool_exec, ToolResult(True, "", None, command_line="katana -u x", exit_code=0),
                           raw_output="x" * (RAW_OUTPUT_LIMIT + 10), raw_format="jsonl")
        db.add(Port(id=str(uuid.uuid4()), scan_target_id=scan_env.target.id, port=None,
                    protocol="tcp", state="open", discovered_by="x"))
        with pytest.raises(Exception) as excinfo:
            db.flush()
        with pytest.raises(PendingRollbackError):
            db.commit()

        fail_tool_exec(db, tool_exec, excinfo.value)

        db.refresh(tool_exec)
        assert tool_exec.exit_code == 1 and tool_exec.finished_at is not None
        assert "IntegrityError" in tool_exec.error_message
        assert len(tool_exec.raw_output) == RAW_OUTPUT_LIMIT
        assert tool_exec.command_line == "katana -u x" and tool_exec.raw_format == "jsonl"

    def test_fail_tool_exec_without_execution_only_rolls_back(self, db, scan_env):
        scan_env.scan.name = "dirty"
        fail_tool_exec(db, None, RuntimeError("x"))
        assert scan_env.scan.name == "t"

    def test_fail_unfinished_tool_execs(self, db, scan_env):
        open_exec = start_tool_exec(db, scan_env.target, "nuclei", scan_env.port)
        done_exec = start_tool_exec(db, scan_env.target, "nmap")
        record_tool_result(done_exec, ToolResult(True, "<x/>", None, exit_code=0))
        db.commit()

        assert fail_unfinished_tool_execs(db, scan_env.scan.id, "Scan aborted: boom") == 1
        db.commit()

        assert open_exec.exit_code == 1 and open_exec.error_message == "Scan aborted: boom"
        assert open_exec.finished_at is not None
        assert done_exec.exit_code == 0 and done_exec.error_message is None


class TestProgress:
    def test_ranges_are_contiguous_and_cover_zero_to_one(self):
        ranges = list(PHASE_PROGRESS.values())
        assert ranges[0][0] == 0.0 and ranges[-1][1] == 1.0
        for (start, end), (next_start, _next_end) in zip(ranges, ranges[1:]):
            assert start < end and end == next_start

    def test_phase_progress_is_clamped(self):
        assert phase_progress("nuclei", 0) == 0.85
        assert phase_progress("nuclei", 1) == 0.88
        assert phase_progress("nuclei", 5) == 0.88 and phase_progress("nuclei", -1) == 0.85
        assert phase_progress("httpx", 0.5) == 0.765

    def test_progress_never_goes_backwards(self, db, scan_env):
        scan = scan_env.scan
        seen = []
        for phase, done, total in [("nmap_discovery", 1, 1), ("nmap", 1, 2), ("nmap", 2, 2),
                                   ("ssh-audit", 1, 1), ("nuclei", 1, 1),
                                   ("nuclei_endpoints", 1, 3),  # used to drop from 1.0 to 0.88
                                   ("httpx", 1, 1),  # an earlier phase can never lower it
                                   ("nse", 0, 0), ("zap", 1, 1)]:
            set_phase_progress(db, scan, phase, done, total)
            seen.append(scan.progress_percent)
        assert seen == sorted(seen)
        assert seen[-1] == 1.0 and max(seen) <= 1.0

    def test_full_pipeline_order_is_monotonic(self):
        values = [phase_progress(phase, fraction) for phase in PHASE_PROGRESS for fraction in (0, 0.5, 1)]
        assert values == sorted(values)
