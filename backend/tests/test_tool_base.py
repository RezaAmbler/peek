"""Tests for the shared subprocess plumbing in app.tools.base."""
import os
import subprocess
import sys
import time

import pytest

from app.tools import base
from app.tools.base import (
    EXIT_NOT_FOUND,
    EXIT_NOT_RUN,
    EXIT_TIMEOUT,
    ScanCancelled,
    ToolResult,
    failure_reason,
    read_output,
    run_command,
    temp_workdir,
)
from tool_fakes import FakeSubprocess


def test_run_command_captures_exit_code_and_output(monkeypatch):
    fake = FakeSubprocess(returncode=3, stdout="out", stderr="err")
    monkeypatch.setattr(base, "_run_process", fake)

    run = run_command(["tool", "--flag", "a b"], timeout=5)

    assert run.returncode == 3 and run.exit_code == 3
    assert (run.stdout, run.stderr) == ("out", "err")
    assert run.ran and not run.timed_out and not run.not_found
    assert run.command_line == "tool --flag 'a b'"
    assert fake.kwargs[0]["timeout"] == 5
    assert "shell" not in fake.kwargs[0]


def test_run_command_timeout_is_reported_not_raised(monkeypatch):
    fake = FakeSubprocess(raises=subprocess.TimeoutExpired(cmd="tool", timeout=5, output=b"partial"))
    monkeypatch.setattr(base, "_run_process", fake)

    run = run_command(["tool"], timeout=5)

    assert run.timed_out and not run.ran
    assert run.exit_code == EXIT_TIMEOUT
    assert run.stdout == "partial"
    assert failure_reason("Tool", run, 5) == "Tool timed out after 5 seconds"


def test_run_command_missing_binary(monkeypatch):
    monkeypatch.setattr(base, "_run_process", FakeSubprocess(raises=FileNotFoundError("tool")))

    run = run_command(["tool"], timeout=5)

    assert run.not_found and run.exit_code == EXIT_NOT_FOUND
    assert "not found" in failure_reason("Tool", run)


def test_run_command_os_error(monkeypatch):
    monkeypatch.setattr(base, "_run_process", FakeSubprocess(raises=PermissionError("denied")))

    run = run_command(["tool"], timeout=5)

    assert run.exit_code == EXIT_NOT_RUN
    assert "PermissionError" in failure_reason("Tool", run)


def test_failure_reason_none_on_clean_exit_and_quotes_stderr_on_error(monkeypatch):
    monkeypatch.setattr(base, "_run_process", FakeSubprocess(returncode=0))
    assert failure_reason("Tool", run_command(["tool"], timeout=1)) is None

    monkeypatch.setattr(base, "_run_process", FakeSubprocess(returncode=2, stderr="flag provided but not defined: -x"))
    reason = failure_reason("Tool", run_command(["tool"], timeout=1))
    assert reason == "Tool exited with code 2: flag provided but not defined: -x"


def test_tool_result_unpacks_like_a_tuple_and_carries_metadata():
    result = ToolResult(False, "", "boom", command_line="tool -x", exit_code=2, timed_out=False)

    success, output, error = result
    assert (success, output, error) == (False, "", "boom")
    assert result == (False, "", "boom")
    assert (result.success, result.output, result.error) == (False, "", "boom")
    assert result.command_line == "tool -x" and result.exit_code == 2


@pytest.mark.parametrize("success,expected", [(True, 0), (False, EXIT_NOT_RUN)])
def test_tool_result_default_exit_code(success, expected):
    assert ToolResult(success, "", None).exit_code == expected


def test_temp_workdir_is_removed_even_when_not_empty_or_on_error():
    with temp_workdir("peek_test_") as workdir:
        (workdir / "sub").mkdir()
        (workdir / "sub" / "file.txt").write_text("x")
        assert read_output(workdir / "sub" / "file.txt") == "x"
        assert read_output(workdir / "missing.txt") == ""
    assert not workdir.exists()

    with pytest.raises(RuntimeError):
        with temp_workdir("peek_test_") as workdir:
            (workdir / "leftover").write_text("x")
            raise RuntimeError("boom")
    assert not workdir.exists()


def test_scanner_processes_do_not_inherit_application_secrets(monkeypatch):
    monkeypatch.setenv("SECRET_KEY", "s" * 40)
    monkeypatch.setenv("INITIAL_ADMIN_PASSWORD", "Sup3r-Secret")
    monkeypatch.setenv("SMTP_PASSWORD", "mail-secret")
    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://hooks.example/x")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///x")
    monkeypatch.setenv("MY_API_TOKEN", "t")
    monkeypatch.setenv("PEEK_HARMLESS", "1")
    fake = FakeSubprocess(returncode=0)
    monkeypatch.setattr(base, "_run_process", fake)

    run_command(["tool"], timeout=1)

    env = fake.kwargs[0]["env"]
    for secret in ("SECRET_KEY", "INITIAL_ADMIN_PASSWORD", "SMTP_PASSWORD", "SLACK_WEBHOOK_URL",
                   "DATABASE_URL", "MY_API_TOKEN"):
        assert secret not in env
    assert env["PEEK_HARMLESS"] == "1" and "PATH" in env


# --- real processes: process-group ownership and cancellation ---------------

def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    # a killed-but-unreaped orphan still answers signal 0
    try:
        with open(f"/proc/{pid}/stat") as handle:
            return handle.read().rsplit(")", 1)[1].split()[0] != "Z"
    except OSError:
        return False


def _wait_gone(pid: int, seconds: float = 5.0) -> bool:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if not _alive(pid):
            return True
        time.sleep(0.05)
    return False


def test_run_command_runs_a_real_process():
    run = run_command([sys.executable, "-c", "import sys; print('out'); sys.stderr.write('err'); sys.exit(3)"],
                      timeout=30)

    assert (run.returncode, run.stdout.strip(), run.stderr) == (3, "out", "err")
    assert run.exit_code == 3 and not run.timed_out


def test_timeout_kills_the_whole_process_tree(tmp_path):
    pidfile = tmp_path / "child.pid"
    # a "scanner" that starts a long-lived helper (think: headless browser) and hangs
    script = (
        "import subprocess, sys, time\n"
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(300)'])\n"
        f"open({str(pidfile)!r}, 'w').write(str(child.pid))\n"
        "print('partial', flush=True)\n"
        "time.sleep(300)\n"
    )

    run = run_command([sys.executable, "-c", script], timeout=1.5)

    assert run.timed_out and run.exit_code == EXIT_TIMEOUT
    assert "partial" in run.stdout
    assert _wait_gone(int(pidfile.read_text()))


def test_children_left_behind_after_a_clean_exit_are_killed(tmp_path):
    pidfile = tmp_path / "child.pid"
    script = (
        "import subprocess, sys\n"
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(300)'],\n"
        "                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
        f"open({str(pidfile)!r}, 'w').write(str(child.pid))\n"
    )

    run = run_command([sys.executable, "-c", script], timeout=30)

    assert run.returncode == 0
    assert _wait_gone(int(pidfile.read_text()))


def test_cancelled_scan_stops_the_running_command(monkeypatch):
    monkeypatch.setattr(base, "CANCEL_POLL_SECONDS", 0.1)
    base.set_cancel_check(lambda: True)
    try:
        started = time.monotonic()
        with pytest.raises(ScanCancelled):
            run_command([sys.executable, "-c", "import time; time.sleep(300)"], timeout=60)
        assert time.monotonic() - started < 10
    finally:
        base.set_cancel_check(None)


def test_cancel_check_errors_do_not_stop_the_command():
    def broken():
        raise RuntimeError("db down")

    base.set_cancel_check(broken)
    try:
        assert base.cancel_requested() is False
    finally:
        base.set_cancel_check(None)
    assert base.cancel_requested() is False


def test_each_run_gets_a_private_tmpdir_that_is_removed():
    run = run_command([sys.executable, "-c",
                       "import os, tempfile; d = tempfile.mkdtemp(prefix='tool-'); "
                       "open(os.path.join(d, 'x'), 'w').close(); print(os.environ['TMPDIR']); print(d)"],
                      timeout=30)

    tmpdir, leftover = run.stdout.split()
    assert leftover.startswith(tmpdir + os.sep)
    assert not os.path.exists(tmpdir)


def test_error_snippets_drop_terminal_colour_codes():
    assert base.snippet("\x1b[0;35mFatal error: no TLS\x1b[m\n") == "Fatal error: no TLS"


def test_run_command_reports_progress_while_the_tool_runs(monkeypatch):
    from app.tools import base

    calls = []
    monkeypatch.setattr(base, "CANCEL_POLL_SECONDS", 0.05)
    base.set_progress_hook(lambda elapsed, timeout: calls.append((elapsed, timeout)))
    try:
        run = base.run_command(["sleep", "0.4"], timeout=30)
    finally:
        base.set_progress_hook(None)

    assert run.exit_code == 0
    assert calls and all(timeout == 30 and elapsed >= 0 for elapsed, timeout in calls)


def test_a_failing_progress_hook_does_not_fail_the_tool(monkeypatch):
    from app.tools import base

    def broken(elapsed, timeout):
        raise RuntimeError("database is locked")

    monkeypatch.setattr(base, "CANCEL_POLL_SECONDS", 0.05)
    base.set_progress_hook(broken)
    try:
        run = base.run_command(["sleep", "0.2"], timeout=30)
    finally:
        base.set_progress_hook(None)

    assert run.exit_code == 0
