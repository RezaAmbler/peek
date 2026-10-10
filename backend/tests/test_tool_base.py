"""Tests for the shared subprocess plumbing in app.tools.base."""
import subprocess

import pytest

from app.tools import base
from app.tools.base import (
    EXIT_NOT_FOUND,
    EXIT_NOT_RUN,
    EXIT_TIMEOUT,
    ToolResult,
    failure_reason,
    read_output,
    run_command,
    temp_workdir,
)
from tool_fakes import FakeSubprocess


def test_run_command_captures_exit_code_and_output(monkeypatch):
    fake = FakeSubprocess(returncode=3, stdout="out", stderr="err")
    monkeypatch.setattr(base.subprocess, "run", fake)

    run = run_command(["tool", "--flag", "a b"], timeout=5)

    assert run.returncode == 3 and run.exit_code == 3
    assert (run.stdout, run.stderr) == ("out", "err")
    assert run.ran and not run.timed_out and not run.not_found
    assert run.command_line == "tool --flag 'a b'"
    assert fake.kwargs[0]["timeout"] == 5
    assert "shell" not in fake.kwargs[0]


def test_run_command_timeout_is_reported_not_raised(monkeypatch):
    fake = FakeSubprocess(raises=subprocess.TimeoutExpired(cmd="tool", timeout=5, output=b"partial"))
    monkeypatch.setattr(base.subprocess, "run", fake)

    run = run_command(["tool"], timeout=5)

    assert run.timed_out and not run.ran
    assert run.exit_code == EXIT_TIMEOUT
    assert run.stdout == "partial"
    assert failure_reason("Tool", run, 5) == "Tool timed out after 5 seconds"


def test_run_command_missing_binary(monkeypatch):
    monkeypatch.setattr(base.subprocess, "run", FakeSubprocess(raises=FileNotFoundError("tool")))

    run = run_command(["tool"], timeout=5)

    assert run.not_found and run.exit_code == EXIT_NOT_FOUND
    assert "not found" in failure_reason("Tool", run)


def test_run_command_os_error(monkeypatch):
    monkeypatch.setattr(base.subprocess, "run", FakeSubprocess(raises=PermissionError("denied")))

    run = run_command(["tool"], timeout=5)

    assert run.exit_code == EXIT_NOT_RUN
    assert "PermissionError" in failure_reason("Tool", run)


def test_failure_reason_none_on_clean_exit_and_quotes_stderr_on_error(monkeypatch):
    monkeypatch.setattr(base.subprocess, "run", FakeSubprocess(returncode=0))
    assert failure_reason("Tool", run_command(["tool"], timeout=1)) is None

    monkeypatch.setattr(base.subprocess, "run", FakeSubprocess(returncode=2, stderr="flag provided but not defined: -x"))
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
