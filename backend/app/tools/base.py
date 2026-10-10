"""Shared subprocess plumbing for the scan-tool runners.

Every runner goes through :func:`run_command` so that the exact command line,
the real exit code and a timeout / missing-binary marker are always captured,
and returns its result in a form the scan phases can record on the
``ToolExecution`` row.

A runner must never report a failed tool run as a clean scan: a non-zero exit
code, a timeout or a missing binary is a failure even when the output file is
empty (an empty file is *not* proof that nothing was found).
"""
import logging
import shlex
import shutil
import subprocess
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, List, Optional

logger = logging.getLogger(__name__)

# Exit codes recorded when the process never produced one of its own.
# They follow the shell conventions (timeout(1) -> 124, command not found -> 127).
EXIT_TIMEOUT = 124
EXIT_NOT_FOUND = 127
EXIT_NOT_RUN = 1  # validation / internal error before or around the process

# Max characters of stderr/stdout quoted in an error message.
ERROR_SNIPPET_CHARS = 500


@dataclass
class CommandResult:
    """Outcome of one external command."""
    command: List[str]
    returncode: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    not_found: bool = False
    exception: Optional[str] = None
    duration_ms: int = 0

    @property
    def command_line(self) -> str:
        return format_command(self.command)

    @property
    def exit_code(self) -> int:
        """Exit code to record on ToolExecution (never None once the run is over)."""
        if self.timed_out:
            return EXIT_TIMEOUT
        if self.not_found:
            return EXIT_NOT_FOUND
        if self.returncode is None:
            return EXIT_NOT_RUN
        return self.returncode

    @property
    def ran(self) -> bool:
        """True if the process started and exited by itself."""
        return self.returncode is not None and not self.timed_out

    def diagnostics(self) -> str:
        """Short stderr (or stdout) excerpt for error messages."""
        return snippet(self.stderr) or snippet(self.stdout) or "no output"


class ToolResult(tuple):
    """``(success, output, error)`` 3-tuple that also carries execution metadata.

    Unpacks exactly like the plain tuple the runners historically returned, so
    ``success, raw, error = run_x(...)`` keeps working, while the scan phases can
    read ``command_line`` / ``exit_code`` / ``timed_out`` to finalize the
    ``ToolExecution`` row with what actually ran.
    """

    command_line: Optional[str]
    exit_code: Optional[int]
    timed_out: bool

    def __new__(cls, success, output, error, command_line=None, exit_code=None, timed_out=False):
        self = super().__new__(cls, (success, output, error))
        self.command_line = command_line
        if exit_code is None:
            exit_code = 0 if success else EXIT_NOT_RUN
        self.exit_code = exit_code
        self.timed_out = timed_out
        return self

    @classmethod
    def from_command(cls, success, output, error, run: "CommandResult") -> "ToolResult":
        return cls(success, output, error,
                   command_line=run.command_line, exit_code=run.exit_code, timed_out=run.timed_out)

    @property
    def success(self) -> bool:
        return self[0]

    @property
    def output(self):
        return self[1]

    @property
    def error(self) -> Optional[str]:
        return self[2]


def format_command(cmd: List[str]) -> str:
    """Render an argv list as a copy-pasteable shell command line."""
    return " ".join(shlex.quote(str(part)) for part in cmd)


def snippet(text: Optional[str], limit: int = ERROR_SNIPPET_CHARS) -> str:
    """Trimmed tail of tool output (the last lines are where tools report errors)."""
    if not text:
        return ""
    text = text.strip()
    if len(text) <= limit:
        return text
    return "..." + text[-limit:]


def run_command(cmd: List[str], timeout: float) -> CommandResult:
    """Run ``cmd`` (argv list, never a shell string) and capture everything.

    Never raises for the expected failure modes: a timeout, a missing binary or
    an OS error are reported on the returned :class:`CommandResult`.
    """
    result = CommandResult(command=[str(part) for part in cmd])
    started = time.monotonic()
    try:
        completed = subprocess.run(
            result.command,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
        )
        result.returncode = completed.returncode
        result.stdout = completed.stdout or ""
        result.stderr = completed.stderr or ""
    except subprocess.TimeoutExpired as exc:
        result.timed_out = True
        result.stdout = _as_text(exc.stdout)
        result.stderr = _as_text(exc.stderr)
    except FileNotFoundError:
        result.not_found = True
    except Exception as exc:  # PermissionError, OSError, ...
        result.exception = f"{type(exc).__name__}: {exc}"
    result.duration_ms = int((time.monotonic() - started) * 1000)
    return result


def _as_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


@contextmanager
def temp_workdir(prefix: str) -> Iterator[Path]:
    """Private temp directory that is always removed, whatever is left inside.

    Runners point the tool's output flag at a path inside it that does not exist
    yet, so "the tool wrote a file" is a real signal (unlike a pre-created
    ``NamedTemporaryFile``).
    """
    path = Path(tempfile.mkdtemp(prefix=prefix))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def read_output(path: Path) -> str:
    """Read a tool output file; missing file -> empty string."""
    try:
        return path.read_text(errors="replace")
    except FileNotFoundError:
        return ""
    except OSError as exc:
        logger.warning(f"Could not read tool output {path}: {exc}")
        return ""


def failure_reason(tool: str, run: CommandResult, timeout: Optional[float] = None) -> Optional[str]:
    """Error message for a run that did not exit cleanly, or None if it exited 0."""
    if run.timed_out:
        limit = f" after {int(timeout)} seconds" if timeout is not None else ""
        return f"{tool} timed out{limit}"
    if run.not_found:
        return f"{tool} not found (binary '{run.command[0]}' is not installed or not on PATH)"
    if run.exception:
        return f"{tool} execution failed: {run.exception}"
    if run.returncode != 0:
        return f"{tool} exited with code {run.returncode}: {run.diagnostics()}"
    return None
