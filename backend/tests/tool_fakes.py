"""Helpers for testing tool runners without running any scanner binary."""
from pathlib import Path
from types import SimpleNamespace
from typing import List, Optional


class FakeSubprocess:
    """Stand-in for ``app.tools.base._run_process`` (what ``run_command`` executes).

    Records every command and, like the real tool, optionally writes the
    output file named on the command line before "exiting".
    """

    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "",
                 output: Optional[str] = None, output_flag: Optional[str] = None,
                 raises: Optional[BaseException] = None, extra_files: Optional[dict] = None):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.output = output
        self.output_flag = output_flag
        self.raises = raises
        self.extra_files = extra_files or {}
        self.calls: List[List[str]] = []
        self.kwargs: List[dict] = []
        self.output_path: Optional[Path] = None
        self.output_existed_before_run: Optional[bool] = None

    @property
    def cmd(self) -> List[str]:
        return self.calls[-1]

    def _find_output_path(self, cmd: List[str]) -> Optional[Path]:
        if not self.output_flag:
            return None
        for index, arg in enumerate(cmd):
            if arg == self.output_flag and index + 1 < len(cmd):
                return Path(cmd[index + 1])
            if arg.startswith(self.output_flag + "="):
                return Path(arg.split("=", 1)[1])
        return None

    def __call__(self, cmd, **kwargs):
        self.calls.append(list(cmd))
        self.kwargs.append(kwargs)
        self.output_path = self._find_output_path(cmd)
        if self.output_path is not None:
            self.output_existed_before_run = self.output_path.exists()
            if self.output is not None:
                self.output_path.write_text(self.output)
            for relative, content in self.extra_files.items():
                extra = self.output_path.parent / relative
                extra.parent.mkdir(parents=True, exist_ok=True)
                if isinstance(content, bytes):
                    extra.write_bytes(content)
                else:
                    extra.write_text(content)
        if self.raises is not None:
            raise self.raises
        return SimpleNamespace(returncode=self.returncode, stdout=self.stdout, stderr=self.stderr)


def flag_value(cmd: List[str], flag: str) -> Optional[str]:
    """Value following ``flag`` in an argv list."""
    if flag in cmd:
        return cmd[cmd.index(flag) + 1]
    return None
