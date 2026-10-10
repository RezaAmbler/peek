"""
Runner tests with a mocked subprocess: no scanner binary is executed.

The central guarantee (review finding H1): a tool that exits non-zero, times
out or is not installed is reported as a failure with an error message - never
as a clean scan with zero findings - and the exact command line and real exit
code are available for the ToolExecution row.
"""
import json
import subprocess
import tempfile
from pathlib import Path

import pytest

from app.tools import base
from app.tools.base import EXIT_NOT_FOUND, EXIT_NOT_RUN, EXIT_TIMEOUT
from app.tools.httpx import run_httpx
from app.tools.katana import run_katana
from app.tools.masscan import run_masscan
from app.tools.nikto import run_nikto
from app.tools.nmap import run_nmap, run_nmap_discovery
from app.tools.nmap_nse import run_nmap_nse, run_nmap_nse_batch
from app.tools.nuclei import run_nuclei, run_nuclei_list
from app.tools.ssh_audit import run_ssh_audit
from app.tools.sslscan import run_sslscan
from app.tools.testssl import run_testssl
from app.tools import zap as zap_module
from tool_fakes import FakeSubprocess, flag_value

NMAP_XML = '<?xml version="1.0"?><nmaprun><host><ports><port protocol="tcp" portid="22"><state state="open"/></port></ports></host></nmaprun>'
NUCLEI_LINE = json.dumps({"template-id": "tech-detect", "info": {"name": "n", "severity": "info"},
                          "type": "http", "host": "http://10.0.0.5", "matched-at": "http://10.0.0.5/"})


@pytest.fixture
def fake(monkeypatch):
    """Install a FakeSubprocess; the test configures it through the returned factory."""
    def install(**kwargs):
        instance = FakeSubprocess(**kwargs)
        monkeypatch.setattr(base.subprocess, "run", instance)
        return instance
    return install


@pytest.fixture
def templates_dir(tmp_path, monkeypatch):
    """A stand-in for the installed nuclei-templates directory."""
    from app.core.config import settings
    root = tmp_path / "keep_nuclei-templates"
    (root / "http" / "cves").mkdir(parents=True)
    (root / "ssl").mkdir()
    monkeypatch.setattr(settings, "NUCLEI_TEMPLATES_DIR", str(root))
    return root


@pytest.fixture(autouse=True)
def isolated_tmp(tmp_path, monkeypatch):
    """Point tempfile at a per-test directory so leaked temp files are detectable."""
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    yield tmp_path
    leftovers = [p.name for p in tmp_path.iterdir() if not p.name.startswith("keep_")]
    assert leftovers == [], f"runner leaked temp files: {leftovers}"


# --------------------------------------------------------------------------- nuclei

class TestNuclei:
    def test_nonzero_exit_with_empty_output_is_a_failure_not_a_clean_scan(self, fake):
        proc = fake(returncode=1, stderr="[FTL] Could not run nuclei: no templates provided for scan",
                    output_flag="-jsonl-export")

        result = run_nuclei(target="http://10.0.0.5:80")
        success, raw, error = result

        assert success is False
        assert raw == ""
        assert "exited with code 1" in error and "no templates provided" in error
        assert result.exit_code == 1
        assert result.command_line.startswith("nuclei ")
        assert proc.output_existed_before_run is False  # no pre-created empty file

    def test_unknown_flag_style_failure_keeps_stderr(self, fake):
        fake(returncode=2, stderr="flag provided but not defined: -omit-raw", output_flag="-jsonl-export")

        success, _, error = run_nuclei(target="10.0.0.5:22", tags=["ssh"])

        assert not success and "flag provided but not defined" in error

    def test_clean_exit_without_findings_is_success(self, fake):
        # nuclei creates an empty export file on a clean run with no matches
        fake(returncode=0, output="", output_flag="-jsonl-export")

        result = run_nuclei(target="http://10.0.0.5:80")

        assert tuple(result) == (True, "", None)
        assert result.exit_code == 0

    def test_clean_exit_without_export_file_is_success(self, fake):
        fake(returncode=0, output=None, output_flag="-jsonl-export")
        assert tuple(run_nuclei(target="http://10.0.0.5:80")) == (True, "", None)

    def test_findings_are_returned(self, fake):
        fake(returncode=0, output=NUCLEI_LINE + "\n", output_flag="-jsonl-export")

        success, raw, error = run_nuclei(target="http://10.0.0.5:80")

        assert success and error is None
        assert json.loads(raw.strip())["template-id"] == "tech-detect"

    def test_command_uses_flags_verified_against_v3_11_1(self, fake, templates_dir):
        proc = fake(returncode=0, output_flag="-jsonl-export")

        run_nuclei(target="http://10.0.0.5:80", severity="critical,high", tags=["http", "cve"],
                   rate_limit=77, exclude_templates=["a/", "b.yaml"], templates="http/cves")
        cmd = proc.cmd

        assert flag_value(cmd, "-target") == "http://10.0.0.5:80"
        assert flag_value(cmd, "-severity") == "critical,high"
        assert flag_value(cmd, "-tags") == "http,cve"
        assert flag_value(cmd, "-rate-limit") == "77"
        assert flag_value(cmd, "-templates") == str(templates_dir / "http" / "cves")
        assert [cmd[i + 1] for i, a in enumerate(cmd) if a == "-exclude-templates"] == ["a/", "b.yaml"]
        for flag in ("-silent", "-no-color", "-no-interactsh", "-omit-raw", "-disable-update-check"):
            assert flag in cmd
        assert proc.kwargs[0]["timeout"] == 300

    @pytest.mark.parametrize("templates", [
        "/etc/passwd",                      # absolute path
        "../../app/data/evil.yaml",         # traversal
        "http/../../outside",               # traversal inside
        "https://evil.example/t.yaml",      # remote template
        "-debug",                           # option injection
        "http/cves,/tmp/x.yaml",            # one bad entry in a list
        "missing/dir",                      # not part of the installed set
        "link-outside",                     # symlink pointing out of the directory
    ])
    def test_custom_templates_outside_the_template_set_are_rejected(self, fake, templates_dir, templates):
        (templates_dir / "link-outside").symlink_to("/etc")
        proc = fake(returncode=0, output_flag="-jsonl-export")

        result = run_nuclei(target="http://10.0.0.5:80", templates=templates)

        assert not result.success and "Invalid nuclei_templates" in result.error
        assert proc.calls == []

    def test_multiple_custom_templates(self, fake, templates_dir):
        proc = fake(returncode=0, output_flag="-jsonl-export")
        run_nuclei(target="http://10.0.0.5:80", templates="http/cves, ssl")
        assert flag_value(proc.cmd, "-templates") == f"{templates_dir / 'http' / 'cves'},{templates_dir / 'ssl'}"

    def test_timeout(self, fake):
        fake(raises=subprocess.TimeoutExpired(cmd="nuclei", timeout=5), output_flag="-jsonl-export")

        result = run_nuclei(target="http://10.0.0.5:80", timeout=5)

        assert not result.success and result.timed_out
        assert result.exit_code == EXIT_TIMEOUT
        assert result.error == "Nuclei timed out after 5 seconds"

    def test_missing_binary(self, fake):
        fake(raises=FileNotFoundError("nuclei"))

        result = run_nuclei(target="http://10.0.0.5:80")

        assert not result.success and result.exit_code == EXIT_NOT_FOUND
        assert "not found" in result.error

    @pytest.mark.parametrize("target", ["http://x; rm -rf /", "http://x`id`", "$(id)", "-version"])
    def test_rejects_injection_without_running(self, fake, target):
        proc = fake()
        success, _, error = run_nuclei(target=target)
        assert not success and "Invalid target" in error
        assert proc.calls == []

    def test_no_target(self, fake):
        proc = fake()
        assert run_nuclei().error == "No target specified"
        assert proc.calls == []

    def test_list_mode_failure_and_success(self, fake, isolated_tmp):
        urls = isolated_tmp / "keep_urls.txt"
        urls.write_text("http://10.0.0.5/a\n")

        proc = fake(returncode=1, stderr="[FTL] boom", output_flag="-jsonl-export")
        result = run_nuclei_list(str(urls))
        assert not result.success and "exited with code 1" in result.error
        assert flag_value(proc.cmd, "-list") == str(urls)
        assert flag_value(proc.cmd, "-tags") == "http,cve,exposure,misconfig,tech"
        assert "-disable-update-check" in proc.cmd

        fake(returncode=0, output=NUCLEI_LINE, output_flag="-jsonl-export")
        assert run_nuclei_list(str(urls)).success

    def test_list_mode_missing_file(self, fake):
        proc = fake()
        assert "not found" in run_nuclei_list("/nonexistent/urls.txt").error
        assert proc.calls == []


# --------------------------------------------------------------------------- nikto

NIKTO_REPORT = json.dumps([{
    "host": "10.0.0.5", "ip": "10.0.0.5", "port": "80", "server_banner": "Apache",
    "vulnerabilities": [{"id": "999100", "method": "GET", "url": "/", "msg": "Server leaks inodes", "references": ""}],
}])


class TestNikto:
    def test_nonzero_exit_is_failure(self, fake):
        proc = fake(returncode=1, stderr="+ ERROR: Unable to open plugins", output_flag="-output")

        result = run_nikto("10.0.0.5", 80)

        assert tuple(result)[:2] == (False, None)
        assert "exited with code 1" in result.error
        assert result.exit_code == 1
        assert proc.output_existed_before_run is False

    def test_clean_exit_with_empty_report_is_failure(self, fake):
        fake(returncode=0, output="", stdout="+ 0 host(s) tested", output_flag="-output")

        success, raw, error = run_nikto("10.0.0.5", 80)

        assert success is False and raw is None
        assert "no report" in error and "0 host(s) tested" in error

    def test_report_without_hosts_is_failure(self, fake):
        fake(returncode=0, output="[]", output_flag="-output")
        success, _, error = run_nikto("10.0.0.5", 80)
        assert not success and "0 hosts" in error

    def test_invalid_json_report_is_failure(self, fake):
        fake(returncode=0, output="{not json", output_flag="-output")
        success, _, error = run_nikto("10.0.0.5", 80)
        assert not success and "not valid JSON" in error

    def test_success(self, fake):
        proc = fake(returncode=0, output=NIKTO_REPORT, output_flag="-output")

        result = run_nikto("10.0.0.5", 8443, timeout=60, ssl=True)

        assert result.success and result.error is None and result.output == NIKTO_REPORT
        cmd = proc.cmd
        assert flag_value(cmd, "-h") == "10.0.0.5" and flag_value(cmd, "-p") == "8443"
        assert flag_value(cmd, "-maxtime") == "60s" and "-ssl" in cmd
        assert proc.kwargs[0]["timeout"] == 90  # -maxtime plus buffer

    def test_timeout_and_validation(self, fake):
        fake(raises=subprocess.TimeoutExpired(cmd="nikto", timeout=150), output_flag="-output")
        result = run_nikto("10.0.0.5", 80)
        assert not result.success and result.exit_code == EXIT_TIMEOUT

        proc = fake()
        assert "validation" in run_nikto("10.0.0.5; id", 80).error
        assert proc.calls == []


# --------------------------------------------------------------------------- masscan

class TestMasscan:
    def test_nonzero_exit_is_failure_not_zero_ports(self, fake):
        proc = fake(returncode=1, stderr="FAIL: permission denied", output_flag="--output-filename")

        result = run_masscan("10.0.0.5")

        assert not result.success and result.output == ""
        assert "permission denied" in result.error
        assert proc.cmd[0] == "masscan"  # no sudo
        assert proc.output_existed_before_run is False

    def test_clean_exit_empty_means_no_ports(self, fake):
        fake(returncode=0, output="", output_flag="--output-filename")
        assert tuple(run_masscan("10.0.0.5")) == (True, "[]", None)

    def test_success_and_interface(self, fake):
        report = '[{"ip": "10.0.0.5", "ports": [{"port": 22, "proto": "tcp", "status": "open"}]}]'
        proc = fake(returncode=0, output=report, output_flag="--output-filename")

        result = run_masscan("10.0.0.5", rate=500, interface="eth0")

        assert result.success and result.output == report
        assert "--rate=500" in proc.cmd and flag_value(proc.cmd, "--interface") == "eth0"

    @pytest.mark.parametrize("kwargs", [{"ip": "10.0.0.5;id"}, {"ip": "10.0.0.5", "interface": "eth0 --foo"}])
    def test_validation(self, fake, kwargs):
        proc = fake()
        assert not run_masscan(**kwargs).success
        assert proc.calls == []


# --------------------------------------------------------------------------- nmap

class TestNmap:
    def test_nonzero_exit_is_failure(self, fake):
        fake(returncode=1, stderr="QUITTING!", output=NMAP_XML, output_flag="-oX")

        result = run_nmap("10.0.0.5", [22, 80], ["-sT", "-sV"])

        assert not result.success and "exited with code 1" in result.error
        assert result.output == NMAP_XML  # kept for debugging
        assert result.exit_code == 1

    def test_empty_output_is_failure(self, fake):
        proc = fake(returncode=0, output="", output_flag="-oX")
        result = run_nmap("10.0.0.5", [22], ["-sT"])
        assert not result.success and "empty output" in result.error
        assert proc.output_existed_before_run is False

    def test_success_and_command(self, fake, monkeypatch):
        monkeypatch.setattr("app.tools.nmap.os.geteuid", lambda: 1000)
        proc = fake(returncode=0, output=NMAP_XML, output_flag="-oX")

        result = run_nmap("10.0.0.5", [80, 22, 80], ["-sS", "-sV", "-p1-10"])

        assert tuple(result) == (True, NMAP_XML, None)
        cmd = proc.cmd
        assert cmd[0] == "nmap" and "sudo" not in cmd
        assert "--privileged" in cmd  # raw-socket scan as non-root relies on file capabilities
        assert flag_value(cmd, "-p") == "22,80" and "-p1-10" not in cmd
        assert cmd[-1] == "10.0.0.5"

    def test_no_privileged_flag_for_connect_scan_or_root(self, fake, monkeypatch):
        monkeypatch.setattr("app.tools.nmap.os.geteuid", lambda: 1000)
        proc = fake(returncode=0, output=NMAP_XML, output_flag="-oX")
        run_nmap("10.0.0.5", [22], ["-sT", "-sV"])
        assert "--privileged" not in proc.cmd

        monkeypatch.setattr("app.tools.nmap.os.geteuid", lambda: 0)
        run_nmap("10.0.0.5", [22], ["-sS"])
        assert "--privileged" not in proc.cmd

    @pytest.mark.parametrize("args", [
        ["-sV", "-oN", "/app/data/peek.db"],        # arbitrary file write
        ["-sV", "-oA", "/tmp/x"],
        ["-sV", "-iL", "/etc/passwd"],              # local file read
        ["--script=/app/data/x.nse"],               # attacker-supplied Lua
        ["--script", "http-title"],
        ["--script-args-file=/tmp/a"],
        ["--datadir=/tmp/x"],
        ["--resume", "/tmp/x"],
        ["--stylesheet=http://evil/x.xsl"],
        ["-sSV"],                                   # combined short flags are not parsed
        ["-sV", "10.9.9.9"],                        # extra target
        ["--max-retries"],                          # missing value
        ["--max-retries", "two"],
        ["--host-timeout=1;id"],
        ["-sV", 5],
    ])
    def test_dangerous_or_unknown_nmap_args_are_rejected_without_running(self, fake, args):
        proc = fake(returncode=0, output=NMAP_XML, output_flag="-oX")

        result = run_nmap("10.0.0.5", [22], args)

        assert not result.success and "validation failed" in result.error
        assert proc.calls == []

    def test_allowed_nmap_args_pass_through(self, fake):
        proc = fake(returncode=0, output=NMAP_XML, output_flag="-oX")

        result = run_nmap("10.0.0.5", [22], ["-sT", "-sV", "-sC", "-T2", "-Pn", "--max-retries", "3",
                                             "--host-timeout=90s", "-p", "1-1000", "-p80"])

        assert result.success
        cmd = proc.cmd
        assert cmd[1:10] == ["-sT", "-sV", "-sC", "-T2", "-Pn", "--max-retries", "3", "--host-timeout", "90s"]
        assert cmd.count("-p") == 1 and flag_value(cmd, "-p") == "22"
        assert "1-1000" not in cmd and "-p80" not in cmd

    def test_privileged_for_aggressive_scan(self, fake, monkeypatch):
        monkeypatch.setattr("app.tools.nmap.os.geteuid", lambda: 1000)
        proc = fake(returncode=0, output=NMAP_XML, output_flag="-oX")
        run_nmap("10.0.0.5", [22], ["-A"])
        assert "--privileged" in proc.cmd

    def test_no_ports_is_success_without_running(self, fake):
        proc = fake()
        assert tuple(run_nmap("10.0.0.5", [], ["-sT"])) == (True, "", None)
        assert proc.calls == []

    def test_validation_and_timeout(self, fake):
        proc = fake()
        assert not run_nmap("10.0.0.5 -oN /etc/x", [22], []).success
        assert proc.calls == []

        fake(raises=subprocess.TimeoutExpired(cmd="nmap", timeout=9), output_flag="-oX")
        result = run_nmap("10.0.0.5", [22], ["-sT"], timeout=9)
        assert result.timed_out and result.error == "Nmap timed out after 9 seconds"

    def test_discovery(self, fake):
        proc = fake(returncode=0, output=NMAP_XML, output_flag="-oX")

        result = run_nmap_discovery("10.0.0.5", timeout=100, additional_ports="5432, bogus, 70000")

        assert result.success
        cmd = proc.cmd
        assert cmd[0] == "nmap" and "sudo" not in cmd and "-sT" in cmd
        assert flag_value(cmd, "--host-timeout") == "100s"
        ports = flag_value(cmd, "-p").split(",")
        assert "5432" in ports and "70000" not in ports and "bogus" not in ports
        assert proc.kwargs[0]["timeout"] == 130

    def test_discovery_full_scan_and_failure(self, fake):
        proc = fake(returncode=1, stderr="Failed to resolve", output_flag="-oX")

        result = run_nmap_discovery("10.0.0.5", full_scan=True)

        assert "-p-" in proc.cmd
        assert not result.success and "exited with code 1" in result.error

    def test_discovery_rejects_bad_timing(self, fake):
        proc = fake()
        assert not run_nmap_discovery("10.0.0.5", timing_template="T4 --script=x").success
        assert proc.calls == []


class TestNmapNse:
    def test_failure_and_success(self, fake):
        fake(returncode=1, stderr="NSE: failed to initialize the script engine", output_flag="-oX")
        result = run_nmap_nse("10.0.0.5", 3389, ["rdp-enum-encryption"])
        assert not result.success and "script engine" in result.error

        proc = fake(returncode=0, output=NMAP_XML, output_flag="-oX")
        result = run_nmap_nse("10.0.0.5", 3389, ["rdp-enum-encryption", "rdp-ntlm-info"])
        assert result.success
        assert "--script=rdp-enum-encryption,rdp-ntlm-info" in proc.cmd
        assert "-p3389" in proc.cmd and "-sT" in proc.cmd

    def test_udp_uses_privileged_when_not_root(self, fake, monkeypatch):
        monkeypatch.setattr("app.tools.nmap_nse.os.geteuid", lambda: 1000)
        proc = fake(returncode=0, output=NMAP_XML, output_flag="-oX")
        run_nmap_nse("10.0.0.5", 123, ["ntp-info"], protocol="udp")
        assert "-sU" in proc.cmd and "--privileged" in proc.cmd

    @pytest.mark.parametrize("scripts", [["ok", "bad script"], ["x;id"], ["--script-args=x"],
                                         ["../../app/data/evil.nse"], ["/tmp/x/"], ["evil.nse"]])
    def test_rejects_bad_script_names(self, fake, scripts):
        proc = fake()
        result = run_nmap_nse("10.0.0.5", 80, scripts)
        assert not result.success and "validation" in result.error
        assert proc.calls == []

    def test_no_scripts(self, fake):
        proc = fake()
        assert tuple(run_nmap_nse("10.0.0.5", 80, [])) == (True, "", None)
        assert proc.calls == []

    def test_batch(self, fake):
        proc = fake(returncode=0, output=NMAP_XML, output_flag="-oX")
        result = run_nmap_nse_batch("10.0.0.5", [
            {"port": 80, "scripts": ["http-title"]},
            {"port": 123, "protocol": "udp", "scripts": ["ntp-info"]},
        ])
        assert result.success
        assert flag_value(proc.cmd, "-p") == "T:80,U:123"

        fake(returncode=1, stderr="err", output_flag="-oX")
        assert not run_nmap_nse_batch("10.0.0.5", [{"port": 80, "scripts": ["http-title"]}]).success


# --------------------------------------------------------------------------- sslscan

class TestSslscan:
    def test_failure_modes(self, fake):
        fake(returncode=1, stderr="ERROR: Could not resolve hostname", output_flag="--xml")
        result = run_sslscan("10.0.0.5", 443)
        assert not result.success and "exited with code 1" in result.error

        fake(returncode=0, output="", output_flag="--xml")
        assert "empty output" in run_sslscan("10.0.0.5", 443).error

        fake(returncode=0, output="<document/>", stdout="Failed to connect", output_flag="--xml")
        assert tuple(run_sslscan("10.0.0.5", 443)) == (False, "<document/>", "Connection failed")

        fake(raises=FileNotFoundError("sslscan"))
        assert run_sslscan("10.0.0.5", 443).exit_code == EXIT_NOT_FOUND

    def test_success(self, fake):
        proc = fake(returncode=0, output="<document/>", output_flag="--xml")
        result = run_sslscan("10.0.0.5", 443)
        assert tuple(result) == (True, "<document/>", None)
        assert proc.cmd[-1] == "10.0.0.5:443" and "--connect-timeout=10" in proc.cmd

    def test_validation(self, fake):
        proc = fake()
        assert not run_sslscan("10.0.0.5 --targets=/etc/passwd", 443).success
        assert proc.calls == []


# --------------------------------------------------------------------------- ssh-audit

class TestSshAudit:
    def test_nonzero_exit_with_valid_json_is_success(self, fake):
        # ssh-audit exits 3 when the audit found failures; the JSON is still valid
        fake(returncode=3, stdout='{"banner": {"raw": "SSH-2.0-OpenSSH_8.2"}}')

        result = run_ssh_audit("10.0.0.5", 22)

        assert result.success and result.error is None
        assert result.exit_code == 3  # real exit code is preserved
        assert result.command_line == "ssh-audit -j -p 22 10.0.0.5"

    def test_empty_output_is_failure(self, fake):
        fake(returncode=1, stdout="", stderr="connection refused")
        assert tuple(run_ssh_audit("10.0.0.5", 22)) == (False, "", "connection refused")

    def test_non_json_output_is_failure(self, fake):
        fake(returncode=1, stdout="\x1b[0;31m[exception] cannot connect to 10.0.0.5 port 22: timed out\x1b[0m")
        success, _, error = run_ssh_audit("10.0.0.5", 22)
        assert not success and "cannot connect" in error

    def test_timeout_and_missing(self, fake):
        fake(raises=subprocess.TimeoutExpired(cmd="ssh-audit", timeout=60))
        result = run_ssh_audit("10.0.0.5", 22)
        assert not result.success and result.exit_code == EXIT_TIMEOUT

        fake(raises=FileNotFoundError("ssh-audit"))
        assert run_ssh_audit("10.0.0.5", 22).exit_code == EXIT_NOT_FOUND


# --------------------------------------------------------------------------- httpx

HTTPX_LINE = json.dumps({"url": "http://10.0.0.5:80", "status_code": 200, "title": "Home", "failed": False})


class TestHttpx:
    def test_nonzero_exit_is_failure(self, fake):
        proc = fake(returncode=2, stderr="flag provided but not defined: -ssw", output_flag="-o")

        output = run_httpx("http://10.0.0.5:80")

        assert not output.success and "flag provided but not defined" in output.error
        assert output.exit_code == 2 and output.command_line.startswith("httpx -u http://10.0.0.5:80")
        assert proc.output_existed_before_run is False

    def test_clean_exit_without_output_means_no_http_response(self, fake):
        fake(returncode=0, output_flag="-o")
        output = run_httpx("http://10.0.0.5:80")
        assert not output.success and output.error == "No HTTP response"
        assert output.exit_code == 0

    def test_success_and_flags_verified_against_v1_12_0(self, fake):
        proc = fake(returncode=0, output=HTTPX_LINE, output_flag="-o")

        output = run_httpx("http://10.0.0.5:80", timeout=7, retries=1, vhost_discovery=True)

        assert output.success and output.raw_json == HTTPX_LINE and output.screenshot_path is None
        cmd = proc.cmd
        for flag in ("-json", "-silent", "-nc", "-duc", "-sc", "-cl", "-ct", "-title", "-server",
                     "-fr", "-include-chain", "-td", "-tls-grab", "-jarm", "-cdn", "-vhost"):
            assert flag in cmd, flag
        assert "-tls-probe" not in cmd  # would probe hostnames outside the target
        assert "-ssw" not in cmd and "-ss" not in cmd
        assert flag_value(cmd, "-timeout") == "7" and flag_value(cmd, "-retries") == "1"
        assert proc.kwargs[0]["timeout"] == 7 * 2 + 30

    def test_screenshot_is_found_in_nested_dir_and_cleaned_up(self, fake):
        # httpx writes <srd>/screenshot/<host>/<hash>.png
        proc = fake(returncode=0, output=HTTPX_LINE, output_flag="-o",
                    extra_files={"screenshots/screenshot/10.0.0.5_80/abc.png": b"\x89PNG"})

        output = run_httpx("http://10.0.0.5:80", screenshots=True, screenshot_timeout=12)

        cmd = proc.cmd
        assert "-ss" in cmd and "-system-chrome" in cmd and "-ho=--no-sandbox" in cmd
        assert "-esb" in cmd and "-ehb" in cmd
        assert flag_value(cmd, "-st") == "12s"
        assert output.success and output.screenshot_path.name == "abc.png"
        assert output.screenshot_path.read_bytes() == b"\x89PNG"
        temp_dir = output.temp_dir
        assert temp_dir is not None and temp_dir.exists()

        output.cleanup()
        output.cleanup()  # idempotent
        assert not temp_dir.exists() and output.screenshot_path is None

    def test_screenshot_requested_but_not_captured_leaves_nothing_behind(self, fake):
        fake(returncode=0, output=HTTPX_LINE, output_flag="-o")
        output = run_httpx("http://10.0.0.5:80", screenshots=True)
        assert output.success and output.screenshot_path is None and output.temp_dir is None

    def test_timeout_missing_and_validation(self, fake):
        fake(raises=subprocess.TimeoutExpired(cmd="httpx", timeout=120), output_flag="-o")
        output = run_httpx("http://10.0.0.5:80")
        assert not output.success and output.timed_out and output.exit_code == EXIT_TIMEOUT
        assert "timed out after 120 seconds" in output.error  # the real limit, not the per-request one

        fake(raises=FileNotFoundError("httpx"))
        assert run_httpx("http://10.0.0.5:80").exit_code == EXIT_NOT_FOUND

        proc = fake()
        output = run_httpx("http://10.0.0.5:80/$(id)")
        assert not output.success and output.exit_code == EXIT_NOT_RUN
        assert proc.calls == []


# --------------------------------------------------------------------------- katana

KATANA_LINES = "\n".join([
    json.dumps({"timestamp": "2026-10-10T00:00:00Z",
                "request": {"method": "GET", "endpoint": "http://10.0.0.5/a", "tag": "a", "attribute": "href",
                            "source": "http://10.0.0.5/"},
                "response": {"status_code": 200, "headers": {"content-type": "text/html"}, "content_length": 12}}),
    "not json",
    json.dumps({"request": {"method": "post", "endpoint": "http://10.0.0.5/login", "tag": "form"}}),
    json.dumps({"error": "no endpoint here"}),
])


class TestKatana:
    def test_nonzero_exit_is_failure(self, fake):
        fake(returncode=1, stderr="[FTL] could not execute crawling", output_flag="-o")

        output = run_katana("http://10.0.0.5")

        assert not output.success and "exited with code 1" in output.error
        assert output.endpoints == [] and output.exit_code == 1

    def test_clean_exit_without_endpoints_is_success(self, fake):
        fake(returncode=0, output="", output_flag="-o")
        output = run_katana("http://10.0.0.5")
        assert output.success and output.endpoints == [] and output.error is None

    def test_success_parsing_and_flags_verified_against_v1_8_0(self, fake):
        proc = fake(returncode=0, output=KATANA_LINES, output_flag="-o")

        output = run_katana("http://10.0.0.5", depth=3, timeout=90, concurrency=5, rate_limit=20)

        assert output.success
        assert [(e.url, e.method) for e in output.endpoints] == [
            ("http://10.0.0.5/a", "GET"), ("http://10.0.0.5/login", "POST")]
        first = output.endpoints[0]
        assert (first.status_code, first.content_type, first.content_length) == (200, "text/html", 12)
        cmd = proc.cmd
        assert flag_value(cmd, "-timeout") == "10"  # per-request timeout
        assert flag_value(cmd, "-crawl-duration") == "90s"  # overall budget
        assert flag_value(cmd, "-d") == "3" and flag_value(cmd, "-c") == "5"
        assert flag_value(cmd, "-rate-limit") == "20" and flag_value(cmd, "-field-scope") == "rdn"
        for flag in ("-jsonl", "-silent", "-nc", "-duc", "-omit-raw", "-omit-body", "-automatic-form-fill"):
            assert flag in cmd, flag
        assert "-headless" not in cmd
        assert proc.kwargs[0]["timeout"] == 120

    def test_headless_uses_system_chrome(self, fake):
        proc = fake(returncode=0, output="", output_flag="-o")
        run_katana("http://10.0.0.5", headless=True)
        assert {"-headless", "-system-chrome", "-no-sandbox"} <= set(proc.cmd)

    def test_max_endpoints(self, fake):
        lines = "\n".join(json.dumps({"request": {"endpoint": f"http://10.0.0.5/{i}"}}) for i in range(10))
        fake(returncode=0, output=lines, output_flag="-o")
        assert len(run_katana("http://10.0.0.5", max_endpoints=3).endpoints) == 3

    def test_timeout_keeps_partial_results_but_is_a_failure(self, fake):
        fake(raises=subprocess.TimeoutExpired(cmd="katana", timeout=150), output=KATANA_LINES, output_flag="-o")

        output = run_katana("http://10.0.0.5")

        assert not output.success and output.timed_out
        assert len(output.endpoints) == 2 and "partial results: 2 endpoints" in output.error

    def test_missing_and_validation(self, fake):
        fake(raises=FileNotFoundError("katana"))
        assert run_katana("http://10.0.0.5").exit_code == EXIT_NOT_FOUND

        proc = fake()
        assert not run_katana("http://10.0.0.5/|id").success
        assert proc.calls == []


# --------------------------------------------------------------------------- testssl

TESTSSL_OK = json.dumps([{"id": "TLS1_2", "severity": "OK", "finding": "offered"}])
TESTSSL_FATAL = json.dumps([{"id": "scanProblem", "severity": "FATAL", "finding": "Can't connect to '10.0.0.5:443'"}])


class TestTestssl:
    def test_success_with_ambiguous_exit_code(self, fake):
        # low non-zero exit codes count ambiguous findings of a scan that ran
        proc = fake(returncode=3, output=TESTSSL_OK, output_flag="--jsonfile")

        output = run_testssl("10.0.0.5", 443)

        assert output.success and output.parsed_data[0]["id"] == "TLS1_2"
        assert output.exit_code == 3
        assert proc.cmd[-1] == "10.0.0.5:443" and "--fast" in proc.cmd
        assert proc.output_existed_before_run is False

    def test_fatal_finding_in_flat_json_is_failure(self, fake):
        fake(returncode=246, output=TESTSSL_FATAL, output_flag="--jsonfile")
        output = run_testssl("10.0.0.5", 443)
        assert not output.success and "Can't connect" in output.error
        assert output.raw_json == TESTSSL_FATAL

    def test_fatal_finding_in_pretty_json_is_failure(self, fake):
        pretty = json.dumps([{"scanResult": [{"severity": "FATAL", "finding": "No engine"}]}])
        fake(returncode=0, output=pretty, output_flag="--jsonfile")
        assert run_testssl("10.0.0.5", 443).error == "No engine"

    def test_fatal_exit_code_is_failure_even_with_output(self, fake):
        fake(returncode=250, output=TESTSSL_OK, stderr="openssl binary problem", output_flag="--jsonfile")
        output = run_testssl("10.0.0.5", 443)
        assert not output.success and "fatal code 250" in output.error

    def test_no_output_invalid_json_timeout_missing(self, fake):
        fake(returncode=254, stderr="unknown option", output_flag="--jsonfile")
        output = run_testssl("10.0.0.5", 443)
        assert not output.success and "exit code 254" in output.error and "unknown option" in output.error

        fake(returncode=0, output="[{", output_flag="--jsonfile")
        assert "Invalid JSON" in run_testssl("10.0.0.5", 443).error

        fake(raises=subprocess.TimeoutExpired(cmd="testssl", timeout=300), output="[{", output_flag="--jsonfile")
        output = run_testssl("10.0.0.5", 443)
        assert not output.success and output.timed_out and output.raw_json == "[{"

        fake(raises=FileNotFoundError("testssl"))
        assert run_testssl("10.0.0.5", 443).exit_code == EXIT_NOT_FOUND

    def test_validation(self, fake):
        proc = fake()
        output = run_testssl("10.0.0.5 --file=/etc/passwd", 443)
        assert not output.success and output.exit_code == EXIT_NOT_RUN
        assert proc.calls == []


# --------------------------------------------------------------------------- zap

class FakeResponse:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status
        self.text = json.dumps(payload)

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise zap_module.requests.HTTPError(f"{self.status_code} error")


@pytest.fixture
def zap(monkeypatch):
    """Route ZAP API calls to canned responses keyed by URL fragment."""
    routes = {}

    def fake_get(url, params=None, timeout=None):
        for fragment, response in routes.items():
            if fragment in url:
                if isinstance(response, Exception):
                    raise response
                return response
        raise AssertionError(f"unexpected ZAP call: {url}")

    monkeypatch.setattr(zap_module.requests, "get", fake_get)
    monkeypatch.setattr(zap_module.time, "sleep", lambda _seconds: None)
    routes["core/view/version"] = FakeResponse({"version": "2.16"})
    routes["spider/action/scan"] = FakeResponse({"scan": "1"})
    routes["spider/view/status"] = FakeResponse({"status": "100"})
    routes["core/view/alerts"] = FakeResponse({"alerts": [{"alert": "X-Frame-Options", "risk": "Medium"}]})
    return routes


class TestZap:
    def test_success(self, zap):
        result = zap_module.run_zap_baseline("http://10.0.0.5:80")
        success, alerts_json, error = result
        assert success and error is None
        assert json.loads(alerts_json)["alerts"][0]["alert"] == "X-Frame-Options"
        assert result.exit_code == 0 and "http://10.0.0.5:80" in result.command_line

    def test_spider_start_failure_is_not_a_clean_scan(self, zap):
        zap["spider/action/scan"] = zap_module.requests.ConnectionError("refused")
        success, alerts_json, error = zap_module.run_zap_baseline("http://10.0.0.5:80")
        assert not success and alerts_json is None and "spider failed to start" in error

    def test_spider_refused_url(self, zap):
        zap["spider/action/scan"] = FakeResponse({"code": "url_not_found", "message": "URL Not Found"})
        success, _, error = zap_module.run_zap_baseline("http://10.0.0.5:80")
        assert not success and "did not start" in error

    def test_alerts_http_error_and_bad_payload(self, zap):
        zap["core/view/alerts"] = FakeResponse({"code": "internal_error"}, status=500)
        result = zap_module.run_zap_baseline("http://10.0.0.5:80")
        assert not result.success and "500" in result.error

        zap["core/view/alerts"] = FakeResponse({"code": "bad_format"})
        result = zap_module.run_zap_baseline("http://10.0.0.5:80")
        assert not result.success and "Unexpected ZAP alerts response" in result.error

    def test_unfinished_spider_is_reported_as_warning(self, zap):
        zap["spider/view/status"] = FakeResponse({"status": "40"})
        result = zap_module.run_zap_baseline("http://10.0.0.5:80", spider_timeout=0)
        assert result.success and "did not finish" in result.error

    def test_zap_unavailable(self, zap, monkeypatch):
        monkeypatch.setattr(zap_module, "wait_for_zap", lambda timeout=60: False)
        assert tuple(zap_module.run_zap_baseline("http://10.0.0.5:80")) == (False, None, "ZAP not available")
