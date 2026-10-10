"""
Unit tests for CIDR validation and expansion functions.
"""

import pytest
from app.core.validators import validate_cidr, expand_cidr, ValidationError


class TestValidateCidr:
    """Tests for validate_cidr function."""

    def test_valid_cidr_24(self):
        """Test valid /24 network."""
        network, host_count = validate_cidr("192.168.1.0/24")
        assert network == "192.168.1.0/24"
        assert host_count == 254

    def test_valid_cidr_25(self):
        """Test valid /25 network."""
        network, host_count = validate_cidr("192.168.1.0/25")
        assert network == "192.168.1.0/25"
        assert host_count == 126

    def test_valid_cidr_30(self):
        """Test valid /30 network (4 IPs, 2 usable hosts)."""
        network, host_count = validate_cidr("192.168.1.0/30")
        assert network == "192.168.1.0/30"
        assert host_count == 2

    def test_valid_cidr_32(self):
        """Test valid /32 network (single host)."""
        network, host_count = validate_cidr("192.168.1.5/32")
        assert network == "192.168.1.5/32"
        assert host_count == 1

    def test_valid_cidr_31(self):
        """Test valid /31 network (point-to-point link, 2 hosts)."""
        network, host_count = validate_cidr("192.168.1.0/31")
        assert network == "192.168.1.0/31"
        assert host_count == 2

    def test_normalizes_non_network_address(self):
        """Test that non-network address is normalized."""
        network, host_count = validate_cidr("192.168.1.100/24")
        assert network == "192.168.1.0/24"
        assert host_count == 254

    def test_strips_whitespace(self):
        """Test that whitespace is stripped."""
        network, host_count = validate_cidr("  192.168.1.0/24  ")
        assert network == "192.168.1.0/24"

    def test_rejects_too_large_range_16(self):
        """Test that /16 is rejected (too large)."""
        with pytest.raises(ValidationError) as exc_info:
            validate_cidr("10.0.0.0/16")
        assert "too large" in str(exc_info.value).lower()
        assert "/24" in str(exc_info.value)

    def test_rejects_too_large_range_20(self):
        """Test that /20 is rejected with default max_prefix."""
        with pytest.raises(ValidationError) as exc_info:
            validate_cidr("10.0.0.0/20")
        assert "too large" in str(exc_info.value).lower()

    def test_custom_max_prefix(self):
        """Test custom max_prefix allows larger ranges."""
        network, host_count = validate_cidr("10.0.0.0/20", max_prefix=20)
        assert network == "10.0.0.0/20"
        assert host_count == 4094

    def test_rejects_invalid_cidr_format(self):
        """Test that invalid CIDR format is rejected."""
        with pytest.raises(ValidationError) as exc_info:
            validate_cidr("192.168.1.0/")
        assert "invalid" in str(exc_info.value).lower()

    def test_rejects_invalid_prefix(self):
        """Test that invalid prefix (>32) is rejected."""
        with pytest.raises(ValidationError) as exc_info:
            validate_cidr("192.168.1.0/33")
        assert "invalid" in str(exc_info.value).lower()

    def test_rejects_empty_string(self):
        """Test that empty string is rejected."""
        with pytest.raises(ValidationError) as exc_info:
            validate_cidr("")
        assert "empty" in str(exc_info.value).lower()

    def test_rejects_non_string(self):
        """Test that non-string input is rejected."""
        with pytest.raises(ValidationError) as exc_info:
            validate_cidr(123)
        assert "string" in str(exc_info.value).lower()

    def test_rejects_shell_metacharacters(self):
        """Test that shell metacharacters are rejected."""
        dangerous_inputs = [
            "192.168.1.0/24; rm -rf /",
            "192.168.1.0/24 | cat /etc/passwd",
            "192.168.1.0/24 && whoami",
            "$(whoami)/24",
            "`whoami`/24",
        ]
        for dangerous in dangerous_inputs:
            with pytest.raises(ValidationError) as exc_info:
                validate_cidr(dangerous)
            assert "invalid characters" in str(exc_info.value).lower()


class TestExpandCidr:
    """Tests for expand_cidr function."""

    def test_expand_cidr_30(self):
        """Test expanding /30 network (2 usable hosts)."""
        hosts, cidr = expand_cidr("192.168.1.0/30")
        assert cidr == "192.168.1.0/30"
        assert hosts == ["192.168.1.1", "192.168.1.2"]
        assert len(hosts) == 2

    def test_expand_cidr_32(self):
        """Test expanding /32 network (single host)."""
        hosts, cidr = expand_cidr("192.168.1.5/32")
        assert cidr == "192.168.1.5/32"
        assert hosts == ["192.168.1.5"]
        assert len(hosts) == 1

    def test_expand_cidr_31(self):
        """Test expanding /31 network (point-to-point, both IPs usable)."""
        hosts, cidr = expand_cidr("192.168.1.0/31")
        assert cidr == "192.168.1.0/31"
        assert hosts == ["192.168.1.0", "192.168.1.1"]
        assert len(hosts) == 2

    def test_expand_cidr_29(self):
        """Test expanding /29 network (6 usable hosts)."""
        hosts, cidr = expand_cidr("192.168.1.0/29")
        assert cidr == "192.168.1.0/29"
        assert len(hosts) == 6
        assert hosts[0] == "192.168.1.1"
        assert hosts[-1] == "192.168.1.6"

    def test_expand_cidr_24(self):
        """Test expanding /24 network (254 usable hosts)."""
        hosts, cidr = expand_cidr("192.168.1.0/24")
        assert cidr == "192.168.1.0/24"
        assert len(hosts) == 254
        assert hosts[0] == "192.168.1.1"
        assert hosts[-1] == "192.168.1.254"

    def test_non_cidr_single_ip(self):
        """Test that single IP is returned as-is."""
        hosts, cidr = expand_cidr("192.168.1.5")
        assert cidr is None
        assert hosts == ["192.168.1.5"]

    def test_non_cidr_hostname(self):
        """Test that hostname is returned as-is."""
        hosts, cidr = expand_cidr("example.com")
        assert cidr is None
        assert hosts == ["example.com"]

    def test_invalid_cidr_returned_as_is(self):
        """Test that invalid CIDR is returned as-is for downstream validation."""
        hosts, cidr = expand_cidr("not-a-cidr/24")
        assert cidr is None
        assert hosts == ["not-a-cidr/24"]

    def test_strips_whitespace(self):
        """Test that whitespace is stripped."""
        hosts, cidr = expand_cidr("  192.168.1.0/30  ")
        assert cidr == "192.168.1.0/30"
        assert len(hosts) == 2

    def test_normalizes_non_network_address(self):
        """Test that non-network address is normalized."""
        # 192.168.1.101/30 should normalize to 192.168.1.100/30
        hosts, cidr = expand_cidr("192.168.1.101/30")
        assert cidr == "192.168.1.100/30"
        assert "192.168.1.101" in hosts
        assert "192.168.1.102" in hosts

    def test_non_string_input(self):
        """Test that non-string input is converted."""
        hosts, cidr = expand_cidr(12345)
        assert cidr is None
        assert hosts == ["12345"]


# ---------------------------------------------------------------------------
# Scan-config values that reach a scanner's command line
# ---------------------------------------------------------------------------

from app.core.validators import validate_nmap_args, validate_nuclei_template_paths  # noqa: E402
from app.schemas.scan_config import ScanConfigCreate, ScanConfigUpdate  # noqa: E402


class TestNmapArgsAllowList:
    def test_schema_default_is_allowed(self):
        default = ScanConfigCreate.model_fields["nmap_args"].default
        assert validate_nmap_args(default) == default

    @pytest.mark.parametrize("args,expected", [
        (["-sT", "-sV", "-sC", "-T2", "-Pn"], ["-sT", "-sV", "-sC", "-T2", "-Pn"]),
        ([" -sV ", "--open"], ["-sV", "--open"]),
        (["--max-retries", "3"], ["--max-retries", "3"]),
        (["--max-retries=3", "--host-timeout=10m"], ["--max-retries", "3", "--host-timeout", "10m"]),
        (["-O", "--osscan-limit", "--version-intensity", "5"], ["-O", "--osscan-limit", "--version-intensity", "5"]),
    ])
    def test_allowed(self, args, expected):
        assert validate_nmap_args(args) == expected

    @pytest.mark.parametrize("args", [
        [], None, "-sV", ["-oN", "/tmp/x"], ["-oX", "-"], ["-oG=/tmp/x"], ["-iL", "/etc/passwd"],
        ["--script=vuln"], ["--script", "/tmp/x.nse"], ["--script-args", "a=b"], ["--datadir", "/tmp"],
        ["--resume", "x"], ["--stylesheet", "x"], ["-p", "1-65535"], ["-p-"], ["--excludefile", "/x"],
        ["-sV", "scanme.example"], ["-e", "eth0"], ["--proxies", "http://x"], ["-S", "1.2.3.4"],
        ["--version-intensity", "10"], ["--max-rate", "-1"], ["--host-timeout", "10m; id"],
        ["--max-retries"], ["-sV"] * 33, [None], ["-sV\n-oN /tmp/x"],
    ])
    def test_rejected(self, args):
        with pytest.raises(ValidationError):
            validate_nmap_args(args)

    def test_create_and_update_schemas_both_enforce_it(self):
        from pydantic import ValidationError as PydanticValidationError
        with pytest.raises(PydanticValidationError):
            ScanConfigUpdate(nmap_args=["-sV", "-oN", "/app/data/peek.db"])
        with pytest.raises(PydanticValidationError):
            ScanConfigCreate(name="c", targets=["10.0.0.5"], nmap_args=["--script=/tmp/x.nse"])
        assert ScanConfigUpdate(nmap_args=["-sT", "-sV"]).nmap_args == ["-sT", "-sV"]
        assert ScanConfigUpdate().nmap_args is None


class TestNucleiTemplatePaths:
    @pytest.mark.parametrize("value,expected", [
        (None, None), ("", None), ("  ", None),
        ("http/cves/2024", "http/cves/2024"),
        ("http/cves, ssl ,dns/x.yaml", "http/cves,ssl,dns/x.yaml"),
    ])
    def test_allowed(self, value, expected):
        assert validate_nuclei_template_paths(value) == expected

    @pytest.mark.parametrize("value", [
        "/etc/passwd", "../x", "http/../../x", "https://evil.example/t.yaml", "-debug",
        "http//cves", "a,,b", "a b", "a;b", "~/x", ".hidden", 5,
    ])
    def test_rejected(self, value):
        with pytest.raises(ValidationError):
            validate_nuclei_template_paths(value)

    def test_schemas_enforce_it(self):
        from pydantic import ValidationError as PydanticValidationError
        with pytest.raises(PydanticValidationError):
            ScanConfigUpdate(nuclei_templates="/etc/passwd")
        with pytest.raises(PydanticValidationError):
            ScanConfigUpdate(nuclei_templates="https://evil.example/t.yaml")
        assert ScanConfigUpdate(nuclei_templates="http/cves").nuclei_templates == "http/cves"


def test_httpx_screenshots_is_part_of_the_config_api():
    # The Configs page sends this flag; it used to be dropped silently because
    # the schemas did not declare it, so screenshots could never be enabled.
    assert ScanConfigCreate(name="x").httpx_screenshots is False
    assert ScanConfigCreate(name="x", httpx_screenshots=True).model_dump()["httpx_screenshots"] is True
    assert ScanConfigUpdate(httpx_screenshots=True).model_dump(exclude_unset=True) == {"httpx_screenshots": True}
    assert "httpx_screenshots" not in ScanConfigUpdate().model_dump(exclude_unset=True)
