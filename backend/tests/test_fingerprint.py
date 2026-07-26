"""
Unit tests for stable finding fingerprints and ephemeral-port normalization.
"""

from app.services.fingerprint import (
    finding_fingerprint,
    normalize_port,
    LINUX_EPHEMERAL_PORT_MIN,
    LINUX_EPHEMERAL_PORT_MAX,
    IANA_EPHEMERAL_PORT_MIN,
)


class TestNormalizePort:
    """Tests for normalize_port ephemeral/RPC collapsing."""

    def test_well_known_port_passes_through(self):
        assert normalize_port(443, "https") == "443"
        assert normalize_port(22, "ssh") == "22"

    def test_rpcbind_on_fixed_port_not_collapsed(self):
        # rpcbind on its standard 111 is stable and must survive unchanged.
        assert normalize_port(111, "rpcbind") == "111"

    def test_rpc_service_on_high_port_collapses_by_service(self):
        # mountd:49163 and mountd:50011 must collapse to the SAME sentinel.
        assert normalize_port(49163, "mountd") == "ephemeral:mountd"
        assert normalize_port(50011, "mountd") == "ephemeral:mountd"
        assert normalize_port(49163, "mountd") == normalize_port(50011, "mountd")

    def test_nlockmgr_collapses(self):
        assert normalize_port(44971, "nlockmgr") == "ephemeral:nlockmgr"

    def test_linux_dynamic_range_collapses(self):
        assert normalize_port(LINUX_EPHEMERAL_PORT_MIN) == "ephemeral:dyn"
        assert normalize_port(LINUX_EPHEMERAL_PORT_MAX) == "ephemeral:dyn"
        assert normalize_port(45000) == "ephemeral:dyn"

    def test_iana_dynamic_range_collapses(self):
        assert normalize_port(IANA_EPHEMERAL_PORT_MIN) == "ephemeral:dyn"
        assert normalize_port(65535) == "ephemeral:dyn"

    def test_ephemeral_range_uses_service_name_when_present(self):
        assert normalize_port(45000, "someservice") == "ephemeral:someservice"

    def test_none_port(self):
        assert normalize_port(None) == "none"

    def test_boundary_just_below_ephemeral_passes_through(self):
        assert normalize_port(LINUX_EPHEMERAL_PORT_MIN - 1) == str(LINUX_EPHEMERAL_PORT_MIN - 1)


class TestFindingFingerprint:
    """Tests for finding_fingerprint stability across re-detection."""

    def test_deterministic(self):
        fp1 = finding_fingerprint("10.0.0.5", "CVE-2023-1234", 443, "https://10.0.0.5/login")
        fp2 = finding_fingerprint("10.0.0.5", "CVE-2023-1234", 443, "https://10.0.0.5/login")
        assert fp1 == fp2
        assert len(fp1) == 64  # sha256 hex

    def test_stable_across_volatile_query_params(self):
        # Same finding, different session token / random query params -> same fp.
        fp1 = finding_fingerprint("10.0.0.5", "CVE-2023-1234", 443, "https://10.0.0.5/app?sid=abc123&t=1")
        fp2 = finding_fingerprint("10.0.0.5", "CVE-2023-1234", 443, "https://10.0.0.5/app?sid=zzz999&t=2")
        assert fp1 == fp2

    def test_stable_across_ephemeral_port_rotation(self):
        # Same RPC finding on a rebooted box with a rotated port -> same fp.
        fp1 = finding_fingerprint("10.0.0.5", "rpc-info", 49163, "rpc://10.0.0.5/", service_name="mountd")
        fp2 = finding_fingerprint("10.0.0.5", "rpc-info", 50011, "rpc://10.0.0.5/", service_name="mountd")
        assert fp1 == fp2

    def test_host_case_insensitive(self):
        fp1 = finding_fingerprint("Example.COM", "CVE-1", 80, "http://example.com/x")
        fp2 = finding_fingerprint("example.com", "CVE-1", 80, "http://example.com/x")
        assert fp1 == fp2

    def test_cve_takes_precedence_over_template_id(self):
        fp_cve = finding_fingerprint("h", template_id="tpl", cve_id="CVE-2023-1", port=80, matched_at="http://h/")
        fp_direct = finding_fingerprint("h", template_id="CVE-2023-1", port=80, matched_at="http://h/")
        assert fp_cve == fp_direct

    def test_different_identity_differs(self):
        fp1 = finding_fingerprint("10.0.0.5", "CVE-2023-1", 443, "https://10.0.0.5/")
        fp2 = finding_fingerprint("10.0.0.5", "CVE-2023-2", 443, "https://10.0.0.5/")
        assert fp1 != fp2

    def test_different_path_differs(self):
        fp1 = finding_fingerprint("10.0.0.5", "CVE-2023-1", 443, "https://10.0.0.5/a")
        fp2 = finding_fingerprint("10.0.0.5", "CVE-2023-1", 443, "https://10.0.0.5/b")
        assert fp1 != fp2

    def test_handles_missing_matched_at(self):
        fp = finding_fingerprint("10.0.0.5", "CVE-2023-1", 443, None)
        assert len(fp) == 64

    def test_host_port_suffix_stripped(self):
        # Ghostcat regression: one scan reported host "ip:8080", the next "ip".
        # These must fingerprint identically (the port is keyed separately).
        fp1 = finding_fingerprint("184.72.78.242:8080", "CVE-2020-1938", 8009, "184.72.78.242:8009")
        fp2 = finding_fingerprint("184.72.78.242", "CVE-2020-1938", 8009, "184.72.78.242:8009")
        assert fp1 == fp2

    def test_bare_ipv6_host_not_truncated(self):
        # Bare IPv6 has multiple colons and must NOT be treated as host:port.
        fp1 = finding_fingerprint("2001:db8::1", "CVE-1", 443, "https://[2001:db8::1]/x")
        fp2 = finding_fingerprint("2001:db8::1", "CVE-1", 443, "https://[2001:db8::1]/x")
        assert fp1 == fp2

    def test_random_path_segment_collapsed(self):
        # Tomcat path-normalization regression: nuclei injects a random cache-buster
        # segment into the traversal path, different every run -> same finding.
        fp1 = finding_fingerprint("h", "apache-tomcat-manager-path-normalization", 8180,
                                  "http://h:8180/3Gyr71aqWq1eqSFtRDKYFaqClfY/..;/manager/html")
        fp2 = finding_fingerprint("h", "apache-tomcat-manager-path-normalization", 8180,
                                  "http://h:8180/3Gyw0k3CrDkVj8fy7TWFFPazYtX/..;/manager/html")
        assert fp1 == fp2

    def test_real_word_path_segments_still_distinguish(self):
        # Short/word-like segments are NOT random -> distinct paths stay distinct.
        fp1 = finding_fingerprint("h", "CVE-1", 80, "http://h/manager/html")
        fp2 = finding_fingerprint("h", "CVE-1", 80, "http://h/admin/html")
        assert fp1 != fp2
