"""
Unit tests for service_profile.py CVE detection fixes

Tests the following fixes:
1. Service-specific tags preserved when merging with scan_mode tags
2. Multiple product tag matches allowed (no break after first match)
3. Case-insensitive service name matching (miniserv)
4. CVE tag in scan_modes (not cves)
"""

import pytest
import sys
import os

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.service_profile import get_nuclei_profile, build_nuclei_target, reload_config, determine_http_protocol


class TestServiceTagPreservation:
    """Test that service-specific tags are preserved when merging with scan_mode tags."""

    def test_miniserv_retains_webmin_tag(self):
        """miniserv profile should retain 'webmin' tag after scan_mode merge."""
        profile = get_nuclei_profile("miniserv", scan_mode="deep")
        assert "webmin" in profile.tags, f"Expected 'webmin' in tags, got: {profile.tags}"

    def test_miniserv_uses_https(self):
        """miniserv profile should use HTTPS protocol for Webmin CVE detection."""
        profile = get_nuclei_profile("miniserv", scan_mode="deep")
        assert profile.protocol == "https", f"Expected 'https' protocol, got: {profile.protocol}"

    def test_elasticsearch_retains_tag(self):
        """elasticsearch profile should retain 'elasticsearch' tag."""
        profile = get_nuclei_profile("elasticsearch", scan_mode="deep")
        assert "elasticsearch" in profile.tags, f"Expected 'elasticsearch' in tags, got: {profile.tags}"

    def test_http_service_gets_scan_mode_tags(self):
        """Generic HTTP service should get scan_mode tags (cve, vulnerabilities, etc)."""
        profile = get_nuclei_profile("http", scan_mode="deep")
        assert "cve" in profile.tags, f"Expected 'cve' in tags, got: {profile.tags}"
        assert "vulnerabilities" in profile.tags, f"Expected 'vulnerabilities' in tags"


class TestMultipleProductMatches:
    """Test that multiple product tag matches are allowed (no break after first)."""

    def test_apache_tomcat_gets_both_tags(self):
        """Product 'Apache Tomcat' should get both 'apache' and 'tomcat' tags."""
        profile = get_nuclei_profile(
            "http",
            product="Apache Tomcat/Coyote JSP engine 1.1",
            scan_mode="deep"
        )
        assert "apache" in profile.tags, f"Expected 'apache' in tags, got: {profile.tags}"
        assert "tomcat" in profile.tags, f"Expected 'tomcat' in tags, got: {profile.tags}"

    def test_single_product_match(self):
        """Single product name should still match correctly."""
        profile = get_nuclei_profile("http", product="nginx 1.18.0", scan_mode="deep")
        assert "nginx" in profile.tags, f"Expected 'nginx' in tags, got: {profile.tags}"

    def test_drupal_product_match(self):
        """Drupal product should get 'drupal' tag."""
        profile = get_nuclei_profile("http", product="Drupal", scan_mode="deep")
        assert "drupal" in profile.tags, f"Expected 'drupal' in tags, got: {profile.tags}"


class TestServiceMappings:
    """Test that new service mappings work correctly."""

    def test_microsoft_ds_smb_mapping(self):
        """microsoft-ds (port 445) should map to SMB scanning."""
        profile = get_nuclei_profile("microsoft-ds", scan_mode="deep")
        assert profile.should_scan, "microsoft-ds should be scanned"
        assert "smb" in profile.tags, f"Expected 'smb' in tags, got: {profile.tags}"
        assert "samba" in profile.tags, f"Expected 'samba' in tags, got: {profile.tags}"

    def test_ajp13_tomcat_mapping(self):
        """ajp13 (port 8009) should map to Tomcat AJP scanning."""
        profile = get_nuclei_profile("ajp13", scan_mode="deep")
        assert profile.should_scan, "ajp13 should be scanned"
        assert "tomcat" in profile.tags, f"Expected 'tomcat' in tags, got: {profile.tags}"
        assert "ajp" in profile.tags, f"Expected 'ajp' in tags, got: {profile.tags}"

    def test_netbios_ssn_mapping(self):
        """netbios-ssn (port 139) should map to SMB scanning."""
        profile = get_nuclei_profile("netbios-ssn", scan_mode="deep")
        assert profile.should_scan, "netbios-ssn should be scanned"
        assert "smb" in profile.tags or "netbios" in profile.tags


class TestCVEDetectionScenarios:
    """Test realistic CVE detection scenarios from Hellbox v3."""

    def test_vsftpd_cve_2011_2523(self):
        """vsftpd 2.3.4 should be detected for CVE-2011-2523."""
        profile = get_nuclei_profile("ftp", product="vsftpd 2.3.4", scan_mode="deep")
        assert "ftp" in profile.tags
        assert "vsftpd" in profile.tags

    def test_samba_cve_2017_7494(self):
        """Samba should be detected for CVE-2017-7494 (SambaCry)."""
        profile = get_nuclei_profile("microsoft-ds", product="Samba 4.6.3", scan_mode="deep")
        assert "smb" in profile.tags
        assert "samba" in profile.tags

    def test_ghostcat_cve_2020_1938(self):
        """Tomcat AJP should be detected for CVE-2020-1938 (Ghostcat)."""
        profile = get_nuclei_profile("ajp13", scan_mode="deep")
        assert "tomcat" in profile.tags
        assert "ajp" in profile.tags

    def test_apache_path_traversal_cve_2021_41773(self):
        """Apache 2.4.49 should be detected for CVE-2021-41773."""
        profile = get_nuclei_profile("http", product="Apache httpd 2.4.49", scan_mode="deep")
        assert "apache" in profile.tags
        assert "cve" in profile.tags

    def test_webmin_rce_cve_2019_15107(self):
        """Webmin/MiniServ should use HTTPS and include webmin tag."""
        profile = get_nuclei_profile("miniserv", product="MiniServ 1.910 (Webmin httpd)", scan_mode="deep")
        assert profile.protocol == "https"
        assert "webmin" in profile.tags

    def test_elasticsearch_groovy_cve_2015_1427(self):
        """Elasticsearch should be detected for CVE-2015-1427."""
        profile = get_nuclei_profile("elasticsearch", product="Elasticsearch 1.4.2", scan_mode="deep")
        assert "elasticsearch" in profile.tags

    def test_drupal_drupalgeddon_cve_2018_7600(self):
        """Drupal should be detected for CVE-2018-7600."""
        profile = get_nuclei_profile("http", product="Drupal", scan_mode="deep")
        assert "drupal" in profile.tags


class TestTargetBuilding:
    """Test target URL/host building."""

    def test_http_url_format(self):
        """HTTP services should use URL format."""
        profile = get_nuclei_profile("http", scan_mode="deep")
        target = build_nuclei_target("192.168.1.1", 8080, profile)
        assert target == "http://192.168.1.1:8080"

    def test_https_url_format(self):
        """HTTPS services should use URL format with https."""
        profile = get_nuclei_profile("miniserv", scan_mode="deep")
        target = build_nuclei_target("192.168.1.1", 10000, profile)
        assert target == "https://192.168.1.1:10000"

    def test_host_port_format(self):
        """Network services should use host:port format."""
        profile = get_nuclei_profile("ssh", scan_mode="deep")
        target = build_nuclei_target("192.168.1.1", 22, profile)
        assert target == "192.168.1.1:22"


class TestScanModes:
    """Test scan mode configurations."""

    def test_deep_mode_has_cve_tag(self):
        """Deep mode should include 'cve' tag (not 'cves')."""
        profile = get_nuclei_profile("http", scan_mode="deep")
        assert "cve" in profile.tags, f"Expected 'cve' in deep mode tags, got: {profile.tags}"

    def test_fast_mode_has_cve_tag(self):
        """Fast mode should include 'cve' tag (not 'cves')."""
        profile = get_nuclei_profile("http", scan_mode="fast")
        assert "cve" in profile.tags, f"Expected 'cve' in fast mode tags, got: {profile.tags}"


class MockHttpxResult:
    """Mock HttpxResult for testing protocol detection."""
    def __init__(self, tls_version=None, final_url=None):
        self.tls_version = tls_version
        self.final_url = final_url


class TestProtocolDetection:
    """Test TLS-aware protocol detection for Nuclei, Nikto, and ZAP."""

    def test_httpx_tls_detection_overrides_default(self):
        """httpx TLS detection should override default HTTP protocol."""
        httpx_result = MockHttpxResult(tls_version="TLS 1.2")
        protocol = determine_http_protocol(
            ip="192.168.1.1",
            port=10000,
            httpx_result=httpx_result,
            profile_protocol='http'
        )
        assert protocol == 'https', f"Expected 'https' when TLS detected, got: {protocol}"

    def test_httpx_final_url_https_redirect(self):
        """Protocol should be HTTPS if httpx was redirected to HTTPS."""
        httpx_result = MockHttpxResult(final_url="https://192.168.1.1:10000/")
        protocol = determine_http_protocol(
            ip="192.168.1.1",
            port=10000,
            httpx_result=httpx_result,
            profile_protocol='http'
        )
        assert protocol == 'https', f"Expected 'https' from redirect, got: {protocol}"

    def test_nmap_ssl_service_detection(self):
        """ssl/http service name should use HTTPS."""
        protocol = determine_http_protocol(
            ip="192.168.1.1",
            port=8443,
            service_name="ssl/http",
            profile_protocol='http'
        )
        assert protocol == 'https', f"Expected 'https' for ssl/http, got: {protocol}"

    def test_well_known_ssl_port_443(self):
        """Port 443 should use HTTPS by default."""
        protocol = determine_http_protocol(
            ip="192.168.1.1",
            port=443,
            profile_protocol='http'
        )
        assert protocol == 'https', f"Expected 'https' for port 443, got: {protocol}"

    def test_well_known_ssl_port_8443(self):
        """Port 8443 should use HTTPS by default."""
        protocol = determine_http_protocol(
            ip="192.168.1.1",
            port=8443,
            profile_protocol='http'
        )
        assert protocol == 'https', f"Expected 'https' for port 8443, got: {protocol}"

    def test_profile_protocol_fallback(self):
        """Should use profile_protocol when no TLS indicators."""
        protocol = determine_http_protocol(
            ip="192.168.1.1",
            port=8080,
            profile_protocol='http'
        )
        assert protocol == 'http', f"Expected 'http' as fallback, got: {protocol}"

    def test_priority_httpx_over_service_name(self):
        """httpx TLS should have higher priority than service_name."""
        httpx_result = MockHttpxResult(tls_version="TLS 1.3")
        # Even with http service_name, httpx TLS should win
        protocol = determine_http_protocol(
            ip="192.168.1.1",
            port=80,
            service_name="http",
            httpx_result=httpx_result,
            profile_protocol='http'
        )
        assert protocol == 'https', f"httpx TLS should override service_name"


class TestBuildNucleiTargetWithTLS:
    """Test build_nuclei_target with httpx TLS detection."""

    def test_webmin_port_with_tls(self):
        """Webmin (port 10000) should use HTTPS when TLS detected."""
        profile = get_nuclei_profile("miniserv", scan_mode="deep")
        httpx_result = MockHttpxResult(tls_version="TLS 1.2")
        target = build_nuclei_target(
            ip="203.0.113.20",
            port=10000,
            profile=profile,
            httpx_result=httpx_result,
            service_name="miniserv"
        )
        assert target == "https://203.0.113.20:10000", f"Expected HTTPS URL, got: {target}"

    def test_standard_http_port(self):
        """Standard HTTP on port 80 should omit port in URL."""
        profile = get_nuclei_profile("http", scan_mode="deep")
        target = build_nuclei_target(
            ip="192.168.1.1",
            port=80,
            profile=profile
        )
        assert target == "http://192.168.1.1", f"Expected URL without port, got: {target}"

    def test_standard_https_port(self):
        """Standard HTTPS on port 443 should omit port in URL."""
        profile = get_nuclei_profile("https", scan_mode="deep")
        target = build_nuclei_target(
            ip="192.168.1.1",
            port=443,
            profile=profile,
            service_name="https"
        )
        assert target == "https://192.168.1.1", f"Expected URL without port, got: {target}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
