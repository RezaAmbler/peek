"""
Parser tests against sample outputs.

The nuclei / httpx / katana samples follow the JSON field names of the pinned
releases (nuclei v3.11.1 pkg/output/output.go, httpx v1.12.0 runner/types.go,
katana v1.8.0 pkg/navigation), read from the upstream source. They were not
captured from a live run - see "Live verification checklist" in
docs/reviews/2026-10-scan-tool-review.md.
"""
import json

import pytest

from app.tools.httpx import parse_httpx_output
from app.tools.katana import _parse_katana_line, _parse_katana_output
from app.tools.masscan import parse_masscan_output
from app.tools.nikto import count_nikto_hosts, parse_nikto_output
from app.tools.nmap import parse_nmap_discovery
from app.tools.nmap_nse import parse_nse_output
from app.tools.nuclei import extract_port_from_matched_at, parse_nuclei_output
from app.tools.zap import parse_zap_alerts

# --------------------------------------------------------------------------- nuclei

NUCLEI_V3_EVENT = {
    "template": "http/cves/2021/CVE-2021-41773.yaml",
    "template-url": "https://cloud.projectdiscovery.io/public/CVE-2021-41773",
    "template-id": "CVE-2021-41773",
    "template-path": "/home/peek/nuclei-templates/http/cves/2021/CVE-2021-41773.yaml",
    "info": {
        "name": "Apache 2.4.49 - Path Traversal",
        "author": ["daffainfo"],
        "tags": ["cve", "cve2021", "lfi", "apache"],
        "description": "A flaw was found in Apache HTTP Server 2.4.49.",
        "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
        "severity": "high",
        "classification": {"cve-id": ["cve-2021-41773"], "cvss-score": 7.5},
    },
    "type": "http",
    "host": "10.0.0.5:8080",
    "port": "8080",
    "scheme": "http",
    "url": "http://10.0.0.5:8080",
    "matched-at": "http://10.0.0.5:8080/cgi-bin/.%2e/.%2e/etc/passwd",
    "extracted-results": ["root:x:0:0"],
    "ip": "10.0.0.5",
    "timestamp": "2026-10-10T12:00:00.000000000Z",
    "curl-command": "curl -X 'GET' 'http://10.0.0.5:8080/cgi-bin/.%2e/.%2e/etc/passwd'",
    "matcher-status": True,
}


class TestNucleiParser:
    def test_parses_v3_event(self):
        vulns = parse_nuclei_output(json.dumps(NUCLEI_V3_EVENT) + "\n")

        assert len(vulns) == 1
        vuln = vulns[0]
        assert vuln["template_id"] == "CVE-2021-41773"
        assert vuln["name"] == "Apache 2.4.49 - Path Traversal"
        assert vuln["severity"] == "high"
        assert vuln["type"] == "http"
        assert vuln["matched_at"].endswith("/etc/passwd")
        assert vuln["host"] == "10.0.0.5:8080"
        assert vuln["port"] == 8080
        assert vuln["extracted_results"] == ["root:x:0:0"]
        assert vuln["curl_command"].startswith("curl ")
        assert vuln["reference"] == ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"]
        assert vuln["tags"] == ["cve", "cve2021", "lfi", "apache"]

    def test_empty_and_whitespace(self):
        assert parse_nuclei_output("") == []
        assert parse_nuclei_output("  \n\n") == []

    def test_malformed_lines_are_skipped_but_valid_ones_kept(self):
        raw = "\n".join(["{truncated", json.dumps(NUCLEI_V3_EVENT), "", "[WRN] not json"])
        assert [v["template_id"] for v in parse_nuclei_output(raw)] == ["CVE-2021-41773"]

    def test_minimal_event_gets_defaults(self):
        vuln = parse_nuclei_output('{"template-id": "x"}')[0]
        assert vuln["name"] == "Unknown Vulnerability" and vuln["severity"] == "info"
        assert vuln["port"] is None and vuln["tags"] == []

    @pytest.mark.parametrize("matched_at,port", [
        ("203.0.113.10:22", 22),
        ("ssh://203.0.113.10:2222", 2222),
        ("https://example.com:8443/x", 8443),
        ("https://example.com/x", 443),
        ("http://example.com/x", 80),
        ("", None),
        ("example.com", None),
    ])
    def test_port_extraction(self, matched_at, port):
        assert extract_port_from_matched_at(matched_at) == port


# --------------------------------------------------------------------------- httpx

HTTPX_V1_12_RESULT = {
    "timestamp": "2026-10-10T12:00:00.000000000Z",
    "tls": {"host": "10.0.0.5", "port": "8443", "tls_version": "tls13",
            "cipher": "TLS_AES_128_GCM_SHA256", "subject_cn": "hellbox"},
    "hash": {"body_md5": "5d41402abc4b2a76b9719d911017c592", "header_md5": "aaa"},
    "cdn_name": "cloudflare",
    "cdn_type": "waf",
    "port": "8443",
    "url": "https://10.0.0.5:8443",
    "input": "https://10.0.0.5:8443",
    "title": "Apache2 Ubuntu Default Page",
    "scheme": "https",
    "webserver": "Apache/2.4.41 (Ubuntu)",
    "content_type": "text/html",
    "method": "GET",
    "host": "10.0.0.5",
    "path": "/",
    "final_url": "https://10.0.0.5:8443/login",
    "time": "245.5ms",
    "jarm_hash": "29d29d00029d29d21c41d41d00041d",
    "chain_status_codes": [302, 200],
    "tech": ["Apache HTTP Server:2.4.41", "Ubuntu"],
    "chain": [
        {"request": "GET / HTTP/1.1", "response": "HTTP/1.1 302", "status_code": 302,
         "location": "/login", "request-url": "https://10.0.0.5:8443"},
        {"request": "GET /login HTTP/1.1", "status_code": 200, "request-url": "https://10.0.0.5:8443/login"},
    ],
    "words": 100,
    "lines": 20,
    "status_code": 200,
    "content_length": 10918,
    "failed": False,
    "vhost": True,
    "cdn": True,
}


class TestHttpxParser:
    def test_parses_v1_12_result(self):
        parsed = parse_httpx_output(json.dumps(HTTPX_V1_12_RESULT))

        assert parsed["url"] == "https://10.0.0.5:8443"
        assert parsed["status_code"] == 200 and parsed["content_length"] == 10918
        assert parsed["content_type"] == "text/html"
        assert parsed["title"] == "Apache2 Ubuntu Default Page"
        assert parsed["webserver"] == "Apache/2.4.41 (Ubuntu)"
        assert parsed["technologies"] == ["Apache HTTP Server:2.4.41", "Ubuntu"]
        assert parsed["final_url"] == "https://10.0.0.5:8443/login"
        assert parsed["redirect_chain"] == ["https://10.0.0.5:8443", "https://10.0.0.5:8443/login"]
        assert parsed["response_time_ms"] == 245
        assert parsed["body_hash"] == "5d41402abc4b2a76b9719d911017c592"
        assert parsed["tls_version"] == "tls13" and parsed["tls_cipher"] == "TLS_AES_128_GCM_SHA256"
        assert parsed["jarm_hash"] == "29d29d00029d29d21c41d41d00041d"
        assert parsed["failed"] is False

    def test_cdn_and_waf_come_from_name_and_type_not_the_boolean(self):
        parsed = parse_httpx_output(json.dumps(HTTPX_V1_12_RESULT))
        assert parsed["cdn"] is None and parsed["waf"] == "cloudflare"

        cdn = dict(HTTPX_V1_12_RESULT, cdn_type="cdn", cdn_name="akamai")
        parsed = parse_httpx_output(json.dumps(cdn))
        assert parsed["cdn"] == "akamai" and parsed["waf"] is None

        plain = {k: v for k, v in HTTPX_V1_12_RESULT.items() if not k.startswith("cdn")}
        parsed = parse_httpx_output(json.dumps(plain))
        assert parsed["cdn"] is None and parsed["waf"] is None

    def test_vhost_boolean_never_becomes_the_host_list(self):
        parsed = parse_httpx_output(json.dumps(HTTPX_V1_12_RESULT))
        assert parsed["virtual_hosts"] == [] and parsed["vhost_detected"] is True

    def test_legacy_field_names_still_accepted(self):
        legacy = {"url": "http://x", "status-code": 301, "jarm": "abc", "cdn": "fastly",
                  "chain": ["http://x", "http://x/a"], "vhost": ["a.example", "b.example"], "time": "1.5s"}
        parsed = parse_httpx_output(json.dumps(legacy))
        assert parsed["status_code"] == 301 and parsed["jarm_hash"] == "abc" and parsed["cdn"] == "fastly"
        assert parsed["redirect_chain"] == ["http://x", "http://x/a"]
        assert parsed["virtual_hosts"] == ["a.example", "b.example"]
        assert parsed["response_time_ms"] == 1500

    def test_only_first_line_is_used(self):
        raw = json.dumps({"url": "http://a", "status_code": 200}) + "\n" + json.dumps({"url": "http://b"})
        assert parse_httpx_output(raw)["url"] == "http://a"

    @pytest.mark.parametrize("raw", ["", "   ", "{truncated", "[1, 2]", None])
    def test_empty_or_malformed_returns_none(self, raw):
        assert parse_httpx_output(raw) is None

    def test_minimal_result(self):
        parsed = parse_httpx_output('{"url": "http://a", "failed": true}')
        assert parsed["failed"] is True and parsed["technologies"] == [] and parsed["redirect_chain"] == []
        assert parsed["tls_version"] is None and parsed["response_time_ms"] is None


# --------------------------------------------------------------------------- katana

class TestKatanaParser:
    def test_v1_8_line(self):
        endpoint = _parse_katana_line({
            "timestamp": "2026-10-10T12:00:00Z",
            "request": {"method": "GET", "endpoint": "http://10.0.0.5/admin", "tag": "a",
                        "attribute": "href", "source": "http://10.0.0.5/"},
            "response": {"status_code": 403, "headers": {"content-type": "text/html; charset=utf-8"},
                         "content_length": 199, "technologies": ["Apache"]},
        })
        assert endpoint.url == "http://10.0.0.5/admin" and endpoint.method == "GET"
        assert endpoint.status_code == 403 and endpoint.content_length == 199
        assert endpoint.content_type == "text/html; charset=utf-8"
        assert endpoint.depth == 0 and endpoint.source == "a"

    def test_request_only_and_flat_lines(self):
        assert _parse_katana_line({"request": {"endpoint": "http://x/a"}}).method == "GET"
        flat = _parse_katana_line({"url": "http://x/b", "method": "post", "status_code": "201"})
        assert (flat.url, flat.method, flat.status_code) == ("http://x/b", "POST", 201)

    @pytest.mark.parametrize("data", [{}, {"request": {}}, {"request": None, "response": None},
                                      {"error": "context deadline exceeded"}])
    def test_lines_without_endpoint_are_dropped(self, data):
        assert _parse_katana_line(data) is None

    def test_output_tolerates_garbage(self):
        raw = "\n".join(["", "garbage", "[1]", '"str"', json.dumps({"request": {"endpoint": "http://x/a"}})])
        assert [e.url for e in _parse_katana_output(raw, 10)] == ["http://x/a"]
        assert _parse_katana_output("", 10) == [] and _parse_katana_output(None, 10) == []


# --------------------------------------------------------------------------- nikto

NIKTO_2_6_REPORT = [{
    "host": "10.0.0.5", "ip": "10.0.0.5", "port": "80", "server_banner": "Apache/2.4.41",
    "start_time": "2026-10-10 12:00:00 +0000", "end_time": "2026-10-10 12:01:00 +0000",
    "vulnerabilities": [
        {"id": "999957", "references": "https://developer.mozilla.org/x", "method": "GET", "url": "/",
         "msg": "The anti-clickjacking X-Frame-Options header is not present."},
        {"id": "000366", "references": "", "method": "GET", "url": "/backup.sql",
         "msg": "Database backup file found."},
    ],
}]


class TestNiktoParser:
    def test_2_6_host_record_layout(self):
        findings = parse_nikto_output(json.dumps(NIKTO_2_6_REPORT))

        assert [f["id"] for f in findings] == ["999957", "000366"]
        assert findings[1]["url"] == "/backup.sql" and findings[1]["method"] == "GET"
        assert findings[1]["name"] == "Database backup file found."

    def test_host_record_without_findings_is_not_a_finding(self):
        report = [{"host": "10.0.0.5", "ip": "10.0.0.5", "port": "80", "vulnerabilities": []}]
        assert parse_nikto_output(json.dumps(report)) == []
        assert count_nikto_hosts(json.dumps(report)) == 1

    def test_legacy_layouts(self):
        single_host = {"host": "h", "ip": "1.2.3.4", "vulnerabilities": [{"id": "1", "msg": "m", "url": "/a"}]}
        assert parse_nikto_output(json.dumps(single_host))[0]["url"] == "/a"
        bare_list = [{"id": "2", "msg": "m2", "url": "/b"}]
        assert parse_nikto_output(json.dumps(bare_list))[0]["id"] == "2"

    def test_empty_and_malformed(self):
        assert parse_nikto_output("") == [] and parse_nikto_output(None) == []
        assert parse_nikto_output("{broken") == []
        assert parse_nikto_output("[]") == []
        assert count_nikto_hosts("[]") == 0 and count_nikto_hosts("{broken") is None


# --------------------------------------------------------------------------- masscan / nmap / zap

class TestOtherParsers:
    def test_masscan(self):
        raw = json.dumps([{"ip": "10.0.0.5", "ports": [{"port": 22, "proto": "tcp", "status": "open"}]},
                          {"ip": "10.0.0.5", "ports": [{"port": 53, "proto": "udp", "status": "open"}]}])
        assert parse_masscan_output(raw) == [
            {"port": 22, "protocol": "tcp", "state": "open"},
            {"port": 53, "protocol": "udp", "state": "open"},
        ]
        assert parse_masscan_output("[]") == []
        with pytest.raises(ValueError):
            parse_masscan_output('[{"ip": "10.0.0.5", "ports": [')

    def test_nmap_discovery(self):
        xml = """<?xml version="1.0"?><nmaprun><host><ports>
            <port protocol="tcp" portid="22"><state state="open"/></port>
            <port protocol="tcp" portid="23"><state state="closed"/></port>
            <port protocol="tcp" portid="8080"><state state="open"/></port>
        </ports></host></nmaprun>"""
        assert [p["port"] for p in parse_nmap_discovery(xml)] == [22, 8080]
        assert parse_nmap_discovery("<nmaprun></nmaprun>") == []
        with pytest.raises(ValueError):
            parse_nmap_discovery("<nmaprun><host>")

    def test_nse(self):
        xml = """<nmaprun><host><ports><port protocol="tcp" portid="3389">
            <script id="rdp-enum-encryption" output="Security layer">
                <elem key="Security layer">CredSSP</elem>
                <table key="levels"><elem>High</elem><elem>FIPS</elem></table>
            </script>
        </port></ports></host></nmaprun>"""
        findings = parse_nse_output(xml)
        assert findings[0]["script_id"] == "rdp-enum-encryption" and findings[0]["port"] == 3389
        assert findings[0]["elements"] == {"Security layer": "CredSSP", "levels": ["High", "FIPS"]}
        with pytest.raises(ValueError):
            parse_nse_output("<nmaprun><host")

    def test_zap(self):
        raw = json.dumps({"alerts": [{"pluginId": "10020", "alert": "Missing Anti-clickjacking Header",
                                      "risk": "Medium", "url": "http://10.0.0.5/", "cweid": "1021"}]})
        finding = parse_zap_alerts(raw)[0]
        assert (finding["alert_id"], finding["severity"], finding["cwe"]) == ("10020", "medium", "1021")
        assert parse_zap_alerts("") == [] and parse_zap_alerts("{broken") == []
        assert parse_zap_alerts('{"alerts": []}') == []
