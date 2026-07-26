"""
Unit tests for risk enrichment (CVE identity, CVSS/EPSS/KEV, risk_score).

No real network: external feeds are monkeypatched. The offline test proves the
bundled KEV snapshot resolves the CVEs the hellbox QA plants when every network
call fails.
"""

import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base
import app.models  # noqa: F401  (register all tables)
from app.models import Scan, ScanTarget, Vulnerability
from app.services import enrichment_service as es


# CVEs the hellbox QA plants — must resolve from the bundled snapshot offline.
PLANTED_KEV_CVES = [
    "CVE-2021-41773",
    "CVE-2019-15107",
    "CVE-2017-12615",
    "CVE-2018-7600",
    "CVE-2015-1427",
    "CVE-2011-2523",
]


@pytest.fixture(autouse=True)
def reset_caches():
    """Clear the process-level enrichment caches around every test."""
    es._kev_set_mem = None
    es._cvss_cache.clear()
    es._epss_cache.clear()
    yield
    es._kev_set_mem = None
    es._cvss_cache.clear()
    es._epss_cache.clear()


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        yield session
    finally:
        session.close()


# =============================================================================
# CVE extraction
# =============================================================================
class TestExtractCve:
    def test_from_template_id_plain(self):
        assert es.extract_cve("CVE-2021-41773", None, None) == "CVE-2021-41773"

    def test_from_template_id_embedded_and_lowercase(self):
        assert es.extract_cve("apache-cve-2021-41773-lfi", None, None) == "CVE-2021-41773"

    def test_from_tags_when_template_has_none(self):
        assert es.extract_cve("generic-lfi", ["lfi", "cve-2018-7600"], None) == "CVE-2018-7600"

    def test_from_reference_list_last(self):
        refs = ["https://example.com", "https://nvd.nist.gov/vuln/detail/CVE-2019-15107"]
        assert es.extract_cve("some-template", ["misc"], refs) == "CVE-2019-15107"

    def test_precedence_template_over_tags_and_refs(self):
        cve = es.extract_cve("CVE-2011-2523", ["cve-2018-7600"], ["CVE-2017-12615"])
        assert cve == "CVE-2011-2523"

    def test_returns_none_when_absent(self):
        assert es.extract_cve("wordpress-exposure", ["wordpress", "exposure"], ["http://x"]) is None

    def test_handles_none_inputs(self):
        assert es.extract_cve(None, None, None) is None

    def test_five_digit_cve(self):
        assert es.extract_cve("CVE-2024-123456", None, None) == "CVE-2024-123456"


# =============================================================================
# CVSS / EPSS with mocked HTTP
# =============================================================================
class TestFetchWithMockedHttp:
    def test_fetch_cvss_prefers_v31(self, monkeypatch):
        def fake(url, params=None):
            assert url == es.NVD_CVE_URL
            assert params["cveId"] == "CVE-2021-41773"
            return {
                "vulnerabilities": [
                    {"cve": {"metrics": {
                        "cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "vectorString": "CVSS:3.1/AV:N/AC:L"}}],
                        "cvssMetricV2": [{"cvssData": {"baseScore": 5.0, "vectorString": "AV:N/AC:L"}}],
                    }}}
                ]
            }
        monkeypatch.setattr(es, "_fetch_json", fake)
        score, vector = es.fetch_cvss("CVE-2021-41773")
        assert score == 7.5
        assert vector == "CVSS:3.1/AV:N/AC:L"

    def test_fetch_cvss_falls_back_to_v2(self, monkeypatch):
        def fake(url, params=None):
            return {"vulnerabilities": [{"cve": {"metrics": {
                "cvssMetricV2": [{"cvssData": {"baseScore": 6.4, "vectorString": "AV:N/AC:L"}}],
            }}}]}
        monkeypatch.setattr(es, "_fetch_json", fake)
        score, vector = es.fetch_cvss("CVE-2000-0001")
        assert score == 6.4
        assert vector == "AV:N/AC:L"

    def test_fetch_cvss_network_failure_returns_none(self, monkeypatch):
        def boom(*a, **k):
            raise ConnectionError("no net")
        monkeypatch.setattr(es, "_fetch_json", boom)
        assert es.fetch_cvss("CVE-2000-0002") == (None, None)

    def test_fetch_cvss_memoized(self, monkeypatch):
        calls = {"n": 0}

        def fake(url, params=None):
            calls["n"] += 1
            return {"vulnerabilities": [{"cve": {"metrics": {
                "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "vectorString": "v"}}],
            }}}]}
        monkeypatch.setattr(es, "_fetch_json", fake)
        es.fetch_cvss("CVE-2021-44228")
        es.fetch_cvss("CVE-2021-44228")
        assert calls["n"] == 1

    def test_fetch_epss(self, monkeypatch):
        def fake(url, params=None):
            assert url == es.EPSS_URL
            return {"status": "OK", "data": [{"cve": "CVE-2021-41773", "epss": "0.94321"}]}
        monkeypatch.setattr(es, "_fetch_json", fake)
        assert es.fetch_epss("CVE-2021-41773") == pytest.approx(0.94321)

    def test_fetch_epss_failure_returns_none(self, monkeypatch):
        def boom(*a, **k):
            raise TimeoutError()
        monkeypatch.setattr(es, "_fetch_json", boom)
        assert es.fetch_epss("CVE-2000-0003") is None


# =============================================================================
# Risk scoring
# =============================================================================
class TestComputeRiskScore:
    def test_kev_high_outranks_no_exploit_critical(self):
        # The core prioritization invariant.
        kev_high = es.compute_risk_score(
            cvss=7.5, epss=None, kev_flag=True, exploit_known=True, severity="high"
        )
        no_exploit_critical = es.compute_risk_score(
            cvss=9.0, epss=None, kev_flag=False, exploit_known=False, severity="critical"
        )
        assert kev_high > no_exploit_critical

    def test_cvss_scaled_x10(self):
        assert es.compute_risk_score(
            cvss=5.0, epss=None, kev_flag=False, exploit_known=False, severity="medium"
        ) == 50.0

    def test_severity_fallback_when_no_cvss(self):
        # No CVSS -> severity map (critical -> 90).
        assert es.compute_risk_score(
            cvss=None, epss=None, kev_flag=False, exploit_known=False, severity="critical"
        ) == 90.0

    def test_epss_increases_score(self):
        low = es.compute_risk_score(
            cvss=5.0, epss=0.0, kev_flag=False, exploit_known=False, severity="medium"
        )
        high = es.compute_risk_score(
            cvss=5.0, epss=0.9, kev_flag=False, exploit_known=False, severity="medium"
        )
        assert high > low

    def test_clamped_to_100(self):
        assert es.compute_risk_score(
            cvss=10.0, epss=1.0, kev_flag=True, exploit_known=True, severity="critical"
        ) == 100.0

    def test_never_negative(self):
        assert es.compute_risk_score(
            cvss=0.0, epss=None, kev_flag=False, exploit_known=False, severity="info"
        ) >= 0.0

    def test_info_detection_with_high_cvss_is_capped(self):
        # Regression: an info-severity detection template mapped to a high-CVSS CVE
        # (e.g. "OpenSSH Service - Detect" / CVE-2016-6210) must NOT score 100.
        # base = min(9.9*10, info ceiling 20) = 20.
        score = es.compute_risk_score(
            cvss=9.9, epss=None, kev_flag=False, exploit_known=False, severity="info"
        )
        assert score == 20.0
        assert score < 50.0

    def test_low_severity_base_capped_at_40(self):
        score = es.compute_risk_score(
            cvss=9.0, epss=None, kev_flag=False, exploit_known=False, severity="low"
        )
        assert score == 40.0

    def test_medium_and_above_uncapped_by_ceiling(self):
        # A real high/critical keeps the full CVSS-derived base (ceiling = 100).
        assert es.compute_risk_score(
            cvss=9.0, epss=None, kev_flag=False, exploit_known=False, severity="high"
        ) == 90.0
        assert es.compute_risk_score(
            cvss=9.8, epss=None, kev_flag=False, exploit_known=False, severity="medium"
        ) == 98.0

    def test_capped_info_still_ranks_below_real_high(self):
        info_high_cvss = es.compute_risk_score(
            cvss=9.9, epss=0.5, kev_flag=False, exploit_known=False, severity="info"
        )
        real_high = es.compute_risk_score(
            cvss=7.0, epss=0.0, kev_flag=False, exploit_known=False, severity="high"
        )
        assert info_high_cvss < real_high


# =============================================================================
# KEV offline fallback
# =============================================================================
class TestKevOfflineFallback:
    def test_falls_back_to_bundled_snapshot(self, monkeypatch, tmp_path):
        # Every network call fails and no on-disk cache exists.
        def boom(*a, **k):
            raise ConnectionError("no net")

        monkeypatch.setattr(es, "_fetch_json", boom)
        monkeypatch.setattr(es, "KEV_CACHE_FILE", tmp_path / "does_not_exist.json")

        kev = es.load_kev_catalog(force_refresh=True)

        for cve in PLANTED_KEV_CVES:
            assert cve in kev, f"{cve} should resolve from bundled snapshot offline"

    def test_live_feed_used_when_available(self, monkeypatch, tmp_path):
        def fake(url, params=None):
            assert url == es.KEV_FEED_URL
            return {"vulnerabilities": [{"cveID": "CVE-2099-0001"}]}

        monkeypatch.setattr(es, "_fetch_json", fake)
        monkeypatch.setattr(es, "KEV_CACHE_FILE", tmp_path / "cache.json")

        kev = es.load_kev_catalog(force_refresh=True)
        assert "CVE-2099-0001" in kev
        # And it was persisted to the daily cache.
        assert (tmp_path / "cache.json").exists()


# =============================================================================
# Enrichment field mapping (unit) + batch DB integration
# =============================================================================
class _FakeVuln:
    def __init__(self, template_id, tags=None, reference=None, severity="high"):
        self.template_id = template_id
        self.tags = tags
        self.reference = reference
        self.severity = severity
        self.cve_id = None
        self.cvss_score = None
        self.cvss_vector = None
        self.epss_score = None
        self.kev_flag = None
        self.exploit_known = None
        self.risk_score = None


class TestApplyEnrichment:
    def test_maps_all_fields_for_kev_cve(self, monkeypatch):
        monkeypatch.setattr(es, "fetch_cvss", lambda cve: (7.5, "CVSS:3.1/AV:N"))
        monkeypatch.setattr(es, "fetch_epss", lambda cve: 0.9)

        vuln = _FakeVuln("CVE-2021-41773", tags=["cve", "apache"], severity="high")
        es._apply_enrichment(vuln, kev_set={"CVE-2021-41773"})

        assert vuln.cve_id == "CVE-2021-41773"
        assert vuln.cvss_score == 7.5
        assert vuln.cvss_vector == "CVSS:3.1/AV:N"
        assert vuln.epss_score == 0.9
        assert vuln.kev_flag is True
        assert vuln.exploit_known is True  # KEV implies exploit known
        assert vuln.risk_score == 100.0

    def test_no_cve_uses_severity_fallback(self, monkeypatch):
        monkeypatch.setattr(es, "fetch_cvss", lambda cve: (None, None))
        monkeypatch.setattr(es, "fetch_epss", lambda cve: None)

        vuln = _FakeVuln("wordpress-exposure", tags=["exposure"], severity="medium")
        es._apply_enrichment(vuln, kev_set=set())

        assert vuln.cve_id is None
        assert vuln.kev_flag is False
        assert vuln.exploit_known is False
        assert vuln.risk_score == 40.0  # medium fallback

    def test_exploit_known_inferred_from_tags(self, monkeypatch):
        monkeypatch.setattr(es, "fetch_cvss", lambda cve: (None, None))
        monkeypatch.setattr(es, "fetch_epss", lambda cve: None)

        vuln = _FakeVuln("some-rce-template", tags=["rce", "http"], severity="high")
        es._apply_enrichment(vuln, kev_set=set())

        assert vuln.exploit_known is True  # 'rce' tag


class TestEnrichScan:
    def _make_scan_with_vuln(self, db, template_id, tags, severity):
        scan = Scan(
            id=str(uuid.uuid4()),
            user_id="u1",
            created_by_id="u1",
            config_id="c1",
            name="scan",
            status="completed",
        )
        db.add(scan)
        db.flush()
        target = ScanTarget(id=str(uuid.uuid4()), scan_id=str(scan.id), ip_address="10.0.0.5")
        db.add(target)
        db.flush()
        vuln = Vulnerability(
            id=str(uuid.uuid4()),
            scan_target_id=str(target.id),
            template_id=template_id,
            name="finding",
            severity=severity,
            matched_at="http://10.0.0.5/",
            host="10.0.0.5",
            port=80,
            tags=tags,
        )
        db.add(vuln)
        db.commit()
        return scan, vuln

    def test_enrich_scan_sets_and_persists(self, db, monkeypatch):
        monkeypatch.setattr(es, "load_kev_catalog", lambda *a, **k: {"CVE-2021-41773"})
        monkeypatch.setattr(es, "fetch_cvss", lambda cve: (7.5, "CVSS:3.1/AV:N"))
        monkeypatch.setattr(es, "fetch_epss", lambda cve: 0.5)

        scan, vuln = self._make_scan_with_vuln(db, "CVE-2021-41773", ["cve"], "high")

        n = es.enrich_scan(db, str(scan.id))
        assert n == 1

        refreshed = db.query(Vulnerability).filter(Vulnerability.id == vuln.id).first()
        assert refreshed.cve_id == "CVE-2021-41773"
        assert refreshed.kev_flag is True
        assert refreshed.cvss_score == 7.5
        assert refreshed.epss_score == 0.5
        assert refreshed.risk_score == 100.0

    def test_enrich_scan_idempotent(self, db, monkeypatch):
        monkeypatch.setattr(es, "load_kev_catalog", lambda *a, **k: set())
        monkeypatch.setattr(es, "fetch_cvss", lambda cve: (9.0, "v"))
        monkeypatch.setattr(es, "fetch_epss", lambda cve: None)

        scan, vuln = self._make_scan_with_vuln(db, "CVE-2000-0001", ["cve"], "critical")

        es.enrich_scan(db, str(scan.id))
        first = db.query(Vulnerability).filter(Vulnerability.id == vuln.id).first().risk_score
        es.enrich_scan(db, str(scan.id))
        second = db.query(Vulnerability).filter(Vulnerability.id == vuln.id).first().risk_score
        assert first == second == 90.0
