"""
Risk enrichment for findings — turns raw scanner output into a prioritized worklist.

Scanners (Nuclei/ZAP/...) label a finding with whatever severity string the
template author chose, and the CVE identity is buried inside ``template_id`` / the
``tags`` / ``reference`` lists. That makes triage hard: a template tagged
"critical" with no real-world exploit can drown out a KEV-listed, actively
exploited "high".

This service resolves, for each finding (best-effort, offline-tolerant):
  - a canonical ``cve_id`` (regex-extracted from template_id/tags/reference),
  - CVSS base score + vector (NVD feed),
  - EPSS exploitation-probability (FIRST feed),
  - CISA KEV membership (``kev_flag``) from the Known Exploited Vulnerabilities catalog,
  - ``exploit_known`` (KEV, or nuclei tags implying a working exploit — exploit/rce),
  - a computed ``risk_score`` in [0,100] that makes a KEV-listed exploitable finding
    outrank a no-exploit "critical".

Design constraints:
  - Never raise to the scan pipeline: every network call is wrapped and degrades
    gracefully (live feed -> local daily cache -> bundled snapshot / None).
  - Short timeouts (<=8s). ``requests`` honors HTTPS_PROXY from the environment.
  - Cache per-CVE lookups in-process so a scan with the same CVE on many hosts
    hits each external API once.
  - Idempotent: safe to re-run ``enrich_scan`` / ``enrich_vulnerability``.
"""

import json
import logging
import re
import time
from pathlib import Path
from typing import Optional, Set, Tuple

import requests
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# --- External feed endpoints -------------------------------------------------
KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_URL = "https://api.first.org/data/v1/epss"

# All external calls use a short timeout so a slow/blocked feed can't stall a scan.
HTTP_TIMEOUT_SECONDS = 8

# --- Local cache / bundled fallback ------------------------------------------
_DATA_DIR = Path(__file__).resolve().parent.parent / "data"
KEV_CACHE_FILE = _DATA_DIR / "kev_cache.json"
KEV_SNAPSHOT_FILE = _DATA_DIR / "kev_snapshot.json"
# Refresh the live KEV catalog at most once per day.
KEV_CACHE_TTL_SECONDS = 24 * 60 * 60

# --- CVE extraction ----------------------------------------------------------
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# nuclei tags that imply a working / weaponized exploit exists.
_EXPLOIT_TAGS = frozenset({"exploit", "rce"})

# --- In-process caches (per worker process) ----------------------------------
_kev_set_mem: Optional[Set[str]] = None
_kev_loaded_at: float = 0.0
_cvss_cache: dict = {}   # cve -> (score, vector)
_epss_cache: dict = {}   # cve -> epss float or None


# =============================================================================
# CVE extraction
# =============================================================================
def extract_cve(template_id, tags, reference) -> Optional[str]:
    """
    Extract the first CVE id from a finding's template_id, then tags, then
    reference list. Case-insensitive; returns the canonical UPPERCASE form
    (e.g. ``CVE-2021-41773``) or None if none is present.
    """
    # 1) template_id (e.g. "CVE-2021-41773" or "apache-CVE-2021-41773-lfi")
    if template_id:
        m = _CVE_RE.search(str(template_id))
        if m:
            return m.group(0).upper()

    # 2) tags (list or comma string)
    for tag in _iter_str_items(tags):
        m = _CVE_RE.search(tag)
        if m:
            return m.group(0).upper()

    # 3) reference list (CVE links etc.)
    for ref in _iter_str_items(reference):
        m = _CVE_RE.search(ref)
        if m:
            return m.group(0).upper()

    return None


def _iter_str_items(value):
    """Yield string items from a list/tuple/str; tolerate None and other types."""
    if value is None:
        return
    if isinstance(value, str):
        yield value
        return
    if isinstance(value, (list, tuple, set)):
        for item in value:
            if isinstance(item, str):
                yield item
            elif item is not None:
                yield str(item)


# =============================================================================
# HTTP helper (never raises for our purposes are wrapped by callers)
# =============================================================================
def _fetch_json(url: str, params: Optional[dict] = None) -> dict:
    """GET ``url`` and return parsed JSON. Raises on any failure (caller wraps)."""
    resp = requests.get(url, params=params, timeout=HTTP_TIMEOUT_SECONDS)
    resp.raise_for_status()
    return resp.json()


# =============================================================================
# CISA KEV catalog
# =============================================================================
def _parse_kev_payload(payload: dict) -> Set[str]:
    """Extract the set of UPPERCASE cveIDs from a KEV JSON payload."""
    vulns = payload.get("vulnerabilities") or []
    out = set()
    for v in vulns:
        cid = v.get("cveID")
        if cid:
            out.add(str(cid).upper())
    return out


def fetch_kev_catalog() -> Optional[Set[str]]:
    """
    Fetch the live CISA KEV catalog. Returns the set of cveIDs, or None on any
    network/parse failure (never raises).
    """
    try:
        payload = _fetch_json(KEV_FEED_URL)
        cves = _parse_kev_payload(payload)
        if cves:
            return cves
        return None
    except Exception as e:  # noqa: BLE001 - best-effort by design
        logger.warning(f"KEV live fetch failed: {e}")
        return None


def _read_kev_file(path: Path) -> Optional[Set[str]]:
    try:
        with path.open("r", encoding="utf-8") as f:
            payload = json.load(f)
        return _parse_kev_payload(payload)
    except Exception as e:  # noqa: BLE001
        logger.warning(f"KEV file read failed ({path}): {e}")
        return None


def _write_kev_cache(cves: Set[str]) -> None:
    try:
        _DATA_DIR.mkdir(parents=True, exist_ok=True)
        payload = {
            "fetched_at": time.time(),
            "vulnerabilities": [{"cveID": c} for c in sorted(cves)],
        }
        with KEV_CACHE_FILE.open("w", encoding="utf-8") as f:
            json.dump(payload, f)
    except Exception as e:  # noqa: BLE001
        logger.warning(f"KEV cache write failed: {e}")


def _cache_is_fresh() -> bool:
    try:
        with KEV_CACHE_FILE.open("r", encoding="utf-8") as f:
            payload = json.load(f)
        fetched_at = float(payload.get("fetched_at", 0))
        return (time.time() - fetched_at) < KEV_CACHE_TTL_SECONDS
    except Exception:  # noqa: BLE001
        return False


def load_kev_catalog(force_refresh: bool = False) -> Set[str]:
    """
    Resolve the KEV cveID set with a graceful fallback chain:

        in-process memo
          -> fresh local daily cache (kev_cache.json, <=1 day old)
          -> live feed (then written to cache)
          -> stale local cache
          -> bundled offline snapshot (kev_snapshot.json)
          -> empty set

    Never raises. The live feed is refreshed at most once per day.
    """
    global _kev_set_mem, _kev_loaded_at

    if _kev_set_mem is not None and not force_refresh:
        return _kev_set_mem

    # 1) Fresh on-disk daily cache short-circuits the network.
    if not force_refresh and _cache_is_fresh():
        cached = _read_kev_file(KEV_CACHE_FILE)
        if cached:
            _kev_set_mem = cached
            _kev_loaded_at = time.time()
            return _kev_set_mem

    # 2) Live feed (best effort), persisted to the daily cache on success.
    live = fetch_kev_catalog()
    if live:
        _write_kev_cache(live)
        _kev_set_mem = live
        _kev_loaded_at = time.time()
        return _kev_set_mem

    # 3) Stale cache is better than nothing.
    stale = _read_kev_file(KEV_CACHE_FILE)
    if stale:
        logger.info("KEV: using stale local cache (live feed unavailable)")
        _kev_set_mem = stale
        _kev_loaded_at = time.time()
        return _kev_set_mem

    # 4) Bundled offline snapshot.
    snapshot = _read_kev_file(KEV_SNAPSHOT_FILE)
    if snapshot:
        logger.info("KEV: using bundled offline snapshot")
        _kev_set_mem = snapshot
        _kev_loaded_at = time.time()
        return _kev_set_mem

    logger.warning("KEV: no catalog available (live, cache and snapshot all failed)")
    _kev_set_mem = set()
    return _kev_set_mem


# =============================================================================
# CVSS (NVD) and EPSS (FIRST)
# =============================================================================
def _extract_cvss_from_nvd(payload: dict) -> Tuple[Optional[float], Optional[str]]:
    """
    Pull a CVSS base score + vector from an NVD 2.0 response, preferring
    v3.1 -> v3.0 -> v2.
    """
    vulns = payload.get("vulnerabilities") or []
    if not vulns:
        return None, None
    metrics = (vulns[0].get("cve") or {}).get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData") or {}
            score = data.get("baseScore")
            vector = data.get("vectorString")
            if score is not None:
                try:
                    return float(score), vector
                except (TypeError, ValueError):
                    continue
    return None, None


def fetch_cvss(cve: str) -> Tuple[Optional[float], Optional[str]]:
    """
    Fetch CVSS base score + vector for ``cve`` from NVD. Best-effort: returns
    (None, None) on any failure. Results (including misses) are memoized per
    process so a scan hits NVD once per CVE.
    """
    if cve in _cvss_cache:
        return _cvss_cache[cve]
    try:
        payload = _fetch_json(NVD_CVE_URL, params={"cveId": cve})
        result = _extract_cvss_from_nvd(payload)
    except Exception as e:  # noqa: BLE001
        logger.warning(f"CVSS fetch failed for {cve}: {e}")
        result = (None, None)
    _cvss_cache[cve] = result
    return result


def fetch_epss(cve: str) -> Optional[float]:
    """
    Fetch the EPSS score (0..1) for ``cve`` from FIRST. Best-effort: returns
    None on any failure. Memoized per process.
    """
    if cve in _epss_cache:
        return _epss_cache[cve]
    result: Optional[float] = None
    try:
        payload = _fetch_json(EPSS_URL, params={"cve": cve})
        data = payload.get("data") or []
        if data:
            raw = data[0].get("epss")
            if raw is not None:
                result = float(raw)
    except Exception as e:  # noqa: BLE001
        logger.warning(f"EPSS fetch failed for {cve}: {e}")
        result = None
    _epss_cache[cve] = result
    return result


# =============================================================================
# Risk scoring
# =============================================================================
# Fallback base score (0..100) when a finding has no CVSS (no CVE, or NVD miss).
# Mirrors the qualitative severity buckets scanners emit.
_SEVERITY_BASE = {
    "critical": 90.0,
    "high": 70.0,
    "medium": 40.0,
    "low": 15.0,
    "info": 5.0,
    "informational": 5.0,
    "unknown": 15.0,
}


def compute_risk_score(
    cvss: Optional[float],
    epss: Optional[float],
    kev_flag: bool,
    exploit_known: bool,
    severity: Optional[str],
) -> float:
    """
    Compute a prioritization score in [0, 100].

    Formula (documented and asserted by tests):

        base   = cvss * 10                 if cvss is not None      # 0..100
               = _SEVERITY_BASE[severity]  otherwise (fallback)

        score  = base * (1.0 + epss)       # EPSS in [0,1] scales up to 2x
                                           # (missing EPSS treated as 0 -> x1)

        if kev_flag or exploit_known:      # active-exploitation boost
            score = score * 1.5 + 25.0     # strong, so a KEV-listed high
                                           # outranks a no-exploit critical

        score  = clamp(score, 0.0, 100.0)

    Worked example (the ordering invariant):
        no-exploit critical (cvss 9.0, kev False): 90 * 1 = 90.0
        KEV-listed high      (cvss 7.5, kev True ): 75 * 1 = 75 -> 75*1.5+25 = 100.0
        => the KEV high (100.0) outranks the no-exploit critical (90.0).
    """
    if cvss is not None:
        base = float(cvss) * 10.0
    else:
        base = _SEVERITY_BASE.get((severity or "unknown").strip().lower(), 15.0)

    epss_factor = 1.0 + (epss if epss is not None else 0.0)
    score = base * epss_factor

    if kev_flag or exploit_known:
        score = score * 1.5 + 25.0

    if score < 0.0:
        return 0.0
    if score > 100.0:
        return 100.0
    return round(score, 2)


def _infer_exploit_known(tags, kev_flag: bool) -> bool:
    """
    ``exploit_known`` is True if the CVE is KEV-listed OR the nuclei template tags
    imply a working exploit (contain 'exploit' or 'rce'). Simple + auditable.
    """
    if kev_flag:
        return True
    for tag in _iter_str_items(tags):
        if tag.strip().lower() in _EXPLOIT_TAGS:
            return True
    return False


# =============================================================================
# Enrichment entry points
# =============================================================================
def _apply_enrichment(vuln, kev_set: Set[str]) -> None:
    """
    Resolve and set all enrichment fields on a single Vulnerability ORM object
    (no commit). Uses the process-level per-CVE caches. Idempotent.
    """
    cve = extract_cve(vuln.template_id, vuln.tags, vuln.reference)
    vuln.cve_id = cve

    cvss_score = None
    cvss_vector = None
    epss_score = None
    kev_flag = False

    if cve:
        kev_flag = cve in kev_set
        cvss_score, cvss_vector = fetch_cvss(cve)
        epss_score = fetch_epss(cve)

    exploit_known = _infer_exploit_known(vuln.tags, kev_flag)

    vuln.cvss_score = cvss_score
    vuln.cvss_vector = cvss_vector
    vuln.epss_score = epss_score
    vuln.kev_flag = kev_flag
    vuln.exploit_known = exploit_known
    vuln.risk_score = compute_risk_score(
        cvss=cvss_score,
        epss=epss_score,
        kev_flag=kev_flag,
        exploit_known=exploit_known,
        severity=vuln.severity,
    )


def enrich_vulnerability(db: Session, vuln) -> None:
    """
    Enrich a single Vulnerability row and commit. Idempotent. Never raises for
    network reasons (feeds degrade to cache/snapshot/None).
    """
    kev_set = load_kev_catalog()
    _apply_enrichment(vuln, kev_set)
    db.commit()


def enrich_scan(db: Session, scan_id: str) -> int:
    """
    Batch-enrich every Vulnerability belonging to ``scan_id``.

    - Loads the KEV catalog once.
    - Resolves each distinct CVE's CVSS/EPSS once (per-process caches).
    - Sets cve_id/cvss_score/cvss_vector/epss_score/kev_flag/exploit_known/risk_score
      on every row, then commits.

    Idempotent (safe to re-run). Returns the number of rows enriched.
    """
    # Local imports to avoid import cycles at module import time.
    from ..models import Vulnerability, ScanTarget

    vulns = (
        db.query(Vulnerability)
        .join(ScanTarget, Vulnerability.scan_target_id == ScanTarget.id)
        .filter(ScanTarget.scan_id == str(scan_id))
        .all()
    )
    if not vulns:
        return 0

    kev_set = load_kev_catalog()
    for vuln in vulns:
        _apply_enrichment(vuln, kev_set)

    db.commit()
    logger.info(f"Enrichment: enriched {len(vulns)} finding(s) for scan {scan_id}")
    return len(vulns)
