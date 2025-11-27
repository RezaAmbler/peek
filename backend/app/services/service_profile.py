"""
Service Profile Mapper for Nuclei Template Selection

Maps Nmap service detection to Nuclei scanning configuration.
Loads from config/nuclei_profiles.yaml for easy maintenance.
"""

from typing import Optional, List
from dataclasses import dataclass, field
from pathlib import Path
import yaml
import logging

logger = logging.getLogger(__name__)

CONFIG_PATH = Path(__file__).parent.parent.parent / "config" / "nuclei_profiles.yaml"

_config_cache = None


@dataclass
class NucleiProfile:
    """Configuration for running Nuclei against a specific service."""
    should_scan: bool
    target_format: str  # 'url' or 'host_port'
    protocol: Optional[str]  # 'http', 'https', or None
    tags: List[str] = field(default_factory=list)
    timeout_multiplier: float = 1.0


def load_config(force_reload: bool = False) -> dict:
    """Load configuration from YAML file with caching."""
    global _config_cache

    if _config_cache and not force_reload:
        return _config_cache

    if not CONFIG_PATH.exists():
        logger.warning(f"Config not found: {CONFIG_PATH}, using defaults")
        return {'service_profiles': {}, 'product_tags': {}, 'scan_unknown_services': False}

    try:
        with open(CONFIG_PATH) as f:
            _config_cache = yaml.safe_load(f) or {}
        logger.info(f"Loaded {len(_config_cache.get('service_profiles', {}))} service profiles")
        return _config_cache
    except Exception as e:
        logger.error(f"Failed to load config: {e}")
        return {'service_profiles': {}, 'product_tags': {}, 'scan_unknown_services': False}


def get_nuclei_profile(
    service_name: Optional[str],
    product: Optional[str] = None,
    version: Optional[str] = None,
    extra_info: Optional[dict] = None
) -> NucleiProfile:
    """
    Get Nuclei scanning profile for a detected service.

    Args:
        service_name: Nmap service (e.g., 'http', 'ssh', 'mysql')
        product: Nmap product (e.g., 'Apache httpd', 'OpenSSH')
        version: Nmap version string
        extra_info: Additional Nmap data

    Returns:
        NucleiProfile with scan configuration
    """
    config = load_config()
    profiles = config.get('service_profiles', {})
    product_tags = config.get('product_tags', {})
    scan_unknown = config.get('scan_unknown_services', False)

    if not service_name:
        return NucleiProfile(should_scan=False, target_format='host_port', protocol=None)

    normalized = service_name.lower().strip()

    # Handle ssl/* prefix (e.g., ssl/http -> https)
    is_ssl = normalized.startswith('ssl/')
    if is_ssl:
        base_service = normalized[4:]
        profile_data = profiles.get(normalized) or profiles.get(base_service)
    else:
        profile_data = profiles.get(normalized)

    # Build profile from config or use fallback
    if profile_data:
        tags = list(profile_data.get('tags', []))
        target_format = profile_data.get('target_format', 'host_port')
        protocol = profile_data.get('protocol')
        timeout_mult = profile_data.get('timeout_multiplier', 1.0)
        should_scan = True
    elif scan_unknown:
        # Fallback: try service name as tag + network
        tags = [normalized.replace('/', '-'), 'network']
        target_format = 'host_port'
        protocol = None
        timeout_mult = 0.5
        should_scan = True
        logger.debug(f"Using fallback profile for unknown service: {service_name}")
    else:
        return NucleiProfile(should_scan=False, target_format='host_port', protocol=None)

    # Add SSL tag if needed
    if is_ssl and 'ssl' not in tags:
        tags.append('ssl')
    if is_ssl and protocol == 'http':
        protocol = 'https'

    # Add product-specific tags
    if product:
        product_lower = product.lower()
        for key, extra_tags in product_tags.items():
            if key in product_lower:
                tags.extend(t for t in extra_tags if t not in tags)
                break

    return NucleiProfile(
        should_scan=should_scan,
        target_format=target_format,
        protocol=protocol,
        tags=tags,
        timeout_multiplier=timeout_mult
    )


def build_nuclei_target(ip: str, port: int, profile: NucleiProfile) -> str:
    """Build target string for Nuclei based on profile."""
    if profile.target_format == 'url':
        proto = profile.protocol or 'http'
        if (proto == 'http' and port == 80) or (proto == 'https' and port == 443):
            return f"{proto}://{ip}"
        return f"{proto}://{ip}:{port}"
    return f"{ip}:{port}"


def reload_config():
    """Force reload configuration from disk."""
    load_config(force_reload=True)
