"""
Service Profile Mapper for Nuclei Template Selection

Maps Nmap service detection to Nuclei scanning configuration.
Loads from config/nuclei_profiles.yaml for easy maintenance.
"""

from typing import Optional, List, Tuple
from dataclasses import dataclass, field
from pathlib import Path
from functools import lru_cache
import subprocess
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
    rate_limit: Optional[int] = None  # Custom rate limit for sensitive services


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
    extra_info: Optional[dict] = None,
    port: Optional[int] = None,
    scan_mode: str = "deep",
    technologies: Optional[List[str]] = None
) -> NucleiProfile:
    """
    Get Nuclei scanning profile for a detected service.

    Args:
        service_name: Nmap service (e.g., 'http', 'ssh', 'mysql')
        product: Nmap product (e.g., 'Apache httpd', 'OpenSSH')
        version: Nmap version string
        extra_info: Additional Nmap data
        port: Port number for fallback hints when service_name is unknown
        scan_mode: "fast" or "deep" - affects HTTP tag selection
        technologies: List of technologies detected by httpx (e.g., ['WordPress', 'PHP', 'nginx'])

    Returns:
        NucleiProfile with scan configuration
    """
    config = load_config()
    profiles = config.get('service_profiles', {})
    product_tags = config.get('product_tags', {})
    technology_tags = config.get('technology_tags', {})
    port_hints = config.get('port_hints', {})
    scan_modes = config.get('scan_modes', {})
    scan_unknown = config.get('scan_unknown_services', False)

    # If no service_name, try port hint
    if not service_name and port:
        hinted_service = port_hints.get(port)
        if hinted_service:
            service_name = hinted_service
            logger.debug(f"Using port hint: port {port} -> {service_name}")

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
        # Fallback: try service name as tag only (no 'network' to avoid timeouts)
        tags = [normalized.replace('/', '-')]
        target_format = 'host_port'
        protocol = None
        timeout_mult = 1.0
        should_scan = True
        logger.debug(f"Using fallback profile for unknown service: {service_name}")
    else:
        return NucleiProfile(should_scan=False, target_format='host_port', protocol=None)

    # Add SSL tag if needed
    if is_ssl and 'ssl' not in tags:
        tags.append('ssl')
    if is_ssl and protocol == 'http':
        protocol = 'https'

    # Add product-specific tags ONLY if not in comprehensive mode
    # Empty tags [] means comprehensive scan - don't narrow it down
    if product and tags:
        product_lower = product.lower()
        for key, extra_tags in product_tags.items():
            if key in product_lower:
                tags.extend(t for t in extra_tags if t not in tags)
                break

    # Apply scan mode for HTTP services
    if target_format == 'url' and scan_mode == 'fast':
        fast_config = scan_modes.get('fast', {})
        http_tags = fast_config.get('http_tags', [])
        if http_tags:
            # In fast mode, use fast mode tags + any product-specific tags
            product_specific_tags = [t for t in tags if t not in ['http', 'https']]
            tags = list(http_tags) + product_specific_tags

    # Add technology-specific tags from httpx detection
    # Only applied when using tag-based scanning (not comprehensive mode with empty tags)
    if technologies and tags:
        for tech in technologies:
            tech_lower = tech.lower()
            for key, extra_tags in technology_tags.items():
                if key in tech_lower:
                    tags.extend(t for t in extra_tags if t not in tags)
                    break  # Only match first matching technology key

    # Extract rate_limit from profile if available
    rate_limit = profile_data.get('rate_limit') if profile_data else None

    return NucleiProfile(
        should_scan=should_scan,
        target_format=target_format,
        protocol=protocol,
        tags=tags,
        timeout_multiplier=timeout_mult,
        rate_limit=rate_limit
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


def get_excluded_templates() -> List[str]:
    """Get list of template patterns to exclude from nuclei scans."""
    config = load_config()
    return config.get('excluded_templates', [])


@lru_cache(maxsize=200)
def validate_tags_have_templates(tags_tuple: Tuple[str, ...]) -> Tuple[bool, int]:
    """
    Check if the given tags have any matching nuclei templates.
    Results are cached to avoid repeated subprocess calls.

    Args:
        tags_tuple: Tuple of tag strings (must be tuple for caching)

    Returns:
        Tuple of (has_templates: bool, template_count: int)
    """
    if not tags_tuple:
        return True, -1  # Empty tags = all templates

    tags_str = ','.join(tags_tuple)

    try:
        result = subprocess.run(
            ['nuclei', '-tl', '-tags', tags_str],
            capture_output=True,
            text=True,
            timeout=30
        )
        # Count non-empty lines in output
        templates = [l for l in result.stdout.strip().split('\n') if l.strip()]
        template_count = len(templates)
        return template_count > 0, template_count
    except subprocess.TimeoutExpired:
        logger.warning(f"Timeout validating tags: {tags_str}")
        return True, -1  # Assume valid on timeout
    except Exception as e:
        logger.warning(f"Failed to validate tags {tags_str}: {e}")
        return True, -1  # Assume valid on error


def validate_tags(tags: List[str]) -> Tuple[bool, int]:
    """
    Wrapper that converts list to tuple for caching.

    Returns:
        Tuple of (has_templates: bool, template_count: int)
    """
    if not tags:
        return True, -1
    return validate_tags_have_templates(tuple(sorted(tags)))


def clear_tag_validation_cache():
    """Clear the tag validation cache (useful after template updates)."""
    validate_tags_have_templates.cache_clear()
