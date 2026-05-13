"""
NSE Profile Service - Matches services to NSE scripts.

This service loads NSE profiles from YAML configuration and provides
methods to determine which NSE scripts should run for a given service.
"""
import logging
import yaml
from pathlib import Path
from typing import List, Dict, Optional, Set
from functools import lru_cache


logger = logging.getLogger(__name__)

# Default path to NSE profiles configuration
NSE_PROFILES_PATH = Path(__file__).parent.parent.parent / 'config' / 'nse_profiles.yaml'


class NseProfileService:
    """
    Service for matching ports/services to NSE scripts.

    Usage:
        service = NseProfileService()
        scripts = service.get_scripts_for_service('ms-wbt-server', 3389, 'tcp')
        # Returns: ['rdp-enum-encryption', 'rdp-ntlm-info']
    """

    def __init__(self, config_path: Optional[Path] = None):
        """
        Initialize the NSE profile service.

        Args:
            config_path: Path to nse_profiles.yaml (defaults to config/nse_profiles.yaml)
        """
        self.config_path = config_path or NSE_PROFILES_PATH
        self._config = None
        self._profiles = None
        self._settings = None

    @property
    def config(self) -> Dict:
        """Lazy load configuration."""
        if self._config is None:
            self._config = self._load_config()
        return self._config

    @property
    def profiles(self) -> Dict:
        """Get profiles section of config."""
        if self._profiles is None:
            self._profiles = self.config.get('profiles', {})
        return self._profiles

    @property
    def settings(self) -> Dict:
        """Get settings section of config."""
        if self._settings is None:
            self._settings = self.config.get('settings', {})
        return self._settings

    def _load_config(self) -> Dict:
        """Load NSE profiles from YAML file."""
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r') as f:
                    return yaml.safe_load(f) or {}
            else:
                logger.warning("NSE profile config not found at %s, using defaults", self.config_path)
                return {'profiles': {}, 'settings': {'enabled': True}}
        except Exception as e:
            logger.warning("Failed to load NSE profile config: %s", e)
            return {'profiles': {}, 'settings': {'enabled': True}}

    def is_enabled(self) -> bool:
        """Check if NSE scanning is globally enabled."""
        return self.settings.get('enabled', True)

    def get_default_timeout(self) -> int:
        """Get default script timeout in seconds."""
        return self.settings.get('default_timeout', 300)

    def get_scripts_for_service(
        self,
        service_name: Optional[str],
        port: int,
        protocol: str = 'tcp'
    ) -> List[str]:
        """
        Get list of NSE scripts to run for a given service.

        Args:
            service_name: Service name from nmap detection (e.g., 'ssh', 'ms-wbt-server')
            port: Port number
            protocol: 'tcp' or 'udp'

        Returns:
            List of NSE script names to run
        """
        if not self.is_enabled():
            return []

        matching_scripts = set()

        for profile_name, profile in self.profiles.items():
            if self._profile_matches(profile, service_name, port, protocol):
                matching_scripts.update(profile.get('scripts', []))

        return list(matching_scripts)

    def get_profile_for_service(
        self,
        service_name: Optional[str],
        port: int,
        protocol: str = 'tcp'
    ) -> Optional[Dict]:
        """
        Get the matching profile for a service.

        Returns the first matching profile dict, or None if no match.
        """
        for profile_name, profile in self.profiles.items():
            if self._profile_matches(profile, service_name, port, protocol):
                return {'name': profile_name, **profile}
        return None

    def _profile_matches(
        self,
        profile: Dict,
        service_name: Optional[str],
        port: int,
        protocol: str
    ) -> bool:
        """
        Check if a profile matches the given service/port/protocol.

        A profile matches if:
        - service_name matches any of the profile's 'services' list, OR
        - port matches any of the profile's 'ports' list

        AND:
        - protocol matches the profile's 'protocol' (default: 'tcp')
        """
        profile_protocol = profile.get('protocol', 'tcp')
        if protocol != profile_protocol:
            return False

        # Check service name match
        profile_services = profile.get('services', [])
        if service_name and service_name.lower() in [s.lower() for s in profile_services]:
            return True

        # Check port match
        profile_ports = profile.get('ports', [])
        if port in profile_ports:
            return True

        return False

    def get_timeout_for_profile(self, profile_name: str) -> int:
        """Get timeout for a specific profile."""
        profile = self.profiles.get(profile_name, {})
        return profile.get('timeout', self.get_default_timeout())

    def get_all_profiles(self) -> Dict:
        """Get all configured profiles."""
        return self.profiles

    def get_profile_names(self) -> List[str]:
        """Get list of all profile names."""
        return list(self.profiles.keys())

    def get_ports_for_nse(self, ports_with_services: List[Dict]) -> List[Dict]:
        """
        Filter ports that should have NSE scripts run.

        Args:
            ports_with_services: List of dicts with port info:
                [{"port": 22, "protocol": "tcp", "service_name": "ssh"}, ...]

        Returns:
            List of dicts with matching ports and their scripts:
                [{"port": 22, "protocol": "tcp", "service_name": "ssh",
                  "profile": "ssh", "scripts": ["ssh2-enum-algos", ...]}]
        """
        if not self.is_enabled():
            return []

        results = []
        for port_info in ports_with_services:
            port = port_info.get('port')
            protocol = port_info.get('protocol', 'tcp')
            service_name = port_info.get('service_name')

            profile = self.get_profile_for_service(service_name, port, protocol)
            if profile and profile.get('scripts'):
                results.append({
                    **port_info,
                    'profile': profile['name'],
                    'scripts': profile['scripts'],
                    'timeout': profile.get('timeout', self.get_default_timeout())
                })

        return results


# Singleton instance for easy import
_nse_profile_service = None


def get_nse_profile_service() -> NseProfileService:
    """Get singleton NSE profile service instance."""
    global _nse_profile_service
    if _nse_profile_service is None:
        _nse_profile_service = NseProfileService()
    return _nse_profile_service


def get_scripts_for_service(
    service_name: Optional[str],
    port: int,
    protocol: str = 'tcp'
) -> List[str]:
    """
    Convenience function to get scripts for a service.

    Usage:
        from app.services.nse_profile import get_scripts_for_service
        scripts = get_scripts_for_service('ms-wbt-server', 3389, 'tcp')
    """
    return get_nse_profile_service().get_scripts_for_service(service_name, port, protocol)
