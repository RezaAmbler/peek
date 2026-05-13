"""
Input validation utilities for security-critical operations.

These validators prevent command injection attacks by ensuring user-supplied
values (IP addresses, ports, hostnames) are safe before passing to subprocess calls.
"""

import ipaddress
import re
from typing import List, Tuple, Optional, Union


# RFC 1123 compliant hostname regex - no shell metacharacters allowed
# Allows: alphanumeric, hyphens (not at start/end), dots for subdomains
HOSTNAME_REGEX = re.compile(
    r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
    r'(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
)

# Characters that could enable shell injection - must never appear in targets
SHELL_METACHARACTERS = set(';&|`$(){}[]<>\\"\'\n\r\t')


class ValidationError(ValueError):
    """Raised when input validation fails."""
    pass


def validate_ip_address(ip: str) -> str:
    """
    Validate and normalize an IP address (IPv4 or IPv6).

    Args:
        ip: String that should be a valid IP address

    Returns:
        Normalized IP address string

    Raises:
        ValidationError: If the input is not a valid IP address

    Examples:
        >>> validate_ip_address("192.168.1.1")
        '192.168.1.1'
        >>> validate_ip_address("  10.0.0.1  ")
        '10.0.0.1'
        >>> validate_ip_address("::1")
        '::1'
        >>> validate_ip_address("8.8.8.8; rm -rf /")  # Raises ValidationError
    """
    if not isinstance(ip, str):
        raise ValidationError(f"IP address must be a string, got {type(ip).__name__}")

    ip = ip.strip()

    if not ip:
        raise ValidationError("IP address cannot be empty")

    # Check for shell metacharacters BEFORE parsing
    # This catches injection attempts like "8.8.8.8; rm -rf /"
    dangerous_chars = SHELL_METACHARACTERS.intersection(ip)
    if dangerous_chars:
        raise ValidationError(
            f"IP address contains invalid characters: {dangerous_chars}. "
            "Shell metacharacters are not allowed."
        )

    try:
        # ipaddress module validates and normalizes
        ip_obj = ipaddress.ip_address(ip)
        return str(ip_obj)
    except ValueError as e:
        raise ValidationError(f"Invalid IP address '{ip}': {e}")


def validate_hostname(hostname: str) -> str:
    """
    Validate a hostname according to RFC 1123.

    Args:
        hostname: String that should be a valid hostname

    Returns:
        Lowercase normalized hostname

    Raises:
        ValidationError: If the input is not a valid hostname

    Examples:
        >>> validate_hostname("example.com")
        'example.com'
        >>> validate_hostname("sub.domain.example.com")
        'sub.domain.example.com'
        >>> validate_hostname("my-server")
        'my-server'
        >>> validate_hostname("$(malicious)")  # Raises ValidationError
    """
    if not isinstance(hostname, str):
        raise ValidationError(f"Hostname must be a string, got {type(hostname).__name__}")

    hostname = hostname.strip().lower()

    if not hostname:
        raise ValidationError("Hostname cannot be empty")

    # Check for shell metacharacters
    dangerous_chars = SHELL_METACHARACTERS.intersection(hostname)
    if dangerous_chars:
        raise ValidationError(
            f"Hostname contains invalid characters: {dangerous_chars}. "
            "Shell metacharacters are not allowed."
        )

    # Check length limits (RFC 1123)
    if len(hostname) > 253:
        raise ValidationError(f"Hostname too long: {len(hostname)} chars (max 253)")

    # Validate format
    if not HOSTNAME_REGEX.match(hostname):
        raise ValidationError(
            f"Invalid hostname '{hostname}'. Must contain only alphanumeric "
            "characters, hyphens (not at start/end), and dots for subdomains."
        )

    # Check individual label lengths
    for label in hostname.split('.'):
        if len(label) > 63:
            raise ValidationError(f"Hostname label '{label}' too long: {len(label)} chars (max 63)")

    return hostname


def validate_target(target: str) -> str:
    """
    Validate a scan target, which can be either an IP address or hostname.

    Args:
        target: String that should be a valid IP address or hostname

    Returns:
        Validated and normalized target string

    Raises:
        ValidationError: If the input is not a valid IP or hostname

    Examples:
        >>> validate_target("192.168.1.1")
        '192.168.1.1'
        >>> validate_target("example.com")
        'example.com'
    """
    if not isinstance(target, str):
        raise ValidationError(f"Target must be a string, got {type(target).__name__}")

    target = target.strip()

    if not target:
        raise ValidationError("Target cannot be empty")

    # Try as IP address first
    try:
        return validate_ip_address(target)
    except ValidationError:
        pass

    # Try as hostname
    try:
        return validate_hostname(target)
    except ValidationError:
        pass

    # Neither worked
    raise ValidationError(
        f"Invalid target '{target}'. Must be a valid IP address or hostname."
    )


def validate_port(port: Union[int, str]) -> int:
    """
    Validate a port number is within valid range.

    Args:
        port: Port number (int or string representation)

    Returns:
        Validated port number as integer

    Raises:
        ValidationError: If the port is invalid or out of range

    Examples:
        >>> validate_port(80)
        80
        >>> validate_port("443")
        443
        >>> validate_port(0)  # Raises ValidationError
        >>> validate_port(70000)  # Raises ValidationError
    """
    # Convert string to int if needed
    if isinstance(port, str):
        port = port.strip()
        if not port:
            raise ValidationError("Port cannot be empty")
        try:
            port = int(port)
        except ValueError:
            raise ValidationError(f"Port must be a number, got '{port}'")

    if not isinstance(port, int):
        raise ValidationError(f"Port must be an integer, got {type(port).__name__}")

    if port < 1 or port > 65535:
        raise ValidationError(
            f"Port {port} out of valid range. Must be between 1 and 65535."
        )

    return port


def validate_port_list(ports: List[Union[int, str]]) -> List[int]:
    """
    Validate a list of port numbers.

    Args:
        ports: List of port numbers (int or string)

    Returns:
        List of validated port numbers as integers

    Raises:
        ValidationError: If any port is invalid

    Examples:
        >>> validate_port_list([80, 443, "8080"])
        [80, 443, 8080]
    """
    if not isinstance(ports, (list, tuple)):
        raise ValidationError(f"Ports must be a list, got {type(ports).__name__}")

    if not ports:
        raise ValidationError("Port list cannot be empty")

    validated = []
    for i, port in enumerate(ports):
        try:
            validated.append(validate_port(port))
        except ValidationError as e:
            raise ValidationError(f"Invalid port at index {i}: {e}")

    return validated


def validate_port_string(port_string: str) -> str:
    """
    Validate a comma-separated port string (e.g., "80,443,8080").

    Args:
        port_string: Comma-separated string of port numbers

    Returns:
        Validated port string with normalized format

    Raises:
        ValidationError: If any port is invalid

    Examples:
        >>> validate_port_string("80, 443, 8080")
        '80,443,8080'
    """
    if not isinstance(port_string, str):
        raise ValidationError(f"Port string must be a string, got {type(port_string).__name__}")

    port_string = port_string.strip()

    if not port_string:
        raise ValidationError("Port string cannot be empty")

    # Check for shell metacharacters (except comma which is valid)
    dangerous_chars = (SHELL_METACHARACTERS - {','}).intersection(port_string)
    if dangerous_chars:
        raise ValidationError(
            f"Port string contains invalid characters: {dangerous_chars}"
        )

    # Parse and validate each port
    try:
        ports = [validate_port(p.strip()) for p in port_string.split(',') if p.strip()]
    except ValidationError as e:
        raise ValidationError(f"Invalid port in port string: {e}")

    if not ports:
        raise ValidationError("Port string contains no valid ports")

    return ','.join(str(p) for p in sorted(set(ports)))


def validate_cidr(cidr: str, max_prefix: int = 24) -> Tuple[str, int]:
    """
    Validate CIDR notation and return normalized network and host count.

    Args:
        cidr: CIDR string like "192.168.1.0/24"
        max_prefix: Minimum prefix length allowed (24 = max 254 hosts)

    Returns:
        Tuple of (normalized network string, host count)

    Raises:
        ValidationError if invalid or too large

    Examples:
        >>> validate_cidr("192.168.1.0/24")
        ('192.168.1.0/24', 254)
        >>> validate_cidr("10.0.0.0/16")  # Raises ValidationError - too large
    """
    if not isinstance(cidr, str):
        raise ValidationError(f"CIDR must be a string, got {type(cidr).__name__}")

    cidr = cidr.strip()

    if not cidr:
        raise ValidationError("CIDR cannot be empty")

    # Check for shell metacharacters
    dangerous_chars = SHELL_METACHARACTERS.intersection(cidr)
    if dangerous_chars:
        raise ValidationError(
            f"CIDR contains invalid characters: {dangerous_chars}. "
            "Shell metacharacters are not allowed."
        )

    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        raise ValidationError(f"Invalid CIDR notation '{cidr}': {e}")

    if network.prefixlen < max_prefix:
        max_hosts = 2 ** (32 - max_prefix) - 2
        raise ValidationError(
            f"CIDR range /{network.prefixlen} too large. "
            f"Maximum allowed: /{max_prefix} ({max_hosts} hosts)"
        )

    # Calculate host count (exclude network and broadcast for /31 and smaller)
    if network.prefixlen >= 31:
        host_count = network.num_addresses
    else:
        host_count = network.num_addresses - 2

    return str(network), host_count


def expand_cidr(target: str) -> Tuple[List[str], Optional[str]]:
    """
    Expand CIDR notation to individual host IPs.

    Args:
        target: IP, hostname, or CIDR notation

    Returns:
        Tuple of (list of individual IPs/hostnames, original CIDR or None)

    Examples:
        >>> expand_cidr("192.168.1.0/30")
        (['192.168.1.1', '192.168.1.2'], '192.168.1.0/30')
        >>> expand_cidr("example.com")
        (['example.com'], None)
    """
    if not isinstance(target, str):
        return [str(target)], None

    target = target.strip()

    if '/' not in target:
        # Not CIDR - return as single-item list
        return [target], None

    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError:
        # Invalid CIDR - return as-is, let validate_target handle it
        return [target], None

    # Handle /32 specially - network.hosts() returns empty for /32
    if network.prefixlen == 32:
        return [str(network.network_address)], str(network)

    # Handle /31 - returns both addresses (point-to-point link)
    if network.prefixlen == 31:
        return [str(ip) for ip in network], str(network)

    # Standard case - return usable hosts (excludes network and broadcast)
    hosts = [str(ip) for ip in network.hosts()]
    return hosts, str(network)
