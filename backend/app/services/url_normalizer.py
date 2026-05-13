"""
URL Normalization Utilities for Endpoint Deduplication

Provides canonical URL normalization for comparing discovered endpoints
across tools and scan runs.
"""

import hashlib
import re
from typing import Tuple, Dict, Optional
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode


# Default ports that should be stripped from normalized URLs
DEFAULT_PORTS = {
    'http': 80,
    'https': 443,
}


def normalize_url(url: str) -> Tuple[str, Dict]:
    """
    Normalize a URL to canonical form for deduplication.

    Normalization rules:
    - Lowercase scheme and host
    - Remove fragment
    - Ensure leading / in path
    - Collapse // to / in path
    - Remove default ports (80 for http, 443 for https)
    - Sort query parameters alphabetically by key

    Args:
        url: Original URL string

    Returns:
        Tuple of (normalized_url, components_dict)
        components_dict contains: scheme, host, port, path, query
    """
    # Handle URLs without scheme
    if not url:
        url = "http:///"
    elif not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', url):
        # No scheme detected, assume http
        url = 'http://' + url

    # Parse the URL
    parsed = urlparse(url)

    # Lowercase scheme
    scheme = parsed.scheme.lower()

    # Extract and lowercase host, handle port
    netloc = parsed.netloc.lower()
    host = parsed.hostname.lower() if parsed.hostname else ''
    port = parsed.port

    # Remove default ports
    if port and scheme in DEFAULT_PORTS and port == DEFAULT_PORTS[scheme]:
        port = None

    # Build netloc without default port
    if port:
        netloc = f"{host}:{port}"
    else:
        netloc = host

    # Normalize path
    path = parsed.path
    if not path:
        path = '/'
    elif not path.startswith('/'):
        path = '/' + path

    # Collapse multiple slashes to single slash (but preserve leading slash)
    path = re.sub(r'/+', '/', path)

    # Sort query parameters alphabetically
    query_params = parse_qsl(parsed.query, keep_blank_values=True)
    sorted_params = sorted(query_params, key=lambda x: x[0])
    query = urlencode(sorted_params) if sorted_params else ''

    # Remove fragment entirely
    fragment = ''

    # Build normalized URL
    normalized = urlunparse((scheme, netloc, path, '', query, fragment))

    # Build components dict
    components = {
        'scheme': scheme,
        'host': host,
        'port': port,  # None if default port
        'path': path,
        'query': query if query else None,
    }

    return normalized, components


def compute_endpoint_hash(normalized_url: str, method: str = "GET") -> str:
    """
    Compute a hash for endpoint comparison across scan runs.

    The hash combines the normalized URL and HTTP method to uniquely
    identify an endpoint. Same URL with different methods (GET vs POST)
    will have different hashes.

    Args:
        normalized_url: Canonicalized URL from normalize_url()
        method: HTTP method (GET, POST, etc.)

    Returns:
        Hex digest string (first 32 chars of SHA256)
    """
    method_upper = method.upper() if method else "GET"
    hash_input = f"{method_upper}:{normalized_url}"
    hash_digest = hashlib.sha256(hash_input.encode('utf-8')).hexdigest()
    # Return first 32 chars for reasonable uniqueness with compact storage
    return hash_digest[:32]


def extract_base_url(url: str) -> str:
    """
    Extract base URL (scheme + host + port) from a full URL.

    Useful for grouping endpoints by their base origin.

    Args:
        url: Full URL string

    Returns:
        Base URL (e.g., "https://example.com:8443")
    """
    normalized, components = normalize_url(url)
    scheme = components['scheme']
    host = components['host']
    port = components['port']

    if port:
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{host}"
