"""
Unit tests for URL normalization functions.
"""

import pytest
from app.services.url_normalizer import normalize_url, compute_endpoint_hash, extract_base_url


class TestNormalizeUrl:
    """Tests for normalize_url function."""

    def test_default_port_removal_http(self):
        """Test that default HTTP port 80 is removed."""
        normalized, components = normalize_url("http://example.com:80/path")
        assert normalized == "http://example.com/path"
        assert components['port'] is None

    def test_default_port_removal_https(self):
        """Test that default HTTPS port 443 is removed."""
        normalized, components = normalize_url("https://example.com:443/path")
        assert normalized == "https://example.com/path"
        assert components['port'] is None

    def test_non_default_port_preserved_8080(self):
        """Test that non-default port 8080 is preserved."""
        normalized, components = normalize_url("http://example.com:8080/path")
        assert normalized == "http://example.com:8080/path"
        assert components['port'] == 8080

    def test_non_default_port_preserved_8443(self):
        """Test that non-default port 8443 is preserved."""
        normalized, components = normalize_url("https://example.com:8443/path")
        assert normalized == "https://example.com:8443/path"
        assert components['port'] == 8443

    def test_host_lowercasing(self):
        """Test that host is lowercased."""
        normalized, components = normalize_url("HTTP://EXAMPLE.COM/Path")
        assert normalized == "http://example.com/Path"
        assert components['host'] == "example.com"
        assert components['scheme'] == "http"

    def test_scheme_lowercasing(self):
        """Test that scheme is lowercased."""
        normalized, components = normalize_url("HTTPS://example.com/path")
        assert normalized == "https://example.com/path"
        assert components['scheme'] == "https"

    def test_query_param_sorting(self):
        """Test that query parameters are sorted alphabetically."""
        normalized, components = normalize_url("http://example.com/path?z=1&a=2&m=3")
        assert normalized == "http://example.com/path?a=2&m=3&z=1"
        assert components['query'] == "a=2&m=3&z=1"

    def test_fragment_removal(self):
        """Test that URL fragments are removed."""
        normalized, components = normalize_url("http://example.com/path#section")
        assert normalized == "http://example.com/path"
        assert "#" not in normalized

    def test_slash_collapsing(self):
        """Test that multiple slashes are collapsed to single slash."""
        normalized, components = normalize_url("http://example.com/api//v1///users")
        assert normalized == "http://example.com/api/v1/users"
        assert components['path'] == "/api/v1/users"

    def test_leading_slash_enforcement(self):
        """Test that path always has leading slash."""
        # This is a tricky case - URL parser should handle it
        normalized, components = normalize_url("http://example.com")
        assert normalized == "http://example.com/"
        assert components['path'] == "/"

    def test_empty_path_gets_slash(self):
        """Test that empty path gets a slash."""
        normalized, components = normalize_url("http://example.com")
        assert normalized == "http://example.com/"
        assert components['path'] == "/"

    def test_empty_query_string_removed(self):
        """Test that empty query string is removed."""
        normalized, components = normalize_url("http://example.com/path?")
        assert normalized == "http://example.com/path"
        assert components['query'] is None

    def test_url_without_scheme_assumes_http(self):
        """Test that URL without scheme assumes http."""
        normalized, components = normalize_url("example.com/path")
        assert normalized == "http://example.com/path"
        assert components['scheme'] == "http"

    def test_preserves_path_case(self):
        """Test that path case is preserved (only host is lowercased)."""
        normalized, components = normalize_url("http://example.com/API/Users")
        assert normalized == "http://example.com/API/Users"
        assert components['path'] == "/API/Users"

    def test_query_with_empty_value(self):
        """Test query parameter with empty value."""
        normalized, components = normalize_url("http://example.com/path?key=&other=value")
        assert "key=" in normalized
        assert "other=value" in normalized

    def test_complex_url(self):
        """Test complex URL with all components."""
        normalized, components = normalize_url(
            "HTTPS://API.Example.COM:443/v1/users//list?page=2&sort=name&filter=active#results"
        )
        assert normalized == "https://api.example.com/v1/users/list?filter=active&page=2&sort=name"
        assert components['scheme'] == "https"
        assert components['host'] == "api.example.com"
        assert components['port'] is None  # Default port removed
        assert components['path'] == "/v1/users/list"
        assert components['query'] == "filter=active&page=2&sort=name"


class TestComputeEndpointHash:
    """Tests for compute_endpoint_hash function."""

    def test_hash_consistency(self):
        """Test that same URL produces same hash every time."""
        url = "https://example.com/api/users"
        hash1 = compute_endpoint_hash(url, "GET")
        hash2 = compute_endpoint_hash(url, "GET")
        assert hash1 == hash2

    def test_hash_differs_by_method(self):
        """Test that same URL with different methods produces different hashes."""
        url = "https://example.com/api/users"
        hash_get = compute_endpoint_hash(url, "GET")
        hash_post = compute_endpoint_hash(url, "POST")
        assert hash_get != hash_post

    def test_hash_differs_by_url(self):
        """Test that different URLs produce different hashes."""
        hash1 = compute_endpoint_hash("https://example.com/api/users", "GET")
        hash2 = compute_endpoint_hash("https://example.com/api/products", "GET")
        assert hash1 != hash2

    def test_hash_length(self):
        """Test that hash is 32 characters (first 32 of SHA256)."""
        hash_value = compute_endpoint_hash("https://example.com/path", "GET")
        assert len(hash_value) == 32

    def test_hash_is_hex(self):
        """Test that hash is valid hexadecimal."""
        hash_value = compute_endpoint_hash("https://example.com/path", "GET")
        # Should not raise - validates it's valid hex
        int(hash_value, 16)

    def test_method_case_insensitive(self):
        """Test that method comparison is case-insensitive (normalized to upper)."""
        hash_lower = compute_endpoint_hash("https://example.com/path", "get")
        hash_upper = compute_endpoint_hash("https://example.com/path", "GET")
        assert hash_lower == hash_upper

    def test_default_method_is_get(self):
        """Test that default method is GET when None provided."""
        hash_none = compute_endpoint_hash("https://example.com/path", None)
        hash_get = compute_endpoint_hash("https://example.com/path", "GET")
        assert hash_none == hash_get


class TestExtractBaseUrl:
    """Tests for extract_base_url function."""

    def test_extracts_base_with_default_port(self):
        """Test base URL extraction with default port."""
        base = extract_base_url("https://example.com/api/v1/users?page=1")
        assert base == "https://example.com"

    def test_extracts_base_with_non_default_port(self):
        """Test base URL extraction with non-default port."""
        base = extract_base_url("https://example.com:8443/api/v1/users")
        assert base == "https://example.com:8443"

    def test_extracts_base_lowercased(self):
        """Test that base URL host is lowercased."""
        base = extract_base_url("HTTPS://EXAMPLE.COM/path")
        assert base == "https://example.com"
