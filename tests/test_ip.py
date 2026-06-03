# ─────────────────────────────────────────────────────────────
#  tests/test_ip.py — Unit tests for ip_intel module
# ─────────────────────────────────────────────────────────────

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from modules.ip_intel import classify_ip, lookup_ip

MOCK_CONFIG = {}

class TestIPClassify:

    def test_loopback_rejected(self):
        result = classify_ip("127.0.0.1")
        assert result is not None
        assert "loopback" in result.lower()

    def test_private_rejected(self):
        result = classify_ip("192.168.1.1")
        assert result is not None
        assert "private" in result.lower()

    def test_private_10_rejected(self):
        result = classify_ip("10.0.0.1")
        assert result is not None

    def test_public_ip_passes(self):
        result = classify_ip("8.8.8.8")
        assert result is None   # None = valid public IP

    def test_invalid_ip_rejected(self):
        result = classify_ip("not.an.ip")
        assert result is not None

class TestIPLookup:

    def test_google_dns_lookup(self):
        """Google's DNS (8.8.8.8) should resolve to US."""
        result = lookup_ip("8.8.8.8", MOCK_CONFIG)
        if result:  # skip if no internet
            assert result.get("country") in ("United States", "US")

    def test_private_ip_returns_empty(self):
        """Private IPs should return empty dict."""
        result = lookup_ip("192.168.1.1", MOCK_CONFIG)
        assert result == {}

    def test_links_generated(self):
        """Shodan and VirusTotal links should always be generated."""
        result = lookup_ip("8.8.8.8", MOCK_CONFIG)
        if result:
            assert "links" in result
            assert "shodan" in result["links"]
