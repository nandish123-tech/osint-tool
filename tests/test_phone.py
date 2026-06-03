# ─────────────────────────────────────────────────────────────
#  tests/test_phone.py — Unit tests for phone_lookup module
#  Run with: pytest tests/
# ─────────────────────────────────────────────────────────────

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from modules.phone_lookup import lookup_phone

# Mock config — no real API key needed for offline tests
MOCK_CONFIG = {}

class TestPhoneLookup:

    def test_valid_indian_number(self):
        """A valid Indian mobile number should return results."""
        result = lookup_phone("+919876543210", MOCK_CONFIG)
        assert result != {}
        assert result.get("is_valid") == True
        assert result.get("region_code") == "IN"
        assert result.get("country_code") == "91"

    def test_valid_us_number(self):
        """A valid US number should return correct region."""
        result = lookup_phone("+14155552671", MOCK_CONFIG)
        assert result != {}
        assert result.get("region_code") == "US"

    def test_invalid_number_returns_empty(self):
        """Completely invalid number should return empty dict."""
        result = lookup_phone("hello", MOCK_CONFIG)
        assert result == {}

    def test_short_number_returns_empty(self):
        """Too-short number should fail validation."""
        result = lookup_phone("+91123", MOCK_CONFIG)
        assert result == {}

    def test_e164_format_present(self):
        """Result should always include E164 format."""
        result = lookup_phone("+919876543210", MOCK_CONFIG)
        if result:
            assert "e164" in result
            assert result["e164"].startswith("+")

    def test_mobile_whatsapp_likely(self):
        """Mobile numbers should be flagged as WhatsApp likely."""
        result = lookup_phone("+919876543210", MOCK_CONFIG)
        if result:
            assert result.get("whatsapp_likely") == True

    def test_search_links_generated(self):
        """Search links should always be generated for valid numbers."""
        result = lookup_phone("+919876543210", MOCK_CONFIG)
        if result:
            assert "search_links" in result
            assert "google" in result["search_links"]
            assert "truecaller" in result["search_links"]
