"""Tests for LLM rewrite cache."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from teeshield.rewriter.cache import cache_key, get_cached, set_cached, clear_cache


class TestCacheKey:
    def test_deterministic(self):
        k1 = cache_key("tool", "desc", "model")
        k2 = cache_key("tool", "desc", "model")
        assert k1 == k2

    def test_different_inputs(self):
        k1 = cache_key("tool1", "desc", "model")
        k2 = cache_key("tool2", "desc", "model")
        assert k1 != k2

    def test_sha256_length(self):
        k = cache_key("t", "d", "m")
        assert len(k) == 64  # SHA-256 hex digest


class TestCacheOps:
    def test_roundtrip(self, tmp_path: Path):
        with patch("teeshield.rewriter.cache.CACHE_DIR", tmp_path):
            set_cached("tool", "desc", "model", "rewritten text")
            result = get_cached("tool", "desc", "model")
            assert result == "rewritten text"

    def test_miss(self, tmp_path: Path):
        with patch("teeshield.rewriter.cache.CACHE_DIR", tmp_path):
            result = get_cached("nonexistent", "desc", "model")
            assert result is None

    def test_clear(self, tmp_path: Path):
        with patch("teeshield.rewriter.cache.CACHE_DIR", tmp_path):
            set_cached("t1", "d", "m", "r1")
            set_cached("t2", "d", "m", "r2")
            count = clear_cache()
            assert count == 2
            assert get_cached("t1", "d", "m") is None
