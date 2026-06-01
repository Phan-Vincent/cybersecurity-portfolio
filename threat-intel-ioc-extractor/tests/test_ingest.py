#!/usr/bin/env python3
"""
test_ingest.py - Unit tests for the feed ingestion layer.

Tests RSS/Atom parsing, sample mode, malformed feed handling, and rate limiting.
"""

from unittest.mock import MagicMock, patch

import pytest
import requests

from src.ingest import Article, _parse_rss_atom, fetch_feed, load_samples


class TestRSSParsing:
    """Test RSS 2.0 and Atom 1.0 parsing with mocked XML."""

    def test_parse_rss_basic(self) -> None:
        xml = """<?xml version="1.0"?>
        <rss version="2.0">
          <channel>
            <item>
              <title>Test Item</title>
              <description>Summary with IOC 192.0.2.1</description>
              <link>https://example.com/1</link>
              <pubDate>Mon, 01 Jun 2024 12:00:00 GMT</pubDate>
            </item>
          </channel>
        </rss>"""
        articles = _parse_rss_atom(xml, "https://example.com/rss")
        assert len(articles) == 1
        assert articles[0].title == "Test Item"
        assert "192.0.2.1" in articles[0].summary

    def test_parse_atom_basic(self) -> None:
        xml = """<?xml version="1.0"?>
        <feed xmlns="http://www.w3.org/2005/Atom">
          <entry>
            <title>Atom Entry</title>
            <summary>Malware at 198.51.100.1</summary>
            <link href="https://example.com/2"/>
            <published>2024-06-01T12:00:00Z</published>
          </entry>
        </feed>"""
        articles = _parse_rss_atom(xml, "https://example.com/atom")
        assert len(articles) == 1
        assert articles[0].title == "Atom Entry"
        assert "198.51.100.1" in articles[0].summary

    def test_parse_rss_no_channel(self) -> None:
        xml = """<?xml version="1.0"?>
        <rss version="2.0">
          <item><title>Orphan</title></item>
        </rss>"""
        with pytest.raises(ValueError, match="No <channel>"):
            _parse_rss_atom(xml, "https://example.com/rss")

    def test_parse_malformed_xml(self) -> None:
        xml = "<rss><unclosed>"
        with pytest.raises(ValueError, match="Malformed XML"):
            _parse_rss_atom(xml, "https://example.com/rss")

    def test_parse_atom_no_ns_fallback(self) -> None:
        xml = """<?xml version="1.0"?>
        <feed>
          <entry>
            <title>No NS Entry</title>
            <summary>Bad domain evil.example.com</summary>
            <link href="https://example.com/3"/>
            <published>2024-06-01T12:00:00Z</published>
          </entry>
        </feed>"""
        articles = _parse_rss_atom(xml, "https://example.com/atom")
        assert len(articles) == 1
        assert articles[0].title == "No NS Entry"


class TestSampleMode:
    """Test offline sample loading."""

    def test_load_samples_success(self) -> None:
        articles = load_samples("data/samples.json")
        assert len(articles) >= 5
        assert all(isinstance(a, Article) for a in articles)

    def test_load_samples_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            load_samples("data/nonexistent.json")


class TestNetworkFetch:
    """Test live feed fetching with mocked requests."""

    def test_fetch_feed_success(self) -> None:
        mock_xml = """<?xml version="1.0"?>
        <rss version="2.0">
          <channel>
            <item>
              <title>Live</title>
              <description>Live IOC 203.0.113.5</description>
              <link>https://example.com/live</link>
              <pubDate>Mon, 01 Jun 2024 12:00:00 GMT</pubDate>
            </item>
          </channel>
        </rss>"""
        with patch("src.ingest.requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.text = mock_xml
            mock_resp.raise_for_status = MagicMock()
            mock_get.return_value = mock_resp

            articles = fetch_feed("https://example.com/feed")
            assert len(articles) == 1
            assert "203.0.113.5" in articles[0].summary

    def test_fetch_feed_http_error(self) -> None:
        with patch("src.ingest.requests.get") as mock_get:
            mock_get.side_effect = requests.ConnectionError("Network down")
            with pytest.raises(RuntimeError, match="Failed to ingest"):
                fetch_feed("https://example.com/feed")

    def test_fetch_feed_rate_limit(self) -> None:
        with patch("src.ingest.requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.text = """<?xml version="1.0"?>
            <rss version="2.0"><channel><item>
              <title>Rate Test</title>
              <description>IP 192.0.2.1</description>
              <link>https://example.com/r</link>
            </item></channel></rss>"""
            mock_resp.raise_for_status = MagicMock()
            mock_get.return_value = mock_resp

            # Two calls should happen even with rate limit
            a1 = fetch_feed("https://example.com/feed1")
            a2 = fetch_feed("https://example.com/feed2")
            assert len(a1) == 1
            assert len(a2) == 1
            # Rate limit should sleep between calls
            assert mock_get.call_count == 2
