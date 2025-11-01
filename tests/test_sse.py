"""Tests for SSE (Server-Sent Events) parser."""

import pytest

from chuk_mcp_client_oauth import parse_sse_json


class TestParseSSEJson:
    """Test parse_sse_json function."""

    def test_parse_single_line_sse(self):
        """Test parsing single-line SSE response."""
        lines = [
            "event: message",
            'data: {"jsonrpc":"2.0","result":{"status":"ok"}}',
            "",
        ]
        result = parse_sse_json(lines)
        assert result == {"jsonrpc": "2.0", "result": {"status": "ok"}}

    def test_parse_multiline_sse(self):
        """Test parsing multi-line SSE response (JSON spanning multiple data lines)."""
        lines = [
            "event: message",
            'data: {"jsonrpc":"2.0",',
            'data: "result":{"tools":[',
            'data: {"name":"test"}]}}',
            "",
        ]
        result = parse_sse_json(lines)
        assert result == {"jsonrpc": "2.0", "result": {"tools": [{"name": "test"}]}}

    def test_parse_sse_with_tools(self):
        """Test parsing SSE response with MCP tools."""
        lines = [
            "event: message",
            'data: {"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"search","description":"Search Notion"}]}}',
        ]
        result = parse_sse_json(lines)
        assert "result" in result
        assert "tools" in result["result"]
        assert len(result["result"]["tools"]) == 1
        assert result["result"]["tools"][0]["name"] == "search"

    def test_parse_sse_no_data_lines(self):
        """Test that ValueError is raised when no data lines found."""
        lines = ["event: message", "id: 123", ""]
        with pytest.raises(ValueError, match="No data lines in SSE response"):
            parse_sse_json(lines)

    def test_parse_sse_invalid_json(self):
        """Test that JSONDecodeError is raised for invalid JSON."""
        lines = [
            "data: {invalid json}",
        ]
        import json

        with pytest.raises(json.JSONDecodeError):
            parse_sse_json(lines)

    def test_parse_sse_empty_list(self):
        """Test that ValueError is raised for empty list."""
        with pytest.raises(ValueError, match="No data lines in SSE response"):
            parse_sse_json([])

    def test_parse_sse_with_nested_data(self):
        """Test parsing SSE with deeply nested JSON."""
        lines = [
            'data: {"a":{"b":{"c":{"d":"value"}}}}',
        ]
        result = parse_sse_json(lines)
        assert result["a"]["b"]["c"]["d"] == "value"
