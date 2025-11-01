"""Server-Sent Events (SSE) utilities for MCP responses."""

import json
from typing import Any, Dict, Iterable, cast


def parse_sse_json(lines: Iterable[str]) -> Dict[str, Any]:
    """
    Parse Server-Sent Events (SSE) response into JSON.

    Many MCP servers return JSON-RPC responses in SSE format:
        event: message
        data: {"jsonrpc":"2.0","result":{...}}

    Args:
        lines: Lines from SSE response (typically response.text.strip().splitlines())

    Returns:
        Parsed JSON object from the data lines

    Raises:
        ValueError: If no data lines found in SSE response
        json.JSONDecodeError: If data is not valid JSON

    Example:
        >>> response = await client.get(url)
        >>> if 'text/event-stream' in response.headers.get('content-type', ''):
        ...     data = parse_sse_json(response.text.strip().splitlines())
        ... else:
        ...     data = response.json()
    """
    data = "".join(line[6:] for line in lines if line.startswith("data: "))
    if not data:
        raise ValueError("No data lines in SSE response")
    return cast(Dict[str, Any], json.loads(data))
