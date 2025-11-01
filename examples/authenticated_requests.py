#!/usr/bin/env python3
"""
Example demonstrating authenticated HTTP requests with automatic 401 handling.

This example shows how to use the authenticated_request() method to make
HTTP requests with automatic token refresh on 401 responses.

**✅ FULLY WORKING EXAMPLES:**
- Example 1: Authenticated REST API request to httpbin.org
- Example 2: Complete Notion MCP integration with SSE support

Features demonstrated:
1. Making authenticated GET/POST requests (working examples!)
2. Automatic token refresh on 401 Unauthorized
3. Custom headers with authentication
4. SSE (Server-Sent Events) response parsing for MCP
5. Full MCP session initialization and tool listing
6. Error handling

Note: All examples are fully functional and demonstrate real-world usage
patterns for OAuth authentication with MCP servers.
"""

import asyncio
import uuid
import httpx
from chuk_mcp_client_oauth import OAuthHandler, parse_sse_json


def safe_display_token(token: str, prefix_len: int = 20, suffix_len: int = 6) -> str:
    """Safely display a token with most characters redacted."""
    if len(token) <= prefix_len + suffix_len:
        return f"{token[:10]}..."

    prefix = token[:prefix_len]
    suffix = token[-suffix_len:]
    redacted_len = len(token) - prefix_len - suffix_len

    return f"{prefix}...{'*' * min(redacted_len, 20)}...{suffix}"


def print_section(title: str):
    """Print a formatted section header."""
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def get_mcp_headers(session_id: str = None) -> dict:
    """Get the required headers for MCP JSON-RPC requests."""
    headers = {
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    return headers


# Note: SSE parsing is now handled by the library's parse_sse_json() function
# No need to define it here - it's imported from chuk_mcp_client_oauth


async def initialize_mcp_session(
    handler: OAuthHandler, server_name: str, server_url: str
) -> str:
    """Initialize an MCP session and return the session ID."""
    session_id = str(uuid.uuid4())

    # Send initialize request (WITHOUT session ID - it's not created yet!)
    init_payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"roots": {"listChanged": True}, "sampling": {}},
            "clientInfo": {"name": "chuk-oauth-example", "version": "0.1.0"},
        },
    }

    # Initialize does NOT use session ID in the header
    response = await handler.authenticated_request(
        server_name=server_name,
        server_url=server_url,
        url=server_url,
        method="POST",
        json=init_payload,
        headers=get_mcp_headers(),  # No session_id for initialize
        timeout=60.0,  # Initialization can be slow
    )

    # Parse response - might be SSE format
    content_type = response.headers.get("content-type", "")
    if "text/event-stream" in content_type:
        # SSE format - extract session ID from header
        session_id = response.headers.get("mcp-session-id", session_id)
        result = parse_sse_json(response.text.strip().splitlines())
    else:
        result = response.json()

    if "result" in result:
        print(f"✅ MCP session initialized: {session_id[:8]}...")
        # Also send initialized notification
        init_notify = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        await handler.authenticated_request(
            server_name=server_name,
            server_url=server_url,
            url=server_url,
            method="POST",
            json=init_notify,
            headers=get_mcp_headers(session_id),
            timeout=30.0,
        )
        return session_id
    else:
        raise Exception(f"Failed to initialize session: {result}")


async def example_basic_get_request(handler: OAuthHandler):
    """Example 1: Demonstrate OAuth authentication with httpbin."""
    print_section("Example 1: Authenticated GET Request (httpbin.org)")

    # Use httpbin.org for a simple, working REST API example
    endpoint_url = "https://httpbin.org/bearer"

    print(f"Making authenticated request to: {endpoint_url}")
    print("This demonstrates:")
    print("  1. OAuth token management (uses cached Notion MCP tokens for demo)")
    print("  2. Authorization header injection")
    print("  3. Automatic 401 handling with token refresh")
    print("  4. Working with standard REST APIs")
    print("\nNote: httpbin.org echoes back the auth header we send")

    try:
        # Get tokens from Notion MCP (already authenticated)
        notion_handler = OAuthHandler()
        notion_tokens = notion_handler.token_manager.load_tokens("notion-mcp")

        if not notion_tokens:
            print(
                "\n⚠️  No Notion MCP tokens found. Run oauth_handler_example.py first."
            )
            return False

        print(f"\n🔑 Using token: {notion_tokens.access_token[:20]}...")

        # Make request to httpbin which will echo our auth header
        response = await handler.authenticated_request(
            server_name="notion-mcp",  # Use existing tokens
            server_url="https://mcp.notion.com/mcp",  # For auth
            url=endpoint_url,  # Actual request goes here
            method="GET",
        )

        print("\n✅ Request successful!")
        print(f"   Status: {response.status_code}")

        # httpbin echoes back the token
        data = response.json()
        if "authenticated" in data:
            print(f"   Authenticated: {data['authenticated']}")
        if "token" in data:
            token = data["token"]
            print(f"   Token received by server: {token[:20]}...")

        return True

    except httpx.HTTPStatusError as e:
        print(f"\n❌ HTTP Error: {e.response.status_code}")
        print(f"   {e.response.text[:200]}")
        return False
    except Exception as e:
        print(f"\n❌ Error: {type(e).__name__}: {e}")
        return False


async def example_post_request(handler: OAuthHandler):
    """Example 2: Complete Notion MCP workflow - Initialize and list tools."""
    print_section("Example 2: Complete Notion MCP Example")

    server_name = "notion-mcp"
    server_url = "https://mcp.notion.com/mcp"

    print(f"Connecting to: {server_url}")
    print("This demonstrates:")
    print("  1. OAuth authentication (automatic)")
    print("  2. MCP session initialization")
    print("  3. Listing available tools")
    print("\nNote: Initialization may take 10-30 seconds...")

    try:
        # Step 1: Initialize MCP session (WITHOUT session ID)
        print("\n📋 Step 1: Initializing MCP session...")
        session_id = str(uuid.uuid4())

        init_payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"roots": {"listChanged": True}, "sampling": {}},
                "clientInfo": {"name": "chuk-oauth-example", "version": "0.1.0"},
            },
        }

        # Initialize request with 60 second timeout (it can be slow)
        init_response = await handler.authenticated_request(
            server_name=server_name,
            server_url=server_url,
            url=server_url,
            method="POST",
            json=init_payload,
            headers=get_mcp_headers(),  # No session ID for initialize
            timeout=60.0,  # 60 second timeout for initialize
        )

        # Parse response - MCP uses SSE (Server-Sent Events) format
        content_type = init_response.headers.get("content-type", "")
        if "text/event-stream" in content_type:
            # SSE format - extract session ID from header
            session_id = init_response.headers.get("mcp-session-id", session_id)
            print("   📡 SSE response received")
            print(f"   🔑 Session ID: {session_id[:16]}...")
            init_result = parse_sse_json(init_response.text.strip().splitlines())
        else:
            # Regular JSON response
            init_result = init_response.json()
        if "error" in init_result:
            print(f"   ❌ Initialize error: {init_result['error']}")
            return False

        print(f"   ✅ Session initialized: {session_id[:8]}...")

        # Step 2: Send initialized notification (WITH session ID)
        print("\n📨 Step 2: Sending initialized notification...")
        notify_payload = {"jsonrpc": "2.0", "method": "notifications/initialized"}

        await handler.authenticated_request(
            server_name=server_name,
            server_url=server_url,
            url=server_url,
            method="POST",
            json=notify_payload,
            headers=get_mcp_headers(session_id),
            timeout=30.0,
        )
        print("   ✅ Notification sent")

        # Step 3: List tools (WITH session ID)
        print("\n🔧 Step 3: Listing available tools...")
        tools_payload = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {},
        }

        tools_response = await handler.authenticated_request(
            server_name=server_name,
            server_url=server_url,
            url=server_url,
            method="POST",
            json=tools_payload,
            headers=get_mcp_headers(session_id),
            timeout=30.0,
        )

        print("\n✅ Request successful!")
        print(f"   Status: {tools_response.status_code}")

        # Parse response - might be SSE format
        content_type = tools_response.headers.get("content-type", "")
        if "text/event-stream" in content_type:
            data = parse_sse_json(tools_response.text.strip().splitlines())
        else:
            data = tools_response.json()
        if "result" in data and "tools" in data["result"]:
            tools = data["result"]["tools"]
            print(f"\n📦 Found {len(tools)} tools:")
            for tool in tools[:5]:  # Show first 5
                print(f"   • {tool.get('name', 'Unknown')}")
                if "description" in tool:
                    desc = tool["description"]
                    print(f"     {desc[:80]}{'...' if len(desc) > 80 else ''}")
            if len(tools) > 5:
                print(f"   ... and {len(tools) - 5} more")
        elif "error" in data:
            print(f"   ❌ JSON-RPC Error: {data['error']}")
        else:
            print(f"   Response: {data}")

        return True

    except httpx.TimeoutException as e:
        print("\n❌ Timeout Error: Request took too long")
        print(f"   {str(e)}")
        return False
    except httpx.HTTPStatusError as e:
        print(f"\n❌ HTTP Error: {e.response.status_code}")
        print(f"   {e.response.text[:200]}")
        return False
    except Exception as e:
        print(f"\n❌ Error: {type(e).__name__}: {e}")
        return False


async def example_custom_headers(handler: OAuthHandler):
    """Example 3: JSON-RPC request with custom headers."""
    print_section("Example 3: JSON-RPC Request with Custom Headers")

    server_name = "notion-mcp"
    server_url = "https://mcp.notion.com/mcp"

    print("Making JSON-RPC request with custom headers")
    print("Custom headers: X-Custom-Header, X-Request-ID, Accept-Language")
    print("\nNote: Initializing session first...")

    try:
        # Initialize session
        session_id = await initialize_mcp_session(handler, server_name, server_url)

        # Merge custom headers with required MCP headers (including session ID)
        custom_headers = {
            **get_mcp_headers(session_id),  # MCP headers with session ID
            "X-Custom-Header": "example-value",
            "X-Request-ID": "12345",
            "Accept-Language": "en-US",
        }

        jsonrpc_payload = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "resources/list",
            "params": {},
        }

        print("\n📤 Sending resources/list request with custom headers...")
        response = await handler.authenticated_request(
            server_name=server_name,
            server_url=server_url,
            url=server_url,
            method="POST",
            json=jsonrpc_payload,
            headers=custom_headers,  # Merged headers (MCP + custom)
            timeout=30.0,
        )

        print("\n✅ Request successful!")
        print(f"   Status: {response.status_code}")
        print("   Both Authorization and custom headers were sent")

        # Parse response - might be SSE format
        content_type = response.headers.get("content-type", "")
        if "text/event-stream" in content_type:
            data = parse_sse_json(response.text.strip().splitlines())
        else:
            data = response.json()

        if "result" in data and "resources" in data["result"]:
            resources = data["result"]["resources"]
            print(f"\n📦 Found {len(resources)} resources:")
            for resource in resources:
                print(f"   • {resource.get('name', 'Unknown')}")
                if "uri" in resource:
                    print(f"     URI: {resource['uri']}")
                if "description" in resource:
                    desc = resource["description"]
                    print(f"     {desc[:80]}{'...' if len(desc) > 80 else ''}")

        return True

    except httpx.HTTPStatusError as e:
        print(f"\n❌ HTTP Error: {e.response.status_code}")
        return False
    except Exception as e:
        print(f"\n❌ Error: {e}")
        return False


async def example_manual_401_handling(handler: OAuthHandler):
    """Example 4: Disabling automatic 401 retry."""
    print_section("Example 4: Manual 401 Handling")

    server_name = "notion-mcp"
    server_url = "https://mcp.notion.com/mcp"

    print("Making JSON-RPC request with retry_on_401=False")
    print("If server returns 401, we'll handle it manually")
    print("\nNote: Initializing session first...")

    try:
        # Initialize session
        session_id = await initialize_mcp_session(handler, server_name, server_url)

        jsonrpc_payload = {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "resources/list",
            "params": {},
        }

        print("\n📤 Sending resources/list request with retry_on_401=False...")
        response = await handler.authenticated_request(
            server_name=server_name,
            server_url=server_url,
            url=server_url,
            method="POST",
            json=jsonrpc_payload,
            headers=get_mcp_headers(session_id),
            retry_on_401=False,  # Disable automatic retry
            timeout=30.0,
        )

        print("\n✅ Request successful!")
        print(f"   Status: {response.status_code}")
        print("   No 401 error occurred (tokens are valid)")

        # Parse and display resources
        content_type = response.headers.get("content-type", "")
        if "text/event-stream" in content_type:
            data = parse_sse_json(response.text.strip().splitlines())
        else:
            data = response.json()

        if "result" in data and "resources" in data["result"]:
            resources = data["result"]["resources"]
            print(f"\n📦 Found {len(resources)} resources:")
            for resource in resources:
                print(f"   • {resource.get('name', 'Unknown')}")
                if "uri" in resource:
                    print(f"     URI: {resource['uri']}")

        return True

    except httpx.HTTPStatusError as e:
        if e.response.status_code == 401:
            print("\n⚠️  Got 401 Unauthorized")
            print("   Handling manually...")
            print("   Could prompt user, log out, or refresh manually")
        else:
            print(f"\n❌ HTTP Error: {e.response.status_code}")
        return False
    except Exception as e:
        print(f"\n❌ Error: {e}")
        return False


async def example_error_scenarios(handler: OAuthHandler):
    """Example 5: Common error scenarios."""
    print_section("Example 5: Error Handling")

    server_name = "notion-mcp"
    server_url = "https://mcp.notion.com/mcp"

    # Scenario 1: Invalid JSON-RPC method
    print("\n📌 Scenario 1: Invalid JSON-RPC method")
    try:
        invalid_payload = {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "nonexistent/method",
            "params": {},
        }
        response = await handler.authenticated_request(
            server_name=server_name,
            server_url=server_url,
            url=server_url,
            method="POST",
            json=invalid_payload,
            headers=get_mcp_headers(),
        )
        data = response.json()
        if "error" in data:
            print(f"   ✅ Caught expected JSON-RPC error: {data['error']['message']}")
        else:
            print(f"   Status: {response.status_code}")
    except httpx.HTTPStatusError as e:
        print(f"   ✅ Caught expected error: {e.response.status_code}")

    # Scenario 2: Malformed JSON-RPC request
    print("\n📌 Scenario 2: Malformed JSON-RPC request")
    try:
        malformed_payload = {"not": "valid", "jsonrpc": "request"}
        response = await handler.authenticated_request(
            server_name=server_name,
            server_url=server_url,
            url=server_url,
            method="POST",
            json=malformed_payload,
            headers=get_mcp_headers(),
        )
        data = response.json()
        if "error" in data:
            print(f"   ✅ Caught expected JSON-RPC error: {data['error']['code']}")
    except httpx.HTTPStatusError as e:
        print(f"   ✅ Caught expected error: {e.response.status_code}")

    # Scenario 3: Network error
    print("\n📌 Scenario 3: Network error (invalid hostname)")
    try:
        response = await handler.authenticated_request(
            server_name=server_name,
            server_url=server_url,
            url="https://invalid-hostname-that-does-not-exist.example.com/api",
            method="POST",
            json={"jsonrpc": "2.0", "id": 6, "method": "test", "params": {}},
        )
        print(f"   Status: {response.status_code}")
    except httpx.HTTPError as e:
        print(f"   ✅ Caught expected network error: {type(e).__name__}")


async def example_token_lifecycle(handler: OAuthHandler):
    """Example 6: Understanding the token lifecycle during requests."""
    print_section("Example 6: Token Lifecycle During Requests")

    server_name = "notion-mcp"
    server_url = "https://mcp.notion.com/mcp"

    print("What happens during authenticated_request():\n")
    print("1️⃣  Check if we have cached tokens")
    has_cached = handler.get_authorization_header(server_name) is not None
    print(f"   Has cached tokens: {has_cached}")

    print("\n2️⃣  If no cached tokens, authenticate")
    if not has_cached:
        print("   Will trigger OAuth flow (browser opens)")
    else:
        print("   Will use cached tokens")

    print("\n3️⃣  Initialize MCP session (for MCP servers)")
    print("   - Send initialize request")
    print("   - Get session ID from response header")
    print("   - Send initialized notification")

    print("\n4️⃣  Make JSON-RPC request with Authorization header")
    print("   Authorization: Bearer <token>")
    print("   Mcp-Session-Id: <session-id>")

    print("\n5️⃣  If server returns 401 Unauthorized:")
    print("   - Clear cached tokens")
    print("   - Re-authenticate (uses refresh token if available)")
    print("   - Retry request with new token")

    print("\n6️⃣  Return final response")

    print("\n📋 Now demonstrating the actual flow...")

    try:
        # Initialize session
        session_id = await initialize_mcp_session(handler, server_name, server_url)

        jsonrpc_payload = {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "resources/list",
            "params": {},
        }

        print("\n📤 Making the authenticated request...")
        response = await handler.authenticated_request(
            server_name=server_name,
            server_url=server_url,
            url=server_url,
            method="POST",
            json=jsonrpc_payload,
            headers=get_mcp_headers(session_id),
            timeout=30.0,
        )

        print(f"\n✅ Final status: {response.status_code}")

        # Parse response - might be SSE format
        content_type = response.headers.get("content-type", "")
        if "text/event-stream" in content_type:
            data = parse_sse_json(response.text.strip().splitlines())
        else:
            data = response.json()

        if "result" in data:
            print(f"   Result type: {type(data['result'])}")
            if "resources" in data["result"]:
                resources = data["result"]["resources"]
                print(f"\n📦 Found {len(resources)} resources:")
                for resource in resources:
                    print(f"   • {resource.get('name', 'Unknown')}")
                    if "uri" in resource:
                        print(f"     URI: {resource['uri']}")

    except Exception as e:
        print(f"\n❌ Error: {e}")


async def main():
    """Main example runner."""
    print("=" * 70)
    print("Authenticated Requests - Complete Example")
    print("=" * 70)
    print("""
This example demonstrates authenticated requests to MCP servers with automatic
token refresh on 401 Unauthorized responses.

✅ FULLY WORKING: Both examples demonstrate real, working authentication!

Example 1: httpbin.org - Shows OAuth authentication with a standard REST API
Example 2: Notion MCP - Shows complete MCP session with SSE response handling

NOTE: MCP uses JSON-RPC over HTTP with SSE (Server-Sent Events) responses.
This example handles both regular JSON and SSE response formats automatically.

The authenticated_request() method handles:
✅ Token management (get, refresh, cache)
✅ Authorization header injection
✅ Automatic retry on 401
✅ All HTTP methods (POST for JSON-RPC, GET, PUT, DELETE for other APIs)
✅ Custom headers and request options
✅ SSE response parsing for MCP servers
✅ MCP session management (session IDs, initialization)
""")

    # Create OAuth handler
    handler = OAuthHandler()
    print("✅ Created OAuthHandler")
    print(f"   Storage: {handler.token_manager.token_store.__class__.__name__}\n")

    # Run examples
    print("Choose an example to run:")
    print("1. Working example: Authenticated GET to httpbin.org")
    print("2. Complete Notion MCP example: Initialize session and list tools")
    print("3. Custom headers with JSON-RPC")
    print("4. Manual 401 handling")
    print("5. Error scenarios (invalid methods, malformed requests)")
    print("6. Token lifecycle explanation")
    print("7. Run all examples")

    try:
        choice = input("\nEnter choice (1-7): ").strip()

        examples = {
            "1": example_basic_get_request,
            "2": example_post_request,
            "3": example_custom_headers,
            "4": example_manual_401_handling,
            "5": example_error_scenarios,
            "6": example_token_lifecycle,
        }

        if choice == "7":
            # Run all examples
            for func in examples.values():
                await func(handler)
        elif choice in examples:
            await examples[choice](handler)
        else:
            print("Invalid choice")
            return

        print_section("Complete!")
        print("""
✅ Authenticated request examples demonstrated!

Key Takeaways:
• authenticated_request() simplifies making authenticated API calls
• Automatic token refresh on 401 means no manual token management
• Works with all HTTP methods and request options
• Errors are raised as httpx.HTTPStatusError for easy handling

💡 In Production:
• Use authenticated_request() for all MCP API calls
• Let the library handle token lifecycle automatically
• Focus on your application logic, not OAuth complexity

📚 Related Examples:
• oauth_handler_example.py - Full OAuth workflow
• basic_mcp_oauth.py - Lower-level OAuth client
• token_storage_example.py - Storage backend options
""")

    except KeyboardInterrupt:
        print("\n\n👋 Cancelled by user")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
