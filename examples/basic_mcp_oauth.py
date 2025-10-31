#!/usr/bin/env python3
"""
Basic example of MCP OAuth authentication.

This example demonstrates how to use the MCP OAuth client to authenticate
with an MCP server using the full OAuth 2.0 flow with PKCE.

NOTE: This example requires a real MCP OAuth server. To use it:

1. Replace the server_url with your actual MCP server URL
2. The server must implement:
   - OAuth Authorization Server Metadata (RFC 8414) at /.well-known/oauth-authorization-server
   - Dynamic Client Registration (RFC 7591) at the registration endpoint
   - OAuth 2.0 Authorization Code Flow with PKCE

Example MCP servers:
- Notion MCP: https://mcp.notion.com/mcp
- Custom MCP servers with OAuth enabled
- Enterprise MCP deployments

For testing without a real server, see token_storage_example.py which demonstrates
the library functionality with mock tokens.
"""

import asyncio
import sys
from chuk_mcp_client_oauth import MCPOAuthClient


def safe_display_token(token: str, prefix_len: int = 20, suffix_len: int = 6) -> str:
    """Safely display a token with most characters redacted.

    Shows the first prefix_len and last suffix_len characters to prove validity
    while keeping the token secure.
    """
    if len(token) <= prefix_len + suffix_len:
        # Token too short, just show first few chars
        return f"{token[:10]}..."

    prefix = token[:prefix_len]
    suffix = token[-suffix_len:]
    redacted_len = len(token) - prefix_len - suffix_len

    return f"{prefix}...{'*' * min(redacted_len, 20)}...{suffix}"


async def main():
    # Check if server URL was provided, default to Notion MCP
    if len(sys.argv) < 2:
        print("No server URL provided, using Notion MCP as example")
        print("Usage: python basic_mcp_oauth.py <server_url>")
        print("\nExamples:")
        print("  python basic_mcp_oauth.py https://mcp.notion.com/mcp")
        print("  python basic_mcp_oauth.py https://your-mcp-server.com/mcp")
        print("\nThe server must support:")
        print("  - OAuth Authorization Server Metadata (RFC 8414)")
        print("  - Dynamic Client Registration (RFC 7591)")
        print("  - Authorization Code Flow with PKCE")
        print("\nProceeding with Notion MCP example...")
        server_url = "https://mcp.notion.com/mcp"
    else:
        server_url = sys.argv[1]

    # Create MCP OAuth client
    client = MCPOAuthClient(
        server_url=server_url,
        redirect_uri="http://localhost:8080/callback",
    )

    print(f"Starting MCP OAuth flow with {server_url}...")
    print("=" * 60)

    try:
        # Perform full OAuth flow (discovery, registration, authorization)
        # This will:
        # 1. Discover the OAuth server metadata
        # 2. Register as a dynamic client
        # 3. Open browser for user authorization
        # 4. Exchange authorization code for tokens
        tokens = await client.authorize(scopes=["read", "write"])

        print("\n✅ Authentication successful!")
        print(f"Access Token: {safe_display_token(tokens.access_token)}")
        print(f"Token Type: {tokens.token_type}")
        if tokens.expires_in:
            print(f"Expires In: {tokens.expires_in} seconds")
        if tokens.refresh_token:
            print(f"Refresh Token: {safe_display_token(tokens.refresh_token)}")

        # Use the token to make authenticated requests
        headers = {"Authorization": tokens.get_authorization_header()}
        auth_header = headers["Authorization"]
        print(
            f"\nAuthorization Header: {safe_display_token(auth_header, prefix_len=15, suffix_len=6)}"
        )

        # Example: Refresh the token if needed
        if tokens.refresh_token:
            print("\n🔄 Refreshing token...")
            new_tokens = await client.refresh_token(tokens.refresh_token)
            print(f"New Access Token: {safe_display_token(new_tokens.access_token)}")
            print("✅ Token refresh successful!")

    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("\nMake sure your server supports MCP OAuth:")
        print(f"  - Metadata: {server_url}/.well-known/oauth-authorization-server")
        print("  - Dynamic Client Registration (RFC 7591)")
        print("  - PKCE support")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
