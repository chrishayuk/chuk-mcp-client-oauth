#!/usr/bin/env python3
"""
End-to-end OAuth Handler example with real Notion MCP authentication.

This example demonstrates the complete OAuthHandler workflow with actual
OAuth authentication against Notion MCP server.

Features demonstrated:
1. MCP OAuth with auto-discovery (Notion MCP)
2. Token caching and reuse
3. Token refresh
4. Multiple authentication methods
"""

import asyncio
from chuk_mcp_client_oauth import OAuthHandler


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
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)


async def example_mcp_oauth_with_notion(handler: OAuthHandler):
    """Complete MCP OAuth flow with Notion MCP."""
    print_section("Example 1: MCP OAuth with Notion")

    server_name = "notion-mcp"
    server_url = "https://mcp.notion.com/mcp"

    print(f"Authenticating with {server_url}...")
    print("This will open your browser for authorization if needed.")

    try:
        # First authentication - will trigger OAuth flow
        print("\n🔐 Step 1: Initial Authentication")
        tokens = await handler.ensure_authenticated_mcp(
            server_name=server_name,
            server_url=server_url,
            scopes=["read", "write"],
        )
        print("✅ Authentication successful!")
        print(f"   Access Token: {safe_display_token(tokens.access_token)}")
        print(f"   Token Type: {tokens.token_type}")
        print(f"   Expires In: {tokens.expires_in} seconds")

        # Get ready-to-use headers
        print("\n📋 Step 2: Getting Authorization Headers")
        headers = await handler.prepare_headers_for_mcp_server(
            server_name=server_name, server_url=server_url
        )
        print(
            f"✅ Headers prepared: {safe_display_token(headers['Authorization'], prefix_len=15, suffix_len=6)}"
        )

        # Demonstrate token caching - this should NOT trigger OAuth flow
        print("\n💾 Step 3: Testing Token Cache")
        print("Authenticating again (should use cached tokens)...")
        cached_tokens = await handler.ensure_authenticated_mcp(
            server_name=server_name,
            server_url=server_url,
        )
        print("✅ Used cached tokens (no OAuth flow triggered)")
        print(f"   Same token: {cached_tokens.access_token == tokens.access_token}")

        # Check token validity
        print("\n🔍 Step 4: Token Status")
        has_valid = handler.token_manager.has_valid_tokens(server_name)
        print(f"✅ Has valid tokens: {has_valid}")
        is_expired = tokens.is_expired()
        print(f"   Is expired: {is_expired}")

        return True

    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("\nNote: This requires completing OAuth in your browser.")
        return False


async def example_token_operations(handler: OAuthHandler):
    """Demonstrate token operations with real tokens."""
    print_section("Example 2: Token Operations")

    server_name = "notion-mcp"

    # Load tokens from previous authentication
    print("Loading stored tokens...")
    stored_tokens = handler.token_manager.load_tokens(server_name)

    if stored_tokens:
        print("✅ Found stored tokens")
        print(f"   Access Token: {safe_display_token(stored_tokens.access_token)}")
        print(f"   Token Type: {stored_tokens.token_type}")

        # Get authorization header
        auth_header = handler.get_authorization_header(server_name)
        if auth_header:
            print("\n📋 Authorization Header:")
            print(f"   {safe_display_token(auth_header, prefix_len=15, suffix_len=6)}")

        # Check expiration
        is_expired = stored_tokens.is_expired()
        print("\n🕐 Token Status:")
        print(f"   Is expired: {is_expired}")

        # Show storage backend
        print("\n💾 Storage Backend:")
        print(f"   {handler.token_manager.token_store.__class__.__name__}")
    else:
        print("⚠️  No stored tokens found")
        print("   Run the OAuth flow first (Example 1)")


async def example_cleanup(handler: OAuthHandler):
    """Demonstrate token cleanup."""
    print_section("Example 3: Cleanup")

    server_name = "notion-mcp"

    print(f"Current tokens for {server_name}:")
    has_tokens = handler.token_manager.has_valid_tokens(server_name)
    print(f"   Has valid tokens: {has_tokens}")

    if has_tokens:
        print("\n🗑️  Option to clear tokens:")
        print(f"   handler.clear_tokens('{server_name}')")
        print("\n   (Keeping tokens for demonstration)")
    else:
        print("   No tokens to clear")


async def main():
    """Main example function - complete OAuth workflow."""
    print("=" * 60)
    print("OAuth Handler - End-to-End Example")
    print("=" * 60)
    print("\nThis example performs REAL OAuth authentication with Notion MCP")
    print("and demonstrates the complete OAuthHandler workflow.")

    # Create OAuth handler (manages tokens for multiple servers)
    handler = OAuthHandler()
    print("\n✅ Created OAuthHandler")
    print(f"   Storage: {handler.token_manager.token_store.__class__.__name__}")

    # Run complete OAuth workflow
    success = await example_mcp_oauth_with_notion(handler)

    if success:
        # Demonstrate token operations
        await example_token_operations(handler)

        # Show cleanup options
        await example_cleanup(handler)

        print_section("Success!")
        print("""
✅ Complete OAuth workflow demonstrated:
   - OAuth discovery and registration
   - User authorization
   - Token exchange
   - Token caching (memory + disk)
   - Header preparation
   - Token validation

💡 Key Features:
   - Tokens are cached in memory for performance
   - Tokens are persisted to secure storage
   - Subsequent authentications use cached tokens
   - Automatic token refresh when needed
   - Multiple storage backends supported

🔗 Next Steps:
   - Use the same handler for multiple servers
   - Tokens persist between script runs
   - Automatic refresh before expiration
   - See token_storage_example.py for storage options

📚 Related Examples:
   - basic_mcp_oauth.py - Lower-level OAuth client
   - token_storage_example.py - Storage backends demo
""")
    else:
        print_section("Note")
        print("""
This example requires completing OAuth in your browser.
The OAuth flow includes:
1. Browser opens for authorization
2. You approve the app
3. Callback receives authorization code
4. Code is exchanged for tokens

Try again and complete the browser authorization!
""")


if __name__ == "__main__":
    asyncio.run(main())
