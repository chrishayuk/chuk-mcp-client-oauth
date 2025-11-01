#!/usr/bin/env python3
"""
Simple CLI tool for managing OAuth tokens.

This tool makes it easy to:
- Authenticate with MCP servers
- View stored tokens (safely redacted)
- Logout and revoke tokens with server
- Clear tokens locally
- List all servers with tokens
- Test connections

Usage:
    uv run examples/oauth_cli.py auth <server_name> <server_url>
    uv run examples/oauth_cli.py get <server_name>
    uv run examples/oauth_cli.py list
    uv run examples/oauth_cli.py logout <server_name> --url <server_url>
    uv run examples/oauth_cli.py clear <server_name>
    uv run examples/oauth_cli.py test <server_name>
"""

import argparse
import asyncio
import sys
import uuid
from typing import Optional

from chuk_mcp_client_oauth import OAuthHandler, TokenManager, parse_sse_json


def safe_display_token(token: str, prefix_len: int = 20, suffix_len: int = 6) -> str:
    """Safely display a token with most characters redacted."""
    if len(token) <= prefix_len + suffix_len:
        return f"{token[:10]}..."

    prefix = token[:prefix_len]
    suffix = token[-suffix_len:]
    redacted_len = len(token) - prefix_len - suffix_len

    return f"{prefix}...{'*' * min(redacted_len, 20)}...{suffix}"


def print_header(text: str):
    """Print a formatted header."""
    print("\n" + "=" * 60)
    print(text)
    print("=" * 60)


async def cmd_auth(
    server_name: str, server_url: str, scopes: Optional[list[str]] = None
):
    """Authenticate with an MCP server."""
    print_header(f"Authenticating with {server_name}")
    print(f"Server URL: {server_url}")

    if scopes:
        print(f"Scopes: {', '.join(scopes)}")
    else:
        scopes = ["read", "write"]
        print(f"Scopes: {', '.join(scopes)} (default)")

    handler = OAuthHandler()

    try:
        print("\n🔐 Starting OAuth flow...")
        print("This will open your browser for authorization.\n")

        tokens = await handler.ensure_authenticated_mcp(
            server_name=server_name,
            server_url=server_url,
            scopes=scopes,
        )

        print("\n✅ Authentication successful!")
        print(f"Access Token: {safe_display_token(tokens.access_token)}")
        print(f"Token Type: {tokens.token_type}")
        print(f"Expires In: {tokens.expires_in} seconds")

        if tokens.refresh_token:
            print(f"Refresh Token: {safe_display_token(tokens.refresh_token)}")

        print("\n💾 Tokens saved to secure storage")
        print(
            f"Storage Backend: {handler.token_manager.token_store.__class__.__name__}"
        )

        return 0

    except Exception as e:
        print(f"\n❌ Authentication failed: {e}")
        return 1


def cmd_get(server_name: str):
    """Get stored token for a server."""
    print_header(f"Token Information for {server_name}")

    token_manager = TokenManager()

    # Check if tokens exist
    if not token_manager.has_valid_tokens(server_name):
        print(f"❌ No valid tokens found for '{server_name}'")
        print("\nTip: Authenticate first with:")
        print(f"  uv run examples/oauth_cli.py auth {server_name} <server_url>")
        return 1

    # Load tokens
    tokens = token_manager.load_tokens(server_name)
    if not tokens:
        print(f"❌ Failed to load tokens for '{server_name}'")
        return 1

    # Display token information
    print(f"✅ Found valid tokens for '{server_name}'")
    print(f"\nAccess Token: {safe_display_token(tokens.access_token)}")
    print(f"Token Type: {tokens.token_type}")
    print(f"Expires In: {tokens.expires_in} seconds")

    if tokens.refresh_token:
        print(f"Refresh Token: {safe_display_token(tokens.refresh_token)}")

    if tokens.scope:
        print(f"Scopes: {tokens.scope}")

    # Check expiration
    is_expired = tokens.is_expired()
    print(f"\nStatus: {'❌ EXPIRED' if is_expired else '✅ VALID'}")

    # Show authorization header
    auth_header = tokens.get_authorization_header()
    print("\nAuthorization Header:")
    print(f"  {safe_display_token(auth_header, prefix_len=15, suffix_len=6)}")

    print(f"\n💾 Storage Backend: {token_manager.token_store.__class__.__name__}")

    return 0


def cmd_list():
    """List all servers with stored tokens."""
    print_header("Stored OAuth Tokens")

    token_manager = TokenManager()

    # Get list of stored servers
    # This is a bit of a hack since we don't have a direct API for this
    # We'll need to check the token directory
    try:
        if hasattr(token_manager.token_store, "token_dir"):
            token_dir = token_manager.token_store.token_dir
            if token_dir.exists():
                # Look for .enc files (encrypted tokens)
                token_files = list(token_dir.glob("*.enc"))

                if not token_files:
                    print("No stored tokens found.")
                    print("\nTip: Authenticate with:")
                    print(
                        "  uv run examples/oauth_cli.py auth <server_name> <server_url>"
                    )
                    return 0

                print(f"Found {len(token_files)} server(s) with stored tokens:\n")

                for token_file in sorted(token_files):
                    # Remove .enc extension to get server name
                    server_name = token_file.stem

                    # Try to load and check validity
                    has_valid = token_manager.has_valid_tokens(server_name)
                    tokens = token_manager.load_tokens(server_name)

                    status = "✅ VALID" if has_valid else "❌ EXPIRED/INVALID"

                    print(f"  • {server_name}")
                    print(f"    Status: {status}")

                    if tokens:
                        print(
                            f"    Token: {safe_display_token(tokens.access_token, prefix_len=15, suffix_len=4)}"
                        )
                        print(f"    Type: {tokens.token_type}")
                    print()

            else:
                print("No token directory found.")
                return 0

        elif hasattr(token_manager.token_store, "__class__"):
            # For keychain/other backends
            print(f"Storage Backend: {token_manager.token_store.__class__.__name__}")
            print("\nNote: This storage backend doesn't support listing all tokens.")
            print("Try: uv run examples/oauth_cli.py get <server_name>")
            return 0

    except Exception as e:
        print(f"❌ Error listing tokens: {e}")
        return 1

    print(f"💾 Storage Backend: {token_manager.token_store.__class__.__name__}")
    return 0


def cmd_clear(server_name: str):
    """Clear tokens for a server (local only, no server notification)."""
    print_header(f"Clearing Tokens for {server_name}")

    handler = OAuthHandler()

    # Check if tokens exist
    if not handler.token_manager.has_valid_tokens(server_name):
        print(f"⚠️  No tokens found for '{server_name}'")
        return 0

    # Clear tokens
    try:
        handler.clear_tokens(server_name)
        print(f"✅ Tokens cleared for '{server_name}'")
        print("   - Removed from memory cache")
        print("   - Removed from secure storage")
        print("\n⚠️  Note: Tokens were NOT revoked with server")
        print("   Server may still accept these tokens until they expire.")
        print("   Use 'logout' command to revoke tokens with server.")
        return 0

    except Exception as e:
        print(f"❌ Error clearing tokens: {e}")
        return 1


async def cmd_logout(server_name: str, server_url: Optional[str] = None):
    """Logout from a server (revokes tokens with server if URL provided)."""
    print_header(f"Logging Out from {server_name}")

    handler = OAuthHandler()

    # Check if tokens exist
    tokens = handler.token_manager.load_tokens(server_name)
    if not tokens:
        print(f"⚠️  No tokens found for '{server_name}'")
        print("Already logged out.")
        return 0

    print(f"Found tokens for '{server_name}'")

    # Try to logout with server revocation
    try:
        if server_url:
            print(f"\n🔄 Revoking tokens with server: {server_url}")
            await handler.logout(server_name, server_url)

            print(f"\n✅ Successfully logged out from '{server_name}'")
            print("   ✓ Tokens revoked with server")
            print("   ✓ Removed from memory cache")
            print("   ✓ Removed from secure storage")
            print("   ✓ Client registration deleted")
        else:
            # Just local cleanup
            await handler.logout(server_name)

            print(f"\n✅ Tokens cleared locally for '{server_name}'")
            print("   ✓ Removed from memory cache")
            print("   ✓ Removed from secure storage")
            print("\n⚠️  Server URL not provided")
            print("   Tokens were NOT revoked with server (will expire naturally).")
            print("\nTip: Include server URL to revoke with server:")
            print(
                f"  uv run examples/oauth_cli.py logout {server_name} --url <server_url>"
            )

        return 0

    except Exception as e:
        print(f"\n⚠️  Token revocation failed: {e}")
        print("   Tokens cleared locally but may still be valid on server.")
        return 1


async def cmd_test(server_name: str):
    """Test connection with stored tokens."""
    print_header(f"Testing Connection for {server_name}")

    handler = OAuthHandler()

    # Check if tokens exist
    if not handler.token_manager.has_valid_tokens(server_name):
        print(f"❌ No valid tokens found for '{server_name}'")
        print("\nTip: Authenticate first with:")
        print(f"  uv run examples/oauth_cli.py auth {server_name} <server_url>")
        return 1

    # Load tokens
    tokens = handler.token_manager.load_tokens(server_name)
    if not tokens:
        print(f"❌ Failed to load tokens for '{server_name}'")
        return 1

    print(f"✅ Found tokens for '{server_name}'")

    # Check expiration
    is_expired = tokens.is_expired()
    if is_expired:
        print("⚠️  Token is EXPIRED")
        print("\nTip: Re-authenticate with:")
        print(f"  uv run examples/oauth_cli.py auth {server_name} <server_url>")
        return 1

    print("✅ Token is VALID")
    print("\nToken Info:")
    print(f"  Access Token: {safe_display_token(tokens.access_token)}")
    print(f"  Type: {tokens.token_type}")
    print(f"  Expires In: {tokens.expires_in} seconds")

    # Get authorization header
    auth_header = tokens.get_authorization_header()
    print("\n📋 Authorization Header (ready to use):")
    print(f"  {safe_display_token(auth_header, prefix_len=15, suffix_len=6)}")

    print("\n✅ Connection test successful!")
    print("You can use this token for API requests.")

    return 0


async def cmd_tools(server_name: str, server_url: str):
    """List available tools from an MCP server."""
    print_header(f"Listing Tools for {server_name}")

    handler = OAuthHandler()

    try:
        # Step 1: Authenticate
        print("🔐 Authenticating...")
        await handler.ensure_authenticated_mcp(
            server_name=server_name, server_url=server_url
        )
        print("✅ Authenticated\n")

        # Step 2: Initialize MCP session
        print("📋 Initializing MCP session...")
        session_id = str(uuid.uuid4())

        init_payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"roots": {"listChanged": True}, "sampling": {}},
                "clientInfo": {"name": "chuk-oauth-cli", "version": "0.1.0"},
            },
        }

        init_response = await handler.authenticated_request(
            server_name=server_name,
            server_url=server_url,
            url=server_url,
            method="POST",
            json=init_payload,
            headers={
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
            },
            timeout=60.0,
        )

        # Parse init response
        content_type = init_response.headers.get("content-type", "")
        if content_type.startswith("text/event-stream"):
            session_id = init_response.headers.get("mcp-session-id", session_id)
            init_result = parse_sse_json(init_response.text.strip().splitlines())
        else:
            init_result = init_response.json()

        if "error" in init_result:
            print(f"❌ Initialize error: {init_result['error']}")
            return 1

        print(f"✅ Session initialized: {session_id[:8]}...\n")

        # Step 3: Send initialized notification
        print("📨 Sending initialized notification...")
        notify_payload = {"jsonrpc": "2.0", "method": "notifications/initialized"}

        await handler.authenticated_request(
            server_name=server_name,
            server_url=server_url,
            url=server_url,
            method="POST",
            json=notify_payload,
            headers={
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
                "Mcp-Session-Id": session_id,
            },
            timeout=30.0,
        )
        print("✅ Notification sent\n")

        # Step 4: List tools
        print("🔧 Listing available tools...")
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
            headers={
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
                "Mcp-Session-Id": session_id,
            },
            timeout=30.0,
        )

        # Parse tools response
        content_type = tools_response.headers.get("content-type", "")
        if content_type.startswith("text/event-stream"):
            data = parse_sse_json(tools_response.text.strip().splitlines())
        else:
            data = tools_response.json()

        if "result" in data and "tools" in data["result"]:
            tools = data["result"]["tools"]
            print(f"\n📦 Found {len(tools)} tools:\n")
            for tool in tools:
                print(f"   • {tool.get('name', 'Unknown')}")
                if "description" in tool:
                    desc = tool["description"]
                    print(f"     {desc[:80]}{'...' if len(desc) > 80 else ''}")
                print()
            return 0
        elif "error" in data:
            print(f"❌ JSON-RPC Error: {data['error']}")
            return 1
        else:
            print(f"⚠️  Unexpected response: {data}")
            return 1

    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback

        traceback.print_exc()
        return 1


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="OAuth Token Manager CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Using uvx (no installation required)
  uvx chuk-mcp-client-oauth auth notion-mcp https://mcp.notion.com/mcp
  uvx chuk-mcp-client-oauth tools notion-mcp https://mcp.notion.com/mcp
  uvx chuk-mcp-client-oauth list
  uvx chuk-mcp-client-oauth get notion-mcp
  uvx chuk-mcp-client-oauth test notion-mcp
  uvx chuk-mcp-client-oauth logout notion-mcp --url https://mcp.notion.com/mcp
  uvx chuk-mcp-client-oauth clear notion-mcp

  # Or after installation: chuk-oauth <command>
  chuk-oauth auth notion-mcp https://mcp.notion.com/mcp
  chuk-oauth tools notion-mcp https://mcp.notion.com/mcp
  chuk-oauth list
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Auth command
    auth_parser = subparsers.add_parser("auth", help="Authenticate with an MCP server")
    auth_parser.add_argument(
        "server_name", help="Name for the server (e.g., notion-mcp)"
    )
    auth_parser.add_argument("server_url", help="MCP server URL")
    auth_parser.add_argument(
        "--scopes", nargs="+", help="OAuth scopes (default: read write)"
    )

    # Get command
    get_parser = subparsers.add_parser("get", help="Get stored token for a server")
    get_parser.add_argument("server_name", help="Server name")

    # List command
    subparsers.add_parser("list", help="List all servers with stored tokens")

    # Clear command
    clear_parser = subparsers.add_parser(
        "clear", help="Clear tokens locally (no server notification)"
    )
    clear_parser.add_argument("server_name", help="Server name")

    # Logout command
    logout_parser = subparsers.add_parser(
        "logout", help="Logout (revoke tokens with server)"
    )
    logout_parser.add_argument("server_name", help="Server name")
    logout_parser.add_argument(
        "--url", dest="server_url", help="Server URL (required for token revocation)"
    )

    # Test command
    test_parser = subparsers.add_parser(
        "test", help="Test connection with stored tokens"
    )
    test_parser.add_argument("server_name", help="Server name")

    # Tools command
    tools_parser = subparsers.add_parser(
        "tools", help="List available tools from an MCP server"
    )
    tools_parser.add_argument("server_name", help="Server name")
    tools_parser.add_argument("server_url", help="MCP server URL")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    # Execute command
    try:
        if args.command == "auth":
            return asyncio.run(cmd_auth(args.server_name, args.server_url, args.scopes))
        elif args.command == "get":
            return cmd_get(args.server_name)
        elif args.command == "list":
            return cmd_list()
        elif args.command == "clear":
            return cmd_clear(args.server_name)
        elif args.command == "logout":
            return asyncio.run(cmd_logout(args.server_name, args.server_url))
        elif args.command == "test":
            return asyncio.run(cmd_test(args.server_name))
        elif args.command == "tools":
            return asyncio.run(cmd_tools(args.server_name, args.server_url))
        else:  # pragma: no cover
            # This should never be reached due to argparse validation
            parser.print_help()
            return 1

    except KeyboardInterrupt:
        print("\n\n❌ Interrupted by user")
        return 130
    except Exception as e:
        print(f"\n❌ Error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
