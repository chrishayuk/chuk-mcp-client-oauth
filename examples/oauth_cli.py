#!/usr/bin/env python3
"""
Simple CLI tool for managing OAuth tokens.

This tool makes it easy to:
- Authenticate with MCP servers
- View stored tokens (safely redacted)
- Clear tokens
- List all servers with tokens
- Test connections

Usage:
    uv run examples/oauth_cli.py auth <server_name> <server_url>
    uv run examples/oauth_cli.py get <server_name>
    uv run examples/oauth_cli.py list
    uv run examples/oauth_cli.py clear <server_name>
    uv run examples/oauth_cli.py test <server_name>
"""

import argparse
import asyncio
import sys
from typing import Optional

from chuk_mcp_client_oauth import OAuthHandler, TokenManager


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
    """Clear tokens for a server."""
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
        return 0

    except Exception as e:
        print(f"❌ Error clearing tokens: {e}")
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


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="OAuth Token Manager CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Authenticate with Notion MCP
  uv run examples/oauth_cli.py auth notion-mcp https://mcp.notion.com/mcp

  # Get token for a server
  uv run examples/oauth_cli.py get notion-mcp

  # List all stored tokens
  uv run examples/oauth_cli.py list

  # Test connection
  uv run examples/oauth_cli.py test notion-mcp

  # Clear tokens
  uv run examples/oauth_cli.py clear notion-mcp
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
    clear_parser = subparsers.add_parser("clear", help="Clear tokens for a server")
    clear_parser.add_argument("server_name", help="Server name")

    # Test command
    test_parser = subparsers.add_parser(
        "test", help="Test connection with stored tokens"
    )
    test_parser.add_argument("server_name", help="Server name")

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
        elif args.command == "test":
            return asyncio.run(cmd_test(args.server_name))
        else:
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
