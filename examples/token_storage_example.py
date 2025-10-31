#!/usr/bin/env python3
"""
Example demonstrating different token storage backends.

This shows how to use various secure storage backends for OAuth tokens.
"""

import asyncio
from pathlib import Path
from chuk_mcp_client_oauth import TokenManager, TokenStoreBackend, OAuthTokens


def safe_display_token(token: str, prefix_len: int = 20, suffix_len: int = 6) -> str:
    """Safely display a token with most characters redacted."""
    if len(token) <= prefix_len + suffix_len:
        return f"{token[:10]}..."

    prefix = token[:prefix_len]
    suffix = token[-suffix_len:]
    redacted_len = len(token) - prefix_len - suffix_len

    return f"{prefix}...{'*' * min(redacted_len, 20)}...{suffix}"


def print_section(title: str):
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)


async def main():
    print_section("Token Storage Backend Examples")

    # Example tokens
    example_tokens = OAuthTokens(
        access_token="example_access_token_12345",
        token_type="Bearer",
        expires_in=3600,
        refresh_token="example_refresh_token_67890",
        scope="read write",
    )

    # Example 1: Auto-detection (platform-specific)
    print_section("Example 1: Auto Backend (Platform Detection)")

    auto_manager = TokenManager(backend=TokenStoreBackend.AUTO)
    print(f"Using backend: {auto_manager.token_store.__class__.__name__}")

    # Save tokens
    auto_manager.save_tokens("example-server", example_tokens)
    print("✅ Tokens saved")

    # Load tokens
    loaded = auto_manager.load_tokens("example-server")
    if loaded:
        print(f"✅ Tokens loaded: {safe_display_token(loaded.access_token)}")

    # Example 2: Encrypted File Storage
    print_section("Example 2: Encrypted File Storage")

    encrypted_manager = TokenManager(
        backend=TokenStoreBackend.ENCRYPTED_FILE,
        token_dir=Path.home() / ".chuk_oauth" / "tokens",
        password="my-secure-password-123",  # In production, use secure password management
    )
    print(f"Using backend: {encrypted_manager.token_store.__class__.__name__}")

    encrypted_manager.save_tokens("encrypted-server", example_tokens)
    print("✅ Tokens saved with encryption")

    loaded_encrypted = encrypted_manager.load_tokens("encrypted-server")
    if loaded_encrypted:
        print(
            f"✅ Encrypted tokens loaded: {safe_display_token(loaded_encrypted.access_token)}"
        )

    # Example 3: Keychain (macOS)
    print_section("Example 3: Keychain Storage (macOS)")

    try:
        keychain_manager = TokenManager(backend=TokenStoreBackend.KEYCHAIN)
        print(f"Using backend: {keychain_manager.token_store.__class__.__name__}")

        keychain_manager.save_tokens("keychain-server", example_tokens)
        print("✅ Tokens saved to Keychain")

        loaded_keychain = keychain_manager.load_tokens("keychain-server")
        if loaded_keychain:
            print(
                f"✅ Keychain tokens loaded: {safe_display_token(loaded_keychain.access_token)}"
            )
    except Exception as e:
        print(f"⚠️  Keychain not available: {e}")

    # Example 4: HashiCorp Vault
    print_section("Example 4: HashiCorp Vault (if configured)")

    try:
        vault_manager = TokenManager(
            backend=TokenStoreBackend.VAULT,
            vault_url="http://localhost:8200",
            vault_token="your-vault-token",
            vault_mount_point="secret",
            vault_path_prefix="mcp-oauth",
        )
        print(f"Using backend: {vault_manager.token_store.__class__.__name__}")

        vault_manager.save_tokens("vault-server", example_tokens)
        print("✅ Tokens saved to Vault")

        loaded_vault = vault_manager.load_tokens("vault-server")
        if loaded_vault:
            print(
                f"✅ Vault tokens loaded: {safe_display_token(loaded_vault.access_token)}"
            )
    except Exception as e:
        print(f"⚠️  Vault not available: {e}")

    # Example 5: Token Operations
    print_section("Example 5: Token Operations")

    manager = TokenManager(backend=TokenStoreBackend.AUTO)

    # Check if tokens exist and are valid
    has_valid = manager.has_valid_tokens("example-server")
    print(f"Has valid tokens: {has_valid}")

    # Check expiration
    tokens = manager.load_tokens("example-server")
    if tokens:
        is_expired = tokens.is_expired()
        print(f"Tokens expired: {is_expired}")

    # Delete tokens
    print("\n🗑️  Deleting tokens...")
    deleted = manager.delete_tokens("example-server")
    print(f"✅ Tokens deleted: {deleted}")

    # Clean up examples
    print("\nCleaning up...")
    encrypted_manager.delete_tokens("encrypted-server")
    try:
        keychain_manager.delete_tokens("keychain-server")
    except Exception:
        pass
    print("✅ Cleanup complete")


if __name__ == "__main__":
    asyncio.run(main())
