# chuk_mcp_client_oauth/token_manager.py
"""Token storage and management."""

import json
import os
from pathlib import Path
from typing import Any, Optional, TYPE_CHECKING

from .oauth_config import OAuthTokens
from .secure_token_store import SecureTokenStore
from .token_store_factory import TokenStoreBackend, TokenStoreFactory
from .token_registry import TokenRegistry

if TYPE_CHECKING:
    from .mcp_oauth import DynamicClientRegistration


class TokenManager:
    """Manages OAuth token storage and retrieval using secure backends."""

    def __init__(
        self,
        token_dir: Optional[Path] = None,
        backend: TokenStoreBackend = TokenStoreBackend.AUTO,
        password: Optional[str] = None,
        namespace: str = "oauth",
        backend_config: Optional[dict] = None,
    ):
        """
        Initialize token manager with secure storage backend.

        Args:
            token_dir: Directory for file-based storage (default: ~/.chuk_oauth/tokens)
            backend: Storage backend to use (default: AUTO for auto-detection)
            password: Password for encrypted file storage
            namespace: Namespace for token registry (default: "oauth")
            backend_config: Backend-specific configuration dict (e.g., Vault settings)
                           Example for Vault:
                           {
                               "vault_url": "https://vault.example.com",
                               "vault_token": "token",
                               "vault_mount_point": "secret",
                               "vault_namespace": "enterprise-ns"
                           }
        """
        if token_dir is None:
            token_dir = Path.home() / ".chuk_oauth" / "tokens"

        self.token_dir = token_dir
        self.namespace = namespace

        # Build backend configuration
        store_kwargs: dict[str, Any] = {
            "backend": backend,
            "token_dir": token_dir,
            "password": password,
        }

        # Add backend-specific config
        if backend_config:
            store_kwargs.update(backend_config)

        # Set default vault_path_prefix derived from namespace if using Vault
        if (
            backend == TokenStoreBackend.VAULT
            and "vault_path_prefix" not in store_kwargs
        ):
            store_kwargs["vault_path_prefix"] = f"{namespace}/oauth"

        # Create secure token store
        self.token_store: SecureTokenStore = TokenStoreFactory.create(**store_kwargs)  # type: ignore[arg-type]

        # Create token registry for tracking
        self.registry = TokenRegistry()

        # Keep file-based storage for client registration (less sensitive)
        self.token_dir.mkdir(parents=True, exist_ok=True)

    def _sanitize_name(self, server_name: str) -> str:
        """Sanitize server name for filesystem."""
        return "".join(c if c.isalnum() or c in "-_" else "_" for c in server_name)

    def _get_token_path(self, server_name: str) -> Path:
        """Get path to token file for a server."""
        safe_name = self._sanitize_name(server_name)
        return self.token_dir / f"{safe_name}.json"

    def _get_client_registration_path(self, server_name: str) -> Path:
        """Get path to client registration file for a server."""
        safe_name = self._sanitize_name(server_name)
        return self.token_dir / f"{safe_name}_client.json"

    def save_tokens(self, server_name: str, tokens: OAuthTokens) -> None:
        """
        Save tokens for a server using secure storage.

        Args:
            server_name: Name of the MCP server
            tokens: OAuth tokens to save
        """
        from .token_types import TokenType

        self.token_store.store_token(server_name, tokens)

        # Register in token registry for listing
        metadata = {}
        if tokens.expires_in:
            # Calculate expiration timestamp
            import time

            if tokens.issued_at:
                metadata["expires_at"] = tokens.issued_at + tokens.expires_in
            else:
                metadata["expires_at"] = time.time() + tokens.expires_in

        self.registry.register(
            server_name, TokenType.OAUTH, self.namespace, metadata=metadata
        )

    def load_tokens(self, server_name: str) -> Optional[OAuthTokens]:
        """
        Load tokens for a server from secure storage.

        Args:
            server_name: Name of the MCP server

        Returns:
            OAuth tokens if found, None otherwise
        """
        return self.token_store.retrieve_token(server_name)

    def delete_tokens(self, server_name: str) -> bool:
        """
        Delete tokens for a server from secure storage.

        Args:
            server_name: Name of the MCP server

        Returns:
            True if tokens were deleted, False if they didn't exist
        """
        result = self.token_store.delete_token(server_name)

        # Unregister from token registry
        if result:
            self.registry.unregister(server_name, "oauth")

        return result

    def has_valid_tokens(self, server_name: str) -> bool:
        """
        Check if valid tokens exist for a server.

        Args:
            server_name: Name of the MCP server

        Returns:
            True if valid (non-expired) tokens exist
        """
        tokens = self.load_tokens(server_name)
        if tokens is None:
            return False
        return not tokens.is_expired()

    def save_client_registration(
        self, server_name: str, registration: "DynamicClientRegistration"
    ) -> None:
        """
        Save OAuth client registration for a server.

        Args:
            server_name: Name of the MCP server
            registration: Client registration to save
        """
        reg_path = self._get_client_registration_path(server_name)

        with open(reg_path, "w") as f:
            json.dump(registration.model_dump(), f, indent=2)

        # Set file permissions to user-only read/write
        os.chmod(reg_path, 0o600)

    def load_client_registration(
        self, server_name: str
    ) -> Optional["DynamicClientRegistration"]:
        """
        Load OAuth client registration for a server.

        Args:
            server_name: Name of the MCP server

        Returns:
            Client registration if found, None otherwise
        """
        from .mcp_oauth import DynamicClientRegistration

        reg_path = self._get_client_registration_path(server_name)

        if not reg_path.exists():
            return None

        try:
            with open(reg_path, "r") as f:
                reg_data = json.load(f)
            return DynamicClientRegistration.model_validate(reg_data)
        except (json.JSONDecodeError, KeyError, FileNotFoundError):
            return None

    def delete_client_registration(self, server_name: str) -> bool:
        """
        Delete OAuth client registration for a server.

        Args:
            server_name: Name of the MCP server

        Returns:
            True if registration was deleted, False if it didn't exist
        """
        reg_path = self._get_client_registration_path(server_name)

        if reg_path.exists():
            reg_path.unlink()
            return True
        return False
