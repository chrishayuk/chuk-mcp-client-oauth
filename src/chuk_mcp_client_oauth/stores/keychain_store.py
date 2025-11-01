# chuk_mcp_client_oauth/stores/keychain_store.py
"""macOS Keychain token storage backend."""

import json
import platform
from typing import Optional

from chuk_mcp_client_oauth.oauth_config import OAuthTokens
from chuk_mcp_client_oauth.secure_token_store import SecureTokenStore, TokenStorageError


class KeychainTokenStore(SecureTokenStore):
    """Token storage using macOS Keychain."""

    DEFAULT_SERVICE_NAME = "chuk-oauth"

    def __init__(self, service_name: Optional[str] = None):
        """
        Initialize Keychain token store.

        Args:
            service_name: Custom service name for keychain entries (default: "chuk-oauth")
        """
        if platform.system() != "Darwin":
            raise TokenStorageError("Keychain storage is only available on macOS")

        self.service_name = service_name or self.DEFAULT_SERVICE_NAME

        try:
            import keyring

            self.keyring = keyring
        except ImportError:
            raise TokenStorageError(
                "keyring library not installed. Install with: pip install keyring"
            )

    def store_token(self, server_name: str, tokens: OAuthTokens) -> None:
        """Store tokens in macOS Keychain."""
        try:
            safe_name = self._sanitize_name(server_name)

            # Add issued_at timestamp if not present
            if tokens.issued_at is None:
                import time

                tokens.issued_at = time.time()

            # Serialize tokens to JSON
            token_json = json.dumps(tokens.model_dump())

            # Store in Keychain
            self.keyring.set_password(self.service_name, safe_name, token_json)
        except Exception as e:
            raise TokenStorageError(f"Failed to store token in Keychain: {e}")

    def retrieve_token(self, server_name: str) -> Optional[OAuthTokens]:
        """Retrieve tokens from macOS Keychain."""
        try:
            safe_name = self._sanitize_name(server_name)

            # Retrieve from Keychain
            token_json = self.keyring.get_password(self.service_name, safe_name)

            if token_json is None:
                return None

            # Deserialize from JSON
            token_data = json.loads(token_json)
            return OAuthTokens.model_validate(token_data)
        except json.JSONDecodeError as e:
            raise TokenStorageError(f"Failed to parse token data: {e}")
        except Exception as e:
            raise TokenStorageError(f"Failed to retrieve token from Keychain: {e}")

    def delete_token(self, server_name: str) -> bool:
        """Delete tokens from macOS Keychain."""
        try:
            safe_name = self._sanitize_name(server_name)

            # Check if token exists
            if self.keyring.get_password(self.service_name, safe_name) is None:
                return False

            # Delete from Keychain
            self.keyring.delete_password(self.service_name, safe_name)
            return True
        except Exception as e:
            raise TokenStorageError(f"Failed to delete token from Keychain: {e}")

    def has_token(self, server_name: str) -> bool:
        """Check if tokens exist in macOS Keychain."""
        try:
            safe_name = self._sanitize_name(server_name)
            return self.keyring.get_password(self.service_name, safe_name) is not None
        except Exception:
            return False

    # Raw storage methods for generic tokens

    def _store_raw(self, key: str, value: str) -> None:
        """Store raw string value in Keychain."""
        try:
            safe_key = self._sanitize_name(key)
            self.keyring.set_password(self.service_name, safe_key, value)
        except Exception as e:
            raise TokenStorageError(f"Failed to store value in Keychain: {e}")

    def _retrieve_raw(self, key: str) -> Optional[str]:
        """Retrieve raw string value from Keychain."""
        try:
            safe_key = self._sanitize_name(key)
            result = self.keyring.get_password(self.service_name, safe_key)
            return str(result) if result is not None else None
        except Exception as e:
            raise TokenStorageError(f"Failed to retrieve value from Keychain: {e}")

    def _delete_raw(self, key: str) -> bool:
        """Delete raw value from Keychain."""
        try:
            safe_key = self._sanitize_name(key)
            if self.keyring.get_password(self.service_name, safe_key) is None:
                return False
            self.keyring.delete_password(self.service_name, safe_key)
            return True
        except Exception as e:
            raise TokenStorageError(f"Failed to delete value from Keychain: {e}")
