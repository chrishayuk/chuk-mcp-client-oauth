"""Tests for OAuthHandler."""

from unittest.mock import AsyncMock, patch

import pytest

from chuk_mcp_client_oauth.oauth_config import OAuthConfig, OAuthTokens
from chuk_mcp_client_oauth.oauth_handler import OAuthHandler
from chuk_mcp_client_oauth.token_manager import TokenManager
from chuk_mcp_client_oauth.token_store_factory import TokenStoreBackend


class TestOAuthHandler:
    """Test OAuthHandler functionality."""

    @pytest.fixture
    def token_manager(self, tmp_path):
        """Provide a TokenManager instance."""
        return TokenManager(
            backend=TokenStoreBackend.ENCRYPTED_FILE,
            token_dir=tmp_path / "tokens",
            password="test-password",
        )

    @pytest.fixture
    def handler(self, token_manager):
        """Provide an OAuthHandler instance."""
        return OAuthHandler(token_manager=token_manager)

    @pytest.fixture
    def valid_tokens(self):
        """Provide valid OAuth tokens."""
        return OAuthTokens(
            access_token="test_access_token",
            token_type="Bearer",
            expires_in=3600,
            refresh_token="test_refresh_token",
        )

    @pytest.fixture
    def oauth_config(self):
        """Provide OAuth configuration."""
        return OAuthConfig(
            authorization_url="https://example.com/oauth/authorize",
            token_url="https://example.com/oauth/token",
            client_id="test_client_id",
            client_secret="test_client_secret",
            scopes=["read", "write"],
        )

    def test_init_with_default_token_manager(self):
        """Test initialization with default token manager."""
        handler = OAuthHandler()
        assert handler.token_manager is not None
        assert isinstance(handler.token_manager, TokenManager)
        assert handler._active_tokens == {}

    def test_init_with_custom_token_manager(self, token_manager):
        """Test initialization with custom token manager."""
        handler = OAuthHandler(token_manager=token_manager)
        assert handler.token_manager is token_manager
        assert handler._active_tokens == {}

    async def test_ensure_authenticated_mcp_with_cached_tokens(
        self, handler, valid_tokens
    ):
        """Test MCP authentication with cached tokens in memory."""
        server_name = "test-server"
        handler._active_tokens[server_name] = valid_tokens

        tokens = await handler.ensure_authenticated_mcp(
            server_name=server_name, server_url="https://example.com/mcp"
        )

        assert tokens == valid_tokens

    async def test_ensure_authenticated_mcp_with_stored_tokens(
        self, handler, valid_tokens
    ):
        """Test MCP authentication with stored tokens on disk."""
        server_name = "test-server"
        handler.token_manager.save_tokens(server_name, valid_tokens)

        tokens = await handler.ensure_authenticated_mcp(
            server_name=server_name, server_url="https://example.com/mcp"
        )

        assert tokens.access_token == valid_tokens.access_token
        assert server_name in handler._active_tokens

    async def test_ensure_authenticated_mcp_full_flow(self, handler):
        """Test MCP authentication with full OAuth flow."""
        server_name = "test-server"
        server_url = "https://example.com/mcp"

        mock_tokens = OAuthTokens(
            access_token="new_token", token_type="Bearer", expires_in=3600
        )

        with patch(
            "chuk_mcp_client_oauth.oauth_handler.MCPOAuthClient"
        ) as mock_client_class:
            mock_client = AsyncMock()
            mock_client.authorize = AsyncMock(return_value=mock_tokens)
            mock_client._client_registration = None
            mock_client_class.return_value = mock_client

            tokens = await handler.ensure_authenticated_mcp(
                server_name=server_name, server_url=server_url
            )

            # Compare just the access tokens since issued_at timestamps differ
            assert tokens.access_token == mock_tokens.access_token
            assert server_name in handler._active_tokens
            mock_client.authorize.assert_called_once()

    async def test_ensure_authenticated_mcp_with_refresh(self, handler, valid_tokens):
        """Test MCP authentication with token refresh."""
        server_name = "test-server"
        server_url = "https://example.com/mcp"

        # Store expired tokens
        expired_tokens = OAuthTokens(
            access_token="expired_token",
            token_type="Bearer",
            expires_in=-1,  # Already expired
            refresh_token="refresh_token",
        )
        handler.token_manager.save_tokens(server_name, expired_tokens)

        refreshed_tokens = OAuthTokens(
            access_token="refreshed_token",
            token_type="Bearer",
            expires_in=3600,
            refresh_token="new_refresh_token",
        )

        with patch(
            "chuk_mcp_client_oauth.oauth_handler.MCPOAuthClient"
        ) as mock_client_class:
            mock_client = AsyncMock()
            mock_client.discover_authorization_server = AsyncMock()
            mock_client.refresh_token = AsyncMock(return_value=refreshed_tokens)
            mock_client._client_registration = None
            mock_client_class.return_value = mock_client

            tokens = await handler.ensure_authenticated_mcp(
                server_name=server_name, server_url=server_url
            )

            assert tokens.access_token == refreshed_tokens.access_token
            assert server_name in handler._active_tokens
            mock_client.refresh_token.assert_called_once_with("refresh_token")

    async def test_ensure_authenticated_mcp_refresh_fails_full_flow(
        self, handler, valid_tokens
    ):
        """Test MCP authentication when refresh fails, falls back to full flow."""
        server_name = "test-server"
        server_url = "https://example.com/mcp"

        # Store expired tokens
        expired_tokens = OAuthTokens(
            access_token="expired_token",
            token_type="Bearer",
            expires_in=-1,
            refresh_token="refresh_token",
        )
        handler.token_manager.save_tokens(server_name, expired_tokens)

        new_tokens = OAuthTokens(
            access_token="new_token", token_type="Bearer", expires_in=3600
        )

        with patch(
            "chuk_mcp_client_oauth.oauth_handler.MCPOAuthClient"
        ) as mock_client_class:
            mock_client = AsyncMock()
            mock_client.discover_authorization_server = AsyncMock()
            mock_client.refresh_token = AsyncMock(
                side_effect=Exception("Refresh failed")
            )
            mock_client.authorize = AsyncMock(return_value=new_tokens)
            mock_client._client_registration = None
            mock_client_class.return_value = mock_client

            tokens = await handler.ensure_authenticated_mcp(
                server_name=server_name, server_url=server_url
            )

            assert tokens.access_token == new_tokens.access_token
            mock_client.authorize.assert_called_once()

    async def test_ensure_authenticated_with_cached_tokens(
        self, handler, valid_tokens, oauth_config
    ):
        """Test legacy authentication with cached tokens."""
        server_name = "test-server"
        handler._active_tokens[server_name] = valid_tokens

        tokens = await handler.ensure_authenticated(
            server_name=server_name, oauth_config=oauth_config
        )

        assert tokens == valid_tokens

    async def test_ensure_authenticated_with_stored_tokens(
        self, handler, valid_tokens, oauth_config
    ):
        """Test legacy authentication with stored tokens."""
        server_name = "test-server"
        handler.token_manager.save_tokens(server_name, valid_tokens)

        tokens = await handler.ensure_authenticated(
            server_name=server_name, oauth_config=oauth_config
        )

        assert tokens.access_token == valid_tokens.access_token
        assert server_name in handler._active_tokens

    async def test_ensure_authenticated_with_refresh(
        self, handler, valid_tokens, oauth_config
    ):
        """Test legacy authentication with token refresh."""
        server_name = "test-server"

        # Store expired tokens
        expired_tokens = OAuthTokens(
            access_token="expired_token",
            token_type="Bearer",
            expires_in=-1,
            refresh_token="refresh_token",
        )
        handler.token_manager.save_tokens(server_name, expired_tokens)

        refreshed_tokens = OAuthTokens(
            access_token="refreshed_token",
            token_type="Bearer",
            expires_in=3600,
            refresh_token="new_refresh_token",
        )

        with patch("chuk_mcp_client_oauth.oauth_handler.OAuthFlow") as mock_flow_class:
            mock_flow = AsyncMock()
            mock_flow.refresh_token = AsyncMock(return_value=refreshed_tokens)
            mock_flow_class.return_value = mock_flow

            tokens = await handler.ensure_authenticated(
                server_name=server_name, oauth_config=oauth_config
            )

            assert tokens.access_token == refreshed_tokens.access_token
            assert server_name in handler._active_tokens
            mock_flow.refresh_token.assert_called_once_with("refresh_token")

    async def test_ensure_authenticated_full_flow(self, handler, oauth_config):
        """Test legacy authentication with full OAuth flow."""
        server_name = "test-server"

        new_tokens = OAuthTokens(
            access_token="new_token", token_type="Bearer", expires_in=3600
        )

        with patch("chuk_mcp_client_oauth.oauth_handler.OAuthFlow") as mock_flow_class:
            mock_flow = AsyncMock()
            mock_flow.authorize = AsyncMock(return_value=new_tokens)
            mock_flow_class.return_value = mock_flow

            tokens = await handler.ensure_authenticated(
                server_name=server_name, oauth_config=oauth_config
            )

            assert tokens.access_token == new_tokens.access_token
            assert server_name in handler._active_tokens
            mock_flow.authorize.assert_called_once()

    async def test_ensure_authenticated_refresh_fails(self, handler, oauth_config):
        """Test legacy authentication when refresh fails."""
        server_name = "test-server"

        # Store expired tokens
        expired_tokens = OAuthTokens(
            access_token="expired_token",
            token_type="Bearer",
            expires_in=-1,
            refresh_token="refresh_token",
        )
        handler.token_manager.save_tokens(server_name, expired_tokens)

        new_tokens = OAuthTokens(
            access_token="new_token", token_type="Bearer", expires_in=3600
        )

        with patch("chuk_mcp_client_oauth.oauth_handler.OAuthFlow") as mock_flow_class:
            mock_flow = AsyncMock()
            mock_flow.refresh_token = AsyncMock(side_effect=Exception("Refresh failed"))
            mock_flow.authorize = AsyncMock(return_value=new_tokens)
            mock_flow_class.return_value = mock_flow

            tokens = await handler.ensure_authenticated(
                server_name=server_name, oauth_config=oauth_config
            )

            assert tokens == new_tokens
            mock_flow.authorize.assert_called_once()

    def test_get_authorization_header_with_tokens(self, handler, valid_tokens):
        """Test getting authorization header when tokens exist."""
        server_name = "test-server"
        handler._active_tokens[server_name] = valid_tokens

        header = handler.get_authorization_header(server_name)

        assert header == "Bearer test_access_token"

    def test_get_authorization_header_without_tokens(self, handler):
        """Test getting authorization header when no tokens exist."""
        header = handler.get_authorization_header("nonexistent-server")
        assert header is None

    def test_clear_tokens_from_memory_and_disk(self, handler, valid_tokens):
        """Test clearing tokens from both memory and disk."""
        server_name = "test-server"
        handler._active_tokens[server_name] = valid_tokens
        handler.token_manager.save_tokens(server_name, valid_tokens)

        # Verify tokens exist
        assert server_name in handler._active_tokens
        assert handler.token_manager.has_valid_tokens(server_name)

        # Clear tokens
        handler.clear_tokens(server_name)

        # Verify tokens are cleared
        assert server_name not in handler._active_tokens
        assert not handler.token_manager.has_valid_tokens(server_name)

    def test_clear_tokens_nonexistent_server(self, handler):
        """Test clearing tokens for a server that doesn't exist."""
        # Should not raise an exception
        handler.clear_tokens("nonexistent-server")

    async def test_prepare_headers_for_mcp_server(self, handler):
        """Test preparing headers for MCP server."""
        server_name = "test-server"
        server_url = "https://example.com/mcp"

        mock_tokens = OAuthTokens(
            access_token="test_token", token_type="Bearer", expires_in=3600
        )

        with patch(
            "chuk_mcp_client_oauth.oauth_handler.MCPOAuthClient"
        ) as mock_client_class:
            mock_client = AsyncMock()
            mock_client.authorize = AsyncMock(return_value=mock_tokens)
            mock_client._client_registration = None
            mock_client_class.return_value = mock_client

            headers = await handler.prepare_headers_for_mcp_server(
                server_name=server_name,
                server_url=server_url,
                scopes=["read"],
                extra_headers={"X-Custom": "value"},
            )

            assert headers["Authorization"] == "Bearer test_token"
            assert headers["X-Custom"] == "value"

    async def test_prepare_headers_for_mcp_server_auth_failure(self, handler):
        """Test preparing headers when authentication fails."""
        server_name = "test-server"
        server_url = "https://example.com/mcp"

        with patch.object(
            handler, "ensure_authenticated_mcp", side_effect=Exception("Auth failed")
        ):
            with pytest.raises(Exception, match="Auth failed"):
                await handler.prepare_headers_for_mcp_server(
                    server_name=server_name, server_url=server_url
                )

    async def test_prepare_headers_with_oauth_config(self, handler, oauth_config):
        """Test preparing headers with OAuth config."""
        server_name = "test-server"

        mock_tokens = OAuthTokens(
            access_token="test_token", token_type="Bearer", expires_in=3600
        )

        with patch("chuk_mcp_client_oauth.oauth_handler.OAuthFlow") as mock_flow_class:
            mock_flow = AsyncMock()
            mock_flow.authorize = AsyncMock(return_value=mock_tokens)
            mock_flow_class.return_value = mock_flow

            headers = await handler.prepare_headers_with_oauth_config(
                server_name=server_name,
                oauth_config=oauth_config,
                extra_headers={"X-Custom": "value"},
            )

            assert headers["Authorization"] == "Bearer test_token"
            assert headers["X-Custom"] == "value"

    async def test_prepare_headers_with_oauth_config_auth_failure(
        self, handler, oauth_config
    ):
        """Test preparing headers when authentication fails."""
        server_name = "test-server"

        with patch.object(
            handler, "ensure_authenticated", side_effect=Exception("Auth failed")
        ):
            with pytest.raises(Exception, match="Auth failed"):
                await handler.prepare_headers_with_oauth_config(
                    server_name=server_name, oauth_config=oauth_config
                )

    async def test_mcp_with_stored_client_registration(self, handler):
        """Test MCP authentication with stored client registration."""
        server_name = "test-server"
        server_url = "https://example.com/mcp"

        # Store a client registration
        from chuk_mcp_client_oauth.mcp_oauth import DynamicClientRegistration

        registration = DynamicClientRegistration(
            client_id="stored_client_id",
            client_secret="stored_client_secret",
        )
        handler.token_manager.save_client_registration(server_name, registration)

        mock_tokens = OAuthTokens(
            access_token="test_token", token_type="Bearer", expires_in=3600
        )

        with patch(
            "chuk_mcp_client_oauth.oauth_handler.MCPOAuthClient"
        ) as mock_client_class:
            mock_client = AsyncMock()
            mock_client.authorize = AsyncMock(return_value=mock_tokens)
            mock_client._client_registration = registration
            mock_client_class.return_value = mock_client

            tokens = await handler.ensure_authenticated_mcp(
                server_name=server_name, server_url=server_url
            )

            assert tokens.access_token == mock_tokens.access_token
            # Verify client registration was loaded
            assert mock_client._client_registration == registration
