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

    async def test_logout_with_server_url(self, handler, valid_tokens):
        """Test logout with server URL (token revocation)."""
        server_name = "test-server"
        server_url = "https://example.com/mcp"

        # Store tokens and registration
        handler.token_manager.save_tokens(server_name, valid_tokens)
        handler._active_tokens[server_name] = valid_tokens

        from chuk_mcp_client_oauth.mcp_oauth import DynamicClientRegistration

        registration = DynamicClientRegistration(client_id="test-client")
        handler.token_manager.save_client_registration(server_name, registration)

        with patch(
            "chuk_mcp_client_oauth.oauth_handler.MCPOAuthClient"
        ) as mock_client_class:
            mock_client = AsyncMock()
            mock_client.discover_authorization_server = AsyncMock()
            mock_client.revoke_token = AsyncMock(return_value=True)
            mock_client._client_registration = registration
            mock_client_class.return_value = mock_client

            await handler.logout(server_name, server_url)

            # Verify revoke_token was called for both tokens
            assert mock_client.revoke_token.call_count == 2
            calls = mock_client.revoke_token.call_args_list
            # First call should be refresh token
            assert calls[0][0][0] == "test_refresh_token"
            assert calls[0][1]["token_type_hint"] == "refresh_token"
            # Second call should be access token
            assert calls[1][0][0] == "test_access_token"
            assert calls[1][1]["token_type_hint"] == "access_token"

            # Verify tokens cleared from memory and disk
            assert server_name not in handler._active_tokens
            assert not handler.token_manager.has_valid_tokens(server_name)
            # Verify registration deleted
            assert handler.token_manager.load_client_registration(server_name) is None

    async def test_logout_without_server_url(self, handler, valid_tokens):
        """Test logout without server URL (local cleanup only)."""
        server_name = "test-server"

        # Store tokens
        handler.token_manager.save_tokens(server_name, valid_tokens)
        handler._active_tokens[server_name] = valid_tokens

        await handler.logout(server_name)

        # Verify tokens cleared locally
        assert server_name not in handler._active_tokens
        assert not handler.token_manager.has_valid_tokens(server_name)

    async def test_logout_with_revocation_failure(self, handler, valid_tokens):
        """Test logout when token revocation fails."""
        server_name = "test-server"
        server_url = "https://example.com/mcp"

        # Store tokens
        handler.token_manager.save_tokens(server_name, valid_tokens)

        with patch(
            "chuk_mcp_client_oauth.oauth_handler.MCPOAuthClient"
        ) as mock_client_class:
            mock_client = AsyncMock()
            mock_client.discover_authorization_server = AsyncMock()
            mock_client.revoke_token = AsyncMock(
                side_effect=Exception("Revocation failed")
            )
            mock_client._client_registration = None
            mock_client_class.return_value = mock_client

            # Should not raise, just clear locally
            await handler.logout(server_name, server_url)

            # Verify tokens still cleared locally
            assert server_name not in handler._active_tokens
            assert not handler.token_manager.has_valid_tokens(server_name)

    async def test_logout_nonexistent_tokens(self, handler):
        """Test logout when no tokens exist."""
        server_name = "nonexistent-server"

        # Should not raise
        await handler.logout(server_name)

        # Should still be no tokens
        assert server_name not in handler._active_tokens
        assert not handler.token_manager.has_valid_tokens(server_name)

    async def test_logout_tokens_only_in_memory(self, handler, valid_tokens):
        """Test logout with tokens only in memory cache."""
        server_name = "test-server"
        server_url = "https://example.com/mcp"

        # Only in memory, not on disk
        handler._active_tokens[server_name] = valid_tokens

        with patch(
            "chuk_mcp_client_oauth.oauth_handler.MCPOAuthClient"
        ) as mock_client_class:
            mock_client = AsyncMock()
            mock_client.discover_authorization_server = AsyncMock()
            mock_client.revoke_token = AsyncMock(return_value=True)
            mock_client._client_registration = None
            mock_client_class.return_value = mock_client

            await handler.logout(server_name, server_url)

            # Verify revocation was attempted
            assert mock_client.revoke_token.called
            # Verify cleared from memory
            assert server_name not in handler._active_tokens

    async def test_logout_tokens_only_on_disk(self, handler, valid_tokens):
        """Test logout with tokens only on disk."""
        server_name = "test-server"
        server_url = "https://example.com/mcp"

        # Only on disk, not in memory
        handler.token_manager.save_tokens(server_name, valid_tokens)

        with patch(
            "chuk_mcp_client_oauth.oauth_handler.MCPOAuthClient"
        ) as mock_client_class:
            mock_client = AsyncMock()
            mock_client.discover_authorization_server = AsyncMock()
            mock_client.revoke_token = AsyncMock(return_value=True)
            mock_client._client_registration = None
            mock_client_class.return_value = mock_client

            await handler.logout(server_name, server_url)

            # Verify revocation was attempted
            assert mock_client.revoke_token.called
            # Verify cleared from disk
            assert not handler.token_manager.has_valid_tokens(server_name)

    async def test_logout_without_refresh_token(self, handler):
        """Test logout when tokens don't have refresh token."""
        server_name = "test-server"
        server_url = "https://example.com/mcp"

        # Tokens without refresh token
        tokens_no_refresh = OAuthTokens(
            access_token="test_access_token",
            token_type="Bearer",
            expires_in=3600,
            refresh_token=None,
        )
        handler.token_manager.save_tokens(server_name, tokens_no_refresh)

        with patch(
            "chuk_mcp_client_oauth.oauth_handler.MCPOAuthClient"
        ) as mock_client_class:
            mock_client = AsyncMock()
            mock_client.discover_authorization_server = AsyncMock()
            mock_client.revoke_token = AsyncMock(return_value=True)
            mock_client._client_registration = None
            mock_client_class.return_value = mock_client

            await handler.logout(server_name, server_url)

            # Should only revoke access token (no refresh token)
            assert mock_client.revoke_token.call_count == 1
            call_args = mock_client.revoke_token.call_args
            assert call_args[0][0] == "test_access_token"
            assert call_args[1]["token_type_hint"] == "access_token"

    async def test_logout_discovery_fails(self, handler, valid_tokens):
        """Test logout when authorization server discovery fails."""
        server_name = "test-server"
        server_url = "https://example.com/mcp"

        handler.token_manager.save_tokens(server_name, valid_tokens)

        with patch(
            "chuk_mcp_client_oauth.oauth_handler.MCPOAuthClient"
        ) as mock_client_class:
            mock_client = AsyncMock()
            mock_client.discover_authorization_server = AsyncMock(
                side_effect=Exception("Discovery failed")
            )
            mock_client_class.return_value = mock_client

            # Should not raise, just clear locally
            await handler.logout(server_name, server_url)

            # Verify tokens still cleared
            assert not handler.token_manager.has_valid_tokens(server_name)

    async def test_prepare_server_headers_remote_mcp(self, handler):
        """Test prepare_server_headers with remote MCP server."""
        from unittest.mock import Mock

        # Create mock server config for remote MCP server (has URL, no command)
        server_config = Mock()
        server_config.name = "test-server"
        server_config.url = "https://example.com/mcp"
        server_config.command = None
        server_config.oauth = None

        with patch.object(
            handler, "prepare_headers_for_mcp_server", new_callable=AsyncMock
        ) as mock_prepare:
            mock_prepare.return_value = {"Authorization": "Bearer test_token"}

            headers = await handler.prepare_server_headers(
                server_config, extra_headers={"X-Custom": "value"}
            )

            assert headers == {"Authorization": "Bearer test_token"}
            mock_prepare.assert_called_once_with(
                server_name="test-server",
                server_url="https://example.com/mcp",
                scopes=None,
                extra_headers={"X-Custom": "value"},
            )

    async def test_prepare_server_headers_explicit_oauth(self, handler, oauth_config):
        """Test prepare_server_headers with explicit OAuth config."""
        from unittest.mock import Mock

        # Create mock server config with explicit OAuth
        server_config = Mock()
        server_config.name = "test-server"
        server_config.url = "https://example.com/mcp"
        server_config.command = "some-command"
        server_config.oauth = oauth_config

        with patch.object(
            handler, "prepare_headers_with_oauth_config", new_callable=AsyncMock
        ) as mock_prepare:
            mock_prepare.return_value = {"Authorization": "Bearer test_token"}

            headers = await handler.prepare_server_headers(
                server_config, extra_headers={"X-Custom": "value"}
            )

            assert headers == {"Authorization": "Bearer test_token"}
            mock_prepare.assert_called_once_with(
                server_name="test-server",
                oauth_config=oauth_config,
                extra_headers={"X-Custom": "value"},
            )

    async def test_prepare_server_headers_no_oauth(self, handler):
        """Test prepare_server_headers with no OAuth (local server)."""
        from unittest.mock import Mock

        # Create mock server config without OAuth
        server_config = Mock()
        server_config.name = "test-server"
        server_config.url = None
        server_config.command = "local-command"
        server_config.oauth = None

        headers = await handler.prepare_server_headers(
            server_config, extra_headers={"X-Custom": "value"}
        )

        # Should return copy of extra headers
        assert headers == {"X-Custom": "value"}

    async def test_prepare_server_headers_no_oauth_no_extras(self, handler):
        """Test prepare_server_headers with no OAuth and no extra headers."""
        from unittest.mock import Mock

        # Create mock server config without OAuth
        server_config = Mock()
        server_config.name = "test-server"
        server_config.url = None
        server_config.command = "local-command"
        server_config.oauth = None

        headers = await handler.prepare_server_headers(server_config)

        # Should return empty dict
        assert headers == {}


class TestAuthenticatedRequest:
    """Test OAuthHandler.authenticated_request() functionality."""

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

    async def test_authenticated_request_success(self, handler, valid_tokens):
        """Test successful authenticated request."""
        import httpx
        from unittest.mock import AsyncMock, MagicMock

        server_name = "test-server"
        server_url = "https://example.com/mcp"
        request_url = "https://example.com/mcp/v1/resources"

        # Mock the ensure_authenticated_mcp to return tokens
        with patch.object(
            handler, "ensure_authenticated_mcp", return_value=valid_tokens
        ):
            # Mock httpx.AsyncClient
            mock_response = MagicMock(spec=httpx.Response)
            mock_response.status_code = 200
            mock_response.json.return_value = {"data": "test"}
            mock_response.raise_for_status = MagicMock()

            mock_client = MagicMock()
            mock_client.request = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)

            with patch("httpx.AsyncClient", return_value=mock_client):
                response = await handler.authenticated_request(
                    server_name=server_name,
                    server_url=server_url,
                    url=request_url,
                    method="GET",
                )

                assert response.status_code == 200
                assert response.json() == {"data": "test"}

                # Verify request was made with Authorization header
                mock_client.request.assert_called_once()
                call_args = mock_client.request.call_args
                assert call_args[0][0] == "GET"  # method
                assert call_args[0][1] == request_url  # url
                assert (
                    call_args[1]["headers"]["Authorization"]
                    == "Bearer test_access_token"
                )

    async def test_authenticated_request_401_retry_success(self, handler, valid_tokens):
        """Test 401 response triggers token refresh and successful retry."""
        import httpx
        from unittest.mock import AsyncMock, MagicMock
        import copy

        server_name = "test-server"
        server_url = "https://example.com/mcp"
        request_url = "https://example.com/mcp/v1/resources"

        # Create refreshed tokens
        refreshed_tokens = OAuthTokens(
            access_token="refreshed_access_token",
            token_type="Bearer",
            expires_in=3600,
            refresh_token="new_refresh_token",
        )

        # Store tokens in handler
        handler._active_tokens[server_name] = valid_tokens

        # First call returns valid tokens, second call (after 401) returns refreshed tokens
        ensure_auth_mock = AsyncMock(side_effect=[valid_tokens, refreshed_tokens])

        # Capture headers at time of each call
        captured_headers = []

        async def capture_request(method, url, headers=None, **kwargs):
            # Deep copy headers to capture their state at call time
            captured_headers.append(copy.deepcopy(headers))
            if len(captured_headers) == 1:
                # First call returns 401
                mock_401 = MagicMock(spec=httpx.Response)
                mock_401.status_code = 401
                return mock_401
            else:
                # Second call returns 200
                mock_200 = MagicMock(spec=httpx.Response)
                mock_200.status_code = 200
                mock_200.json.return_value = {"data": "success"}
                mock_200.raise_for_status = MagicMock()
                return mock_200

        with patch.object(handler, "ensure_authenticated_mcp", ensure_auth_mock):
            mock_client = MagicMock()
            mock_client.request = AsyncMock(side_effect=capture_request)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)

            with patch("httpx.AsyncClient", return_value=mock_client):
                response = await handler.authenticated_request(
                    server_name=server_name,
                    server_url=server_url,
                    url=request_url,
                    method="GET",
                )

                assert response.status_code == 200
                assert response.json() == {"data": "success"}

                # Verify ensure_authenticated_mcp was called twice
                assert ensure_auth_mock.call_count == 2

                # Verify request was made twice (initial + retry)
                assert mock_client.request.call_count == 2

                # Verify first request used original token
                assert len(captured_headers) == 2
                assert (
                    captured_headers[0]["Authorization"] == "Bearer test_access_token"
                )

                # Verify second request used refreshed token
                assert (
                    captured_headers[1]["Authorization"]
                    == "Bearer refreshed_access_token"
                )

    async def test_authenticated_request_401_retry_fails(self, handler, valid_tokens):
        """Test 401 response on retry raises error."""
        import httpx
        from unittest.mock import AsyncMock, MagicMock

        server_name = "test-server"
        server_url = "https://example.com/mcp"
        request_url = "https://example.com/mcp/v1/resources"

        with patch.object(
            handler, "ensure_authenticated_mcp", return_value=valid_tokens
        ):
            # Mock httpx.AsyncClient - both requests return 401
            mock_401_response = MagicMock(spec=httpx.Response)
            mock_401_response.status_code = 401
            mock_401_response.raise_for_status = MagicMock(
                side_effect=httpx.HTTPStatusError(
                    "401 Unauthorized", request=MagicMock(), response=mock_401_response
                )
            )

            mock_client = MagicMock()
            mock_client.request = AsyncMock(return_value=mock_401_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)

            with patch("httpx.AsyncClient", return_value=mock_client):
                with pytest.raises(httpx.HTTPStatusError, match="401"):
                    await handler.authenticated_request(
                        server_name=server_name,
                        server_url=server_url,
                        url=request_url,
                        method="GET",
                    )

                # Verify request was made twice (initial + retry)
                assert mock_client.request.call_count == 2

    async def test_authenticated_request_401_no_retry(self, handler, valid_tokens):
        """Test 401 response with retry_on_401=False raises immediately."""
        import httpx
        from unittest.mock import AsyncMock, MagicMock

        server_name = "test-server"
        server_url = "https://example.com/mcp"
        request_url = "https://example.com/mcp/v1/resources"

        with patch.object(
            handler, "ensure_authenticated_mcp", return_value=valid_tokens
        ):
            # Mock httpx.AsyncClient - returns 401
            mock_401_response = MagicMock(spec=httpx.Response)
            mock_401_response.status_code = 401
            mock_401_response.raise_for_status = MagicMock(
                side_effect=httpx.HTTPStatusError(
                    "401 Unauthorized", request=MagicMock(), response=mock_401_response
                )
            )

            mock_client = MagicMock()
            mock_client.request = AsyncMock(return_value=mock_401_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)

            with patch("httpx.AsyncClient", return_value=mock_client):
                with pytest.raises(httpx.HTTPStatusError, match="401"):
                    await handler.authenticated_request(
                        server_name=server_name,
                        server_url=server_url,
                        url=request_url,
                        method="GET",
                        retry_on_401=False,
                    )

                # Verify request was only made once (no retry)
                assert mock_client.request.call_count == 1

    async def test_authenticated_request_with_post_data(self, handler, valid_tokens):
        """Test authenticated POST request with JSON data."""
        import httpx
        from unittest.mock import AsyncMock, MagicMock

        server_name = "test-server"
        server_url = "https://example.com/mcp"
        request_url = "https://example.com/mcp/v1/resources"
        post_data = {"key": "value"}

        with patch.object(
            handler, "ensure_authenticated_mcp", return_value=valid_tokens
        ):
            # Mock httpx.AsyncClient
            mock_response = MagicMock(spec=httpx.Response)
            mock_response.status_code = 201
            mock_response.json.return_value = {"created": True}
            mock_response.raise_for_status = MagicMock()

            mock_client = MagicMock()
            mock_client.request = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)

            with patch("httpx.AsyncClient", return_value=mock_client):
                response = await handler.authenticated_request(
                    server_name=server_name,
                    server_url=server_url,
                    url=request_url,
                    method="POST",
                    json=post_data,
                )

                assert response.status_code == 201
                assert response.json() == {"created": True}

                # Verify request was made with correct method and JSON data
                call_args = mock_client.request.call_args
                assert call_args[0][0] == "POST"
                assert call_args[1]["json"] == post_data

    async def test_authenticated_request_with_custom_headers(
        self, handler, valid_tokens
    ):
        """Test authenticated request with custom headers."""
        import httpx
        from unittest.mock import AsyncMock, MagicMock

        server_name = "test-server"
        server_url = "https://example.com/mcp"
        request_url = "https://example.com/mcp/v1/resources"
        custom_headers = {"X-Custom-Header": "custom-value"}

        with patch.object(
            handler, "ensure_authenticated_mcp", return_value=valid_tokens
        ):
            # Mock httpx.AsyncClient
            mock_response = MagicMock(spec=httpx.Response)
            mock_response.status_code = 200
            mock_response.raise_for_status = MagicMock()

            mock_client = MagicMock()
            mock_client.request = AsyncMock(return_value=mock_response)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)

            with patch("httpx.AsyncClient", return_value=mock_client):
                response = await handler.authenticated_request(
                    server_name=server_name,
                    server_url=server_url,
                    url=request_url,
                    method="GET",
                    headers=custom_headers,
                )

                assert response.status_code == 200

                # Verify both Authorization and custom headers were sent
                call_args = mock_client.request.call_args
                headers = call_args[1]["headers"]
                assert headers["Authorization"] == "Bearer test_access_token"
                assert headers["X-Custom-Header"] == "custom-value"

    async def test_authenticated_request_clears_cached_token_on_401(
        self, handler, valid_tokens
    ):
        """Test that 401 response clears cached token before refresh."""
        import httpx
        from unittest.mock import AsyncMock, MagicMock

        server_name = "test-server"
        server_url = "https://example.com/mcp"
        request_url = "https://example.com/mcp/v1/resources"

        # Store tokens in cache
        handler._active_tokens[server_name] = valid_tokens

        refreshed_tokens = OAuthTokens(
            access_token="refreshed_token",
            token_type="Bearer",
            expires_in=3600,
        )

        ensure_auth_mock = AsyncMock(side_effect=[valid_tokens, refreshed_tokens])

        with patch.object(handler, "ensure_authenticated_mcp", ensure_auth_mock):
            # Mock httpx.AsyncClient
            mock_401_response = MagicMock(spec=httpx.Response)
            mock_401_response.status_code = 401

            mock_200_response = MagicMock(spec=httpx.Response)
            mock_200_response.status_code = 200
            mock_200_response.raise_for_status = MagicMock()

            mock_client = MagicMock()
            mock_client.request = AsyncMock(
                side_effect=[mock_401_response, mock_200_response]
            )
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)

            with patch("httpx.AsyncClient", return_value=mock_client):
                # Verify token is in cache before request
                assert server_name in handler._active_tokens

                response = await handler.authenticated_request(
                    server_name=server_name,
                    server_url=server_url,
                    url=request_url,
                    method="GET",
                )

                assert response.status_code == 200

                # Verify ensure_authenticated_mcp was called twice
                # (second time should force refresh since we cleared cache)
                assert ensure_auth_mock.call_count == 2
