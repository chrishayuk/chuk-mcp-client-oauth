# chuk_mcp_client_oauth/oauth_handler.py
"""OAuth handler for MCP server connections."""

import logging
from typing import Dict, Optional

import httpx

from .mcp_oauth import MCPOAuthClient
from .oauth_config import OAuthConfig, OAuthTokens
from .oauth_flow import OAuthFlow
from .token_manager import TokenManager

logger = logging.getLogger(__name__)


class OAuthHandler:
    """Handles OAuth authentication for MCP servers."""

    def __init__(self, token_manager: Optional[TokenManager] = None):
        """
        Initialize OAuth handler.

        Args:
            token_manager: Token manager instance (creates default if not provided)
        """
        self.token_manager = token_manager or TokenManager()
        self._active_tokens: Dict[str, OAuthTokens] = {}

    async def ensure_authenticated_mcp(
        self, server_name: str, server_url: str, scopes: Optional[list[str]] = None
    ) -> OAuthTokens:
        """
        Ensure remote MCP server has valid authentication using MCP OAuth spec.

        This uses:
        - OAuth Authorization Server Metadata discovery (RFC 8414)
        - Dynamic Client Registration (RFC 7591)
        - Authorization Code Flow with PKCE

        Args:
            server_name: Name of the MCP server
            server_url: Base URL of the MCP server
            scopes: Optional OAuth scopes

        Returns:
            Valid OAuth tokens
        """
        # Check memory cache first
        if server_name in self._active_tokens:
            tokens = self._active_tokens[server_name]
            if not tokens.is_expired():
                return tokens

        # Check disk storage
        stored_tokens = self.token_manager.load_tokens(server_name)
        if stored_tokens and not stored_tokens.is_expired():
            self._active_tokens[server_name] = stored_tokens
            return stored_tokens

        # If we have expired tokens WITHOUT a refresh token, clear them immediately
        # If we have a refresh token, we'll try to refresh first before clearing
        if (
            stored_tokens
            and stored_tokens.is_expired()
            and not stored_tokens.refresh_token
        ):
            logger.info(
                f"Clearing expired tokens for {server_name} (no refresh token available)"
            )
            self.token_manager.delete_tokens(server_name)
            stored_tokens = None

        # Create MCP OAuth client
        mcp_client = MCPOAuthClient(server_url)

        # Load stored client registration if exists
        stored_registration = self.token_manager.load_client_registration(server_name)
        if stored_registration:
            mcp_client._client_registration = stored_registration
            logger.info(f"Using stored client registration for {server_name}")

        # Try refresh if we have a refresh token
        if stored_tokens and stored_tokens.refresh_token:
            try:
                # Need to discover metadata first for refresh
                await mcp_client.discover_authorization_server()
                if not mcp_client._client_registration:
                    mcp_client._client_registration = stored_registration

                tokens = await mcp_client.refresh_token(stored_tokens.refresh_token)
                self.token_manager.save_tokens(server_name, tokens)
                self._active_tokens[server_name] = tokens
                logger.info(f"Refreshed tokens for {server_name}")
                return tokens
            except Exception as e:
                logger.warning(f"Token refresh failed for {server_name}: {e}")
                # Clear invalid tokens to force full auth
                logger.info(f"Clearing invalid tokens for {server_name}")
                self.token_manager.delete_tokens(server_name)
                # Fall through to full auth flow

        # Perform full MCP OAuth flow
        logger.info(f"🔐 Authentication required for {server_name}")
        # Removed decoration
        tokens = await mcp_client.authorize(scopes)

        # Save both tokens and client registration
        self.token_manager.save_tokens(server_name, tokens)
        if mcp_client._client_registration:
            self.token_manager.save_client_registration(
                server_name, mcp_client._client_registration
            )

        self._active_tokens[server_name] = tokens
        logger.info(f"Completed MCP OAuth flow for {server_name}")

        return tokens

    async def ensure_authenticated(
        self, server_name: str, oauth_config: OAuthConfig
    ) -> OAuthTokens:
        """
        Ensure server has valid authentication tokens (legacy OAuth).

        This method:
        1. Checks for cached tokens in memory
        2. Checks for stored tokens on disk
        3. Refreshes expired tokens if refresh token available
        4. Performs full OAuth flow if no valid tokens exist

        Args:
            server_name: Name of the MCP server
            oauth_config: OAuth configuration for the server

        Returns:
            Valid OAuth tokens

        Raises:
            Exception: If authentication fails
        """
        # Check memory cache first
        if server_name in self._active_tokens:
            tokens = self._active_tokens[server_name]
            if not tokens.is_expired():
                return tokens

        # Check disk storage
        stored_tokens = self.token_manager.load_tokens(server_name)
        if stored_tokens and not stored_tokens.is_expired():
            self._active_tokens[server_name] = stored_tokens
            return stored_tokens

        # Try refresh if we have a refresh token
        if stored_tokens and stored_tokens.refresh_token:
            try:
                tokens = await self._refresh_tokens(
                    server_name, oauth_config, stored_tokens.refresh_token
                )
                return tokens
            except Exception as e:
                logger.warning(f"Token refresh failed for {server_name}: {e}")
                # Fall through to full auth flow

        # Perform full OAuth flow
        tokens = await self._perform_oauth_flow(server_name, oauth_config)
        return tokens

    async def _refresh_tokens(
        self, server_name: str, oauth_config: OAuthConfig, refresh_token: str
    ) -> OAuthTokens:
        """Refresh access token."""
        flow = OAuthFlow(oauth_config)
        tokens = await flow.refresh_token(refresh_token)

        # Save and cache new tokens
        self.token_manager.save_tokens(server_name, tokens)
        self._active_tokens[server_name] = tokens

        logger.info(f"Refreshed tokens for {server_name}")
        return tokens

    async def _perform_oauth_flow(
        self, server_name: str, oauth_config: OAuthConfig
    ) -> OAuthTokens:
        """Perform full OAuth authorization flow."""
        flow = OAuthFlow(oauth_config)

        logger.info(f"🔐 Authentication required for {server_name}")
        # Removed decoration

        tokens = await flow.authorize()

        # Save and cache tokens
        self.token_manager.save_tokens(server_name, tokens)
        self._active_tokens[server_name] = tokens

        logger.info(f"✅ Successfully authenticated {server_name}")
        logger.info(f"Completed OAuth flow for {server_name}")

        return tokens

    def get_authorization_header(self, server_name: str) -> Optional[str]:
        """
        Get Authorization header value for a server.

        Args:
            server_name: Name of the MCP server

        Returns:
            Authorization header value or None if not authenticated
        """
        if server_name in self._active_tokens:
            return self._active_tokens[server_name].get_authorization_header()
        return None

    def clear_tokens(self, server_name: str) -> None:
        """
        Clear tokens for a server (from memory and disk).

        Args:
            server_name: Name of the MCP server
        """
        if server_name in self._active_tokens:
            del self._active_tokens[server_name]
        self.token_manager.delete_tokens(server_name)

    async def logout(self, server_name: str, server_url: Optional[str] = None) -> None:
        """
        Logout from a server by revoking tokens and clearing them.

        This method:
        1. Attempts to revoke the access/refresh tokens with the server (if revocation endpoint available)
        2. Clears tokens from memory cache
        3. Deletes tokens from secure storage
        4. Removes client registration

        Args:
            server_name: Name of the MCP server
            server_url: Base URL of the MCP server (required for token revocation)

        Note:
            If server_url is not provided or revocation fails, tokens are still cleared locally.
            The server may continue to accept the tokens until they expire naturally.
        """
        tokens = None

        # Get tokens from memory or storage
        if server_name in self._active_tokens:
            tokens = self._active_tokens[server_name]
        else:
            tokens = self.token_manager.load_tokens(server_name)

        # Try to revoke with server if we have a URL and tokens
        if server_url and tokens:
            try:
                # Create MCP OAuth client for revocation
                mcp_client = MCPOAuthClient(server_url)

                # Discover OAuth metadata to find revocation endpoint
                await mcp_client.discover_authorization_server()

                # Load stored client registration
                stored_registration = self.token_manager.load_client_registration(
                    server_name
                )
                if stored_registration:
                    mcp_client._client_registration = stored_registration

                # Revoke refresh token first (more powerful)
                if tokens.refresh_token:
                    await mcp_client.revoke_token(
                        tokens.refresh_token, token_type_hint="refresh_token"
                    )
                    logger.info(f"Revoked refresh token for {server_name}")

                # Then revoke access token
                if tokens.access_token:
                    await mcp_client.revoke_token(
                        tokens.access_token, token_type_hint="access_token"
                    )
                    logger.info(f"Revoked access token for {server_name}")

            except Exception as e:
                logger.warning(
                    f"Token revocation failed for {server_name}: {e}. "
                    "Tokens will be cleared locally but may remain valid on server."
                )

        # Clear tokens locally (always do this, even if revocation fails)
        if server_name in self._active_tokens:
            del self._active_tokens[server_name]

        # Delete from storage
        self.token_manager.delete_tokens(server_name)
        self.token_manager.delete_client_registration(server_name)

        logger.info(f"Logged out from {server_name}")

    async def prepare_headers_for_mcp_server(
        self,
        server_name: str,
        server_url: str,
        scopes: Optional[list[str]] = None,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, str]:
        """
        Prepare HTTP headers for MCP server connection with OAuth authentication.

        Args:
            server_name: Name of the MCP server
            server_url: Base URL of the MCP server
            scopes: Optional OAuth scopes to request
            extra_headers: Optional additional headers to include

        Returns:
            Dictionary of HTTP headers including Authorization header

        Raises:
            Exception: If authentication fails
        """
        headers: Dict[str, str] = extra_headers.copy() if extra_headers else {}

        try:
            tokens = await self.ensure_authenticated_mcp(
                server_name, server_url, scopes=scopes
            )
            headers["Authorization"] = tokens.get_authorization_header()
            logger.debug(f"Added Authorization header for {server_name}")
        except Exception as e:
            logger.error(f"MCP OAuth authentication failed for {server_name}: {e}")
            raise

        return headers

    async def prepare_headers_with_oauth_config(
        self,
        server_name: str,
        oauth_config: OAuthConfig,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, str]:
        """
        Prepare HTTP headers with OAuth authentication using explicit OAuth config.

        Args:
            server_name: Name of the server
            oauth_config: OAuth configuration
            extra_headers: Optional additional headers to include

        Returns:
            Dictionary of HTTP headers including Authorization header

        Raises:
            Exception: If authentication fails
        """
        headers: Dict[str, str] = extra_headers.copy() if extra_headers else {}

        try:
            tokens = await self.ensure_authenticated(server_name, oauth_config)
            headers["Authorization"] = tokens.get_authorization_header()
            logger.debug(f"Added Authorization header for {server_name}")
        except Exception as e:
            logger.error(f"OAuth authentication failed for {server_name}: {e}")
            raise

        return headers

    async def prepare_server_headers(
        self,
        server_config,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, str]:
        """
        Prepare HTTP headers for a server (compatibility method for mcp-cli).

        This method handles both MCP OAuth and explicit OAuth configs.

        Args:
            server_config: Server configuration object with name, url, and optional oauth
            extra_headers: Optional additional headers to include

        Returns:
            Dictionary of HTTP headers including Authorization header

        Raises:
            Exception: If authentication fails
        """
        server_name = server_config.name

        # Check if this is a remote MCP server (has URL, no command)
        is_remote_mcp = server_config.url and not server_config.command

        # Check if explicit OAuth config is provided
        has_explicit_oauth = server_config.oauth is not None

        if is_remote_mcp:
            # Use MCP OAuth (auto-discovery)
            return await self.prepare_headers_for_mcp_server(
                server_name=server_name,
                server_url=server_config.url,
                scopes=None,
                extra_headers=extra_headers,
            )
        elif has_explicit_oauth:
            # Use explicit OAuth config
            return await self.prepare_headers_with_oauth_config(
                server_name=server_name,
                oauth_config=server_config.oauth,
                extra_headers=extra_headers,
            )
        else:
            # No OAuth needed
            return extra_headers.copy() if extra_headers else {}

    async def authenticated_request(
        self,
        server_name: str,
        server_url: str,
        url: str,
        method: str = "GET",
        scopes: Optional[list[str]] = None,
        retry_on_401: bool = True,
        **kwargs,
    ) -> httpx.Response:
        """
        Make an authenticated HTTP request to an MCP server with automatic token refresh.

        This method handles the common pattern of making authenticated requests to MCP servers:
        1. Ensures valid authentication (gets/refreshes tokens as needed)
        2. Makes the request with the Authorization header
        3. If 401 Unauthorized is returned, refreshes the token and retries once

        Args:
            server_name: Name of the MCP server
            server_url: Base URL of the MCP server (for OAuth discovery)
            url: Full URL to request
            method: HTTP method (GET, POST, etc.)
            scopes: Optional OAuth scopes to request
            retry_on_401: Whether to automatically retry on 401 with token refresh (default: True)
            **kwargs: Additional arguments to pass to httpx.request()

        Returns:
            httpx.Response object

        Raises:
            httpx.HTTPStatusError: If the request fails (including 401 after retry)
            Exception: If authentication fails

        Example:
            ```python
            handler = OAuthHandler()
            response = await handler.authenticated_request(
                server_name="notion",
                server_url="https://mcp.notion.com/mcp",
                url="https://mcp.notion.com/mcp/v1/resources",
                method="GET"
            )
            data = response.json()
            ```
        """
        # Ensure we have valid tokens
        tokens = await self.ensure_authenticated_mcp(server_name, server_url, scopes)

        # Prepare headers with authorization
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = tokens.get_authorization_header()

        async with httpx.AsyncClient() as client:
            # Make the request
            response = await client.request(method, url, headers=headers, **kwargs)

            # Handle 401 Unauthorized with automatic token refresh
            if response.status_code == 401 and retry_on_401:
                logger.info(
                    f"Received 401 Unauthorized from {server_name}, refreshing token and retrying"
                )

                # Clear cached tokens to force refresh
                if server_name in self._active_tokens:
                    del self._active_tokens[server_name]

                # Re-authenticate (this will use refresh token if available)
                tokens = await self.ensure_authenticated_mcp(
                    server_name, server_url, scopes
                )

                # Update authorization header with new token
                headers["Authorization"] = tokens.get_authorization_header()

                # Retry the request once with new token
                response = await client.request(method, url, headers=headers, **kwargs)

                if response.status_code == 401:
                    logger.error(
                        f"Still received 401 after token refresh for {server_name}"
                    )

            # Raise for any error status codes
            response.raise_for_status()

            return response
