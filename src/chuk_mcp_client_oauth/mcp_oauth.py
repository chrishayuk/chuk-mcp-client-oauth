# chuk_mcp_client_oauth/mcp_oauth.py
"""MCP OAuth 2.0 implementation following the MCP authorization specification.

This implements:
- OAuth Authorization Server Metadata discovery (RFC 8414)
- Dynamic Client Registration (RFC 7591)
- Authorization Code Flow with PKCE
- Token management and refresh
"""

import asyncio
import base64
import hashlib
import logging
import secrets
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from typing import Dict, Optional
from urllib.parse import urljoin

import httpx
from pydantic import BaseModel, Field

from .oauth_config import OAuthTokens

logger = logging.getLogger(__name__)


class ProtectedResourceMetadata(BaseModel):
    """Protected Resource Metadata (RFC 9728).

    Discovered at /.well-known/oauth-protected-resource
    Points to authorization servers that protect this resource.
    """

    resource: str  # Resource identifier
    authorization_servers: list[str]  # List of AS metadata URLs
    scopes_supported: Optional[list[str]] = Field(default_factory=list)
    bearer_methods_supported: Optional[list[str]] = Field(
        default_factory=lambda: ["header"]
    )

    model_config = {"frozen": False}


class MCPAuthorizationMetadata(BaseModel):
    """OAuth Authorization Server Metadata from .well-known endpoint."""

    authorization_endpoint: str
    token_endpoint: str
    registration_endpoint: Optional[str] = None
    revocation_endpoint: Optional[str] = None  # RFC 7009
    device_authorization_endpoint: Optional[str] = None  # RFC 8628
    scopes_supported: list[str] = Field(default_factory=list)
    response_types_supported: list[str] = Field(default_factory=lambda: ["code"])
    grant_types_supported: list[str] = Field(
        default_factory=lambda: ["authorization_code", "refresh_token"]
    )
    code_challenge_methods_supported: list[str] = Field(
        default_factory=lambda: ["S256"]
    )

    model_config = {"frozen": False}


class DynamicClientRegistration(BaseModel):
    """OAuth client credentials from dynamic registration."""

    client_id: str
    client_secret: Optional[str] = None
    client_id_issued_at: Optional[int] = None
    client_secret_expires_at: int = 0

    model_config = {"frozen": False}


class MCPOAuthClient:
    """MCP OAuth client following the MCP authorization specification."""

    def __init__(
        self, server_url: str, redirect_uri: str = "http://localhost:8080/callback"
    ):
        """
        Initialize MCP OAuth client.

        Args:
            server_url: Base URL of the MCP server (e.g., https://mcp.notion.com/mcp)
            redirect_uri: OAuth callback URI
        """
        self.server_url = server_url.rstrip("/")
        self.redirect_uri = redirect_uri
        self._prm_metadata: Optional[ProtectedResourceMetadata] = None
        self._auth_metadata: Optional[MCPAuthorizationMetadata] = None
        self._client_registration: Optional[DynamicClientRegistration] = None
        self._code_verifier: Optional[str] = None
        self._auth_result: Optional[Dict[str, str]] = None
        # Resource indicator for token requests (RFC 8707)
        self._resource_indicator: Optional[str] = None

    @staticmethod
    def parse_www_authenticate_header(header_value: str) -> Optional[str]:
        """
        Parse WWW-Authenticate header to extract resource_metadata URL.

        Per MCP spec, servers may return:
        WWW-Authenticate: Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource"

        Args:
            header_value: Value of WWW-Authenticate header

        Returns:
            PRM URL if found, None otherwise
        """
        # Simple parser for resource_metadata parameter
        if "resource_metadata=" in header_value:
            # Extract URL from quotes
            parts = header_value.split("resource_metadata=")
            if len(parts) > 1:
                url_part = parts[1].strip()
                # Remove quotes
                if url_part.startswith('"') and '"' in url_part[1:]:
                    return url_part[1 : url_part.index('"', 1)]
                elif url_part.startswith("'") and "'" in url_part[1:]:
                    return url_part[1 : url_part.index("'", 1)]
        return None

    async def discover_protected_resource(
        self, prm_url: Optional[str] = None
    ) -> ProtectedResourceMetadata:
        """
        Discover Protected Resource Metadata (RFC 9728).

        Per MCP spec, PRM can be discovered via:
        1. Default location: /.well-known/oauth-protected-resource
        2. WWW-Authenticate header on 401/403 responses

        This is the MCP-compliant discovery method.

        Args:
            prm_url: Optional PRM URL (from WWW-Authenticate header)

        Returns:
            Protected Resource Metadata

        Raises:
            httpx.HTTPStatusError: If PRM endpoint returns error
        """
        if not prm_url:
            # Extract the base URL (scheme + host + path)
            parsed = urllib.parse.urlparse(self.server_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            # PRM discovery endpoint (RFC 9728)
            prm_url = urljoin(base_url, "/.well-known/oauth-protected-resource")

        logger.debug(f"Discovering PRM at: {prm_url}")

        async with httpx.AsyncClient() as client:
            response = await client.get(prm_url)
            response.raise_for_status()
            prm = ProtectedResourceMetadata.model_validate(response.json())
            self._prm_metadata = prm
            # Set resource indicator for token requests
            self._resource_indicator = prm.resource
            logger.debug(f"Discovered resource: {prm.resource}")
            logger.debug(f"Authorization servers: {prm.authorization_servers}")
            return prm

    async def discover_from_error_response(
        self, response: httpx.Response
    ) -> Optional[ProtectedResourceMetadata]:
        """
        Attempt to discover PRM from WWW-Authenticate header in 401/403 response.

        Per MCP spec, servers SHOULD include PRM URL in WWW-Authenticate header:
        WWW-Authenticate: Bearer resource_metadata="<prm-url>"

        Args:
            response: 401/403 response from server

        Returns:
            PRM metadata if discovered, None otherwise
        """
        if response.status_code not in (401, 403):
            return None

        www_auth = response.headers.get("WWW-Authenticate")
        if not www_auth:
            logger.debug("No WWW-Authenticate header in 401/403 response")
            return None

        prm_url = self.parse_www_authenticate_header(www_auth)
        if prm_url:
            logger.debug(f"Found PRM URL in WWW-Authenticate: {prm_url}")
            try:
                return await self.discover_protected_resource(prm_url)
            except Exception as e:
                logger.debug(f"Failed to discover PRM from WWW-Authenticate: {e}")

        return None

    async def discover_authorization_server(
        self, as_metadata_url: Optional[str] = None
    ) -> MCPAuthorizationMetadata:
        """
        Discover OAuth authorization server metadata.

        MCP-compliant flow:
        1. First discover PRM (/.well-known/oauth-protected-resource)
        2. Get AS metadata URL from PRM
        3. Fetch AS metadata

        Fallback (legacy):
        - Direct AS discovery at /.well-known/oauth-authorization-server

        Args:
            as_metadata_url: Optional direct AS metadata URL (from PRM)

        Returns:
            Authorization server metadata
        """
        # If no AS URL provided, try MCP-compliant discovery first
        if not as_metadata_url:
            try:
                # Try PRM discovery first (MCP-compliant)
                prm = await self.discover_protected_resource()
                if prm.authorization_servers:
                    as_url = prm.authorization_servers[0]
                    logger.debug(f"Using AS from PRM: {as_url}")

                    # RFC 9728: authorization_servers should contain AS metadata URLs
                    # However, some servers return base URLs instead. Handle both:
                    if "/.well-known/" in as_url:
                        # Already a well-known URL, use directly
                        as_metadata_url = as_url
                    else:
                        # Assume it's a base URL, append well-known path
                        as_metadata_url = urljoin(
                            as_url.rstrip("/"),
                            "/.well-known/oauth-authorization-server",
                        )
                        logger.debug(f"Constructing AS metadata URL: {as_metadata_url}")
            except httpx.HTTPError as e:
                # Fallback to legacy direct AS discovery
                logger.debug(
                    f"PRM discovery failed ({e}), falling back to direct AS discovery"
                )
                parsed = urllib.parse.urlparse(self.server_url)
                base_url = f"{parsed.scheme}://{parsed.netloc}"
                as_metadata_url = urljoin(
                    base_url, "/.well-known/oauth-authorization-server"
                )
                logger.debug(f"Trying legacy AS discovery at: {as_metadata_url}")

        # Fetch AS metadata
        if not as_metadata_url:
            raise ValueError("No AS metadata URL available")

        logger.debug(f"Fetching AS metadata from: {as_metadata_url}")
        async with httpx.AsyncClient() as client:
            response = await client.get(as_metadata_url)
            response.raise_for_status()
            metadata = MCPAuthorizationMetadata.model_validate(response.json())
            self._auth_metadata = metadata
            logger.debug(f"Discovered AS endpoints: {metadata.authorization_endpoint}")
            return metadata

    async def register_client(
        self, client_name: str = "MCP CLI", redirect_uris: Optional[list[str]] = None
    ) -> DynamicClientRegistration:
        """
        Perform Dynamic Client Registration (RFC 7591).

        Args:
            client_name: Name of the OAuth client
            redirect_uris: List of redirect URIs (defaults to self.redirect_uri)

        Returns:
            Client registration credentials
        """
        if not self._auth_metadata:
            await self.discover_authorization_server()

        if not self._auth_metadata or not self._auth_metadata.registration_endpoint:
            raise ValueError("Server does not support dynamic client registration")

        if redirect_uris is None:
            redirect_uris = [self.redirect_uri]

        registration_data = {
            "client_name": client_name,
            "redirect_uris": redirect_uris,
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",  # Public client
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                self._auth_metadata.registration_endpoint,
                json=registration_data,
                headers={"Content-Type": "application/json"},
            )
            response.raise_for_status()
            registration = DynamicClientRegistration.model_validate(response.json())
            self._client_registration = registration
            return registration

    def _generate_pkce_pair(self) -> tuple[str, str]:
        """Generate PKCE code verifier and challenge."""
        code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(
            "utf-8"
        )
        code_verifier = code_verifier.rstrip("=")

        challenge_bytes = hashlib.sha256(code_verifier.encode("utf-8")).digest()
        code_challenge = base64.urlsafe_b64encode(challenge_bytes).decode("utf-8")
        code_challenge = code_challenge.rstrip("=")

        return code_verifier, code_challenge

    def get_authorization_url(self, scopes: Optional[list[str]] = None) -> str:
        """
        Generate authorization URL for user consent.

        Args:
            scopes: List of OAuth scopes to request

        Returns:
            Authorization URL
        """
        if not self._auth_metadata or not self._client_registration:
            raise ValueError("Must discover and register before authorization")

        # Generate PKCE parameters
        self._code_verifier, code_challenge = self._generate_pkce_pair()

        params = {
            "client_id": self._client_registration.client_id,
            "response_type": "code",
            "redirect_uri": self.redirect_uri,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": secrets.token_urlsafe(16),
        }

        if scopes:
            params["scope"] = " ".join(scopes)

        query_string = urllib.parse.urlencode(params)
        return f"{self._auth_metadata.authorization_endpoint}?{query_string}"

    def _create_callback_handler(self):
        """Create HTTP callback handler."""
        oauth_client = self

        class CallbackHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                # Log to stdout for debugging
                logger.debug(f"Callback Server: {format % args}")

            def do_GET(self):
                logger.debug(f"Callback Server: Received request: {self.path}")
                parsed = urllib.parse.urlparse(self.path)

                # Ignore non-callback requests (favicon, etc.)
                if not parsed.path.startswith("/callback"):
                    self.send_response(404)
                    self.send_header("Content-type", "text/html")
                    self.end_headers()
                    self.wfile.write(b"<html><body>Not Found</body></html>")
                    return

                params = dict(urllib.parse.parse_qsl(parsed.query))
                logger.debug(f"Callback Server: Query params: {params}")

                # Only set _auth_result if we haven't already got a successful result
                if oauth_client._auth_result is None:
                    if "error" in params:
                        error_description = params.get(
                            "error_description", params["error"]
                        )
                        oauth_client._auth_result = {"error": error_description}
                        response = f"<html><body><h1>Authorization Failed</h1><p>{error_description}</p></body></html>"
                        self.send_response(400)
                    elif "code" in params:
                        oauth_client._auth_result = params
                        response = "<html><body><h1>Authorization Successful</h1><p>You can close this window and return to the terminal.</p></body></html>"
                        self.send_response(200)
                        print(
                            "[Callback Server] Authorization successful, code received"
                        )
                    else:
                        # Invalid callback request (no code, no error)
                        response = "<html><body><h1>Invalid Callback</h1><p>No authorization code received</p></body></html>"
                        self.send_response(400)
                else:
                    # Already got result, just return success page
                    response = "<html><body><h1>Authorization Successful</h1><p>You can close this window.</p></body></html>"
                    self.send_response(200)

                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(response.encode())

        return CallbackHandler

    async def _run_callback_server(self, port: int) -> None:
        """Run local callback server."""
        handler_class = self._create_callback_handler()
        server = HTTPServer(("localhost", port), handler_class)

        logger.debug(f"Callback Server: Starting server on localhost:{port}")
        server_thread = Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        logger.debug("Callback Server: Server started, waiting for callback...")

        # Wait for callback or timeout (5 minutes)
        timeout_seconds = 300
        for i in range(timeout_seconds):
            if self._auth_result is not None:
                logger.debug(f"Callback Server: Callback received after {i} seconds")
                break
            await asyncio.sleep(1)

            # Print progress every 30 seconds
            if i > 0 and i % 30 == 0:
                remaining = timeout_seconds - i
                logger.debug(
                    f"Callback Server: Still waiting... ({remaining}s remaining)"
                )

        if self._auth_result is None:
            logger.debug(f"Callback Server: Timeout after {timeout_seconds} seconds")

        logger.debug("Callback Server: Shutting down server...")
        server.shutdown()
        logger.debug("Callback Server: Server stopped")

    async def exchange_code_for_token(self, code: str) -> OAuthTokens:
        """
        Exchange authorization code for access token.

        Args:
            code: Authorization code from callback

        Returns:
            OAuth tokens
        """
        if not self._auth_metadata or not self._client_registration:
            raise ValueError("Must discover and register before token exchange")

        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "client_id": self._client_registration.client_id,
            "code_verifier": self._code_verifier,
        }

        # Add resource indicator (RFC 8707) to bind token to this resource
        if self._resource_indicator:
            data["resource"] = self._resource_indicator
            logger.debug(f"Including resource indicator: {self._resource_indicator}")

        if self._client_registration.client_secret:
            data["client_secret"] = self._client_registration.client_secret

        async with httpx.AsyncClient() as client:
            response = await client.post(
                self._auth_metadata.token_endpoint,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            response.raise_for_status()
            return OAuthTokens.model_validate(response.json())

    async def refresh_token(self, refresh_token: str) -> OAuthTokens:
        """
        Refresh access token.

        Args:
            refresh_token: Refresh token

        Returns:
            New OAuth tokens
        """
        if not self._auth_metadata or not self._client_registration:
            raise ValueError("Must discover and register before token refresh")

        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self._client_registration.client_id,
        }

        # Add resource indicator (RFC 8707) to bind token to this resource
        if self._resource_indicator:
            data["resource"] = self._resource_indicator
            logger.debug(
                f"Including resource indicator in refresh: {self._resource_indicator}"
            )

        if self._client_registration.client_secret:
            data["client_secret"] = self._client_registration.client_secret

        async with httpx.AsyncClient() as client:
            response = await client.post(
                self._auth_metadata.token_endpoint,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            response.raise_for_status()
            return OAuthTokens.model_validate(response.json())

    async def revoke_token(
        self, token: str, token_type_hint: Optional[str] = None
    ) -> bool:
        """
        Revoke an access or refresh token (RFC 7009).

        Args:
            token: The token to revoke (access_token or refresh_token)
            token_type_hint: Hint about token type ("access_token" or "refresh_token")

        Returns:
            True if revocation succeeded or if server doesn't support revocation

        Note:
            If the server doesn't have a revocation endpoint, this returns True
            (the token will expire naturally on the server).
        """
        if not self._auth_metadata:
            raise ValueError("Must discover authorization server before revocation")

        # Check if server supports token revocation
        # RFC 8414 specifies this as "revocation_endpoint"
        revocation_endpoint = getattr(self._auth_metadata, "revocation_endpoint", None)
        if not revocation_endpoint:
            # Server doesn't support revocation, tokens will expire naturally
            return True

        # Prepare revocation request
        data = {"token": token}
        if token_type_hint:
            data["token_type_hint"] = token_type_hint

        # Include client credentials if available
        if self._client_registration:
            data["client_id"] = self._client_registration.client_id
            if self._client_registration.client_secret:
                data["client_secret"] = self._client_registration.client_secret

        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    revocation_endpoint,
                    data=data,
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                # RFC 7009: Server responds with HTTP 200 for successful revocation
                # Token might already be invalid, but that's still considered success
                return response.status_code == 200
        except Exception:
            # If revocation fails, log but don't raise - tokens will expire naturally
            return False

    async def authorize(self, scopes: Optional[list[str]] = None) -> OAuthTokens:
        """
        Perform full MCP OAuth authorization flow.

        This includes:
        1. Discovery of authorization server metadata
        2. Dynamic client registration
        3. User authorization via browser
        4. Token exchange

        Args:
            scopes: OAuth scopes to request

        Returns:
            OAuth tokens
        """
        # Step 1: Discover authorization server
        logger.info("🔍 Discovering authorization server...")
        await self.discover_authorization_server()

        # Step 2: Register as OAuth client
        logger.info("📝 Registering OAuth client...")
        await self.register_client()

        # Step 3: Get authorization from user
        logger.info("🔐 Opening browser for authorization...")
        auth_url = self.get_authorization_url(scopes)
        logger.info(f"If browser doesn't open, visit: {auth_url}\n")
        webbrowser.open(auth_url)

        # Step 4: Wait for callback
        parsed = urllib.parse.urlparse(self.redirect_uri)
        port = parsed.port or 8080
        server_task = asyncio.create_task(self._run_callback_server(port))
        await server_task

        if self._auth_result is None:
            raise Exception("Authorization timed out")

        if "error" in self._auth_result:
            raise Exception(f"Authorization failed: {self._auth_result['error']}")

        # Step 5: Exchange code for token
        logger.info("🔄 Exchanging code for token...")
        code = self._auth_result["code"]
        tokens = await self.exchange_code_for_token(code)

        logger.info("✅ Authorization complete!\n")
        return tokens
