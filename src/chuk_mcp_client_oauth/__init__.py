"""MCP OAuth Client Library - A reusable OAuth 2.0 client for MCP servers.

This library provides OAuth 2.0 authentication support for MCP (Model Context Protocol) servers,
implementing:
- OAuth Authorization Server Metadata discovery (RFC 8414)
- Dynamic Client Registration (RFC 7591)
- Authorization Code Flow with PKCE
- Token management and secure storage
"""

from .oauth_config import OAuthConfig, OAuthTokens
from .oauth_flow import OAuthFlow
from .mcp_oauth import (
    MCPOAuthClient,
    MCPAuthorizationMetadata,
    DynamicClientRegistration,
)
from .oauth_handler import OAuthHandler
from .token_manager import TokenManager
from .token_store_factory import TokenStoreBackend, TokenStoreFactory
from .secure_token_store import SecureTokenStore
from .token_types import TokenType, StoredToken, APIKeyToken, BearerToken
from .token_registry import TokenRegistry

__version__ = "0.1.0"

__all__ = [
    "OAuthConfig",
    "OAuthTokens",
    "OAuthFlow",
    "MCPOAuthClient",
    "MCPAuthorizationMetadata",
    "DynamicClientRegistration",
    "OAuthHandler",
    "TokenManager",
    "TokenStoreBackend",
    "TokenStoreFactory",
    "SecureTokenStore",
    "TokenType",
    "StoredToken",
    "APIKeyToken",
    "BearerToken",
    "TokenRegistry",
]
