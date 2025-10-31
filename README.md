# chuk-mcp-client-oauth

A simple, secure OAuth 2.0 client library for connecting to MCP (Model Context Protocol) servers.

**Perfect for developers who want to add OAuth authentication to their MCP applications without wrestling with OAuth complexity.**

[![Tests](https://github.com/chrishayuk/chuk-mcp-client-oauth/workflows/CI/badge.svg)](https://github.com/chrishayuk/chuk-mcp-client-oauth/actions)
[![Coverage](https://img.shields.io/badge/coverage-99%25-brightgreen)](https://github.com/chrishayuk/chuk-mcp-client-oauth)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

---

## 🎯 What is This?

This library makes it **dead simple** to authenticate with OAuth-enabled MCP servers. Whether you're building a CLI tool, web app, or service that needs to connect to MCP servers, this library handles all the OAuth complexity for you.

### What's MCP OAuth?

MCP (Model Context Protocol) servers can use OAuth 2.0 to control who can access them. Think of it like logging into GitHub or Google - but for AI/LLM services.

**As a client developer, you need:**
1. 🔐 **Authenticate** - Get permission from the server
2. 💾 **Store tokens** - Keep credentials secure
3. 🔄 **Refresh tokens** - Keep sessions alive
4. 🔧 **Use tokens** - Include them in API requests

This library does all of that for you.

---

## 🚀 Quick Start (5 minutes)

### Installation

Using `uv` (recommended):
```bash
uv add chuk-mcp-client-oauth
```

Or using pip:
```bash
pip install chuk-mcp-client-oauth
```

### Your First OAuth Flow (Complete Example)

```python
import asyncio
from chuk_mcp_client_oauth import OAuthHandler

async def main():
    # Create handler - it auto-configures secure storage
    handler = OAuthHandler()

    # Authenticate with a server (opens browser once)
    tokens = await handler.ensure_authenticated_mcp(
        server_name="notion-mcp",
        server_url="https://mcp.notion.com/mcp",
        scopes=["read", "write"]
    )

    print(f"✅ Authenticated! Token: {tokens.access_token[:20]}...")

    # Next time you run this, it uses cached tokens (no browser)
    # Headers are ready to use in your HTTP requests
    headers = await handler.prepare_headers_for_mcp_server(
        server_name="notion-mcp",
        server_url="https://mcp.notion.com/mcp"
    )

    print(f"🔑 Authorization header: {headers['Authorization'][:30]}...")

asyncio.run(main())
```

**That's it!** The library handles:
- ✅ OAuth server discovery
- ✅ Dynamic client registration
- ✅ Opening browser for user consent
- ✅ Receiving the callback
- ✅ Exchanging codes for tokens
- ✅ Storing tokens securely
- ✅ Reusing tokens on subsequent runs
- ✅ Refreshing expired tokens

---

## 🧠 Understanding MCP OAuth (The Client Perspective)

### The OAuth Flow (What Actually Happens)

When you authenticate with an MCP server, here's what happens behind the scenes:

```
1. 🔍 DISCOVERY
   Your app asks: "Server, how do I authenticate with you?"
   Server responds: "Here are my OAuth endpoints and capabilities"

2. 📝 REGISTRATION
   Your app: "I'd like to register as a client"
   Server: "OK, here's your client_id"

3. 🌐 AUTHORIZATION
   Your app opens browser: "User, please approve this app"
   User clicks "Allow"
   Browser redirects back with a code

4. 🎟️ TOKEN EXCHANGE
   Your app: "Here's the code, give me tokens"
   Server: "Here's your access_token and refresh_token"

5. 💾 STORAGE
   Your app saves tokens to secure storage (Keychain/etc)

6. ✅ AUTHENTICATED
   Your app can now make API requests with the token
```

This library automates **all of these steps**.

### Key Concepts

**Access Token** - Like a temporary password that proves you're authorized
- Used in every API request
- Expires after a time (e.g., 1 hour)
- Format: `Bearer <long-random-string>`

**Refresh Token** - Like a "get a new password" token
- Used to get new access tokens when they expire
- Long-lived (days/weeks)
- Stored securely

**Scopes** - What permissions you're requesting
- Examples: `["read", "write"]`, `["notion:read"]`
- Server decides what to grant

**PKCE** - Security enhancement that prevents token theft
- Automatically handled by this library
- You don't need to think about it

**Discovery URL** - Where OAuth configuration is published
- Standard location: `<server_url>/.well-known/oauth-authorization-server`
- Contains all OAuth endpoints and capabilities
- Automatically discovered by this library

---

## 📊 Flow Diagrams

### Auth Code + PKCE (Desktop/CLI with Browser)

This is the **primary flow** used by this library for interactive applications:

```
┌──────────────────┐        ┌──────────────┐         ┌──────────────────────┐        ┌───────────────┐
│  MCP Client      │        │  User        │         │  OAuth 2.1 Server    │        │  MCP Server    │
│  (CLI / Agent)   │        │  Browser     │         │  (Auth + Token)      │        │               │
└──┬───────────────┘        └──────┬───────┘         └──────────┬───────────┘        └───────┬───────┘
   │ 1) GET /.well-known/oauth-authorization-server            │                             │
   ├──────────────────────────────────────────────────────────▶│                             │
   │                                                           │ 2) Return endpoints         │
   │◀───────────────────────────────────────────────────────────┤  (authorize, token, etc.)  │
   │                                                           │                             │
   │ 3) Build Auth URL (PKCE: code_challenge)                  │                             │
   │ 4) Open browser ----------------------------------------▶ │                             │
   │                                                           │ 5) User login + consent     │
   │                                                           │◀────────────────────────────┤
   │                                                           │ 6) Redirect with ?code=...  │
   │◀───────────────────────────────────────────────────────────┤  to http://127.0.0.1:PORT   │
   │ 7) Local redirect handler captures code + state           │                             │
   │ 8) POST /token (code + code_verifier)                     │                             │
   ├──────────────────────────────────────────────────────────▶│                             │
   │                                                           │ 9) access_token + refresh   │
   │◀───────────────────────────────────────────────────────────┤    (expires_in, scopes…)   │
   │ 10) Store tokens securely (keyring / pluggable)           │                             │
   │                                                           │                             │
   │ 11) Connect to MCP with Authorization: Bearer <token>     │                             │
   ├────────────────────────────────────────────────────────────────────────────────────────▶│
   │                                                           │                             │ 12) Session OK
   │◀────────────────────────────────────────────────────────────────────────────────────────┤
   │                                                           │                             │
   │ 13) (When expired) POST /token (refresh_token)            │                             │
   ├──────────────────────────────────────────────────────────▶│                             │
   │                                                           │ 14) New access/refresh      │
   │◀───────────────────────────────────────────────────────────┤     -> update secure store │
   │                                                           │                             │
```

**Legend:**
- **PKCE**: `code_challenge = SHA256(code_verifier)` (sent at authorize), `code_verifier` (sent at token)
- Tokens are stored in OS keychain (or pluggable secure backend)
- MCP requests carry `Authorization: Bearer <access_token>`

### Device Code Flow (Headless TTY / SSH Agents)

**Coming in v0.2.0** - Perfect for SSH-only boxes, CI runners, and background agents:

```
┌──────────────────┐                          ┌──────────────────────┐                          ┌───────────────┐
│  MCP Client      │                          │  OAuth 2.1 Server    │                          │  MCP Server    │
│  (Headless)      │                          │  (Device + Token)    │                          │               │
└──┬───────────────┘                          └──────────┬───────────┘                          └───────┬───────┘
   │ 1) POST /device_authorization (client_id, scope)            │                                         │
   ├────────────────────────────────────────────────────────────▶│                                         │
   │                                                            │ 2) device_code, user_code, verify_uri   │
   │◀────────────────────────────────────────────────────────────┤    expires_in, interval                 │
   │ 3) Show: "Go to VERIFY_URI and enter USER_CODE"            │                                         │
   │                                                            │                                         │
   │                (User on any device)                         │                                         │
   │                         ┌──────────────┐                    │                                         │
   │                         │  User        │ 4) Visit verify URI│                                         │
   │                         │  Browser     │ ◀──────────────────▶│                                         │
   │                         └──────┬───────┘ 5) Enter user code │                                         │
   │                                                            │ 6) Consent + login done                  │
   │                                                            │                                         │
   │ 7) Poll POST /token (device_code, grant_type=device_code)  │                                         │
   ├────────────────────────────────────────────────────────────▶│                                         │
   │ (repeat every `interval` seconds until authorized)         │                                         │
   │◀────────────────────────────────────────────────────────────┤ 8) access_token + refresh               │
   │ 9) Store tokens securely                                   │                                         │
   │ 10) Connect MCP: Authorization: Bearer <token>             │                                         │
   ├─────────────────────────────────────────────────────────────────────────────────────────────────────▶│
   │                                                                                                     │ 11) Session OK
   │◀─────────────────────────────────────────────────────────────────────────────────────────────────────┤
   │ 12) Refresh on expiry → POST /token (refresh_token)         │                                        │
   ├────────────────────────────────────────────────────────────▶│                                        │
   │◀────────────────────────────────────────────────────────────┤ New tokens → update store              │
```

**When to use Device Code Flow:**
- **SSH-only environments** - No browser available on the target machine
- **CI/CD pipelines** - Automated builds need OAuth without interactive login
- **Background agents** - Services running without user interaction
- **Shared/headless servers** - Multiple users, no desktop environment

### How Tokens Attach to MCP Requests

> **Whiteboard view:** The client does discovery, performs OAuth (Auth Code + PKCE or Device Code), stores tokens safely, and automatically attaches `Authorization: Bearer <token>` to **every MCP handshake and request**, refreshing silently when needed.

**HTTP Requests:**
```http
GET /mcp/api/resources HTTP/1.1
Host: mcp.example.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json
```

**Server-Sent Events (SSE):**
```http
GET /mcp/events HTTP/1.1
Host: mcp.example.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
Accept: text/event-stream
Connection: keep-alive
```

**WebSocket:**
```http
GET /mcp/ws HTTP/1.1
Host: mcp.example.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
Upgrade: websocket
Connection: Upgrade
```

---

## 🔍 OAuth Discovery (How Your App Finds OAuth Endpoints)

### What is OAuth Discovery?

MCP servers publish their OAuth configuration at a **well-known URL**. This is like a menu that tells your app:
- "Here's where you get authorization"
- "Here's where you exchange codes for tokens"
- "Here's what I support (PKCE, refresh tokens, etc.)"

### The Well-Known Discovery URL

For any MCP server, the discovery endpoint is:
```
<server_url>/.well-known/oauth-authorization-server
```

**Examples:**
```
https://mcp.notion.com/mcp/.well-known/oauth-authorization-server
https://mcp.github.com/mcp/.well-known/oauth-authorization-server
https://your-server.com/mcp/.well-known/oauth-authorization-server
```

### What's in the Discovery Document?

When you fetch the discovery URL, you get a JSON document like this:

```json
{
  "issuer": "https://mcp.notion.com/mcp",
  "authorization_endpoint": "https://mcp.notion.com/oauth/authorize",
  "token_endpoint": "https://mcp.notion.com/oauth/token",
  "registration_endpoint": "https://mcp.notion.com/oauth/register",
  "scopes_supported": ["read", "write"],
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["none"]
}
```

**Key fields:**
- `authorization_endpoint` - Where users approve your app
- `token_endpoint` - Where you exchange codes for tokens
- `registration_endpoint` - Where you register as a client
- `code_challenge_methods_supported` - PKCE support (S256 = SHA-256)

### How This Library Uses Discovery

When you call:
```python
tokens = await handler.ensure_authenticated_mcp(
    server_name="notion-mcp",
    server_url="https://mcp.notion.com/mcp",
    scopes=["read", "write"]
)
```

Behind the scenes:
1. **Discovery**: Fetches `https://mcp.notion.com/mcp/.well-known/oauth-authorization-server`
2. **Parse**: Extracts `authorization_endpoint`, `token_endpoint`, etc.
3. **Validate**: Checks that PKCE is supported
4. **Cache**: Saves the configuration for future use
5. **Proceed**: Uses the discovered endpoints for OAuth flow

### Manual Discovery (Advanced)

You can also discover endpoints manually:

```python
from chuk_mcp_client_oauth import MCPOAuthClient

client = MCPOAuthClient(
    server_url="https://mcp.notion.com/mcp",
    redirect_uri="http://localhost:8080/callback"
)

# Discover OAuth configuration
await client.discover_authorization_server()

# Now you can inspect the discovered endpoints
print(f"Authorization URL: {client.authorization_url}")
print(f"Token URL: {client.token_url}")
print(f"Registration URL: {client.registration_endpoint}")
print(f"Supported scopes: {client.scopes_supported}")
print(f"PKCE methods: {client.code_challenge_methods_supported}")
```

### Testing Discovery with curl

You can test if a server supports OAuth discovery:

```bash
# Test Notion MCP
curl https://mcp.notion.com/mcp/.well-known/oauth-authorization-server

# Test your own server
curl https://your-server.com/mcp/.well-known/oauth-authorization-server
```

**Expected response:** JSON document with OAuth configuration

**Common errors:**
- `404 Not Found` - Server doesn't support OAuth
- `Connection refused` - Server URL is incorrect
- `Invalid JSON` - Server has misconfigured OAuth

### Discovery Specification

The discovery endpoint follows **RFC 8414** (OAuth 2.0 Authorization Server Metadata).

**Must have:**
- `issuer` - Server identifier
- `authorization_endpoint` - Where to send users
- `token_endpoint` - Where to get tokens

**Should have (for MCP):**
- `registration_endpoint` - Dynamic client registration (RFC 7591)
- `code_challenge_methods_supported: ["S256"]` - PKCE support

**Example of checking if a server supports MCP OAuth:**

```python
import httpx

async def check_oauth_support(server_url: str) -> bool:
    """Check if a server supports MCP OAuth."""
    discovery_url = f"{server_url}/.well-known/oauth-authorization-server"

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(discovery_url)

            if response.status_code != 200:
                print(f"❌ No OAuth support (status {response.status_code})")
                return False

            config = response.json()

            # Check required fields
            required = ["authorization_endpoint", "token_endpoint"]
            if not all(field in config for field in required):
                print("❌ Missing required OAuth endpoints")
                return False

            # Check for PKCE support
            if "S256" not in config.get("code_challenge_methods_supported", []):
                print("⚠️  PKCE not supported (less secure)")

            # Check for dynamic registration
            if "registration_endpoint" not in config:
                print("⚠️  No dynamic registration (manual setup required)")

            print("✅ Server supports MCP OAuth")
            print(f"   Auth: {config['authorization_endpoint']}")
            print(f"   Token: {config['token_endpoint']}")
            return True

    except Exception as e:
        print(f"❌ Discovery failed: {e}")
        return False

# Usage
await check_oauth_support("https://mcp.notion.com/mcp")
```

---

## 📦 Installation Options

```bash
# Basic installation (auto-detects storage backend)
uv add chuk-mcp-client-oauth

# With HashiCorp Vault support
uv add chuk-mcp-client-oauth --extra vault

# Development installation (includes testing tools)
git clone https://github.com/chrishayuk/chuk-mcp-client-oauth.git
cd chuk-mcp-client-oauth
uv sync --all-extras
```

---

## 💡 Usage Examples

### Example 1: CLI Tool with Token Management

```python
from chuk_mcp_client_oauth import OAuthHandler

async def connect_to_server(server_name: str, server_url: str):
    """Connect to an MCP server with OAuth."""
    handler = OAuthHandler()

    # First run: Opens browser for auth
    # Subsequent runs: Uses cached tokens
    tokens = await handler.ensure_authenticated_mcp(
        server_name=server_name,
        server_url=server_url,
        scopes=["read", "write"]
    )

    if tokens.is_expired():
        print("⚠️  Token expired, refreshing...")
        # Automatic refresh happens in ensure_authenticated_mcp

    return tokens

# Usage
tokens = await connect_to_server("notion-mcp", "https://mcp.notion.com/mcp")
print(f"Connected! Token expires in {tokens.expires_in} seconds")
```

### Example 2: Web App with Multiple Servers

```python
from chuk_mcp_client_oauth import OAuthHandler

class MCPClient:
    def __init__(self):
        self.handler = OAuthHandler()
        self.servers = {}

    async def add_server(self, name: str, url: str):
        """Add and authenticate with a server."""
        tokens = await self.handler.ensure_authenticated_mcp(
            server_name=name,
            server_url=url,
            scopes=["read", "write"]
        )
        self.servers[name] = url
        return tokens

    async def call_server(self, name: str, endpoint: str):
        """Make authenticated API call."""
        import httpx

        # Get headers with valid token
        headers = await self.handler.prepare_headers_for_mcp_server(
            server_name=name,
            server_url=self.servers[name]
        )

        # Make request
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.servers[name]}{endpoint}",
                headers=headers
            )
            return response.json()

# Usage
mcp = MCPClient()
await mcp.add_server("notion", "https://mcp.notion.com/mcp")
await mcp.add_server("github", "https://mcp.github.com/mcp")

data = await mcp.call_server("notion", "/api/pages")
```

### Example 3: Lower-Level Control

```python
from chuk_mcp_client_oauth import MCPOAuthClient

async def manual_oauth_flow():
    """Full control over the OAuth process."""
    client = MCPOAuthClient(
        server_url="https://mcp.example.com/mcp",
        redirect_uri="http://localhost:8080/callback"
    )

    # Step 1: Discover OAuth endpoints
    await client.discover_authorization_server()
    print(f"📍 Auth URL: {client.authorization_url}")
    print(f"📍 Token URL: {client.token_url}")

    # Step 2: Register as a client
    client_info = await client.register_client(
        client_name="My Awesome App",
        redirect_uris=["http://localhost:8080/callback"]
    )
    print(f"📝 Client ID: {client_info['client_id']}")

    # Step 3: Authorize (opens browser)
    tokens = await client.authorize(scopes=["read", "write"])
    print(f"🎟️ Access Token: {tokens.access_token[:20]}...")

    # Step 4: Use the token
    headers = {"Authorization": tokens.get_authorization_header()}

    # Step 5: Refresh when needed
    if tokens.is_expired():
        new_tokens = await client.refresh_token(tokens.refresh_token)
        print(f"🔄 Refreshed: {new_tokens.access_token[:20]}...")

    return tokens
```

---

## 🗄️ Token Storage (Secure & Automatic)

### How Storage Works

The library automatically stores tokens in the **most secure location** for your platform:

| Platform | Storage Backend | Description |
|----------|----------------|-------------|
| **macOS** | Keychain | Uses the macOS Keychain (same as Safari, Chrome) |
| **Linux** | Secret Service | Uses GNOME Keyring or KDE Wallet |
| **Windows** | Credential Manager | Uses Windows Credential Manager |
| **Vault** | HashiCorp Vault | For enterprise deployments |
| **Fallback** | Encrypted Files | AES-256 encrypted files (requires password) |

### Storage Directory

By default, tokens are stored in:
```
~/.chuk_oauth/tokens/
```

For encrypted file storage:
- Each server gets its own encrypted file: `<server_name>.enc`
- Files are encrypted with AES-256
- You can set a custom password or let it auto-generate

### Storage Examples

#### Auto-Detection (Recommended)
```python
from chuk_mcp_client_oauth import TokenManager

# Automatically uses the best backend for your platform
manager = TokenManager()

# Save tokens
manager.save_tokens("my-server", tokens)

# Load tokens (returns None if not found)
tokens = manager.load_tokens("my-server")

# Check if tokens exist and are valid
if manager.has_valid_tokens("my-server"):
    print("✅ Tokens are valid")

# Delete tokens
manager.delete_tokens("my-server")
```

#### Explicit Backend Selection
```python
from chuk_mcp_client_oauth import TokenManager, TokenStoreBackend

# Use macOS Keychain
manager = TokenManager(backend=TokenStoreBackend.KEYCHAIN)

# Use encrypted files with custom password
manager = TokenManager(
    backend=TokenStoreBackend.ENCRYPTED_FILE,
    password="my-super-secret-password-123"
)

# Use HashiCorp Vault
manager = TokenManager(
    backend=TokenStoreBackend.VAULT,
    vault_url="https://vault.company.com",
    vault_token="s.xyz123...",
    vault_mount_point="secret",
    vault_path_prefix="mcp-oauth"
)
```

#### Custom Storage Directory
```python
from pathlib import Path

manager = TokenManager(
    backend=TokenStoreBackend.ENCRYPTED_FILE,
    token_dir=Path("/secure/custom/path/tokens"),
    password="my-password"
)
```

### Storage Security Features

1. **Platform-Native Security**
   - macOS Keychain: Protected by system keychain access controls
   - Windows: Protected by Windows account credentials
   - Linux: Protected by Secret Service daemon

2. **Encryption**
   - Encrypted file storage uses AES-256-GCM
   - Keys derived from password using PBKDF2
   - Each token file has unique salt and IV

3. **Access Control**
   - Files created with mode 0600 (owner read/write only)
   - Token directory created with mode 0700 (owner access only)

4. **Token Metadata**
   - Creation timestamp
   - Expiration tracking
   - Scope information
   - Automatic cleanup of expired tokens

### Checking Available Backends

```python
from chuk_mcp_client_oauth import TokenStoreFactory

# Get list of available backends on this system
available = TokenStoreFactory.get_available_backends()
print("Available backends:", available)
# Example output: [TokenStoreBackend.KEYCHAIN, TokenStoreBackend.ENCRYPTED_FILE]

# Get the auto-detected backend
detected = TokenStoreFactory._detect_backend()
print(f"Auto-detected backend: {detected}")
# Example output: TokenStoreBackend.KEYCHAIN (on macOS)
```

### Storage Best Practices

**Development:**
```python
# Use auto-detection for simplicity
manager = TokenManager()
```

**Production (Single User):**
```python
# Use platform-native storage
manager = TokenManager(backend=TokenStoreBackend.AUTO)
```

**Production (Multi-User Server):**
```python
# Use Vault for centralized secret management
manager = TokenManager(
    backend=TokenStoreBackend.VAULT,
    vault_url=os.environ["VAULT_URL"],
    vault_token=os.environ["VAULT_TOKEN"]
)
```

**Testing:**
```python
# Use encrypted files in temp directory
import tempfile
manager = TokenManager(
    backend=TokenStoreBackend.ENCRYPTED_FILE,
    token_dir=Path(tempfile.mkdtemp()),
    password="test-password"
)
```

---

## 🛠️ CLI Tool (Quick Testing)

The library includes a CLI tool for testing OAuth flows. You can run it with `uvx` (no installation required) or install it locally:

### Using uvx (Recommended - No Installation)

```bash
# Authenticate with a server
uvx chuk-mcp-client-oauth auth notion-mcp https://mcp.notion.com/mcp

# List all stored tokens
uvx chuk-mcp-client-oauth list

# Get token details (safely redacted)
uvx chuk-mcp-client-oauth get notion-mcp

# Test connection
uvx chuk-mcp-client-oauth test notion-mcp

# Logout and revoke tokens with server (recommended)
uvx chuk-mcp-client-oauth logout notion-mcp --url https://mcp.notion.com/mcp

# Clear tokens locally only (no server notification)
uvx chuk-mcp-client-oauth clear notion-mcp
```

### Using installed CLI

```bash
# Install the package first
uv add chuk-mcp-client-oauth

# Then use the chuk-oauth command
chuk-oauth auth notion-mcp https://mcp.notion.com/mcp
chuk-oauth list
chuk-oauth get notion-mcp
chuk-oauth test notion-mcp
chuk-oauth logout notion-mcp --url https://mcp.notion.com/mcp
chuk-oauth clear notion-mcp
```

### Using examples directory

```bash
# Or run from examples directory
uv run examples/oauth_cli.py auth notion-mcp https://mcp.notion.com/mcp
```

**Example output:**
```
============================================================
Authenticating with notion-mcp
============================================================
Server URL: https://mcp.notion.com/mcp
Scopes: read, write (default)

🔐 Starting OAuth flow...
This will open your browser for authorization.

✅ Authentication successful!
Access Token: 282c6a79-d66f-402e-a...********************...w7q85t
Token Type: Bearer
Expires In: 3600 seconds

💾 Tokens saved to secure storage
Storage Backend: KeychainTokenStore
```

---

## 📚 Working Examples

The library includes complete, working examples:

### 1. Basic MCP OAuth (`basic_mcp_oauth.py`)
**What it shows:** Complete OAuth flow from scratch
```bash
uv run examples/basic_mcp_oauth.py
# Or with custom server
uv run examples/basic_mcp_oauth.py https://your-mcp-server.com/mcp
```

### 2. OAuth Handler (`oauth_handler_example.py`)
**What it shows:** High-level API with token caching
```bash
uv run examples/oauth_handler_example.py
```
Demonstrates:
- MCP OAuth with Notion
- Token caching and reuse
- Token validation
- Header preparation

### 3. Token Storage (`token_storage_example.py`)
**What it shows:** Different storage backends
```bash
uv run examples/token_storage_example.py
```
Demonstrates:
- Auto-detection
- Encrypted file storage
- Keychain integration
- Vault integration

### 4. CLI Tool (`oauth_cli.py`)
**What it shows:** Complete token management tool
```bash
uv run examples/oauth_cli.py --help
```

All examples are **fully functional** and tested with real MCP servers (Notion MCP).

---

## 🔧 API Reference

### OAuthHandler (High-Level API)

**Recommended for most use cases.**

```python
from chuk_mcp_client_oauth import OAuthHandler

handler = OAuthHandler(token_manager=None)  # None = auto-detect storage
```

**Methods:**

- **`ensure_authenticated_mcp(server_name, server_url, scopes=None)`**
  Authenticate with MCP server (uses cached tokens if available)
  ```python
  tokens = await handler.ensure_authenticated_mcp(
      server_name="my-server",
      server_url="https://mcp.example.com/mcp",
      scopes=["read", "write"]
  )
  ```

- **`prepare_headers_for_mcp_server(server_name, server_url, scopes=None)`**
  Get ready-to-use HTTP headers with authorization
  ```python
  headers = await handler.prepare_headers_for_mcp_server(
      server_name="my-server",
      server_url="https://mcp.example.com/mcp"
  )
  # Use in requests: httpx.get(url, headers=headers)
  ```

- **`get_authorization_header(server_name)`**
  Get just the Authorization header value
  ```python
  auth = handler.get_authorization_header("my-server")
  # Returns: "Bearer <token>"
  ```

- **`clear_tokens(server_name)`**
  Remove tokens from cache and storage (local only)
  ```python
  handler.clear_tokens("my-server")
  ```

- **`logout(server_name, server_url=None)`**
  Logout and revoke tokens with server (RFC 7009)
  ```python
  # Revoke tokens with server (recommended)
  await handler.logout(
      server_name="my-server",
      server_url="https://mcp.example.com/mcp"
  )

  # Clear tokens locally only (no server notification)
  await handler.logout("my-server")
  ```
  **Note**: When `server_url` is provided, the library will:
  1. Attempt to revoke the refresh and access tokens with the server
  2. Clear tokens from memory cache
  3. Delete tokens from secure storage
  4. Remove client registration

  If revocation fails (network error, server doesn't support it), tokens are still cleared locally.

### MCPOAuthClient (Low-Level API)

**For advanced control over the OAuth flow.**

```python
from chuk_mcp_client_oauth import MCPOAuthClient

client = MCPOAuthClient(
    server_url="https://mcp.example.com/mcp",
    redirect_uri="http://localhost:8080/callback"
)
```

**Methods:**

- **`discover_authorization_server()`** - RFC 8414 discovery
- **`register_client(client_name, redirect_uris)`** - RFC 7591 registration
- **`authorize(scopes)`** - Full authorization flow with PKCE
- **`refresh_token(refresh_token)`** - Get new access token
- **`revoke_token(token, token_type_hint=None)`** - Revoke token with server (RFC 7009)

### TokenManager

**Manages secure token storage.**

```python
from chuk_mcp_client_oauth import TokenManager, TokenStoreBackend

manager = TokenManager(
    backend=TokenStoreBackend.AUTO,  # or KEYCHAIN, VAULT, etc
    token_dir=None,  # custom directory (for ENCRYPTED_FILE)
    password=None,   # password (for ENCRYPTED_FILE)
)
```

**Methods:**

- **`save_tokens(server_name, tokens)`** - Store tokens securely
- **`load_tokens(server_name)`** - Retrieve stored tokens (returns None if not found)
- **`has_valid_tokens(server_name)`** - Check if valid tokens exist
- **`delete_tokens(server_name)`** - Remove tokens

### OAuthTokens (Token Object)

**Represents OAuth tokens.**

```python
tokens = OAuthTokens(
    access_token="...",
    token_type="Bearer",
    expires_in=3600,
    refresh_token="...",
    scope="read write"
)
```

**Methods:**

- **`get_authorization_header()`** - Returns `"Bearer <token>"`
- **`is_expired()`** - Check if token has expired
- **`to_dict()`** - Convert to dictionary

---

## 🔐 Security Features

- ✅ **PKCE Support** - Prevents authorization code interception
- ✅ **Secure Storage** - Platform-native secure storage (Keychain, etc)
- ✅ **Token Encryption** - AES-256 for file storage
- ✅ **Automatic Expiration** - Tracks and validates token expiration
- ✅ **No Plaintext Storage** - Never stores tokens in plaintext
- ✅ **Scope Validation** - Ensures requested scopes are granted

---

## 📊 Support Matrix

### OAuth Flows & Features

| Feature | Support | Notes |
|---------|---------|-------|
| **Authorization Code + PKCE** | ✅ Full | Primary flow (RFC 6749 + RFC 7636) |
| **Refresh Tokens** | ✅ Full | Automatic token refresh |
| **Dynamic Client Registration** | ✅ Full | RFC 7591 |
| **OAuth Discovery** | ✅ Full | RFC 8414 |
| **Device Code Flow** | 🚧 Planned | For headless/CI environments |
| **Client Credentials** | ❌ Out of scope | Server-to-server only |

### Platforms & Storage

| Platform | Python | Storage Backend | Auto-Detected | Fallback |
|----------|--------|----------------|---------------|----------|
| **macOS** | 3.10+ | Keychain | ✅ | Encrypted File |
| **Linux** | 3.10+ | Secret Service (GNOME Keyring/KWallet) | ✅ | Encrypted File |
| **Windows** | 3.10+ | Credential Manager | ✅ | Encrypted File |
| **Docker/CI** | 3.10+ | Encrypted File | ✅ | N/A |
| **Vault** | 3.10+ | HashiCorp Vault | Manual | Encrypted File |

### MCP Integration

| Feature | Support | How It Works |
|---------|---------|--------------|
| **Bearer Token Injection** | ✅ | `Authorization: Bearer <token>` header |
| **HTTP Requests** | ✅ | Standard HTTP headers |
| **SSE (Server-Sent Events)** | ✅ | Auth header in initial connection |
| **WebSocket** | ✅ | Auth header in handshake |

**How tokens are attached to MCP requests:**
```python
# The library adds this header to all MCP HTTP requests:
headers = {
    "Authorization": f"Bearer {access_token}",
    "Content-Type": "application/json"
}

# For SSE/WebSocket, the header is included in the initial connection:
# GET /mcp/events HTTP/1.1
# Authorization: Bearer <token>
# Connection: keep-alive
```

---

## 🔒 Security Model & Threat Considerations

### PKCE Flow Security

**What is PKCE?**
PKCE (Proof Key for Code Exchange) prevents authorization code interception attacks. Here's how this library implements it:

1. **Code Verifier Generation**
   - Random 128-character string generated for each flow
   - Stored in memory only (never written to disk)
   - Destroyed after token exchange

2. **Code Challenge**
   - SHA-256 hash of verifier sent to authorization endpoint
   - Server validates the verifier matches during token exchange
   - Prevents stolen auth codes from being used

```python
# Behind the scenes (automatic):
code_verifier = secrets.token_urlsafe(96)  # 128 chars base64url
code_challenge = base64url(sha256(code_verifier))

# Authorization request includes:
# code_challenge=<hash>&code_challenge_method=S256

# Token exchange includes:
# code_verifier=<original> (server validates hash matches)
```

### Token Storage Security

**Encryption at Rest:**
```python
# Encrypted File Storage (fallback):
- Algorithm: AES-256-GCM (authenticated encryption)
- Key Derivation: PBKDF2-HMAC-SHA256 (600,000 iterations)
- Salt: 32 bytes random per file
- IV: 16 bytes random per encryption
- Tag: 16 bytes authentication tag

# File structure:
# [32-byte salt][16-byte IV][encrypted data][16-byte tag]
```

**Access Control:**
- **Unix**: Files created with mode `0600` (owner read/write only)
- **Windows**: Protected by Windows account credentials
- **Keychain**: Uses system keychain access controls (requires user authentication)

**Token Lifecycle:**
```
1. Access Token Generated → Stored encrypted
2. Access Token Used → Retrieved, decrypted in memory
3. Access Token Expires → Automatic refresh
4. Refresh Token Used → New tokens stored, old deleted
5. User Logout → All tokens deleted from storage
```

### Redirect URI Strategy

**Default Configuration:**
```python
# Loopback address (RFC 8252 - OAuth for Native Apps)
redirect_uri = "http://127.0.0.1:<random_port>/callback"

# Why this is secure:
# ✅ Random port prevents port hijacking
# ✅ 127.0.0.1 (not localhost) prevents DNS rebinding
# ✅ CSRF state parameter validates redirect
# ✅ PKCE verifier prevents code interception
```

**CSRF Protection:**
```python
# State parameter (RFC 6749):
state = secrets.token_urlsafe(32)  # 256 bits of entropy

# Sent in authorization request, validated on callback
# Prevents cross-site request forgery
```

**Custom Redirect URI (Advanced):**
```python
# For production apps, use custom URI scheme:
client = MCPOAuthClient(
    server_url="https://mcp.example.com/mcp",
    redirect_uri="myapp://oauth/callback"  # Registered scheme
)
```

### Security Checklist

When deploying this library:

- [ ] **Use platform-native storage** (Keychain/Credential Manager) in production
- [ ] **Enable encryption** for file storage (always provide password)
- [ ] **Validate server certificates** (don't disable SSL verification)
- [ ] **Use PKCE** (automatically enabled, don't disable)
- [ ] **Rotate secrets** (configure token refresh intervals on server)
- [ ] **Monitor token usage** (implement logging/audit trails)
- [ ] **Limit scopes** (request minimum necessary permissions)
- [ ] **Implement logout** (revoke tokens when done)

### What's NOT Stored

For security, these are **never** written to disk:

- ❌ **PKCE code verifier** (memory only during flow)
- ❌ **CSRF state parameter** (memory only during flow)
- ❌ **User passwords** (never handled by this library)
- ❌ **Plaintext tokens** (always encrypted in file storage)

---

## ⚠️ Error Handling & Recovery

### Error Taxonomy

The library uses specific exceptions for different failure modes:

```python
from chuk_mcp_client_oauth.exceptions import (
    OAuthError,              # Base exception
    DiscoveryError,          # Discovery endpoint failed
    RegistrationError,       # Client registration failed
    AuthorizationError,      # User denied consent
    TokenExchangeError,      # Token exchange failed
    TokenRefreshError,       # Token refresh failed
    TokenStorageError,       # Storage backend failed
)
```

### Common Errors & Solutions

#### Discovery Failures

**Error:** `DiscoveryError: Failed to fetch discovery document`

**Causes:**
- Server doesn't support OAuth discovery
- Network connectivity issues
- Invalid server URL

**Recovery:**
```python
try:
    await handler.ensure_authenticated_mcp(
        server_name="my-server",
        server_url="https://mcp.example.com/mcp"
    )
except DiscoveryError as e:
    print(f"❌ Discovery failed: {e}")

    # Fallback: Manual configuration
    from chuk_mcp_client_oauth import MCPOAuthClient
    client = MCPOAuthClient(
        server_url="https://mcp.example.com/mcp",
        authorization_url="https://mcp.example.com/oauth/authorize",  # manual
        token_url="https://mcp.example.com/oauth/token",  # manual
        redirect_uri="http://127.0.0.1:8080/callback"
    )
```

#### Authorization Failures

**Error:** `AuthorizationError: User denied consent`

**Causes:**
- User clicked "Deny" in browser
- User closed browser window
- Timeout waiting for callback

**Recovery:**
```python
try:
    tokens = await client.authorize(scopes=["read", "write"])
except AuthorizationError as e:
    if "denied" in str(e).lower():
        print("❌ User denied access")
        print("ℹ️  Please approve the application to continue")
        # Retry with user guidance
    elif "timeout" in str(e).lower():
        print("❌ Authorization timeout")
        print("ℹ️  Please complete the flow within 5 minutes")
        # Retry with longer timeout
```

#### Token Refresh Failures

**Error:** `TokenRefreshError: Refresh token expired`

**Causes:**
- Refresh token expired (server-configured TTL)
- Refresh token revoked by server
- Network error during refresh

**Recovery:**
```python
try:
    new_tokens = await client.refresh_token(old_tokens.refresh_token)
except TokenRefreshError as e:
    print(f"❌ Refresh failed: {e}")

    # Clear old tokens and re-authenticate
    handler.clear_tokens("my-server")
    tokens = await handler.ensure_authenticated_mcp(
        server_name="my-server",
        server_url=server_url
    )
```

#### Storage Failures

**Error:** `TokenStorageError: Failed to store token`

**Causes:**
- Permission denied on storage directory
- Keychain locked (macOS)
- Disk full
- Encryption password wrong

**Recovery:**
```python
from chuk_mcp_client_oauth import TokenManager, TokenStoreBackend
from pathlib import Path

try:
    manager = TokenManager(backend=TokenStoreBackend.AUTO)
    manager.save_tokens("server", tokens)
except TokenStorageError as e:
    print(f"❌ Storage failed: {e}")

    # Fallback to encrypted file with explicit password
    import tempfile
    fallback_manager = TokenManager(
        backend=TokenStoreBackend.ENCRYPTED_FILE,
        token_dir=Path(tempfile.mkdtemp()),
        password="explicit-password-123"
    )
    fallback_manager.save_tokens("server", tokens)
```

### Retry Strategies

**Automatic Retry (Built-in):**
```python
# Token refresh automatically retries with exponential backoff
# 3 attempts: 1s, 2s, 4s delays
tokens = await handler.ensure_authenticated_mcp(...)
# ↑ Handles token refresh internally with retries
```

**Manual Retry (Your Code):**
```python
import asyncio
from tenacity import retry, stop_after_attempt, wait_exponential

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=10)
)
async def connect_with_retry(server_name: str, server_url: str):
    """Connect with automatic retries on network errors."""
    handler = OAuthHandler()
    return await handler.ensure_authenticated_mcp(
        server_name=server_name,
        server_url=server_url
    )

# Usage
try:
    tokens = await connect_with_retry("my-server", "https://mcp.example.com/mcp")
except Exception as e:
    print(f"❌ Failed after 3 retries: {e}")
```

### Debugging

**Enable Debug Logging:**
```python
import logging

# Enable library debug logs
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("chuk_mcp_client_oauth")
logger.setLevel(logging.DEBUG)

# Now you'll see:
# DEBUG:chuk_mcp_client_oauth:Discovering OAuth server at https://...
# DEBUG:chuk_mcp_client_oauth:Found authorization_endpoint: https://...
# DEBUG:chuk_mcp_client_oauth:Registering client with name: ...
# DEBUG:chuk_mcp_client_oauth:Starting local callback server on port 8080
# ...
```

---

## 🧪 Testing

```bash
# Run all tests
uv run pytest

# Run with coverage
uv run pytest --cov=chuk_mcp_client_oauth --cov-report=html

# Run specific test file
uv run pytest tests/auth/test_oauth_handler.py -v

# Run with markers
uv run pytest -m "not slow"
```

**Test Coverage:** 99%

---

## 🏗️ Development

```bash
# Clone repository
git clone https://github.com/chrishayuk/chuk-mcp-client-oauth.git
cd chuk-mcp-client-oauth

# Install dependencies with uv
uv sync --all-extras

# Run quality checks
make check  # runs format, lint, typecheck, security, tests

# Individual checks
make format      # Format code with ruff
make lint        # Lint code
make typecheck   # Type checking with mypy
make security    # Security scan with bandit
make test        # Run tests
make test-cov    # Run tests with coverage
```

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`make check`)
5. Commit (`git commit -m 'Add amazing feature'`)
6. Push (`git push origin feature/amazing-feature`)
7. Open a Pull Request

---

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

---

## 🆘 Troubleshooting

### "No module named 'keyring'"
```bash
uv add keyring  # or pip install keyring
```

### "OAuth flow failed"
- Check server URL is correct and reachable
- Verify server supports MCP OAuth (has `.well-known/oauth-authorization-server`)
- Ensure scopes are valid for the server

### "Token expired"
```python
# Tokens auto-refresh, but you can manually refresh:
if tokens.is_expired():
    new_tokens = await client.refresh_token(tokens.refresh_token)
```

### "Permission denied" on token storage
```bash
# Check directory permissions
ls -la ~/.chuk_oauth/
# Should be drwx------ (700)

# Fix if needed
chmod 700 ~/.chuk_oauth/
chmod 600 ~/.chuk_oauth/tokens/*.enc
```

---

## 🔗 Links

- **Documentation**: [Full docs](https://github.com/chrishayuk/chuk-mcp-client-oauth)
- **MCP Specification**: [Model Context Protocol](https://modelcontextprotocol.io/)
- **OAuth 2.0**: [RFC 6749](https://tools.ietf.org/html/rfc6749)
- **PKCE**: [RFC 7636](https://tools.ietf.org/html/rfc7636)
- **Issues**: [GitHub Issues](https://github.com/chrishayuk/chuk-mcp-client-oauth/issues)

---

**Made with ❤️ by the chuk-ai team**
