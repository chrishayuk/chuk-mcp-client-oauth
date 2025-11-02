# chuk-mcp-client-oauth

A simple, secure OAuth 2.0 client library for connecting to MCP (Model Context Protocol) servers.

**Perfect for developers who want to add OAuth authentication to their MCP applications without wrestling with OAuth complexity.**

[![Tests](https://github.com/chrishayuk/chuk-mcp-client-oauth/workflows/CI/badge.svg)](https://github.com/chrishayuk/chuk-mcp-client-oauth/actions)
[![Coverage](https://img.shields.io/badge/coverage-99%25-brightgreen)](https://github.com/chrishayuk/chuk-mcp-client-oauth)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Code Quality](https://img.shields.io/badge/code%20quality-A+-success)](https://github.com/chrishayuk/chuk-mcp-client-oauth)

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

### OAuth 2.1 & MCP Compliance

This library implements:
- ✅ **OAuth 2.1 Best Practices** - Authorization Code + PKCE, no legacy grants
- ✅ **MCP Authorization Spec** - Protected Resource Metadata discovery (RFC 9728)
- ✅ **Resource Indicators** - Token binding to prevent reuse (RFC 8707)
- ✅ **WWW-Authenticate Fallback** - Discovery from 401/403 responses
- ✅ **Secure Token Storage** - OS keychain, encrypted files, HashiCorp Vault
- ✅ **Automatic Token Refresh** - Handles expiration transparently
- 🔄 **Device Code Flow** - Coming in v0.2.0 for headless environments

**Standards Compliance:**
- [OAuth 2.1 Draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-10) - Modern OAuth best practices
- [RFC 9728](https://datatracker.ietf.org/doc/html/rfc9728) - Protected Resource Metadata
- [RFC 8707](https://datatracker.ietf.org/doc/html/rfc8707) - Resource Indicators
- [RFC 8414](https://datatracker.ietf.org/doc/html/rfc8414) - Authorization Server Metadata Discovery
- [RFC 7591](https://datatracker.ietf.org/doc/html/rfc7591) - Dynamic Client Registration
- [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) - PKCE

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

### 30-Second Minimal Example

```python
import asyncio
from chuk_mcp_client_oauth import OAuthHandler

async def main():
    handler = OAuthHandler()  # Auto keychain/credential manager or encrypted file

    # Authenticate (opens browser once, then caches tokens)
    await handler.ensure_authenticated_mcp(
        server_name="notion",
        server_url="https://mcp.notion.com/mcp",
        scopes=["read", "write"],
    )

    # Get ready-to-use headers for any HTTP/SSE/WebSocket call
    headers = await handler.prepare_headers_for_mcp_server(
        "notion",
        "https://mcp.notion.com/mcp"
    )
    print(headers["Authorization"][:30], "...")

asyncio.run(main())
```

**That's it!** Subsequent runs use cached tokens—no browser needed. See [Complete MCP Session](#using-the-tokens---complete-mcp-example) for full JSON-RPC + SSE example.

---

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

**Using macOS Keychain (Explicit):**

```python
import asyncio
from chuk_mcp_client_oauth import OAuthHandler, TokenManager, TokenStoreBackend

async def main():
    # Explicitly use macOS Keychain for token storage
    # NOTE: 'keyring' library is automatically installed on macOS/Windows
    # No password needed - uses macOS Keychain Access
    token_manager = TokenManager(backend=TokenStoreBackend.KEYCHAIN)
    handler = OAuthHandler(token_manager=token_manager)

    # Authenticate with a server (tokens stored in macOS Keychain)
    tokens = await handler.ensure_authenticated_mcp(
        server_name="notion-mcp",
        server_url="https://mcp.notion.com/mcp",
        scopes=["read", "write"]
    )

    print(f"✅ Authenticated! Token stored in macOS Keychain")
    print(f"🔑 Access Token: {tokens.access_token[:20]}...")

    # You can verify this in Keychain Access app:
    # 1. Open Keychain Access
    # 2. Search for "chuk-oauth"
    # 3. You'll see "notion-mcp" entry under the "chuk-oauth" service

asyncio.run(main())
```

**Using the Tokens - Complete MCP Example:**

Now let's use those tokens to actually interact with Notion MCP - listing available tools:

```python
import asyncio
import uuid
from chuk_mcp_client_oauth import OAuthHandler, parse_sse_json

async def list_notion_tools():
    """Complete example: Authenticate and list Notion MCP tools."""
    handler = OAuthHandler()
    server_name = "notion-mcp"
    server_url = "https://mcp.notion.com/mcp"

    # Authenticate (uses cached tokens if available)
    print("🔐 Authenticating with Notion MCP...")
    tokens = await handler.ensure_authenticated_mcp(
        server_name=server_name,
        server_url=server_url,
        scopes=["read", "write"]
    )
    print(f"✅ Authenticated! Token: {tokens.access_token[:20]}...")

    # Now use the tokens to make authenticated requests
    session_id = str(uuid.uuid4())

    # Step 1: Initialize MCP session
    print("\n📋 Initializing MCP session...")
    init_response = await handler.authenticated_request(
        server_name=server_name,
        server_url=server_url,
        url=server_url,
        method="POST",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"roots": {"listChanged": True}},
                "clientInfo": {"name": "quickstart-example", "version": "1.0.0"}
            }
        },
        headers={
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json"
        },
        timeout=60.0  # MCP initialization can be slow
    )

    # Extract session ID from response header
    session_id = init_response.headers.get('mcp-session-id', session_id)
    print(f"   ✅ Session initialized: {session_id[:16]}...")

    # Step 2: Send initialized notification
    await handler.authenticated_request(
        server_name=server_name,
        server_url=server_url,
        url=server_url,
        method="POST",
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        headers={
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "Mcp-Session-Id": session_id
        },
        timeout=30.0
    )

    # Step 3: List tools (this is where we use the Bearer token!)
    print("\n🔧 Listing available tools...")
    tools_response = await handler.authenticated_request(
        server_name=server_name,
        server_url=server_url,
        url=server_url,
        method="POST",
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        headers={
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "Mcp-Session-Id": session_id
            # Note: Authorization: Bearer <token> is automatically added!
        },
        timeout=30.0
    )

    # Parse SSE response (MCP servers often return text/event-stream)
    content_type = tools_response.headers.get('content-type', '')
    if 'text/event-stream' in content_type:
        data = parse_sse_json(tools_response.text.strip().splitlines())
    else:
        data = tools_response.json()

    # Display the tools
    if "result" in data and "tools" in data["result"]:
        tools = data["result"]["tools"]
        print(f"\n📦 Found {len(tools)} Notion tools:")
        for tool in tools[:5]:  # Show first 5
            print(f"   • {tool.get('name', 'Unknown')}")
            if 'description' in tool:
                desc = tool['description']
                print(f"     {desc[:80]}{'...' if len(desc) > 80 else ''}")
        if len(tools) > 5:
            print(f"   ... and {len(tools) - 5} more")

    print("\n✅ Complete! Your Bearer token was automatically used in all requests.")
    print(f"   The library added: Authorization: Bearer {tokens.access_token[:20]}...")
    print("   to every HTTP request above.")

asyncio.run(list_notion_tools())
```

**Output:**
```
🔐 Authenticating with Notion MCP...
✅ Authenticated! Token: 282c6a79-d66f-402e-a...

📋 Initializing MCP session...
   ✅ Session initialized: d6b130b8684f5ee9...

🔧 Listing available tools...

📦 Found 15 Notion tools:
   • notion-search
     Perform a search over: - "internal": Semantic search over Notion workspace and c...
   • notion-fetch
     Retrieves details about a Notion entity (page or database) by URL or ID.
Provide...
   • notion-create-pages
     ## Overview
Creates one or more Notion pages, with the specified properties and ...
   • notion-update-page
     ## Overview
Update a Notion page's properties or content.
## Properties
Notion p...
   • notion-move-pages
     Move one or more Notion pages or databases to a new parent.
   ... and 10 more

✅ Complete! Your Bearer token was automatically used in all requests.
   The library added: Authorization: Bearer 282c6a79-d66f-402e-a...
   to every HTTP request above.
```

**What happened behind the scenes:**

Every HTTP request included your Bearer token:
```http
POST /mcp HTTP/1.1
Host: mcp.notion.com
Authorization: Bearer 282c6a79-d66f-402e-a8f4-27b1c5d3e6f7...
Accept: application/json, text/event-stream
Content-Type: application/json
Mcp-Session-Id: d6b130b8684f5ee9...

{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
```

The `authenticated_request()` method:
1. ✅ Retrieved your cached tokens (no re-authentication needed)
2. ✅ Added `Authorization: Bearer <token>` header to every request
3. ✅ Parsed SSE responses automatically
4. ✅ Would have refreshed the token if server returned 401

**Using a Custom Service Name (for your application):**

```python
import asyncio
from chuk_mcp_client_oauth import OAuthHandler, TokenManager, TokenStoreBackend

async def main():
    # Use your own application name for keychain entries
    token_manager = TokenManager(
        backend=TokenStoreBackend.KEYCHAIN,
        service_name="my-awesome-app"  # Custom service name
    )
    handler = OAuthHandler(token_manager=token_manager)

    tokens = await handler.ensure_authenticated_mcp(
        server_name="notion-mcp",
        server_url="https://mcp.notion.com/mcp",
        scopes=["read", "write"]
    )

    print(f"✅ Authenticated! Token stored under 'my-awesome-app' service")

    # In Keychain Access, search for "my-awesome-app" instead of "chuk-oauth"
    # This helps organize tokens for your specific application

asyncio.run(main())
```

**Platform-Specific Token Storage:**
- **macOS**: `keyring` is automatically installed → Uses macOS Keychain (no password needed)
- **Windows**: `keyring` is automatically installed → Uses Windows Credential Manager (no password needed)
- **Linux**: Install with `pip install chuk-mcp-client-oauth[linux]` → Uses Secret Service (GNOME/KDE)
- **All platforms**: Falls back to encrypted file storage if platform backend unavailable

**That's it!** The library handles:
- ✅ OAuth server discovery
- ✅ Dynamic client registration
- ✅ Opening browser for user consent
- ✅ Receiving the callback
- ✅ Exchanging codes for tokens
- ✅ Storing tokens securely
- ✅ Reusing tokens on subsequent runs
- ✅ Refreshing expired tokens

**What happens on each run:**
- **First run**: Opens browser for authentication → Saves tokens to storage
- **Second run**: Loads cached tokens → No browser needed
- **Re-running after clearing tokens**: Opens browser again (like first run)

**Quick Reference: Clearing tokens to re-run quickstart**
```bash
# Method 1: Using CLI (works for all storage backends)
uvx chuk-mcp-client-oauth clear notion-mcp

# Method 2: macOS Keychain (if using Keychain storage)
security delete-generic-password -s "chuk-oauth" -a "notion-mcp"

# Method 3: Delete encrypted file (if using file storage)
rm ~/.chuk_oauth/tokens/notion-mcp.enc
rm ~/.chuk_oauth/tokens/notion-mcp_client.json

# After clearing, run the quickstart again - browser will open
```

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

**Discovery** - How the client finds OAuth configuration
- **MCP-Compliant (RFC 9728)**: Protected Resource Metadata at `/.well-known/oauth-protected-resource`
  - Points to Authorization Server metadata
  - Includes resource identifier for token binding
- **Fallback (Legacy)**: Direct AS discovery at `/.well-known/oauth-authorization-server`
- **WWW-Authenticate Fallback**: PRM URL from 401/403 response headers
- Automatically discovered by this library with fallback support

**Resource Indicators (RFC 8707)** - Token binding to specific resources
- Tokens are bound to the specific MCP server resource
- Prevents token reuse across different resources
- Automatically included in token requests

---

## 📊 Flow Diagrams

### Auth Code + PKCE (Desktop/CLI with Browser)

This is the **primary flow** used by this library for interactive applications:

```
┌──────────────────┐        ┌──────────────┐         ┌──────────────────────┐        ┌───────────────┐
│  MCP Client      │        │  User        │         │  OAuth 2.1 Server    │        │  MCP Server    │
│  (CLI / Agent)   │        │  Browser     │         │  (Auth + Token)      │        │               │
└──┬───────────────┘        └──────┬───────┘         └──────────┬───────────┘        └───────┬───────┘
   │ 1) GET /.well-known/oauth-protected-resource (RFC 9728)   │                             │
   ├────────────────────────────────────────────────────────────────────────────────────────▶│
   │                                                           │ 2) PRM: resource ID,        │
   │◀────────────────────────────────────────────────────────────────────────────────────────┤    AS URLs
   │                                                           │                             │
   │ 3) GET AS metadata from PRM.authorization_servers[0]     │                             │
   ├──────────────────────────────────────────────────────────▶│                             │
   │                                                           │ 4) AS metadata: endpoints   │
   │◀───────────────────────────────────────────────────────────┤                            │
   │                                                           │                             │
   │ 5) Build Auth URL (PKCE: code_challenge)                  │                             │
   │ 6) Open browser ----------------------------------------▶ │                             │
   │                                                           │ 7) User login + consent     │
   │                                                           │◀────────────────────────────┤
   │                                                           │ 8) Redirect with ?code=...  │
   │◀───────────────────────────────────────────────────────────┤  to http://127.0.0.1:PORT   │
   │ 9) Local redirect handler captures code + state           │                             │
   │ 10) POST /token (code + code_verifier + resource=MCP_URL) │                             │
   ├──────────────────────────────────────────────────────────▶│                             │
   │                                                           │ 11) access_token + refresh  │
   │◀───────────────────────────────────────────────────────────┤     (bound to resource)    │
   │ 12) Store tokens securely (keyring / pluggable)           │                             │
   │                                                           │                             │
   │ 13) Connect to MCP with Authorization: Bearer <token>     │                             │
   ├────────────────────────────────────────────────────────────────────────────────────────▶│
   │                                                           │                             │ 14) Session OK
   │◀────────────────────────────────────────────────────────────────────────────────────────┤
   │                                                           │                             │
   │ 15) (When expired) POST /token (refresh_token + resource=MCP_URL)                       │
   ├──────────────────────────────────────────────────────────▶│                             │
   │                                                           │ 16) New access/refresh      │
   │◀───────────────────────────────────────────────────────────┤     -> update secure store │
   │                                                           │                             │
```

**Legend:**
- **PKCE**: `code_challenge = SHA256(code_verifier)` (sent at authorize), `code_verifier` (sent at token)
- **PRM**: Protected Resource Metadata (RFC 9728) - MCP-compliant discovery
- **Resource Indicators**: `resource=` parameter binds tokens to specific MCP server (RFC 8707)
- Tokens are stored in OS keychain (or pluggable secure backend)
- MCP requests carry `Authorization: Bearer <access_token>`

### MCP-Compliant Discovery Flow (RFC 9728)

The library implements the **MCP-specified discovery flow** with automatic fallback:

```
🔍 Discovery Attempt 1: Protected Resource Metadata (MCP-Compliant)
   ┌─────────────────────────────────────────────────────────────┐
   │ GET /.well-known/oauth-protected-resource                   │
   │ → Returns: {                                                │
   │     "resource": "https://mcp.notion.com/mcp",               │
   │     "authorization_servers": [                              │
   │       "https://auth.notion.com/.well-known/oauth-as"        │
   │     ]                                                       │
   │   }                                                         │
   └─────────────────────────────────────────────────────────────┘
                              ↓
   ┌─────────────────────────────────────────────────────────────┐
   │ GET https://auth.notion.com/.well-known/oauth-as            │
   │ → Returns AS metadata (authorization_endpoint, etc.)        │
   └─────────────────────────────────────────────────────────────┘

❌ If PRM fails (404/500):

🔍 Discovery Attempt 2: Direct AS Discovery (Fallback)
   ┌─────────────────────────────────────────────────────────────┐
   │ GET /.well-known/oauth-authorization-server                 │
   │ → Returns AS metadata directly                              │
   └─────────────────────────────────────────────────────────────┘

❌ If both fail, check WWW-Authenticate header:

🔍 Discovery Attempt 3: WWW-Authenticate Fallback
   ┌─────────────────────────────────────────────────────────────┐
   │ On 401/403 response:                                        │
   │ WWW-Authenticate: Bearer                                    │
   │   resource_metadata="https://mcp.example.com/.well-known/..." │
   │ → Extract PRM URL and try again                             │
   └─────────────────────────────────────────────────────────────┘
```

**Why this matters:**
- ✅ **MCP Spec Compliant**: Follows Model Context Protocol authorization specification
- ✅ **Token Binding**: Resource indicators prevent token reuse across servers
- ✅ **Backward Compatible**: Falls back to legacy discovery for older servers
- ✅ **Automatic**: Library handles all discovery methods transparently

### Device Code Flow (Headless TTY / SSH Agents)

**Coming in v0.2.0** - Perfect for SSH-only boxes, CI runners, and background agents.

**Planned API:**

```python
import asyncio
from chuk_mcp_client_oauth import OAuthHandler

async def main():
    handler = OAuthHandler()

    # Device code flow for headless environments
    await handler.ensure_authenticated_mcp_device(
        server_name="notion",
        server_url="https://mcp.notion.com/mcp",
        scopes=["read", "write"],
        prompt=lambda code, url: print(f"🔐 Go to {url} and enter code: {code}")
    )

    # Rest is identical to auth code flow
    headers = await handler.prepare_headers_for_mcp_server(
        "notion",
        "https://mcp.notion.com/mcp"
    )

asyncio.run(main())
```

**Use cases:**
- SSH-only servers
- CI/CD pipelines
- Background agents
- Shared/headless environments

**Flow diagram:**

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

### MCP-Compliant Discovery (Do This First)

**Per the MCP specification**, clients must discover OAuth endpoints via Protected Resource Metadata (RFC 9728):

**Step 1: Discover Protected Resource Metadata (PRM)**
```bash
# MCP-compliant discovery starts here
GET <mcp_server>/.well-known/oauth-protected-resource
```

**Example PRM Response:**
```json
{
  "resource": "https://mcp.notion.com/mcp",
  "authorization_servers": [
    "https://mcp.notion.com/.well-known/oauth-authorization-server"
  ],
  "scopes_supported": ["read", "write"],
  "bearer_methods_supported": ["header"]
}
```

**Key PRM fields:**
- `resource` - The resource identifier (use this in `resource=` parameter for token requests)
- `authorization_servers` - Array of AS metadata URLs to fetch next

**Step 2: Fetch Authorization Server Metadata**
```bash
# Follow the URL from PRM's authorization_servers[0]
GET <authorization_server_url>
```

**Example AS Metadata Response:**
```json
{
  "issuer": "https://mcp.notion.com",
  "authorization_endpoint": "https://mcp.notion.com/authorize",
  "token_endpoint": "https://mcp.notion.com/token",
  "registration_endpoint": "https://mcp.notion.com/register",
  "revocation_endpoint": "https://mcp.notion.com/token",
  "response_types_supported": ["code"],
  "response_modes_supported": ["query"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "code_challenge_methods_supported": ["plain", "S256"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"]
}
```

**Key AS Metadata fields:**
- `authorization_endpoint` - Where users approve your app
- `token_endpoint` - Where you exchange codes for tokens
- `registration_endpoint` - Where you register as a client
- `code_challenge_methods_supported` - PKCE support (S256 = SHA-256)

**Step 3: Include Resource Indicator in Token Requests**

When requesting tokens, include the `resource` parameter from PRM (RFC 8707):

```http
POST /token HTTP/1.1
Host: mcp.notion.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=AUTH_CODE
&redirect_uri=http://localhost:8080/callback
&client_id=CLIENT_ID
&code_verifier=CODE_VERIFIER
&resource=https://mcp.notion.com/mcp
```

This binds the token to the specific MCP resource, preventing token reuse across different servers.

### WWW-Authenticate Fallback

**If PRM discovery fails**, MCP servers **SHOULD** (per MCP spec convention) include the PRM URL in 401/403 responses via the `WWW-Authenticate` header:

> **Note**: The `resource_metadata` parameter is an **MCP-specific convention**, not part of core RFC 6750 (Bearer Token Usage). It extends the standard Bearer authentication scheme to enable OAuth discovery from error responses, as specified in the Model Context Protocol authorization specification.

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="mcp",
  resource_metadata="https://mcp.notion.com/.well-known/oauth-protected-resource"
```

**Example header formats:**
```
WWW-Authenticate: Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"

WWW-Authenticate: Bearer realm="mcp", error="invalid_token",
  resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"
```

The client should:
1. Parse the `resource_metadata` URL from the header
2. Fetch the PRM document from that URL
3. Continue with normal discovery flow (Step 2 above)

### Legacy Fallback (Non-MCP Servers)

For **backward compatibility** with servers that don't implement PRM discovery, the library falls back to direct AS discovery:

```bash
# Legacy OAuth servers (pre-MCP)
GET <server_url>/.well-known/oauth-authorization-server
```

**Discovery priority:**
1. ✅ **First**: Try PRM at `/.well-known/oauth-protected-resource` (MCP-compliant)
2. ✅ **Second**: Check `WWW-Authenticate` header on 401/403 responses
3. ✅ **Third**: Fall back to direct AS discovery (legacy compatibility)

### How This Library Uses Discovery

When you call:
```python
tokens = await handler.ensure_authenticated_mcp(
    server_name="notion-mcp",
    server_url="https://mcp.notion.com/mcp",
    scopes=["read", "write"]
)
```

Behind the scenes (MCP-compliant flow):
1. **PRM Discovery**: Fetches `https://mcp.notion.com/.well-known/oauth-protected-resource`
2. **Extract Resource**: Saves the `resource` identifier for token binding (RFC 8707)
3. **AS Discovery**: Fetches AS metadata from `authorization_servers[0]` URL
4. **Parse**: Extracts `authorization_endpoint`, `token_endpoint`, etc.
5. **Validate**: Checks that PKCE is supported
6. **Cache**: Saves the configuration for future use
7. **Token Requests**: Includes `resource=` parameter in all token requests
8. **Proceed**: Uses the discovered endpoints for OAuth flow

**Fallback**: If PRM discovery fails, falls back to direct AS discovery for legacy server compatibility.

### Manual Discovery (Advanced)

You can also discover endpoints manually:

```python
import asyncio
from chuk_mcp_client_oauth import MCPOAuthClient

async def discover_endpoints():
    client = MCPOAuthClient(
        server_url="https://mcp.notion.com/mcp",
        redirect_uri="http://localhost:8080/callback"
    )

    # Discover OAuth configuration
    metadata = await client.discover_authorization_server()

    # Now you can inspect the discovered endpoints
    print(f"Authorization URL: {metadata.authorization_endpoint}")
    print(f"Token URL: {metadata.token_endpoint}")
    print(f"Registration URL: {metadata.registration_endpoint}")
    print(f"Supported scopes: {metadata.scopes_supported}")
    print(f"PKCE methods: {metadata.code_challenge_methods_supported}")

# Run the async function
asyncio.run(discover_endpoints())
```

### Testing Discovery with curl

You can test if a server supports MCP-compliant OAuth discovery:

```bash
# Step 1: Test PRM discovery (MCP-compliant)
curl https://mcp.notion.com/.well-known/oauth-protected-resource

# Expected response:
# {
#   "resource": "https://mcp.notion.com/mcp",
#   "authorization_servers": ["https://mcp.notion.com/.well-known/oauth-authorization-server"],
#   "scopes_supported": ["read", "write"]
# }

# Step 2: Test AS discovery (from PRM's authorization_servers[0])
curl https://mcp.notion.com/.well-known/oauth-authorization-server

# Expected response: AS metadata with endpoints

# Test your own MCP server
curl https://your-server.com/.well-known/oauth-protected-resource
```

**Expected responses:**
- **PRM**: JSON with `resource`, `authorization_servers`, `scopes_supported`
- **AS Metadata**: JSON with `authorization_endpoint`, `token_endpoint`, etc.

**Common errors:**
- `404 Not Found` on PRM - Server may not be MCP-compliant (library will fall back to direct AS discovery)
- `404 Not Found` on both - Server doesn't support OAuth discovery at all
- `Connection refused` - Server URL is incorrect
- `Invalid JSON` - Server has misconfigured OAuth
- `{"error":"invalid_token"}` - Discovery endpoint is incorrectly protected (should be public)

**Testing WWW-Authenticate fallback:**
```bash
# Make an unauthenticated request to a protected endpoint
curl -i https://mcp.example.com/mcp

# Look for header:
# WWW-Authenticate: Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"
```

### Discovery Specification

**MCP OAuth discovery follows:**
- **RFC 9728** - Protected Resource Metadata (PRM) - Primary discovery method
- **RFC 8414** - OAuth 2.0 Authorization Server Metadata - Secondary discovery from PRM
- **RFC 8707** - Resource Indicators - Token binding with `resource=` parameter

**PRM (/.well-known/oauth-protected-resource) must have:**
- `resource` - Resource identifier (used in token requests)
- `authorization_servers` - Array of AS metadata URLs

**AS Metadata (/.well-known/oauth-authorization-server) must have:**
- `issuer` - Server identifier
- `authorization_endpoint` - Where to send users
- `token_endpoint` - Where to get tokens

**Should have (for MCP):**
- `registration_endpoint` - Dynamic client registration (RFC 7591)
- `code_challenge_methods_supported: ["S256"]` - PKCE support
- `revocation_endpoint` - Token revocation (RFC 7009)

**Example of checking if a server supports MCP OAuth:**

```python
import asyncio
import httpx

async def check_mcp_oauth_support(server_url: str) -> bool:
    """Check if a server supports MCP-compliant OAuth."""
    # Step 1: Check PRM discovery (MCP-compliant)
    prm_url = f"{server_url}/.well-known/oauth-protected-resource"

    try:
        async with httpx.AsyncClient() as client:
            # Try PRM discovery first
            prm_response = await client.get(prm_url)

            if prm_response.status_code != 200:
                print(f"⚠️  No PRM support (falling back to legacy discovery)")
                # Try legacy AS discovery
                as_url = f"{server_url}/.well-known/oauth-authorization-server"
                as_response = await client.get(as_url)

                if as_response.status_code != 200:
                    print(f"❌ No OAuth support at all")
                    return False

                print("✅ Server supports legacy OAuth (not MCP-compliant)")
                return True

            prm = prm_response.json()

            # Check required PRM fields
            if "resource" not in prm or "authorization_servers" not in prm:
                print("❌ Invalid PRM document")
                return False

            # Step 2: Check AS metadata from PRM
            as_url = prm["authorization_servers"][0]
            as_response = await client.get(as_url)

            if as_response.status_code != 200:
                print(f"❌ AS metadata not available")
                return False

            as_config = as_response.json()

            # Check required AS metadata fields
            required = ["authorization_endpoint", "token_endpoint"]
            if not all(field in as_config for field in required):
                print("❌ Missing required OAuth endpoints")
                return False

            # Check for PKCE support
            if "S256" not in as_config.get("code_challenge_methods_supported", []):
                print("⚠️  PKCE not supported (less secure)")

            # Check for dynamic registration
            if "registration_endpoint" not in as_config:
                print("⚠️  No dynamic registration (manual setup required)")

            print("✅ Server supports MCP-compliant OAuth")
            print(f"   Resource: {prm['resource']}")
            print(f"   Auth: {as_config['authorization_endpoint']}")
            print(f"   Token: {as_config['token_endpoint']}")
            return True

    except Exception as e:
        print(f"❌ Discovery failed: {e}")
        return False

# Usage
asyncio.run(check_mcp_oauth_support("https://mcp.notion.com/mcp"))
```

---

## 📦 Installation Options

```bash
# Basic installation
# - macOS: Automatically includes keyring for Keychain support
# - Windows: Automatically includes keyring for Credential Manager support
# - Linux: Uses encrypted file storage by default
uv add chuk-mcp-client-oauth

# Linux with Secret Service support (GNOME/KDE)
uv add chuk-mcp-client-oauth --extra linux

# With HashiCorp Vault support
uv add chuk-mcp-client-oauth --extra vault

# All optional features
uv add chuk-mcp-client-oauth --extra all

# Development installation (includes testing tools)
git clone https://github.com/chrishayuk/chuk-mcp-client-oauth.git
cd chuk-mcp-client-oauth
uv sync --all-extras
```

**Platform-specific dependencies:**
- **macOS/Windows**: `keyring` is installed automatically (no action needed)
- **Linux**: Add `[linux]` extra for Secret Service support, otherwise uses encrypted files
- **Enterprise**: Add `[vault]` extra for HashiCorp Vault integration

**What gets installed on your platform:**

| Platform | Automatic Dependencies | Storage Used |
|----------|----------------------|--------------|
| macOS | `keyring>=24.0.0` | macOS Keychain (no password) |
| Windows | `keyring>=24.0.0` | Credential Manager (no password) |
| Linux | None (encrypted files) | Encrypted files (password prompt) |
| Linux + [linux] | `keyring>=24.0.0`, `secretstorage>=3.3.0` | Secret Service (no password) |

---

## 💡 Usage Examples

### Example 1: CLI Tool with Token Management

```python
import asyncio
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
tokens = asyncio.run(connect_to_server("notion-mcp", "https://mcp.notion.com/mcp"))
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
import asyncio
from chuk_mcp_client_oauth import MCPOAuthClient

async def manual_oauth_flow():
    """Full control over the OAuth process."""
    client = MCPOAuthClient(
        server_url="https://mcp.example.com",
        redirect_uri="http://localhost:8080/callback"
    )

    # Step 1: Discover OAuth endpoints
    metadata = await client.discover_authorization_server()
    print(f"📍 Auth URL: {metadata.authorization_endpoint}")
    print(f"📍 Token URL: {metadata.token_endpoint}")

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

# Run the async function
asyncio.run(manual_oauth_flow())
```

---

## 🗄️ Token Storage (Secure & Automatic)

### How Storage Works

The library automatically stores tokens in the **most secure location** for your platform:

| Platform | Storage Backend | Auto-Installed | Description |
|----------|----------------|----------------|-------------|
| **macOS** | Keychain | ✅ Yes | Uses the macOS Keychain (same as Safari, Chrome) - No password needed |
| **Windows** | Credential Manager | ✅ Yes | Uses Windows Credential Manager - No password needed |
| **Linux** | Secret Service | [linux] extra | Uses GNOME Keyring or KDE Wallet - No password needed |
| **Vault** | HashiCorp Vault | [vault] extra | For enterprise deployments |
| **Fallback** | Encrypted Files | ✅ Always | AES-256 encrypted files (requires password) |

### Storage Directory

By default, tokens are stored in:
```
~/.chuk_oauth/tokens/
```

For encrypted file storage:
- Each server gets its own encrypted file: `<server_name>.enc`
- Files are encrypted with AES-256
- Client registration stored as: `<server_name>_client.json`
- Encryption salt stored as: `.salt`
- You can set a custom password or let it auto-generate

**Example directory structure:**
```bash
$ ls -la ~/.chuk_oauth/tokens/
total 24
drwx------  5 user  staff  160 Nov  1 12:38 .
drwxr-xr-x  4 user  staff  128 Nov  1 12:38 ..
-rw-------  1 user  staff   16 Nov  1 12:38 .salt
-rw-------  1 user  staff  132 Nov  1 12:38 notion-mcp_client.json
-rw-------  1 user  staff  504 Nov  1 12:38 notion-mcp.enc
```

### Inspecting and Clearing Tokens

**Check what tokens are stored:**
```bash
# List all stored tokens
uvx chuk-mcp-client-oauth list

# Get details for a specific server (safely redacted)
uvx chuk-mcp-client-oauth get notion-mcp
```

**Clear tokens to re-run demos:**
```bash
# Option 1: Clear specific server tokens (recommended)
uvx chuk-mcp-client-oauth clear notion-mcp

# Option 2: Logout and revoke with server (best practice)
uvx chuk-mcp-client-oauth logout notion-mcp --url https://mcp.notion.com/mcp

# Option 3: Manual deletion of encrypted files
rm ~/.chuk_oauth/tokens/notion-mcp.enc
rm ~/.chuk_oauth/tokens/notion-mcp_client.json

# Option 4: Delete all tokens
rm -rf ~/.chuk_oauth/
```

**For macOS Keychain storage:**

Using Keychain Access app (GUI):
```
1. Open "Keychain Access" app (in Applications > Utilities)
2. Make sure "login" keychain is selected (left sidebar)
3. Search for "chuk-oauth" in the search box (top right)
4. You'll see entries like "notion-mcp" under the service "chuk-oauth"
5. Right-click on the entry → "Delete"
6. Confirm deletion
```

Using command line:
```bash
# Delete specific server token (e.g., notion-mcp)
security delete-generic-password -s "chuk-oauth" -a "notion-mcp"

# List all tokens stored by this library
security find-generic-password -s "chuk-oauth"

# Search for all entries (shows details)
security find-generic-password -s "chuk-oauth" -g

# Delete all tokens for this library (careful!)
# First, list them to see what you'll delete
security dump-keychain | grep -A 5 "chuk-oauth"
# Then delete each one individually using the account name
```

**Example: Delete notion-mcp token from Keychain**
```bash
# Method 1: Using security command
security delete-generic-password -s "chuk-oauth" -a "notion-mcp"

# Method 2: Using the CLI tool (recommended - also clears client registration)
uvx chuk-mcp-client-oauth clear notion-mcp

# Verify it's deleted
security find-generic-password -s "chuk-oauth" -a "notion-mcp"
# Should return: "The specified item could not be found in the keychain."
```

**Troubleshooting macOS Keychain:**

If you can't find tokens in Keychain Access:
```bash
# 1. Check if tokens are actually in Keychain
security find-generic-password -s "chuk-oauth"

# 2. If empty, check if using encrypted file storage instead
ls -la ~/.chuk_oauth/tokens/

# 3. Check which backend is being used
# Run your app and it should log which storage backend it's using
```

Common issues:
- **Can't find in Keychain Access app**: Make sure you're searching in the "login" keychain, not "System"
- **"Could not be found" error**: Token might already be deleted, or using file storage instead
- **Permission denied**: You may need to allow terminal/app to access Keychain in System Preferences > Privacy & Security

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

# Then use the chuk-mcp-client-oauth command
chuk-mcp-client-oauth auth notion-mcp https://mcp.notion.com/mcp
chuk-mcp-client-oauth list
chuk-mcp-client-oauth get notion-mcp
chuk-mcp-client-oauth test notion-mcp
chuk-mcp-client-oauth logout notion-mcp --url https://mcp.notion.com/mcp
chuk-mcp-client-oauth clear notion-mcp
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

## 💻 CLI Tool

The library includes a command-line interface for managing OAuth tokens and interacting with MCP servers:

### Quick Start

```bash
# Using uvx (no installation required)
uvx chuk-mcp-client-oauth --help

# Authenticate with an MCP server
uvx chuk-mcp-client-oauth auth notion-mcp https://mcp.notion.com/mcp

# List available tools from an MCP server
uvx chuk-mcp-client-oauth tools notion-mcp https://mcp.notion.com/mcp

# List all servers with tokens
uvx chuk-mcp-client-oauth list

# Get token for a specific server
uvx chuk-mcp-client-oauth get notion-mcp

# Test connection
uvx chuk-mcp-client-oauth test notion-mcp

# Logout (revoke tokens)
uvx chuk-mcp-client-oauth logout notion-mcp --url https://mcp.notion.com/mcp

# Clear tokens locally
uvx chuk-mcp-client-oauth clear notion-mcp
```

### CLI Commands

| Command | Description | Example |
|---------|-------------|---------|
| `auth` | Authenticate with MCP server | `uvx chuk-mcp-client-oauth auth notion-mcp https://mcp.notion.com/mcp` |
| `tools` | List available MCP tools | `uvx chuk-mcp-client-oauth tools notion-mcp https://mcp.notion.com/mcp` |
| `list` | List all stored tokens | `uvx chuk-mcp-client-oauth list` |
| `get` | View token for a server | `uvx chuk-mcp-client-oauth get notion-mcp` |
| `test` | Test connection with token | `uvx chuk-mcp-client-oauth test notion-mcp` |
| `logout` | Revoke and delete tokens | `uvx chuk-mcp-client-oauth logout notion-mcp --url https://mcp.notion.com/mcp` |
| `clear` | Delete tokens locally | `uvx chuk-mcp-client-oauth clear notion-mcp` |

### List MCP Tools

The `tools` command makes it easy to discover what an MCP server offers:

```bash
uvx chuk-mcp-client-oauth tools notion-mcp https://mcp.notion.com/mcp
```

**Output:**
```
============================================================
Listing Tools for notion-mcp
============================================================
🔐 Authenticating...
✅ Authenticated

📋 Initializing MCP session...
✅ Session initialized: 7b3c8d2f...

📨 Sending initialized notification...
✅ Notification sent

🔧 Listing available tools...

📦 Found 15 tools:

   • create_page
     Create a new page in Notion

   • search
     Search across your Notion workspace

   • get_page
     Retrieve a specific page by ID

   ... and 12 more
```

This command:
- Authenticates with the MCP server (uses cached tokens if available)
- Initializes a proper MCP session following the protocol
- Sends the required `initialized` notification
- Lists all available tools with descriptions
- Perfect for discovering what an MCP server can do without writing code

---

## 📚 Working Examples

The library includes complete, working examples:

### 1. Authenticated Requests (`authenticated_requests.py`) ✅ **NEW!**
**What it shows:** Complete authenticated requests with SSE support
```bash
uv run examples/authenticated_requests.py
```
Demonstrates:
- ✅ **Working httpbin.org example** - REST API authentication
- ✅ **Complete Notion MCP example** - Full MCP session with SSE support
- Automatic token refresh on 401
- SSE (Server-Sent Events) response parsing
- MCP session initialization and tool listing
- Custom headers with authentication
- Manual 401 handling
- Error scenarios
- Token lifecycle explanation

**Interactive examples:**
1. httpbin.org REST API (working demo)
2. Complete Notion MCP session (15 tools listed)
3. Custom headers with JSON-RPC
4. Manual 401 handling
5. Error handling scenarios
6. Token lifecycle explanation

### 2. Basic MCP OAuth (`basic_mcp_oauth.py`)
**What it shows:** Complete OAuth flow from scratch
```bash
uv run examples/basic_mcp_oauth.py
# Or with custom server
uv run examples/basic_mcp_oauth.py https://your-mcp-server.com/mcp
```

### 3. OAuth Handler (`oauth_handler_example.py`)
**What it shows:** High-level API with token caching
```bash
uv run examples/oauth_handler_example.py
```
Demonstrates:
- MCP OAuth with Notion
- Token caching and reuse
- Token validation
- Header preparation

### 4. Token Storage (`token_storage_example.py`)
**What it shows:** Different storage backends
```bash
uv run examples/token_storage_example.py
```
Demonstrates:
- Auto-detection
- Encrypted file storage
- Keychain integration
- Vault integration

### 5. CLI Tool (`oauth_cli.py`)
**What it shows:** Complete token management tool
```bash
uv run examples/oauth_cli.py --help
```

All examples are **fully functional** and tested with real MCP servers (Notion MCP).

---

## 🔧 API Reference

### Quick Reference

| Class / Function | Purpose | Most Used Methods |
|-----------------|---------|-------------------|
| `OAuthHandler` | High-level "just work" client | `ensure_authenticated_mcp()`, `prepare_headers_for_mcp_server()`, `authenticated_request()`, `logout()` |
| `MCPOAuthClient` | Low-level OAuth controls | `discover_authorization_server()`, `register_client()`, `authorize()`, `refresh_token()`, `revoke_token()` |
| `TokenManager` | Secure token storage | `save_tokens()`, `load_tokens()`, `has_valid_tokens()`, `delete_tokens()` |
| `TokenStoreBackend` | Storage backend enum | `AUTO`, `KEYCHAIN`, `ENCRYPTED_FILE`, `VAULT`, `LINUX_SECRET_SERVICE` |
| `parse_sse_json()` | SSE response parser | Converts `text/event-stream` responses to JSON |

---

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

### Built-in Security Guardrails

1. **Loopback-Only Redirect URIs (RFC 8252)**
   - Default redirect URI: `http://127.0.0.1:<random-port>/callback`
   - Uses `127.0.0.1` (not `localhost`) to prevent DNS rebinding attacks
   - Random port selection prevents port hijacking
   - Custom hosts rejected unless explicitly allowed (advanced use only)

2. **TLS Enforcement**
   - Public APIs do **not** expose a `verify=False` escape hatch
   - All OAuth endpoints must use HTTPS (except loopback for callbacks)
   - For development with custom CAs, pass a custom `httpx.AsyncClient` with trusted CA bundle

3. **Refresh Token Binding**
   - Refresh tokens only sent to the discovered `token_endpoint` for the **same issuer + resource**
   - Binds to PRM `resource` identifier (RFC 8707)
   - Prevents token reuse across different MCP servers

4. **PKCE Enforcement (RFC 7636)**
   - PKCE with S256 (SHA-256) **always** used for authorization code flow
   - Code verifier never written to disk (memory-only during flow)
   - State parameter (256 bits entropy) validates callback authenticity
   - Prevents authorization code interception attacks

5. **Token Storage Encryption**
   - Platform-native secure storage (macOS Keychain, Windows Credential Manager, Linux Secret Service)
   - Fallback: AES-256-GCM encryption with PBKDF2-HMAC-SHA256 (600,000 iterations)
   - Files created with mode 0600 (owner read/write only)
   - Unique salt and IV per token file

6. **Automatic Expiration Tracking**
   - Tracks token expiration timestamps
   - Validates tokens before use
   - Automatic refresh when tokens expire
   - No plaintext storage - all tokens encrypted or in secure OS storage

7. **Scope Validation**
   - Ensures requested scopes match granted scopes
   - Prevents scope escalation attacks

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
| **HTTP Requests** | ✅ | Standard HTTP headers with JSON/JSON-RPC |
| **SSE (Server-Sent Events)** | ✅ **NEW!** | Auth header in initial connection + SSE response parsing |
| **WebSocket** | ✅ | Auth header in handshake |
| **Automatic 401 Retry** | ✅ **NEW!** | Token refresh and request retry on unauthorized |
| **MCP Session Management** | ✅ **NEW!** | Session initialization, notifications, and session IDs |
| **Timeout Support** | ✅ **NEW!** | Configurable timeouts for slow MCP operations |

**How tokens are attached to MCP requests:**
```python
# The library adds this header to all MCP HTTP requests:
headers = {
    "Authorization": f"Bearer {access_token}",
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
    "Mcp-Session-Id": "<session-id>"  # For MCP session requests
}

# For SSE responses (common in MCP), the library can parse:
# Response format:
#   event: message
#   data: {"jsonrpc":"2.0","result":{...}}
#
# Automatically parsed to JSON with parse_sse_response()
```

### Making Authenticated Requests with Auto-Refresh

The library provides `authenticated_request()` which handles the complete request lifecycle, including automatic token refresh on 401 responses and SSE (Server-Sent Events) response parsing:

```python
import asyncio
from chuk_mcp_client_oauth import OAuthHandler

async def main():
    handler = OAuthHandler()

    # Make authenticated JSON-RPC request to MCP server
    # Supports both JSON and SSE response formats
    response = await handler.authenticated_request(
        server_name="notion-mcp",
        server_url="https://mcp.notion.com/mcp",
        url="https://mcp.notion.com/mcp",
        method="POST",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        },
        headers={
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "Mcp-Session-Id": "<session-id>"
        },
        timeout=30.0  # Optional timeout in seconds
    )

    print(f"Status: {response.status_code}")

    # Parse response - automatically handles both JSON and SSE formats
    if 'text/event-stream' in response.headers.get('content-type', ''):
        # SSE response - parse it
        data = parse_sse_response(response.text)
    else:
        # Regular JSON response
        data = response.json()

    print(f"Response: {data}")

asyncio.run(main())
```

**Complete MCP Session Example:**
```python
import asyncio
import uuid
from chuk_mcp_client_oauth import OAuthHandler

async def mcp_session_example():
    handler = OAuthHandler()
    server_name = "notion-mcp"
    server_url = "https://mcp.notion.com/mcp"
    session_id = str(uuid.uuid4())

    # Step 1: Initialize MCP session
    init_response = await handler.authenticated_request(
        server_name=server_name,
        server_url=server_url,
        url=server_url,
        method="POST",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"roots": {"listChanged": True}},
                "clientInfo": {"name": "my-app", "version": "1.0.0"}
            }
        },
        headers={
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json"
        },
        timeout=60.0  # MCP initialization can be slow
    )

    # Extract session ID from response header
    session_id = init_response.headers.get('mcp-session-id', session_id)
    print(f"Session initialized: {session_id}")

    # Step 2: Send initialized notification
    await handler.authenticated_request(
        server_name=server_name,
        server_url=server_url,
        url=server_url,
        method="POST",
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        headers={
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "Mcp-Session-Id": session_id
        },
        timeout=30.0
    )

    # Step 3: List tools
    tools_response = await handler.authenticated_request(
        server_name=server_name,
        server_url=server_url,
        url=server_url,
        method="POST",
        json={"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        headers={
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "Mcp-Session-Id": session_id
        },
        timeout=30.0
    )

    print(f"Tools: {tools_response.json()}")

asyncio.run(mcp_session_example())
```

**SSE (Server-Sent Events) Support:**

Many MCP servers return responses in SSE format instead of plain JSON. The library works with both:

```python
def parse_sse_response(response_text: str) -> dict:
    """
    Parse Server-Sent Events (SSE) response format.

    SSE format example:
        event: message
        data: {"jsonrpc":"2.0","result":{...}}

    Returns the JSON data from the SSE message.
    """
    import json

    lines = response_text.strip().split('\n')
    data_lines = []

    for line in lines:
        if line.startswith('data: '):
            data_lines.append(line[6:])  # Remove 'data: ' prefix

    if data_lines:
        json_str = ''.join(data_lines)
        return json.loads(json_str)

    raise ValueError("No data found in SSE response")

# Use with authenticated_request:
response = await handler.authenticated_request(...)

content_type = response.headers.get('content-type', '')
if 'text/event-stream' in content_type:
    data = parse_sse_response(response.text)  # SSE format
else:
    data = response.json()  # Regular JSON
```

**POST requests with JSON:**
```python
# Create a new resource
response = await handler.authenticated_request(
    server_name="notion-mcp",
    server_url="https://mcp.notion.com/mcp",
    url="https://mcp.notion.com/mcp",
    method="POST",
    json={"jsonrpc": "2.0", "id": 1, "method": "resources/create", "params": {...}}
)
```

**Custom headers:**
```python
# Add custom headers to the authenticated request
response = await handler.authenticated_request(
    server_name="notion-mcp",
    server_url="https://mcp.notion.com/mcp",
    url="https://mcp.notion.com/mcp",
    method="POST",
    json={...},
    headers={
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "Mcp-Session-Id": session_id,
        "X-Custom-Header": "value"
    }
)
# Both Authorization and custom headers are included
```

**Disable automatic retry:**
```python
# If you want to handle 401 responses yourself
try:
    response = await handler.authenticated_request(
        server_name="notion-mcp",
        server_url="https://mcp.notion.com/mcp",
        url="https://mcp.notion.com/mcp",
        method="POST",
        json={...},
        retry_on_401=False  # Don't auto-refresh on 401
    )
except httpx.HTTPStatusError as e:
    if e.response.status_code == 401:
        print("Unauthorized - handle manually")
```

**How it works:**
1. ✅ Ensures you have valid tokens (gets/refreshes if needed)
2. ✅ Makes the HTTP request with `Authorization: Bearer <token>` header
3. ✅ Supports both JSON and SSE (Server-Sent Events) response formats
4. ✅ If server returns `401 Unauthorized`, automatically refreshes the token
5. ✅ Retries the request once with the new token
6. ✅ Returns the final response or raises `httpx.HTTPStatusError` if still unauthorized
7. ✅ Supports custom timeouts for slow operations (e.g., MCP initialization)

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
from chuk_mcp_client_oauth import OAuthHandler

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

async def main():
    """Main function to run the retry example."""
    try:
        tokens = await connect_with_retry("my-server", "https://mcp.example.com")
        print(f"✅ Connected successfully!")
    except Exception as e:
        print(f"❌ Failed after 3 retries: {e}")

# Usage
asyncio.run(main())
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

**Test Coverage:** 99% (467 tests passing)

### Test Coverage Matrix

| Test Category | What It Validates |
|--------------|-------------------|
| **PRM Happy Path** | PRM → AS → Auth Code + PKCE → Token (with `resource=`) |
| **Legacy AS Discovery** | Direct `.well-known/oauth-authorization-server` fallback |
| **WWW-Authenticate Bootstrap** | 401 header → PRM URL → discovery flow |
| **Refresh Rotation** | 401 → refresh token → retry → succeed |
| **SSE JSON-RPC** | `text/event-stream` parsing into JSON |
| **Storage Backends** | Keychain/Credential Manager/Secret Service/Encrypted File |
| **Vault Integration** | Read/write/rotate secrets in HashiCorp Vault |
| **Resource Indicators** | `resource=` parameter in token/refresh requests |
| **Token Revocation** | RFC 7009 revoke_token() implementation |
| **PKCE S256** | Code challenge generation and verification |
| **Dynamic Registration** | RFC 7591 client registration flow |
| **Token Expiration** | Automatic expiration tracking and refresh |

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
