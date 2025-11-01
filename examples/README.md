# chuk-mcp-client-oauth Examples

This directory contains example scripts demonstrating how to use the chuk-mcp-client-oauth library.

## Running the Examples

Make sure you have the library installed:

```bash
# Install the library
pip install -e .

# Or with uv
uv pip install -e .
```

## Examples

### 1. token_storage_example.py ✅ **Fully Working - No OAuth Server Required**

Demonstrates the various secure token storage backends available in the library.

```bash
uv run examples/token_storage_example.py
```

This example shows:
- Auto-detection of platform-specific storage
- Encrypted file storage
- macOS Keychain integration
- HashiCorp Vault integration (if configured)
- Token operations (save, load, delete, expiration checking)

**No OAuth server required** - This example uses mock tokens to demonstrate the storage functionality.

### 2. oauth_handler_example.py ✅ **Fully Working - Complete OAuth Workflow!**

End-to-end OAuth Handler example with **REAL Notion MCP authentication**.

```bash
uv run examples/oauth_handler_example.py
```

**✅ This performs actual OAuth authentication with Notion MCP!**

This example demonstrates:
- **Complete OAuth flow** with Notion MCP (discovery, registration, authorization)
- **Token caching** in memory and disk
- **Token reuse** - subsequent authentications use cached tokens
- **Header preparation** for API requests
- **Token validation** and expiration checking
- **Storage persistence** across script runs

The example will:
1. Authenticate with Notion MCP (opens browser)
2. Cache tokens in memory
3. Persist tokens to secure storage
4. Demonstrate token reuse (no re-authentication needed)
5. Show token operations and management

### 3. basic_mcp_oauth.py ✅ **Fully Working - Tested with Notion MCP!**

Demonstrates the full MCP OAuth 2.0 flow with a real MCP server.

```bash
# Run with Notion MCP (default - tested and working!)
uv run examples/basic_mcp_oauth.py

# Or specify a custom MCP server
uv run examples/basic_mcp_oauth.py <server_url>
```

Examples:
```bash
# Notion MCP (tested - works!)
uv run examples/basic_mcp_oauth.py https://mcp.notion.com/mcp

# Custom MCP server
uv run examples/basic_mcp_oauth.py https://your-server.com/mcp
```

**✅ This example has been tested and works with Notion MCP!**

It demonstrates:
- OAuth server metadata discovery (RFC 8414)
- Dynamic client registration (RFC 7591)
- Authorization code flow with PKCE
- Token exchange and refresh

The example will:
1. Discover Notion's OAuth endpoints
2. Register your app dynamically
3. Open your browser for authorization
4. Receive the callback and exchange code for tokens
5. Demonstrate token refresh

**Note:** Defaults to Notion MCP if no URL is provided.

### 4. authenticated_requests.py ✅ **NEW: Fully Working Authenticated Requests!**

Demonstrates making authenticated HTTP requests with automatic token refresh on 401 responses.

```bash
uv run examples/authenticated_requests.py
```

**✅ Shows the easiest way to make authenticated API calls to MCP servers!**

This example demonstrates:
- **Authenticated GET/POST requests** with automatic token management
- **Automatic 401 handling** - token refresh and retry on unauthorized responses
- **Custom headers** with authentication
- **SSE response parsing** for MCP JSON-RPC over Server-Sent Events
- **Full MCP session management** - initialization and tool listing
- **Error handling** for common HTTP scenarios
- **Token lifecycle** during requests

The example includes:
1. **Working httpbin.org example** - Demonstrates OAuth authentication with REST API
2. **Complete Notion MCP example** - Full session initialization and tools listing with SSE support
3. Adding custom headers to authenticated requests
4. Manual 401 handling (disabling auto-retry)
5. Common error scenarios
6. Understanding the token lifecycle

**Key Features:** The `authenticated_request()` method handles everything:
- ✅ Gets/refreshes tokens automatically
- ✅ Adds Authorization header
- ✅ Makes the HTTP request
- ✅ If 401 → refreshes token → retries once
- ✅ Works with all HTTP methods (GET, POST, PUT, DELETE, etc.)
- ✅ Supports both JSON and SSE (Server-Sent Events) responses

### 5. oauth_cli.py ✅ **CLI Tool for Token Management**

A command-line interface for managing OAuth tokens - makes it easy to test OAuth connections.

```bash
# View help
uv run examples/oauth_cli.py --help

# Authenticate with a server
uv run examples/oauth_cli.py auth notion-mcp https://mcp.notion.com/mcp

# Get stored token (safely redacted)
uv run examples/oauth_cli.py get notion-mcp

# List all stored tokens
uv run examples/oauth_cli.py list

# Test connection with stored tokens
uv run examples/oauth_cli.py test notion-mcp

# Clear tokens for a server
uv run examples/oauth_cli.py clear notion-mcp
```

**Available Commands:**
- **auth** - Authenticate with an MCP server (opens browser for OAuth flow)
- **get** - Display stored token information (token is safely redacted)
- **list** - List all servers with stored tokens
- **test** - Test connection and validate stored tokens
- **clear** - Remove tokens for a specific server

**Features:**
- Safe token display (shows first 20 and last 6 characters)
- Works with any MCP OAuth server
- Shows token expiration status
- Displays storage backend information
- Easy testing of OAuth connections

## OAuth Server Requirements

If you want to test with a real OAuth server, it must support:

1. **OAuth Authorization Server Metadata Discovery (RFC 8414)**
   - Endpoint: `<server_url>/.well-known/oauth-authorization-server`
   - Returns JSON with authorization and token endpoints

2. **Dynamic Client Registration (RFC 7591)**
   - Allows the library to automatically register as an OAuth client
   - No pre-registration required

3. **Authorization Code Flow with PKCE**
   - Secure OAuth flow for public clients
   - PKCE (Proof Key for Code Exchange) for additional security

## Example OAuth Servers

The library can work with:

- **Notion MCP**: `https://mcp.notion.com/mcp` (used in examples)
- Custom MCP servers with OAuth enabled
- Enterprise MCP deployments
- Any OAuth 2.0 server implementing RFC 8414, RFC 7591, and PKCE

## Storage Backends

The library supports multiple secure storage backends:

| Backend | Platform | Description |
|---------|----------|-------------|
| **Keychain** | macOS | Uses the macOS Keychain for secure storage |
| **Secret Service** | Linux | Uses the freedesktop.org Secret Service API |
| **Credential Manager** | Windows | Uses Windows Credential Manager |
| **Vault** | All | HashiCorp Vault integration |
| **Encrypted File** | All | Encrypted file storage (portable) |
| **Auto** | All | Automatically selects the best backend for your platform |

## Getting Help

For more information:
- Library documentation: See the main [README.md](../README.md)
- MCP OAuth specification: See [Model Context Protocol OAuth docs](https://modelcontextprotocol.io/)
- OAuth 2.0: See [RFC 6749](https://tools.ietf.org/html/rfc6749)
- PKCE: See [RFC 7636](https://tools.ietf.org/html/rfc7636)
