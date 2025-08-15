# MCP OAuth Proxy for Rapid Resolver

A lightweight proxy that enables Claude Desktop to connect to [Rapid Resolver's](https://rapidresolver.com/) MCP (Model Context Protocol) server and other OAuth 2.0 protected MCP services. The proxy handles the OAuth client credentials flow and forwards JSON-RPC requests between Claude Desktop and your MCP server.

## Features

- **OAuth 2.0 Client Credentials Flow**: Automatic token acquisition and refresh with configurable scopes
- **MCP Protocol Compliance**: Full support for MCP session management and initialization handshake
- **Server-Sent Events (SSE)**: Handles both JSON and SSE response formats from MCP servers
- **Dual Implementation**: Available in both Node.js and Python with identical functionality
- **Zero Dependencies**: Uses only built-in modules for maximum compatibility
- **Comprehensive Logging**: Detailed logging to both file and console for debugging
- **Graceful Error Handling**: Robust error handling with proper JSON-RPC error responses

## Architecture

```
Claude Desktop ←→ MCP OAuth Proxy ←→ OAuth-Protected MCP Server
                   (STDIN/STDOUT)      (HTTP + OAuth Bearer Token)
```

The proxy acts as a bridge, translating between:
- Claude Desktop's STDIN/STDOUT JSON-RPC communication
- HTTP-based MCP servers with OAuth 2.0 authentication

## Quick Start

### Prerequisites

- **Node.js** (v14+) or **Python** (3.8+)
- OAuth 2.0 credentials from Rapid Resolver or your MCP server provider
- Claude Desktop application

### Installation

1. Clone or download the proxy files
2. Choose either the Node.js or Python implementation
3. Configure your OAuth credentials
4. Update Claude Desktop configuration

### Configuration

#### Option 1: Environment Variables

```bash
export OAUTH_CLIENT_ID="your-rapid-resolver-client-id"
export OAUTH_CLIENT_SECRET="your-rapid-resolver-client-secret"
export OAUTH_TOKEN_URL="https://oauth.rapidresolver.com/api/oauth2/token"
export MCP_SERVER_URL="https://mcp.rapidresolver.com/mcp"
export OAUTH_SCOPE="read write"  # Optional, defaults to "read"
```

#### Option 2: Command Line Arguments

**Node.js:**
```bash
node mcp-oauth-proxy.js \
  --client-id "your-rapid-resolver-client-id" \
  --client-secret "your-rapid-resolver-client-secret" \
  --token-url "https://oauth.rapidresolver.com/api/oauth2/token" \
  --mcp-server-url "https://mcp.rapidresolver.com/mcp" \
  --scope "read write" \
  --debug
```

**Python:**
```bash
python3 mcp-oauth-proxy.py \
  --client-id "your-rapid-resolver-client-id" \
  --client-secret "your-rapid-resolver-client-secret" \
  --token-url "https://oauth.rapidresolver.com/api/oauth2/token" \
  --mcp-server-url "https://mcp.rapidresolver.com/mcp" \
  --scope "read write" \
  --debug
```

### Claude Desktop Integration

Add the proxy to your Claude Desktop configuration file:

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

#### Node.js Configuration:
```json
{
  "mcpServers": {
    "rapid-resolver": {
      "command": "node",
      "args": [
        "/path/to/mcp-oauth-proxy.js",
        "--client-id", "your-rapid-resolver-client-id",
        "--client-secret", "your-rapid-resolver-client-secret",
        "--token-url", "https://oauth.rapidresolver.com/api/oauth2/token",
        "--mcp-server-url", "https://mcp.rapidresolver.com/mcp",
        "--scope", "read write"
      ]
    }
  }
}
```

#### Python Configuration:
```json
{
  "mcpServers": {
    "rapid-resolver": {
      "command": "python3",
      "args": [
        "/path/to/mcp-oauth-proxy.py",
        "--client-id", "your-rapid-resolver-client-id",
        "--client-secret", "your-rapid-resolver-client-secret",
        "--token-url", "https://oauth.rapidresolver.com/api/oauth2/token",
        "--mcp-server-url", "https://mcp.rapidresolver.com/mcp",
        "--scope", "read write"
      ]
    }
  }
}
```

## Command Line Options

| Option | Environment Variable | Description | Default |
|--------|---------------------|-------------|---------|
| `--client-id` | `OAUTH_CLIENT_ID` | OAuth 2.0 client ID | Required |
| `--client-secret` | `OAUTH_CLIENT_SECRET` | OAuth 2.0 client secret | Required |
| `--token-url` | `OAUTH_TOKEN_URL` | OAuth token endpoint URL | Required |
| `--mcp-server-url` | `MCP_SERVER_URL` | MCP server base URL | Required |
| `--scope` | `OAUTH_SCOPE` | OAuth scope(s) | `"read"` |
| `--session-id` | `SESSION_ID` | Pre-existing session ID | Auto-generated |
| `--debug` | - | Enable debug logging | `false` |
| `--help` | - | Show help message | - |

## How It Works

### OAuth Flow
1. **Token Acquisition**: On startup, the proxy exchanges client credentials for an access token
2. **Token Refresh**: Automatically refreshes tokens before expiration (5-minute buffer)
3. **Request Authentication**: Adds `Authorization: Bearer <token>` header to all MCP requests

### MCP Session Management
1. **Initialization**: Sends MCP `initialize` request with protocol version and capabilities
2. **Session ID**: Extracts and manages session ID from server response headers
3. **Handshake Completion**: Sends `notifications/initialized` to complete the MCP handshake
4. **Request Forwarding**: Forwards all subsequent JSON-RPC requests with session context

### Response Handling
- **JSON Responses**: Direct parsing and forwarding of JSON-RPC responses
- **Server-Sent Events**: Extracts JSON data from SSE `data:` lines
- **Error Handling**: Converts HTTP errors to proper JSON-RPC error responses

## Logging

The proxy creates detailed logs in `mcp-oauth-proxy.log` in the same directory as the script. Logs include:

- OAuth token acquisition and refresh events
- MCP session initialization
- Request/response debugging (with `--debug` flag)
- Error conditions and troubleshooting information

### Log Levels
- **INFO**: Normal operation events
- **WARNING**: Non-fatal issues
- **ERROR**: Error conditions
- **DEBUG**: Detailed request/response data (requires `--debug` flag)

## Troubleshooting

### Common Issues

#### Authentication Failures
```
ERROR: OAuth authentication failed: Token endpoint error 401
```
**Solution**: Verify your Rapid Resolver client ID and secret are correct

#### Connection Issues
```
ERROR: HTTP request failed: getaddrinfo ENOTFOUND
```
**Solution**: Check your token URL and MCP server URL are accessible

#### Session Initialization Failures
```
ERROR: Failed to initialize MCP session: HTTP 403
```
**Solution**: Ensure your Rapid Resolver OAuth scope includes necessary permissions

#### Claude Desktop ZodError Response Parsing
**Known Issue**: Claude Desktop may display ZodError messages with response parsing errors when connecting to the Rapid Resolver MCP server.

**Solution**: These ZodError messages can be safely dismissed and do not affect functionality. The Rapid Resolver MCP server will continue to work normally despite these error messages. Simply close the error dialog and continue using the service.

### Debug Mode

Enable debug logging to see detailed request/response data:

```bash
# Node.js
node mcp-oauth-proxy.js --debug [other options]

# Python
python3 mcp-oauth-proxy.py --debug [other options]
```

### Log Analysis

Check the log file for detailed information:
```bash
tail -f mcp-oauth-proxy.log
```

## Security Considerations

- **Credential Storage**: Never commit OAuth credentials to version control
- **Environment Variables**: Use environment variables or secure credential management
- **Token Security**: Access tokens are stored in memory only and automatically refreshed
- **HTTPS Only**: Always use HTTPS URLs for OAuth and MCP endpoints
- **Scope Limitation**: Use minimal OAuth scopes required for your use case

## API Compatibility

### MCP Protocol Version
- Supports MCP protocol version `2024-11-05`
- Compatible with standard MCP JSON-RPC methods
- Handles both request/response and notification patterns

### OAuth 2.0 Compliance
- Implements RFC 6749 Client Credentials Grant
- Supports custom scopes and token refresh
- Handles standard OAuth error responses

## Development

### Project Structure
```
proxies/
├── node/
│   ├── mcp-oauth-proxy.js          # Node.js implementation
│   └── claude_desktop_config.json  # Node.js Claude config template
└── python/
    ├── mcp-oauth-proxy.py          # Python implementation
    └── claude-desktop-config_python.json  # Python Claude config template
```

### Testing

Test OAuth authentication:
```bash
# Node.js
node mcp-oauth-proxy.js --client-id "your-rapid-resolver-client-id" --client-secret "your-rapid-resolver-client-secret" \
  --token-url "https://oauth.rapidresolver.com/api/oauth2/token" --mcp-server-url "https://mcp.rapidresolver.com/mcp"

# Python  
python mcp-oauth-proxy.py --client-id "your-rapid-resolver-client-id" --client-secret "your-rapid-resolver-client-secret" \
  --token-url "https://oauth.rapidresolver.com/api/oauth2/token" --mcp-server-url "https://mcp.rapidresolver.com/mcp"
```

### Contributing

Both implementations should maintain feature parity. When adding features:

1. Implement in both Node.js and Python versions
2. Update configuration templates
3. Add appropriate logging
4. Update documentation

## License

MIT License - see LICENSE file for details.

## Support

For issues and questions:
1. Check the log file for detailed error information
2. Enable debug mode for request/response details
3. Verify your Rapid Resolver OAuth credentials and server URLs
4. Ensure Claude Desktop configuration is correct
5. Contact Rapid Resolver support for credential-related issues

## Rapid Resolver Integration

This proxy was specifically designed for Rapid Resolver's MCP service. The included configuration templates provide ready-to-use integration:

```json
{
  "mcpServers": {
    "rapid-resolver": {
      "command": "node",
      "args": [
        "mcp-oauth-proxy.js",
        "--client-id", "your-rapid-resolver-client-id",
        "--client-secret", "your-rapid-resolver-client-secret", 
        "--token-url", "https://oauth.rapidresolver.com/api/oauth2/token",
        "--mcp-server-url", "https://mcp.rapidresolver.com/mcp",
        "--scope", "read write"
      ]
    }
  }
}
```

Replace the placeholder credentials with your actual Rapid Resolver OAuth credentials obtained from your Rapid Resolver account dashboard.

### Getting Rapid Resolver Credentials

1. Visit [https://rapidresolver.com/](https://rapidresolver.com/) and sign up for a Rapid Resolver account
2. Log in to your Rapid Resolver account
3. Click on the user account menu at the top-right side of the navbar
4. Select "Registered Apps" from the dropdown menu
5. Create a new OAuth 2.0 application or use an existing one
6. Copy the generated client ID and client secret
7. Use these credentials in your proxy configuration

The Rapid Resolver MCP service provides powerful AI-assisted development tools and integrations directly within Claude Desktop. Visit [https://rapidresolver.com/](https://rapidresolver.com/) to learn more about the available features and capabilities.