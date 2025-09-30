#!/usr/bin/env python3
"""
MCP OAuth Proxy (Python) for Rapid Resolver

A lightweight proxy that forwards JSON-RPC requests from Claude Desktop to Rapid Resolver's
MCP server and other OAuth 2.0 protected MCP services, adding client-credentials authentication
and handling Server-Sent Events (SSE).

Features:
- OAuth 2.0 client credentials flow with automatic token refresh
- MCP protocol session management with proper initialization handshake
- Server-Sent Events (SSE) response parsing
- Comprehensive logging for debugging
- No third-party dependencies - uses only Python standard library
- Optimized for Rapid Resolver's MCP service integration

Usage:
    python3 mcp-oauth-proxy.py --client-id <id> --client-secret <secret> \
      --token-url <url> --mcp-server-url <url> [--scope <scope>] [--debug]

Environment Variables:
    OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET, OAUTH_TOKEN_URL, MCP_SERVER_URL, OAUTH_SCOPE

Author: Rapid Resolver Team
License: MIT
"""

import argparse
import asyncio
import json
import logging
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, Optional
import urllib.error
import urllib.parse
import urllib.request

# --------------------------------------------------------------------------- #
#  Logging                                                                    #
# --------------------------------------------------------------------------- #
def setup_logging():
    """Setup logging to both file and stderr."""
    log_file = os.path.join(os.path.dirname(__file__), "mcp-oauth-proxy.log")
    
    # Create formatters
    detailed_formatter = logging.Formatter(
        "%(asctime)s  %(levelname)-8s [%(name)s] %(message)s"
    )
    simple_formatter = logging.Formatter(
        "%(asctime)s  %(levelname)-8s %(message)s"
    )
    
    # File handler with INFO level logging
    file_handler = logging.FileHandler(log_file, mode='a')
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(detailed_formatter)
    
    # Console handler for immediate feedback
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(simple_formatter)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    
    return log_file

# Setup logging and get the log file path
log_file_path = setup_logging()
log = logging.getLogger("mcp-proxy")
log.info(f"Logging to file: {log_file_path}")

# --------------------------------------------------------------------------- #
#  Small helpers                                                              #
# --------------------------------------------------------------------------- #
def jsonrpc_error(id_: Optional[int], code: int, msg: str) -> Dict[str, Any]:
    """Create a JSON-RPC error response."""
    return {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": msg}}


def http_post(url: str, data: bytes, headers: Dict[str, str], timeout: int = 15) -> tuple[int, bytes]:
    """
    Simple HTTP POST helper using urllib.
    
    Args:
        url: Target URL for the POST request
        data: Request body as bytes
        headers: HTTP headers dictionary
        timeout: Request timeout in seconds
        
    Returns:
        Tuple of (status_code, response_body_bytes)
    """
    req = urllib.request.Request(url=url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.getcode(), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except Exception as exc:
        raise RuntimeError(f"HTTP request failed: {exc}") from exc


# --------------------------------------------------------------------------- #
#  OAuth token manager                                                        #
# --------------------------------------------------------------------------- #
@dataclass
class TokenManager:
    """
    Manages OAuth 2.0 client credentials tokens with automatic refresh.
    
    Handles token acquisition and refresh using the client credentials flow,
    with automatic expiration tracking and 5-minute refresh buffer.
    Handles authentication for Rapid Resolver and other OAuth-protected MCP servers.
    """
    client_id: str
    client_secret: str
    token_url: str
    scope: str = "read"
    _token: Optional[str] = field(init=False, default=None)
    _expires_at: Optional[datetime] = field(init=False, default=None)

    async def get(self) -> str:
        """
        Get a valid access token, refreshing if necessary.
        
        Returns:
            Valid OAuth access token string
        """
        # Always check if token is expired or will expire soon (30 second buffer)
        if not self._token or not self._expires_at or datetime.now() >= (self._expires_at - timedelta(seconds=30)):
            await asyncio.to_thread(self._refresh)
        return self._token  # type: ignore

    async def force_refresh(self) -> str:
        """
        Force refresh the token (used when receiving 401 errors).
        
        Returns:
            New OAuth access token string
        """
        await asyncio.to_thread(self._refresh)
        return self._token  # type: ignore

    # --------------------------------------------------------------------- #
    #  Blocking part – runs in thread                                       #
    # --------------------------------------------------------------------- #
    def _refresh(self) -> None:
        """Refresh the OAuth token using client credentials flow."""
        log.info("Refreshing OAuth token…")
        
        form = urllib.parse.urlencode(
            {
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": self.scope,
            }
        ).encode()

        status, body = http_post(
            self.token_url,
            form,
            {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
        )

        if status != 200:
            log.error(f"Token endpoint error {status}")
            raise RuntimeError(f"Token endpoint error {status}")

        payload = json.loads(body)
        self._token = payload["access_token"]
        ttl = int(payload.get("expires_in", 3600)) - 300  # 5-min buffer
        self._expires_at = datetime.now() + timedelta(seconds=max(ttl, 0))
        log.info("Token refreshed successfully, valid until %s", self._expires_at.isoformat(timespec="seconds"))


# --------------------------------------------------------------------------- #
#  MCP proxy                                                                  #
# --------------------------------------------------------------------------- #
class MCPProxy:
    """
    Main proxy class that handles MCP protocol communication with OAuth authentication.
    
    Manages session initialization, request forwarding, and response parsing
    for both JSON and Server-Sent Events formats.
    Designed for Rapid Resolver's MCP service and compatible OAuth-protected servers.
    """
    
    def __init__(self, url: str, tm: TokenManager, session_id: str | None):
        self.url = url
        self.tm = tm
        self.session_id = session_id  # This will be updated by the server

    async def call(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a JSON-RPC request and return the response.
        
        Args:
            request: JSON-RPC request dictionary
            
        Returns:
            JSON-RPC response dictionary
        """
        try:
            # For the first request (initialize), create session
            if not self.session_id:
                log.info("Initializing MCP session...")
                await self._initialize_session()
            
            return await self._make_request(request)

        except Exception as exc:
            log.error("Proxy request failed: %s", str(exc))
            return jsonrpc_error(request.get("id"), -32603, f"Internal error: {exc}")

    async def _make_request(self, request: Dict[str, Any], retry_count: int = 0) -> Dict[str, Any]:
        """
        Make a request with automatic token refresh on 401.
        
        Args:
            request: JSON-RPC request dictionary
            retry_count: Number of retries attempted
            
        Returns:
            JSON-RPC response dictionary
        """
        headers = {
            "Authorization": f"Bearer {await self.tm.get()}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "mcp-session-id": self.session_id,
        }
            
        status, body, response_headers = await asyncio.to_thread(
            self._http_post_with_headers, self.url, json.dumps(request).encode(), headers
        )
        
        if status in (200, 202):  # Accept both 200 OK and 202 Accepted
            # For SSE responses, extract the JSON from the event stream
            # HTTP headers are case-insensitive, so check both variations
            content_type = (response_headers.get("content-type", "") or 
                          response_headers.get("Content-Type", ""))
            
            if content_type.startswith("text/event-stream"):
                result = self._parse_sse_response(body.decode())
                return result
            else:
                # Handle empty responses (common with 202 Accepted)
                body_str = body.decode().strip()
                if not body_str:
                    # Return a success response for empty bodies
                    return {"jsonrpc": "2.0", "id": request.get("id"), "result": {}}
                result = json.loads(body_str)
                return result
        
        # Handle 401 Unauthorized - token might have expired
        if status == 401 and retry_count == 0:
            log.warning("Received 401 Unauthorized, refreshing token and retrying...")
            try:
                await self.tm.force_refresh()
                return await self._make_request(request, retry_count + 1)
            except Exception as refresh_error:
                log.error("Token refresh failed: %s", str(refresh_error))
                return jsonrpc_error(request.get("id"), -32000, f"Authentication failed: {refresh_error}")
        
        log.error("MCP server error: HTTP %s", status)
        return jsonrpc_error(request.get("id"), -32000, f"Server error: {status}")
    
    async def _initialize_session(self) -> None:
        """
        Initialize MCP session with proper handshake.
        
        Performs the two-step MCP initialization:
        1. Send initialize request and get session ID
        2. Send initialized notification to complete handshake
        """
        # Step 1: Send initialize request
        init_request = {
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "mcp-oauth-proxy",
                    "version": "1.0.0"
                }
            }
        }
        
        status, body, response_headers = await self._make_init_request(init_request)
        
        if status != 200:
            log.error(f"Failed to initialize MCP session: HTTP {status}")
            raise RuntimeError(f"Failed to initialize session: {status}")
        
        # Extract session ID from response headers
        self.session_id = response_headers.get("mcp-session-id")
        if not self.session_id:
            log.error("Server did not provide session ID during initialization")
            raise RuntimeError("Server did not provide session ID during initialization")
        
        log.info(f"MCP session initialized successfully")
        
        # Step 2: Send initialized notification to complete the handshake
        initialized_notification = {
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }
        
        status, body, response_headers = await self._make_init_notification(initialized_notification)
        
        if status in (200, 202):  # 200 OK or 202 Accepted are both valid
            log.info("MCP initialization handshake completed")
        else:
            log.warning(f"Unexpected response to initialized notification: HTTP {status}")

    async def _make_init_request(self, request: Dict[str, Any], retry_count: int = 0) -> tuple[int, bytes, Dict[str, str]]:
        """
        Make initialization request with token refresh handling.
        
        Args:
            request: JSON-RPC request dictionary
            retry_count: Number of retries attempted
            
        Returns:
            Tuple of (status_code, response_body_bytes, response_headers_dict)
        """
        headers = {
            "Authorization": f"Bearer {await self.tm.get()}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        
        status, body, response_headers = await asyncio.to_thread(
            self._http_post_with_headers, self.url, json.dumps(request).encode(), headers
        )
        
        # Handle 401 Unauthorized during initialization
        if status == 401 and retry_count == 0:
            log.warning("Received 401 during initialization, refreshing token and retrying...")
            await self.tm.force_refresh()
            return await self._make_init_request(request, retry_count + 1)
        
        return status, body, response_headers

    async def _make_init_notification(self, notification: Dict[str, Any], retry_count: int = 0) -> tuple[int, bytes, Dict[str, str]]:
        """
        Make initialization notification with token refresh handling.
        
        Args:
            notification: JSON-RPC notification dictionary
            retry_count: Number of retries attempted
            
        Returns:
            Tuple of (status_code, response_body_bytes, response_headers_dict)
        """
        headers = {
            "Authorization": f"Bearer {await self.tm.get()}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "mcp-session-id": self.session_id,
        }
        
        status, body, response_headers = await asyncio.to_thread(
            self._http_post_with_headers, self.url, json.dumps(notification).encode(), headers
        )
        
        # Handle 401 Unauthorized during notification
        if status == 401 and retry_count == 0:
            log.warning("Received 401 during notification, refreshing token and retrying...")
            await self.tm.force_refresh()
            return await self._make_init_notification(notification, retry_count + 1)
        
        return status, body, response_headers
    
    def _parse_sse_response(self, sse_data: str) -> Dict[str, Any]:
        """
        Parse Server-Sent Events response to extract JSON data.
        
        Args:
            sse_data: Raw SSE response string
            
        Returns:
            Parsed JSON-RPC response dictionary
        """
        if not sse_data.strip():
            log.warning("Empty SSE response received")
            return {"jsonrpc": "2.0", "result": {}}
            
        lines = sse_data.strip().split('\n')
        
        # Look for data lines in SSE format
        for line in lines:
            if line.startswith('data: '):
                json_data = line[6:]  # Remove 'data: ' prefix
                if json_data.strip():  # Skip empty data lines
                    try:
                        return json.loads(json_data)
                    except json.JSONDecodeError as e:
                        log.warning(f"Failed to parse JSON from SSE data: {e}")
                        continue
        
        log.warning("No valid JSON found in SSE response, returning empty result")
        return {"jsonrpc": "2.0", "result": {}}
    
    def _http_post_with_headers(self, url: str, data: bytes, headers: Dict[str, str], timeout: int = 15) -> tuple[int, bytes, Dict[str, str]]:
        """
        HTTP POST helper that also returns response headers.
        
        Args:
            url: Target URL
            data: Request body as bytes
            headers: HTTP headers dictionary
            timeout: Request timeout in seconds
            
        Returns:
            Tuple of (status_code, response_body_bytes, response_headers_dict)
        """
        req = urllib.request.Request(url=url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                response_headers = dict(resp.headers)
                return resp.getcode(), resp.read(), response_headers
        except urllib.error.HTTPError as e:
            response_headers = dict(e.headers) if hasattr(e, 'headers') else {}
            return e.code, e.read(), response_headers
        except Exception as exc:
            raise RuntimeError(f"HTTP request failed: {exc}") from exc


# --------------------------------------------------------------------------- #
#  STDIN / STDOUT event-loop                                                  #
# --------------------------------------------------------------------------- #
class StdioServer:
    """
    Handles JSON-RPC communication over STDIN/STDOUT for Claude Desktop integration.
    
    Reads JSON-RPC requests from STDIN, forwards them through the proxy,
    and writes responses to STDOUT.
    Enables seamless connection between Claude Desktop and Rapid Resolver's MCP service.
    """
    
    def __init__(self, proxy: MCPProxy):
        self.proxy = proxy

    async def serve(self) -> None:
        """Start the STDIN/STDOUT server loop."""
        loop = asyncio.get_running_loop()
        log.info("MCP OAuth proxy ready")

        while True:
            line = await loop.run_in_executor(None, sys.stdin.readline)
            if not line:  # EOF
                log.info("Shutting down")
                break
            line = line.strip()
            if not line:
                continue

            try:
                req = json.loads(line)
            except json.JSONDecodeError as e:
                log.error(f"Invalid JSON received: {e}")
                error_response = jsonrpc_error(None, -32700, "Parse error")
                print(json.dumps(error_response), flush=True)
                continue

            resp = await self.proxy.call(req)
            print(json.dumps(resp), flush=True)


# --------------------------------------------------------------------------- #
#  Entrypoint                                                                 #
# --------------------------------------------------------------------------- #
async def async_main() -> None:
    """Main async entry point - parse arguments and start the proxy."""
    ap = argparse.ArgumentParser(
        description="MCP OAuth Proxy - Forward JSON-RPC requests to MCP servers with OAuth authentication",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 mcp-oauth-proxy.py \\
    --client-id "your-client-id" \\
    --client-secret "your-client-secret" \\
    --token-url "https://auth.example.com/oauth/token" \\
    --mcp-server-url "https://mcp.example.com/api" \\
    --scope "read write"

Environment Variables:
  OAUTH_CLIENT_ID       OAuth client ID
  OAUTH_CLIENT_SECRET   OAuth client secret  
  OAUTH_TOKEN_URL       OAuth token endpoint URL
  MCP_SERVER_URL        MCP server base URL
  OAUTH_SCOPE           OAuth scope (default: read)
  SESSION_ID            Pre-existing session ID (optional)
        """
    )
    ap.add_argument("--client-id", default=os.getenv("OAUTH_CLIENT_ID"))
    ap.add_argument("--client-secret", default=os.getenv("OAUTH_CLIENT_SECRET"))
    ap.add_argument("--token-url", default=os.getenv("OAUTH_TOKEN_URL"))
    ap.add_argument("--mcp-server-url", default=os.getenv("MCP_SERVER_URL"))
    ap.add_argument("--scope", default=os.getenv("OAUTH_SCOPE", "read"))
    ap.add_argument("--session-id", default=os.getenv("SESSION_ID"))
    ap.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = ap.parse_args()
    
    # Adjust logging level if debug is requested
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        log.info("Debug logging enabled")
    
    log.info("MCP OAuth Proxy starting...")

    # Validate required arguments
    if not args.client_id:
        log.error("Missing client-id (set OAUTH_CLIENT_ID or use --client-id)")
        return
    if not args.client_secret:
        log.error("Missing client-secret (set OAUTH_CLIENT_SECRET or use --client-secret)")
        return
    if not args.token_url:
        log.error("Missing token-url (set OAUTH_TOKEN_URL or use --token-url)")
        return
    if not args.mcp_server_url:
        log.error("Missing mcp-server-url (set MCP_SERVER_URL or use --mcp-server-url)")
        return

    # Test OAuth credentials
    tm = TokenManager(args.client_id, args.client_secret, args.token_url, args.scope)
    try:
        await tm.get()
        log.info("OAuth authentication successful")
    except Exception as e:
        log.error(f"OAuth authentication failed: {e}")
        return

    proxy = MCPProxy(args.mcp_server_url, tm, args.session_id)
    await StdioServer(proxy).serve()


def main() -> None:
    """Main entry point - run the async main function."""
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        log.info("Shutting down")


if __name__ == "__main__":
    main()