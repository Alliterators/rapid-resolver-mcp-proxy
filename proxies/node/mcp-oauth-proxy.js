#!/usr/bin/env node
/**
 * MCP OAuth Proxy (Node.js) for Rapid Resolver
 * 
 * A lightweight proxy that forwards JSON-RPC requests from Claude Desktop to Rapid Resolver's
 * MCP server and other OAuth 2.0 protected MCP services, adding client-credentials authentication
 * and handling Server-Sent Events (SSE).
 * 
 * Features:
 * - OAuth 2.0 client credentials flow with automatic token refresh
 * - MCP protocol session management with proper initialization handshake
 * - Server-Sent Events (SSE) response parsing
 * - Comprehensive logging for debugging
 * - No third-party dependencies - uses only Node.js built-in modules
 * - Optimized for Rapid Resolver's MCP service integration
 * 
 * Usage:
 *   node mcp-oauth-proxy.js --client-id <id> --client-secret <secret> \
 *     --token-url <url> --mcp-server-url <url> [--scope <scope>] [--debug]
 * 
 * Environment Variables:
 *   OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET, OAUTH_TOKEN_URL, MCP_SERVER_URL, OAUTH_SCOPE
 * 
 * @author Rapid Resolver Team
 * @license MIT
 */

const fs = require('fs');
const https = require('https');
const http = require('http');
const path = require('path');
const readline = require('readline');

// --------------------------------------------------------------------------- //
//  Logging                                                                    //
// --------------------------------------------------------------------------- //

/**
 * Simple logger that writes to both file and stderr
 */
class Logger {
    constructor() {
        this.logFile = path.join(__dirname, 'mcp-oauth-proxy.log');
        this.debugEnabled = false;
        console.error(`Logging to file: ${this.logFile}`);
    }

    log(level, message) {
        const timestamp = new Date().toISOString();
        const formatted = `${timestamp}  ${level.padEnd(8)} [mcp-proxy] ${message}`;

        // Write to file
        fs.appendFileSync(this.logFile, formatted + '\n');

        // Write to stderr
        console.error(`${timestamp}  ${level.padEnd(8)} ${message}`);
    }

    info(message) { this.log('INFO', message); }
    error(message) { this.log('ERROR', message); }
    warning(message) { this.log('WARNING', message); }
    debug(message) {
        if (this.debugEnabled) this.log('DEBUG', message);
    }

    enableDebug() { this.debugEnabled = true; }
}

const logger = new Logger();

// --------------------------------------------------------------------------- //
//  HTTP Helper                                                                //
// --------------------------------------------------------------------------- //

/**
 * Simple HTTP POST helper using Node.js built-in modules
 */
function httpPost(targetUrl, data, headers, timeout = 15000) {
    return new Promise((resolve, reject) => {
        const parsedUrl = new URL(targetUrl);
        const isHttps = parsedUrl.protocol === 'https:';
        const client = isHttps ? https : http;

        const options = {
            hostname: parsedUrl.hostname,
            port: parsedUrl.port || (isHttps ? 443 : 80),
            path: parsedUrl.pathname + parsedUrl.search,
            method: 'POST',
            headers: {
                'Content-Length': Buffer.byteLength(data),
                ...headers
            },
            timeout
        };

        const req = client.request(options, (res) => {
            let body = '';
            res.setEncoding('utf8');

            res.on('data', (chunk) => body += chunk);
            res.on('end', () => resolve({
                statusCode: res.statusCode,
                body: body,
                headers: res.headers
            }));
        });

        req.on('error', (err) => reject(new Error(`HTTP request failed: ${err.message}`)));
        req.on('timeout', () => {
            req.destroy();
            reject(new Error('HTTP request timeout'));
        });

        req.write(data);
        req.end();
    });
}

/**
 * Create a JSON-RPC error response
 */
function jsonrpcError(id, code, message) {
    return {
        jsonrpc: "2.0",
        id: id,
        error: { code, message }
    };
}

// --------------------------------------------------------------------------- //
//  OAuth Token Manager                                                        //
// --------------------------------------------------------------------------- //

/**
 * Manages OAuth 2.0 client credentials tokens with automatic refresh
 * Handles authentication for Rapid Resolver and other OAuth-protected MCP servers
 */
class TokenManager {
    constructor(clientId, clientSecret, tokenUrl, scope = 'read') {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.tokenUrl = tokenUrl;
        this.scope = scope;
        this._token = null;
        this._expiresAt = null;
    }

    /**
     * Get a valid access token, refreshing if necessary
     */
    async get() {
        // Always check if token is expired or will expire soon (30 second buffer)
        if (!this._token || !this._expiresAt || new Date() >= new Date(this._expiresAt.getTime() - 30000)) {
            await this._refresh();
        }
        return this._token;
    }

    /**
     * Force refresh the token (used when receiving 401 errors)
     */
    async forceRefresh() {
        await this._refresh();
        return this._token;
    }

    /**
     * Refresh the OAuth token using client credentials flow
     */
    async _refresh() {
        logger.info('Refreshing OAuth token…');

        const formData = new URLSearchParams({
            grant_type: 'client_credentials',
            client_id: this.clientId,
            client_secret: this.clientSecret,
            scope: this.scope
        }).toString();

        try {
            const response = await httpPost(this.tokenUrl, formData, {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Accept': 'application/json'
            });

            if (response.statusCode !== 200) {
                throw new Error(`Token endpoint error ${response.statusCode}`);
            }

            const payload = JSON.parse(response.body);
            this._token = payload.access_token;

            // Set expiration with 5-minute buffer
            const ttl = Math.max((parseInt(payload.expires_in) || 3600) - 300, 0);
            this._expiresAt = new Date(Date.now() + ttl * 1000);

            logger.info(`Token refreshed successfully, valid until ${this._expiresAt.toISOString()}`);
        } catch (error) {
            logger.error(`Token refresh failed: ${error.message}`);
            throw error;
        }
    }
}

// --------------------------------------------------------------------------- //
//  MCP Proxy                                                                  //
// --------------------------------------------------------------------------- //

/**
 * Main proxy class that handles MCP protocol communication with OAuth authentication
 * Designed for Rapid Resolver's MCP service and compatible OAuth-protected servers
 */
class MCPProxy {
    constructor(url, tokenManager, sessionId = null) {
        this.url = url;
        this.tokenManager = tokenManager;
        this.sessionId = sessionId;
    }

    /**
     * Process a JSON-RPC request and return the response
     */
    async call(request) {
        try {
            // Initialize session on first request
            if (!this.sessionId) {
                logger.info('Initializing MCP session...');
                await this._initializeSession();
            }

            return await this._makeRequest(request);

        } catch (error) {
            logger.error(`Proxy request failed: ${error.message}`);
            return jsonrpcError(request.id, -32603, `Internal error: ${error.message}`);
        }
    }

    /**
     * Make a request with automatic token refresh on 401
     */
    async _makeRequest(request, retryCount = 0) {
        // Prepare request headers with OAuth token and session ID
        const headers = {
            'Authorization': `Bearer ${await this.tokenManager.get()}`,
            'Content-Type': 'application/json',
            'Accept': 'application/json, text/event-stream',
            'mcp-session-id': this.sessionId
        };

        const response = await httpPost(this.url, JSON.stringify(request), headers);

        if (response.statusCode === 200 || response.statusCode === 202) {
            return this._parseResponse(response, request.id);
        }

        // Handle 401 Unauthorized - token might have expired
        if (response.statusCode === 401 && retryCount === 0) {
            logger.warning('Received 401 Unauthorized, refreshing token and retrying...');
            try {
                await this.tokenManager.forceRefresh();
                return await this._makeRequest(request, retryCount + 1);
            } catch (refreshError) {
                logger.error(`Token refresh failed: ${refreshError.message}`);
                return jsonrpcError(request.id, -32000, `Authentication failed: ${refreshError.message}`);
            }
        }

        logger.error(`MCP server error: HTTP ${response.statusCode}`);
        return jsonrpcError(request.id, -32000, `Server error: ${response.statusCode}`);
    }

    /**
     * Initialize MCP session with proper handshake
     */
    async _initializeSession() {
        try {
            // Step 1: Send initialize request
            const initRequest = {
                jsonrpc: "2.0",
                id: 0,
                method: "initialize",
                params: {
                    protocolVersion: "2024-11-05",
                    capabilities: {},
                    clientInfo: {
                        name: "mcp-oauth-proxy",
                        version: "1.0.0"
                    }
                }
            };

            const response = await this._makeInitRequest(initRequest);

            if (response.statusCode !== 200) {
                throw new Error(`Failed to initialize session: ${response.statusCode}`);
            }

            // Extract session ID from response headers
            this.sessionId = response.headers['mcp-session-id'];
            if (!this.sessionId) {
                // Generate fallback session ID if server doesn't provide one
                this.sessionId = `proxy-session-${Date.now()}-${Math.random().toString(36).substring(2, 11)}`;
                logger.warning(`Server did not provide session ID, using fallback: ${this.sessionId}`);
            }

            logger.info(`MCP session initialized successfully with ID: ${this.sessionId}`);

            // Step 2: Send initialized notification to complete handshake
            const initializedNotification = {
                jsonrpc: "2.0",
                method: "notifications/initialized"
            };

            const notificationResponse = await this._makeInitNotification(initializedNotification);

            if (notificationResponse.statusCode === 200 || notificationResponse.statusCode === 202) {
                logger.info('MCP initialization handshake completed');
            } else {
                logger.warning(`Unexpected response to initialized notification: HTTP ${notificationResponse.statusCode}`);
            }

        } catch (error) {
            logger.error(`Session initialization failed: ${error.message}`);
            throw error;
        }
    }

    /**
     * Make initialization request with token refresh handling
     */
    async _makeInitRequest(request, retryCount = 0) {
        const headers = {
            'Authorization': `Bearer ${await this.tokenManager.get()}`,
            'Content-Type': 'application/json',
            'Accept': 'application/json, text/event-stream'
        };

        const response = await httpPost(this.url, JSON.stringify(request), headers);

        // Handle 401 Unauthorized during initialization
        if (response.statusCode === 401 && retryCount === 0) {
            logger.warning('Received 401 during initialization, refreshing token and retrying...');
            await this.tokenManager.forceRefresh();
            return await this._makeInitRequest(request, retryCount + 1);
        }

        return response;
    }

    /**
     * Make initialization notification with token refresh handling
     */
    async _makeInitNotification(notification, retryCount = 0) {
        const headers = {
            'Authorization': `Bearer ${await this.tokenManager.get()}`,
            'Content-Type': 'application/json',
            'Accept': 'application/json, text/event-stream',
            'mcp-session-id': this.sessionId
        };

        const response = await httpPost(this.url, JSON.stringify(notification), headers);

        // Handle 401 Unauthorized during notification
        if (response.statusCode === 401 && retryCount === 0) {
            logger.warning('Received 401 during notification, refreshing token and retrying...');
            await this.tokenManager.forceRefresh();
            return await this._makeInitNotification(notification, retryCount + 1);
        }

        return response;
    }

    /**
     * Parse HTTP response, handling both JSON and Server-Sent Events
     */
    _parseResponse(response, requestId) {
        const contentType = response.headers['content-type'] || '';

        if (contentType.startsWith('text/event-stream')) {
            return this._parseSSEResponse(response.body);
        } else {
            const bodyStr = response.body.trim();
            if (!bodyStr) {
                return { jsonrpc: "2.0", id: requestId, result: {} };
            }

            try {
                const parsed = JSON.parse(bodyStr);
                logger.debug(`Server response: ${JSON.stringify(parsed, null, 2)}`);
                return parsed;
            } catch (parseError) {
                logger.error(`Failed to parse JSON response: ${parseError.message}`);
                return jsonrpcError(requestId, -32700, "Parse error in server response");
            }
        }
    }

    /**
     * Parse Server-Sent Events response to extract JSON data
     */
    _parseSSEResponse(sseData) {
        if (!sseData.trim()) {
            logger.warning('Empty SSE response received');
            return { jsonrpc: "2.0", result: {} };
        }

        const lines = sseData.trim().split('\n');

        // Look for data lines in SSE format
        for (const line of lines) {
            if (line.startsWith('data: ')) {
                const jsonData = line.substring(6); // Remove 'data: ' prefix
                if (jsonData.trim()) {
                    try {
                        const parsed = JSON.parse(jsonData);
                        logger.debug(`SSE response: ${JSON.stringify(parsed, null, 2)}`);
                        return parsed;
                    } catch (error) {
                        logger.warning(`Failed to parse JSON from SSE data: ${error.message}`);
                        continue;
                    }
                }
            }
        }

        logger.warning('No valid JSON found in SSE response');
        return { jsonrpc: "2.0", result: {} };
    }
}

// --------------------------------------------------------------------------- //
//  STDIN/STDOUT Server                                                        //
// --------------------------------------------------------------------------- //

/**
 * Handles JSON-RPC communication over STDIN/STDOUT for Claude Desktop integration
 * Enables seamless connection between Claude Desktop and Rapid Resolver's MCP service
 */
class StdioServer {
    constructor(proxy) {
        this.proxy = proxy;
    }

    async serve() {
        logger.info('MCP OAuth proxy ready');

        const rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout,
            terminal: false
        });

        rl.on('line', async (line) => {
            line = line.trim();
            if (!line) return;

            let request;
            try {
                request = JSON.parse(line);
                logger.debug(`Received request: ${request.method || 'unknown'} (id: ${request.id})`);
            } catch (error) {
                logger.error(`Invalid JSON received: ${error.message}`);
                const errorResponse = jsonrpcError(null, -32700, "Parse error");
                console.log(JSON.stringify(errorResponse));
                return;
            }

            try {
                const response = await this.proxy.call(request);
                logger.debug(`Sending response for ${request.method || 'unknown'} (id: ${request.id})`);
                console.log(JSON.stringify(response));
            } catch (error) {
                logger.error(`Unexpected error processing request: ${error.message}`);
                const errorResponse = jsonrpcError(request.id, -32603, "Internal error");
                console.log(JSON.stringify(errorResponse));
            }
        });

        // Handle graceful shutdown
        rl.on('close', () => {
            logger.info('Shutting down');
            process.exit(0);
        });

        process.on('SIGINT', () => {
            logger.info('Shutting down');
            process.exit(0);
        });

        process.on('SIGTERM', () => {
            logger.info('Shutting down');
            process.exit(0);
        });
    }
}

// --------------------------------------------------------------------------- //
//  Command Line Interface                                                     //
// --------------------------------------------------------------------------- //

/**
 * Parse command line arguments and environment variables
 */
function parseArgs() {
    const args = {
        clientId: process.env.OAUTH_CLIENT_ID,
        clientSecret: process.env.OAUTH_CLIENT_SECRET,
        tokenUrl: process.env.OAUTH_TOKEN_URL,
        mcpServerUrl: process.env.MCP_SERVER_URL,
        scope: process.env.OAUTH_SCOPE || 'read',
        sessionId: process.env.SESSION_ID,
        debug: false
    };

    // Parse command line arguments
    for (let i = 2; i < process.argv.length; i++) {
        const arg = process.argv[i];
        switch (arg) {
            case '--client-id':
                args.clientId = process.argv[++i];
                break;
            case '--client-secret':
                args.clientSecret = process.argv[++i];
                break;
            case '--token-url':
                args.tokenUrl = process.argv[++i];
                break;
            case '--mcp-server-url':
                args.mcpServerUrl = process.argv[++i];
                break;
            case '--scope':
                args.scope = process.argv[++i];
                break;
            case '--session-id':
                args.sessionId = process.argv[++i];
                break;
            case '--debug':
                args.debug = true;
                break;
            case '--help':
                console.log(`
MCP OAuth Proxy - Forward JSON-RPC requests to MCP servers with OAuth authentication

Usage: node mcp-oauth-proxy.js [options]

Options:
  --client-id <id>          OAuth client ID (or set OAUTH_CLIENT_ID)
  --client-secret <secret>  OAuth client secret (or set OAUTH_CLIENT_SECRET)
  --token-url <url>         OAuth token endpoint (or set OAUTH_TOKEN_URL)
  --mcp-server-url <url>    MCP server URL (or set MCP_SERVER_URL)
  --scope <scope>           OAuth scope (or set OAUTH_SCOPE, default: read)
  --session-id <id>         Session ID (or set SESSION_ID)
  --debug                   Enable debug logging
  --help                    Show this help message

Examples:
  node mcp-oauth-proxy.js \\
    --client-id "your-client-id" \\
    --client-secret "your-client-secret" \\
    --token-url "https://auth.example.com/oauth/token" \\
    --mcp-server-url "https://mcp.example.com/api" \\
    --scope "read write"
`);
                process.exit(0);
                break;
        }
    }

    return args;
}

// --------------------------------------------------------------------------- //
//  Main Entry Point                                                           //
// --------------------------------------------------------------------------- //

async function main() {
    const args = parseArgs();

    if (args.debug) {
        logger.enableDebug();
        logger.info('Debug logging enabled');
    }

    logger.info('MCP OAuth Proxy starting...');

    // Validate required arguments
    const required = [
        ['client-id', args.clientId, 'OAUTH_CLIENT_ID'],
        ['client-secret', args.clientSecret, 'OAUTH_CLIENT_SECRET'],
        ['token-url', args.tokenUrl, 'OAUTH_TOKEN_URL'],
        ['mcp-server-url', args.mcpServerUrl, 'MCP_SERVER_URL']
    ];

    for (const [name, value, envVar] of required) {
        if (!value) {
            logger.error(`Missing ${name} (set ${envVar} or use --${name})`);
            process.exit(1);
        }
    }

    // Test OAuth credentials
    const tokenManager = new TokenManager(args.clientId, args.clientSecret, args.tokenUrl, args.scope);
    try {
        await tokenManager.get();
        logger.info('OAuth authentication successful');
    } catch (error) {
        logger.error(`OAuth authentication failed: ${error.message}`);
        process.exit(1);
    }

    // Start the proxy server
    const proxy = new MCPProxy(args.mcpServerUrl, tokenManager, args.sessionId);
    const server = new StdioServer(proxy);
    await server.serve();
}

// Run the proxy if this file is executed directly
if (require.main === module) {
    main().catch((error) => {
        logger.error(`Unhandled error: ${error.message}`);
        process.exit(1);
    });
}

// Export classes for testing/reuse
module.exports = { MCPProxy, TokenManager, StdioServer };