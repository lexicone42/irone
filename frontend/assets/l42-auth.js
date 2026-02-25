/**
 * L42 Cognito Passkey - Authentication Library
 *
 * Reusable authentication library with AWS Cognito + WebAuthn/Passkey support.
 * Designed to be self-hosted - copy this file to your project.
 *
 * Usage:
 *   import { configure, isAuthenticated, loginWithPassword } from './auth.js';
 *   configure({ clientId: 'xxx', cognitoDomain: 'xxx.auth.region.amazoncognito.com' });
 *
 * @version 0.20.0
 * @license Apache-2.0
 */

export const VERSION = '0.20.0';

// ==================== CONFIGURATION ====================

const DEFAULT_CONFIG = /*#__PURE__*/ {
    cognitoDomain: null,        // REQUIRED: e.g., 'myapp.auth.us-west-2.amazoncognito.com'
    cognitoRegion: 'us-west-2',
    clientId: null,             // REQUIRED: Cognito app client ID
    tokenKey: 'l42_auth_tokens',
    stateKey: 'l42_auth_state',
    scopes: 'openid email profile aws.cognito.signin.user.admin',
    cookieName: 'l42_id_token',
    allowedDomains: null,       // Auto-allow current domain if not set
    relyingPartyId: null,       // For WebAuthn - usually your domain
    // Token storage: 'handler' (server-side via Token Handler pattern)
    tokenStorage: 'handler',
    // Token Handler endpoints (required when tokenStorage: 'handler')
    tokenEndpoint: null,        // e.g., '/auth/token' - GET tokens from server
    refreshEndpoint: null,      // e.g., '/auth/refresh' - POST to refresh tokens
    logoutEndpoint: null,       // e.g., '/auth/logout' - POST to logout
    sessionEndpoint: null,      // e.g., '/auth/session' - POST tokens after direct login (passkey/password)
    validateCredentialEndpoint: null, // e.g., '/auth/validate-credential' - pre-registration AAGUID/policy check
    oauthCallbackUrl: null,     // e.g., '/auth/callback' - Backend OAuth callback
    // Token Handler cache TTL in milliseconds (default: 30 seconds)
    handlerCacheTtl: 30000,
    // Structured logging for OCSF/Security Lake integration
    // Set to a function(event) to receive OCSF-formatted security events
    // Set to 'console' for console.log output, or null to disable
    securityLogger: null,
    // Debug logging mode:
    // - false: disabled (default)
    // - true: log to console.debug with [l42-auth] prefix
    // - 'verbose': also include data payloads in console output
    // - function(event): receive debug events programmatically
    debug: false,
    // Auto-upgrade: silently offer passkey registration after password login
    // Requires browser support for conditional create (Chrome 136+, Safari 18+)
    autoUpgradeToPasskey: false,
    // Login rate limiting: exponential backoff on failed attempts
    maxLoginAttemptsBeforeDelay: 3,     // Failed attempts before backoff kicks in
    loginBackoffBaseMs: 1000,           // Initial delay (doubles each time)
    loginBackoffMaxMs: 30000            // Cap at 30 seconds
};

// ==================== TOKEN STORAGE ABSTRACTION ====================

/**
 * Token store interface - abstracts where tokens are stored.
 * As of v0.15.0, only HandlerTokenStore is supported.
 */

/**
 * Handler-based token store (v0.8.0).
 * Tokens are stored server-side in HttpOnly session cookies.
 * This store fetches tokens from the server endpoint and caches them briefly.
 *
 * Security benefits:
 * - Tokens are never stored in localStorage/sessionStorage (immune to XSS storage scanning)
 * - refresh_token never leaves the server (only access_token/id_token returned)
 * - Server manages token refresh and session lifecycle
 *
 * Note: While cached tokens are still in JavaScript memory, the attack surface is
 * significantly reduced compared to localStorage.
 */
const HandlerTokenStore = {
    _cache: null,
    _cacheExpiry: 0,
    _fetchPromise: null,

    /**
     * Get tokens - returns cached value or fetches from server.
     * This method is async in handler mode.
     * @param {string} _tokenKey - Ignored in handler mode
     * @returns {Promise<Object|null>} Tokens or null if not authenticated
     */
    async get(_tokenKey) {
        // Return cached value if still valid
        if (this._cache && Date.now() < this._cacheExpiry) {
            return this._cache;
        }

        // Deduplicate concurrent requests
        if (this._fetchPromise) {
            return this._fetchPromise;
        }

        this._fetchPromise = this._fetchTokens();
        try {
            return await this._fetchPromise;
        } finally {
            this._fetchPromise = null;
        }
    },

    /**
     * Fetch tokens from the server endpoint.
     * @returns {Promise<Object|null>} Tokens or null
     * @private
     */
    async _fetchTokens() {
        const endpoint = config.tokenEndpoint;
        if (!endpoint) {
            console.error('HandlerTokenStore: tokenEndpoint not configured');
            return null;
        }

        try {
            const response = await fetch(endpoint, {
                method: 'GET',
                credentials: 'include', // Send session cookies
                headers: {
                    'Accept': 'application/json'
                }
            });

            // 401/403 means not authenticated - return null
            if (response.status === 401 || response.status === 403) {
                this._cache = null;
                this._cacheExpiry = 0;
                return null;
            }

            // 5xx or network errors should throw
            if (!response.ok) {
                throw new Error(`Token fetch failed: ${response.status}`);
            }

            const data = await response.json();

            // Server returns tokens (without refresh_token for security)
            const tokens = {
                access_token: data.access_token,
                id_token: data.id_token,
                auth_method: data.auth_method || 'handler'
                // Note: refresh_token is NOT returned - it stays server-side
            };

            // Cache with TTL
            this._cache = tokens;
            this._cacheExpiry = Date.now() + (config.handlerCacheTtl || 30000);

            return tokens;
        } catch (error) {
            // Network errors throw, let caller handle
            console.error('HandlerTokenStore: fetch failed', error);
            throw error;
        }
    },

    /**
     * Set tokens - in handler mode, this only updates the cache.
     * Actual token storage is managed by the server.
     * @param {string} _tokenKey - Ignored
     * @param {Object} tokens - Tokens to cache
     */
    set(_tokenKey, tokens) {
        // Update cache only - server manages actual storage
        this._cache = tokens;
        this._cacheExpiry = Date.now() + (config.handlerCacheTtl || 30000);
    },

    /**
     * Clear cached tokens.
     * Note: This doesn't log out from server - use logout() for that.
     */
    clear(_tokenKey) {
        this._cache = null;
        this._cacheExpiry = 0;
    },

    /**
     * Get cached tokens synchronously (for isAuthenticated checks).
     * Returns cached value without fetching.
     * @returns {Object|null} Cached tokens or null
     */
    getCached() {
        if (this._cache && Date.now() < this._cacheExpiry) {
            return this._cache;
        }
        return null;
    }
};

/**
 * Persist tokens to the server session after direct login (passkey/password).
 *
 * In handler mode, OAuth login creates a server session via /auth/callback,
 * but direct login (passkey/password) completes client-side. This function
 * bridges the gap by POSTing tokens to the sessionEndpoint so the server
 * can create a session that survives page reloads.
 *
 * @param {Object} tokens - Tokens from Cognito (access_token, id_token, refresh_token, auth_method)
 * @returns {Promise<void>}
 * @throws {Error} If the session endpoint returns a non-OK response
 * @private
 */
async function _persistHandlerSession(tokens) {
    if (!config.sessionEndpoint) {
        return;
    }

    debugLog('token', 'persistHandlerSession', { endpoint: config.sessionEndpoint, auth_method: tokens.auth_method });

    const response = await fetch(config.sessionEndpoint, {
        method: 'POST',
        credentials: 'include',
        headers: {
            'Content-Type': 'application/json',
            'X-L42-CSRF': '1'
        },
        body: JSON.stringify({
            access_token: tokens.access_token,
            id_token: tokens.id_token,
            refresh_token: tokens.refresh_token,
            auth_method: tokens.auth_method
        })
    });

    if (!response.ok) {
        const msg = `Session persist failed: ${response.status}`;
        debugLog('token', 'persistHandlerSession:failed', { status: response.status });
        throw new Error(msg);
    }

    debugLog('token', 'persistHandlerSession:success');
}

/**
 * Validate a credential against server-side policies before completing registration.
 *
 * When validateCredentialEndpoint is configured, this sends the attestation object
 * and client data JSON to the server for AAGUID allowlist and device-bound policy
 * checks. If the server rejects the credential (403), the error is thrown and
 * registration is aborted before reaching Cognito.
 *
 * @param {Object} credentialResponse - The formatted credential from buildCredentialResponse()
 * @returns {Promise<void>}
 * @throws {Error} If the server rejects the credential (reason included in message)
 * @private
 */
async function _validateCredential(credentialResponse) {
    if (!config.validateCredentialEndpoint) {
        return;
    }

    debugLog('passkey', 'validateCredential', { endpoint: config.validateCredentialEndpoint });

    const response = await fetch(config.validateCredentialEndpoint, {
        method: 'POST',
        credentials: 'include',
        headers: {
            'Content-Type': 'application/json',
            'X-L42-CSRF': '1'
        },
        body: JSON.stringify({
            attestation_object: credentialResponse.response.attestationObject,
            client_data_json: credentialResponse.response.clientDataJSON
        })
    });

    if (!response.ok) {
        var body = {};
        try { body = await response.json(); } catch (_) { /* ignore parse errors */ }
        var reason = body.reason || 'Credential rejected by server';
        debugLog('passkey', 'validateCredential:rejected', { status: response.status, reason: reason });
        throw new Error('Credential validation failed: ' + reason);
    }

    debugLog('passkey', 'validateCredential:accepted');
}

/**
 * Get the active token store.
 * @returns {Object} Token store with get/set/clear methods
 */
function getTokenStore() {
    return HandlerTokenStore;
}

// ==================== OCSF SECURITY EVENT SCHEMA ====================
// Open Cybersecurity Schema Framework (OCSF) for AWS Security Lake integration
// See: https://schema.ocsf.io/

/**
 * OCSF Event Class UIDs
 */
const OCSF_CLASS = /*#__PURE__*/ {
    AUTHENTICATION: 3001,       // Authentication events (login, logout, token refresh)
    ACCOUNT_CHANGE: 3002        // Account changes (passkey add/delete)
};

/**
 * OCSF Activity IDs for Authentication (class 3001)
 */
const OCSF_AUTH_ACTIVITY = /*#__PURE__*/ {
    LOGON: 1,
    LOGOFF: 2,
    AUTHENTICATION_TICKET: 3,   // Initial token grant
    SERVICE_TICKET: 4           // Token refresh
};

/**
 * OCSF Activity IDs for Account Change (class 3002)
 */
const OCSF_ACCOUNT_ACTIVITY = /*#__PURE__*/ {
    CREATE: 1,                  // Passkey registered
    DELETE: 4                   // Passkey deleted
};

/**
 * OCSF Status IDs
 */
const OCSF_STATUS = /*#__PURE__*/ {
    SUCCESS: 1,
    FAILURE: 2
};

/**
 * OCSF Severity IDs
 */
const OCSF_SEVERITY = /*#__PURE__*/ {
    INFORMATIONAL: 1,
    LOW: 2,
    MEDIUM: 3,
    HIGH: 4,
    CRITICAL: 5
};

/**
 * Authentication protocol IDs (OCSF auth_protocol_id)
 */
const OCSF_AUTH_PROTOCOL = /*#__PURE__*/ {
    UNKNOWN: 0,
    PASSWORD: 2,                // Username/Password
    OAUTH2: 10,                 // OAuth 2.0 / OIDC
    FIDO2: 99                   // WebAuthn/Passkey (custom, not in OCSF 1.0)
};

/**
 * Log a security event in OCSF format.
 * Events are sent to the configured securityLogger.
 *
 * @param {Object} params - Event parameters
 * @param {number} params.class_uid - OCSF event class
 * @param {number} params.activity_id - Activity within the class
 * @param {string} params.activity_name - Human-readable activity name
 * @param {number} params.status_id - Success or failure
 * @param {number} params.severity_id - Event severity
 * @param {string} [params.user_email] - Actor's email
 * @param {number} [params.auth_protocol_id] - Authentication protocol
 * @param {string} [params.auth_protocol] - Protocol name
 * @param {string} [params.message] - Additional message
 * @param {Object} [params.metadata] - Additional metadata
 */
function logSecurityEvent({
    class_uid,
    activity_id,
    activity_name,
    status_id,
    severity_id,
    user_email = null,
    auth_protocol_id = OCSF_AUTH_PROTOCOL.UNKNOWN,
    auth_protocol = 'Unknown',
    message = null,
    metadata = {}
}) {
    const logger = config.securityLogger;
    if (!logger) return;

    const event = {
        // OCSF base event
        class_uid,
        class_name: class_uid === OCSF_CLASS.AUTHENTICATION ? 'Authentication' : 'Account Change',
        activity_id,
        activity_name,
        severity_id,
        severity: ['Unknown', 'Informational', 'Low', 'Medium', 'High', 'Critical'][severity_id] || 'Unknown',
        status_id,
        status: status_id === OCSF_STATUS.SUCCESS ? 'Success' : 'Failure',
        time: Date.now(),
        // Product info
        metadata: {
            product: {
                name: 'l42-cognito-passkey',
                version: VERSION,
                vendor_name: 'L42'
            },
            ...metadata
        },
        // Actor
        actor: user_email ? {
            user: {
                email_addr: user_email,
                type_id: 1,  // User
                type: 'User'
            }
        } : undefined,
        // Auth-specific fields (for class 3001)
        ...(class_uid === OCSF_CLASS.AUTHENTICATION ? {
            auth_protocol_id,
            auth_protocol
        } : {}),
        // Message
        message
    };

    // Remove undefined fields
    Object.keys(event).forEach(key => event[key] === undefined && delete event[key]);

    if (logger === 'console') {
        console.log('[L42-AUTH-OCSF]', JSON.stringify(event));
    } else if (typeof logger === 'function') {
        try {
            logger(event);
        } catch (e) {
            // Don't let logger errors break auth flow
            console.error('Security logger error:', e);
        }
    }
}

// ==================== DEBUG LOGGING ====================

const DEBUG_HISTORY_MAX = 100;
const _debugHistory = [];

/**
 * Log a debug event to the ring buffer and optional output.
 * @param {string} category - Event category (token, auth, config, state, refresh, session, passkey)
 * @param {string} message - Event message
 * @param {Object} [data] - Optional data payload
 * @private
 */
function debugLog(category, message, data) {
    if (!config.debug) return;

    const event = {
        timestamp: Date.now(),
        category,
        message,
        ...(data !== undefined ? { data } : {}),
        version: VERSION
    };

    _debugHistory.push(event);
    if (_debugHistory.length > DEBUG_HISTORY_MAX) {
        _debugHistory.shift();
    }

    if (config.debug === true) {
        console.debug('[l42-auth]', category, message);
    } else if (config.debug === 'verbose') {
        console.debug('[l42-auth]', category, message, data !== undefined ? data : '');
    } else if (typeof config.debug === 'function') {
        try {
            config.debug(event);
        } catch {
            // Don't let debug callback errors break auth flow
        }
    }
}

/**
 * Get a copy of the debug event history.
 * Returns an empty array if debug mode is disabled.
 * @returns {Array<Object>} Array of debug events (newest last)
 */
export function getDebugHistory() {
    return [..._debugHistory];
}

/**
 * Clear the debug event history.
 */
export function clearDebugHistory() {
    _debugHistory.length = 0;
}

/**
 * Get a snapshot of current auth diagnostics.
 * Works regardless of debug mode.
 * @returns {Object} Current auth state summary
 */
export function getDiagnostics() {
    const tokens = _configured ? getTokensSync() : null;
    let tokenExpiry = null;
    if (tokens && tokens.id_token) {
        try {
            tokenExpiry = new Date(UNSAFE_decodeJwtPayload(tokens.id_token).exp * 1000);
        } catch {
            // Invalid token
        }
    }

    return {
        configured: _configured,
        tokenStorage: config.tokenStorage,
        hasTokens: tokens !== null,
        isAuthenticated: _configured ? isAuthenticated() : false,
        tokenExpiry,
        authMethod: tokens ? (tokens.auth_method || null) : null,
        userEmail: _configured ? getUserEmail() : null,
        userGroups: _configured ? getUserGroups() : [],
        isAdmin: _configured ? isAdmin() : false,
        isReadonly: _configured ? isReadonly() : false,
        autoRefreshActive: isAutoRefreshActive(),
        debug: config.debug,
        version: VERSION
    };
}

// Token refresh configuration by auth method
const REFRESH_CONFIG = /*#__PURE__*/ {
    password: {
        cookieMaxAge: 86400,      // 1 day in seconds
        refreshBefore: 300000     // Refresh 5 minutes before expiry (ms)
    },
    passkey: {
        cookieMaxAge: 2592000,    // 30 days in seconds
        refreshBefore: 3600000    // Refresh 1 hour before expiry (ms)
    }
};

let config = { ...DEFAULT_CONFIG };
let _configured = false;
let _conditionalAbortController = null;

// Login rate limiting: per-email attempt tracking { email → { count, lastAttemptTime } }
const _loginAttempts = new Map();

/**
 * Abort any pending conditional UI (passkey autofill) request.
 * Called automatically when other login methods are used or on logout.
 * @private
 */
function abortConditionalRequest() {
    if (_conditionalAbortController) {
        _conditionalAbortController.abort();
        _conditionalAbortController = null;
    }
}

/**
 * Auto-read configuration from window.L42_AUTH_CONFIG if present.
 * Called automatically on first use if configure() hasn't been called.
 */
function autoConfigureFromWindow() {
    if (_configured) return;

    if (typeof window !== 'undefined' && window.L42_AUTH_CONFIG) {
        const windowConfig = window.L42_AUTH_CONFIG;
        configure({
            clientId: windowConfig.clientId,
            cognitoDomain: windowConfig.domain || windowConfig.cognitoDomain,
            cognitoRegion: windowConfig.region || windowConfig.cognitoRegion || 'us-west-2',
            redirectUri: windowConfig.redirectUri,
            scopes: Array.isArray(windowConfig.scopes)
                ? windowConfig.scopes.join(' ')
                : windowConfig.scopes,
            allowedDomains: windowConfig.allowedDomains,
            tokenEndpoint: windowConfig.tokenEndpoint,
            refreshEndpoint: windowConfig.refreshEndpoint,
            logoutEndpoint: windowConfig.logoutEndpoint,
            sessionEndpoint: windowConfig.sessionEndpoint,
            validateCredentialEndpoint: windowConfig.validateCredentialEndpoint,
        });
    }
}

/**
 * Ensure configuration is valid before use.
 * @throws {Error} If required configuration is missing
 */
function requireConfig() {
    autoConfigureFromWindow();

    if (!_configured) {
        throw new Error(
            'Auth not configured. Call configure() first or set window.L42_AUTH_CONFIG.\n' +
            'Example: configure({ clientId: "xxx", cognitoDomain: "xxx.auth.region.amazoncognito.com" })'
        );
    }
}

/**
 * Check if a domain is allowed for redirects.
 * @param {string} hostname - Hostname to check
 * @returns {boolean} True if allowed
 */
function isDomainAllowed(hostname) {
    hostname = hostname.toLowerCase();

    // Always allow localhost
    if (hostname === 'localhost' || hostname === '127.0.0.1') {
        return true;
    }

    // If allowedDomains is configured, check against it
    if (config.allowedDomains && config.allowedDomains.length > 0) {
        return config.allowedDomains.some(domain =>
            hostname === domain || hostname.endsWith('.' + domain)
        );
    }

    // If not configured, allow current domain and its subdomains
    const currentHostname = window.location.hostname.toLowerCase();
    if (hostname === currentHostname) {
        return true;
    }

    // Allow subdomains of current domain
    const currentParts = currentHostname.split('.');
    if (currentParts.length >= 2) {
        const currentBase = currentParts.slice(-2).join('.');
        return hostname === currentBase || hostname.endsWith('.' + currentBase);
    }

    return false;
}

/**
 * Configure the auth module.
 *
 * @param {Object} options - Configuration options
 * @param {string} options.clientId - REQUIRED: Cognito app client ID
 * @param {string} options.cognitoDomain - REQUIRED: Cognito domain (e.g., 'myapp.auth.us-west-2.amazoncognito.com')
 * @param {string} [options.cognitoRegion='us-west-2'] - AWS region
 * @param {string} [options.tokenKey='l42_auth_tokens'] - Key for token storage
 * @param {string} [options.redirectUri] - OAuth callback URL (defaults to current origin + /callback)
 * @param {string} [options.scopes] - OAuth scopes
 * @param {string[]} [options.allowedDomains] - Allowed redirect domains (auto-allows current domain if not set)
 * @throws {Error} If required configuration is invalid
 */
export function configure(options = {}) {
    const newConfig = { ...DEFAULT_CONFIG, ...options };

    // Validate required fields
    if (!newConfig.clientId || typeof newConfig.clientId !== 'string') {
        throw new Error('configure() requires clientId: must be a non-empty string');
    }
    if (!newConfig.cognitoDomain || typeof newConfig.cognitoDomain !== 'string') {
        throw new Error('configure() requires cognitoDomain: must be a non-empty string');
    }
    // Validate cognitoDomain format to prevent open redirect attacks
    // Format: custom-prefix.auth.region.amazoncognito.com OR custom domain
    const cognitoDomain = newConfig.cognitoDomain.toLowerCase();
    const isAmazonCognito = /^[a-z0-9-]+\.auth\.[a-z0-9-]+\.amazoncognito\.com$/.test(cognitoDomain);
    const isValidCustomDomain = /^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$/.test(cognitoDomain) &&
        !cognitoDomain.includes('..') &&
        !cognitoDomain.includes('://');
    if (!isAmazonCognito && !isValidCustomDomain) {
        throw new Error(
            'Invalid cognitoDomain format.\n' +
            'Expected: "your-app.auth.region.amazoncognito.com" or a valid custom domain.\n' +
            'Do not include protocol (https://).'
        );
    }
    if (!newConfig.cognitoRegion || typeof newConfig.cognitoRegion !== 'string') {
        throw new Error('Invalid cognitoRegion: must be a non-empty string');
    }
    if (!newConfig.tokenKey || typeof newConfig.tokenKey !== 'string') {
        throw new Error('Invalid tokenKey: must be a non-empty string');
    }

    // Reject deprecated tokenStorage values (removed in v0.15.0)
    if (newConfig.tokenStorage && newConfig.tokenStorage !== 'handler') {
        throw new Error(
            `tokenStorage "${newConfig.tokenStorage}" was removed in v0.15.0.\n` +
            'Only handler mode is supported. See docs/architecture.md for details.'
        );
    }

    // Validate handler endpoints (required as of v0.15.0 — handler is the only mode)
    const requiredEndpoints = ['tokenEndpoint', 'refreshEndpoint', 'logoutEndpoint'];
    const missing = requiredEndpoints.filter(ep => !newConfig[ep]);
    if (missing.length > 0) {
        throw new Error(
            `configure() requires handler endpoints: ${missing.join(', ')}.\n` +
            'Example: configure({\n' +
            '    clientId: "xxx",\n' +
            '    cognitoDomain: "xxx.auth.region.amazoncognito.com",\n' +
            '    tokenEndpoint: "/auth/token",\n' +
            '    refreshEndpoint: "/auth/refresh",\n' +
            '    logoutEndpoint: "/auth/logout",\n' +
            '    sessionEndpoint: "/auth/session"  // Required for passkey/password login\n' +
            '})'
        );
    }

    // Warn if sessionEndpoint is not configured — passkey/password sessions won't persist
    if (!newConfig.sessionEndpoint) {
        console.warn(
            '[l42-auth] sessionEndpoint not configured. Passkey and password logins will not ' +
            'persist across page reloads. Add sessionEndpoint: "/auth/session" to your configure() call.'
        );
    }

    // Validate redirectUri if provided
    if (newConfig.redirectUri) {
        try {
            const url = new URL(newConfig.redirectUri);
            const hostname = url.hostname.toLowerCase();
            const isLocalhost = hostname === 'localhost' || hostname === '127.0.0.1';

            // HTTPS required for non-localhost (prevents token interception)
            if (!isLocalhost && url.protocol !== 'https:') {
                throw new Error(
                    'Invalid redirectUri: HTTPS is required for non-localhost URLs.\n' +
                    'HTTP is only allowed for localhost development.'
                );
            }

            // Store allowedDomains first so isDomainAllowed can use it
            config.allowedDomains = newConfig.allowedDomains;

            if (!isDomainAllowed(hostname)) {
                const allowedList = newConfig.allowedDomains
                    ? newConfig.allowedDomains.join(', ')
                    : 'current domain (' + window.location.hostname + ')';
                throw new Error(
                    `Invalid redirectUri: domain '${hostname}' not allowed.\n` +
                    `Allowed: ${allowedList}\n` +
                    `Add it via configure({ allowedDomains: ['${hostname}'] }) or self-host the library.`
                );
            }
        } catch (e) {
            if (e.message.includes('Invalid redirectUri')) throw e;
            throw new Error('Invalid redirectUri: must be a valid URL');
        }
    }

    config = newConfig;
    _configured = true;
    debugLog('config', 'configured', { tokenStorage: config.tokenStorage });
}

/**
 * Check if the library has been configured.
 * @returns {boolean} True if configured
 */
export function isConfigured() {
    return _configured;
}

// ==================== TOKEN MANAGEMENT ====================

/**
 * Get stored authentication tokens synchronously.
 *
 * Returns cached tokens synchronously (may be null if cache expired).
 * Use this for sync functions that need token data (e.g., getUserEmail,
 * isAdmin, getIdTokenClaims). For async contexts where you need fresh
 * tokens from the server, use `await getTokens()` instead.
 *
 * @returns {Object|null} Tokens object or null
 * @private
 */
function getTokensSync() {
    return HandlerTokenStore.getCached();
}

/**
 * Get stored authentication tokens.
 *
 * Returns a Promise that fetches tokens from the server if the cache
 * has expired. Use `await getTokens()` for the freshest token state.
 *
 * @returns {Promise<Object|null>} Tokens object or null.
 */
export function getTokens() {
    requireConfig();
    return getTokenStore().get(config.tokenKey);
}

/**
 * Store tokens in the local cache.
 * The server manages actual token storage in HttpOnly session cookies.
 *
 * @param {Object} tokens - The tokens to store
 * @param {Object} [options] - Options
 * @param {boolean} [options.isRefresh=false] - If true, skip notifying auth state listeners
 *   (prevents reload loops when token refresh triggers onAuthStateChange)
 */
export function setTokens(tokens, options = {}) {
    requireConfig();
    debugLog('token', 'setTokens', { auth_method: tokens?.auth_method, isRefresh: !!options.isRefresh });
    getTokenStore().set(config.tokenKey, tokens);

    // Server manages session cookies — no client-side cookie needed

    // Only notify listeners on new login, not on token refresh
    // This prevents reload loops when listeners perform navigation
    if (!options.isRefresh) {
        notifyAuthStateChange(true);
    }
}

/**
 * Get the auth method used for current session.
 * @returns {string|null} 'password', 'passkey', or null if not authenticated
 */
export function getAuthMethod() {
    const tokens = getTokensSync();
    return tokens ? (tokens.auth_method || 'password') : null;
}

/**
 * Clear stored tokens (logout).
 * Clears the local cache (doesn't call server logout endpoint — use logout() for that).
 */
export function clearTokens() {
    debugLog('token', 'clearTokens');
    getTokenStore().clear(config.tokenKey);
    notifyAuthStateChange(false);
    notifyLogout();
}

/**
 * Decode a JWT token payload WITHOUT signature verification.
 *
 * ⚠️  SECURITY WARNING ⚠️
 * This function does NOT verify the JWT signature.
 * The returned claims are UNVERIFIED and UNTRUSTED.
 *
 * ❌ NEVER use for authorization decisions
 * ✅ ONLY use for display purposes (e.g., showing user email in UI)
 *
 * Server-side validation handles actual authentication and authorization.
 * For authorization checks, use ensureValidTokens() and verify on your server.
 *
 * @param {string} token - JWT token string
 * @returns {Object} Decoded payload (UNVERIFIED - do not trust for auth decisions)
 */
export function UNSAFE_decodeJwtPayload(token) {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(atob(base64));
}

/**
 * Validate token claims against current config.
 * Returns false (and optionally clears tokens) if claims don't match.
 * Catches tokens from a different Cognito pool or tokens with
 * unreasonable expiry.
 * @param {Object} tokens - Token object with id_token
 * @returns {boolean} true if claims are valid
 * @private
 */
function validateTokenClaims(tokens) {
    if (!tokens || !tokens.id_token) return false;

    try {
        const claims = UNSAFE_decodeJwtPayload(tokens.id_token);

        // Verify issuer matches configured Cognito pool
        // iss format: https://cognito-idp.{region}.amazonaws.com/{poolId}
        if (claims.iss) {
            const expectedIssPrefix = 'https://cognito-idp.' + config.cognitoRegion + '.amazonaws.com/';
            if (!claims.iss.startsWith(expectedIssPrefix)) {
                debugLog('token', 'validateTokenClaims:failed', {
                    reason: 'issuer mismatch',
                    expected: expectedIssPrefix + '...',
                    actual: claims.iss
                });
                return false;
            }
        }

        // Verify audience/client_id matches configured clientId
        // ID tokens use 'aud', access tokens use 'client_id'
        const tokenClientId = claims.aud || claims.client_id;
        if (!tokenClientId) {
            debugLog('token', 'validateTokenClaims:failed', {
                reason: 'missing audience claim (aud or client_id)'
            });
            return false;
        }
        if (tokenClientId !== config.clientId) {
            debugLog('token', 'validateTokenClaims:failed', {
                reason: 'client_id mismatch',
                expected: config.clientId,
                actual: tokenClientId
            });
            return false;
        }

        // Reject tokens without expiry or with unreasonable exp (> 30 days in future)
        if (!claims.exp || typeof claims.exp !== 'number') {
            debugLog('token', 'validateTokenClaims:failed', {
                reason: 'missing or invalid expiry claim'
            });
            return false;
        }
        var maxReasonableExp = Date.now() / 1000 + (30 * 24 * 60 * 60);
        if (claims.exp > maxReasonableExp) {
            debugLog('token', 'validateTokenClaims:failed', {
                reason: 'unreasonable expiry',
                exp: claims.exp
            });
            return false;
        }

        return true;
    } catch {
        debugLog('token', 'validateTokenClaims:failed', { reason: 'decode error' });
        return false;
    }
}

/**
 * Check if token is expired.
 * @param {Object} tokens - Tokens object
 * @returns {boolean} True if expired
 */
export function isTokenExpired(tokens) {
    try {
        return Date.now() >= UNSAFE_decodeJwtPayload(tokens.id_token).exp * 1000;
    } catch {
        return true;
    }
}

/**
 * Check if token should be refreshed (approaching expiry).
 * @param {Object} tokens - Tokens object
 * @returns {boolean} True if should refresh
 */
export function shouldRefreshToken(tokens) {
    if (!tokens || !tokens.id_token) return false;
    try {
        const exp = UNSAFE_decodeJwtPayload(tokens.id_token).exp * 1000;
        const authMethod = tokens.auth_method || 'password';
        const refreshConfig = REFRESH_CONFIG[authMethod] || REFRESH_CONFIG.password;
        return Date.now() >= (exp - refreshConfig.refreshBefore);
    } catch {
        return false;
    }
}

/**
 * Detect auth method from token claims (for migration from older versions).
 * @param {Object} tokens - Tokens object
 * @returns {string} Detected auth method ('password' or 'passkey')
 */
function detectAuthMethod(tokens) {
    if (tokens.auth_method) return tokens.auth_method;

    try {
        const claims = UNSAFE_decodeJwtPayload(tokens.id_token);
        const amr = claims.amr || [];
        if (amr.includes('webauthn') || amr.includes('mfa')) {
            return 'passkey';
        }
    } catch {
        // Ignore decode errors
    }

    return 'password';
}

/**
 * Refresh tokens using Cognito refresh token flow.
 * In handler mode, calls the refresh endpoint instead of Cognito directly.
 *
 * @returns {Promise<Object>} New tokens
 * @throws {Error} If refresh fails
 */
export async function refreshTokens() {
    requireConfig();
    const email = getUserEmail();
    return refreshTokensViaHandler(email);
}

/**
 * Refresh tokens via Token Handler endpoint.
 * @param {string} email - User email for logging
 * @returns {Promise<Object>} New tokens
 * @throws {Error} If refresh fails
 * @private
 */
async function refreshTokensViaHandler(email) {
    const endpoint = config.refreshEndpoint;

    try {
        const response = await fetch(endpoint, {
            method: 'POST',
            credentials: 'include', // Send session cookies
            headers: {
                'Content-Type': 'application/json',
                'X-L42-CSRF': '1' // CSRF protection for handler endpoints
            }
        });

        // 401/403 means session expired
        if (response.status === 401 || response.status === 403) {
            clearTokens();
            logSecurityEvent({
                class_uid: OCSF_CLASS.AUTHENTICATION,
                activity_id: OCSF_AUTH_ACTIVITY.SERVICE_TICKET,
                activity_name: 'Service Ticket',
                status_id: OCSF_STATUS.FAILURE,
                severity_id: OCSF_SEVERITY.LOW,
                user_email: email,
                message: 'Handler refresh failed: session expired'
            });
            throw new Error('Session expired. Please log in again.');
        }

        if (!response.ok) {
            throw new Error(`Token refresh failed: ${response.status}`);
        }

        const data = await response.json();

        const newTokens = {
            access_token: data.access_token,
            id_token: data.id_token,
            auth_method: data.auth_method || 'handler'
        };

        // Update cache
        setTokens(newTokens, { isRefresh: true });

        logSecurityEvent({
            class_uid: OCSF_CLASS.AUTHENTICATION,
            activity_id: OCSF_AUTH_ACTIVITY.SERVICE_TICKET,
            activity_name: 'Service Ticket',
            status_id: OCSF_STATUS.SUCCESS,
            severity_id: OCSF_SEVERITY.INFORMATIONAL,
            user_email: email,
            message: 'Handler token refresh successful'
        });

        return newTokens;
    } catch (e) {
        if (!e.message.includes('Session expired')) {
            logSecurityEvent({
                class_uid: OCSF_CLASS.AUTHENTICATION,
                activity_id: OCSF_AUTH_ACTIVITY.SERVICE_TICKET,
                activity_name: 'Service Ticket',
                status_id: OCSF_STATUS.FAILURE,
                severity_id: OCSF_SEVERITY.MEDIUM,
                user_email: email,
                message: 'Handler token refresh failed: ' + e.message
            });
        }
        throw e;
    }
}

/**
 * Ensure tokens are valid, refreshing if needed.
 * Call this before making authenticated API requests.
 * @returns {Promise<Object|null>} Valid tokens or null if not authenticated
 */
export async function ensureValidTokens() {
    // In handler mode, getTokens() returns a Promise
    const tokens = await getTokens();
    if (!tokens) return null;

    // Validate token claims against current config
    if (!validateTokenClaims(tokens)) {
        clearTokens();
        return null;
    }

    if (isTokenExpired(tokens)) {
        try {
            return await refreshTokens();
        } catch (e) {
            console.error('Token refresh failed:', e);
            clearTokens();
            return null;
        }
    }

    if (shouldRefreshToken(tokens)) {
        try {
            return await refreshTokens();
        } catch (e) {
            console.warn('Proactive token refresh failed:', e);
            return tokens;
        }
    }

    return tokens;
}

/**
 * Check if currently authenticated with valid tokens.
 *
 * Uses the local token cache synchronously.
 * Use isAuthenticatedAsync() for an authoritative check that fetches from server.
 *
 * @returns {boolean} True if authenticated, false otherwise
 */
export function isAuthenticated() {
    const cached = HandlerTokenStore.getCached();
    if (cached && !validateTokenClaims(cached)) {
        clearTokens();
        return false;
    }
    return !!(cached && !isTokenExpired(cached));
}

/**
 * Check if currently authenticated (async version).
 * In handler mode, fetches fresh tokens from server if cache is stale.
 * Use this when you need an authoritative auth check.
 *
 * @returns {Promise<boolean>} True if authenticated, false otherwise
 */
export async function isAuthenticatedAsync() {
    try {
        const tokens = await getTokens();
        if (tokens && !validateTokenClaims(tokens)) {
            clearTokens();
            return false;
        }
        return !!(tokens && !isTokenExpired(tokens));
    } catch {
        return false;
    }
}

/**
 * Get parsed ID token claims.
 * @returns {Object|null} ID token claims or null
 */
export function getIdTokenClaims() {
    const tokens = getTokensSync();
    if (!tokens || !tokens.id_token) return null;
    try {
        return UNSAFE_decodeJwtPayload(tokens.id_token);
    } catch {
        return null;
    }
}

/**
 * Get user email from tokens.
 * @returns {string|null} User email or null
 */
export function getUserEmail() {
    const claims = getIdTokenClaims();
    return claims ? claims.email : null;
}

/**
 * Check if tokens have admin scope for passkey management.
 * @returns {boolean} True if admin scope present
 */
export function hasAdminScope() {
    const tokens = getTokensSync();
    if (!tokens || !tokens.access_token) return false;
    try {
        const payload = UNSAFE_decodeJwtPayload(tokens.access_token);
        const scope = payload.scope || '';
        return scope.includes('aws.cognito.signin.user.admin');
    } catch {
        return false;
    }
}

/**
 * Get user's Cognito groups from ID token.
 * @returns {string[]} Array of group names
 */
export function getUserGroups() {
    const claims = getIdTokenClaims();
    return claims && claims['cognito:groups'] ? claims['cognito:groups'] : [];
}

/**
 * Check if user is in the admin group.
 * Handles common Cognito group name aliases (admin, admins, administrators).
 * @returns {boolean} True if user has admin role
 */
export function isAdmin() {
    const groups = getUserGroups().map(g => g.toLowerCase());
    return groups.includes('admin') || groups.includes('admins') || groups.includes('administrators');
}

/**
 * Check if user is in readonly group (and NOT admin).
 * Handles common Cognito group name aliases.
 * @returns {boolean} True if user has readonly-only access
 */
export function isReadonly() {
    const groups = getUserGroups().map(g => g.toLowerCase());
    const hasReadonly = groups.includes('readonly') || groups.includes('read-only') ||
                        groups.includes('viewer') || groups.includes('viewers');
    const hasAdmin = groups.includes('admin') || groups.includes('admins') || groups.includes('administrators');
    return hasReadonly && !hasAdmin;
}

// ==================== COGNITO API ====================

const RETRY_CONFIG = /*#__PURE__*/ {
    maxRetries: 3,
    baseDelayMs: 1000,
    maxDelayMs: 10000,
    retryableStatusCodes: [429, 500, 502, 503, 504]
};

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function getBackoffDelay(attempt) {
    const exponentialDelay = RETRY_CONFIG.baseDelayMs * Math.pow(2, attempt);
    const jitter = Math.random() * 0.3 * exponentialDelay;
    return Math.min(exponentialDelay + jitter, RETRY_CONFIG.maxDelayMs);
}

// ============================================================================
// Login Rate Limiting
// ============================================================================

/**
 * Check rate limit for login attempts and apply delay if needed.
 * Called at the top of login functions. Applies exponential backoff
 * after threshold failures — the delay IS the rate limiting (no throws).
 */
async function checkLoginRateLimit(email) {
    const entry = _loginAttempts.get(email);
    if (!entry || entry.count < config.maxLoginAttemptsBeforeDelay) return;

    const attemptsOverThreshold = entry.count - config.maxLoginAttemptsBeforeDelay;
    const exponentialDelay = config.loginBackoffBaseMs * Math.pow(2, attemptsOverThreshold);
    const jitter = Math.random() * 0.3 * exponentialDelay;
    const delayMs = Math.min(exponentialDelay + jitter, config.loginBackoffMaxMs);

    debugLog('auth', 'login:throttled', {
        email,
        attemptCount: entry.count,
        delayMs: Math.round(delayMs)
    });

    await sleep(delayMs);
}

/**
 * Record a failed login attempt. Logs OCSF event on first threshold breach.
 */
function recordLoginFailure(email) {
    const entry = _loginAttempts.get(email) || { count: 0, lastAttemptTime: 0 };
    entry.count += 1;
    entry.lastAttemptTime = Date.now();
    _loginAttempts.set(email, entry);

    // Log OCSF on first threshold breach
    if (entry.count === config.maxLoginAttemptsBeforeDelay) {
        logSecurityEvent({
            class_uid: OCSF_CLASS.AUTHENTICATION,
            activity_id: OCSF_AUTH_ACTIVITY.LOGON,
            activity_name: 'Logon',
            status_id: OCSF_STATUS.FAILURE,
            severity_id: OCSF_SEVERITY.HIGH,
            user_email: email,
            message: 'Login rate limit activated: ' + entry.count + ' failed attempts for ' + email
        });
    }
}

/**
 * Reset login attempt counter on successful login.
 */
function resetLoginAttempts(email) {
    _loginAttempts.delete(email);
}

/**
 * Detect Cognito account lockout from error response.
 * Returns true if the error indicates a server-side lockout.
 */
function detectCognitoLockout(error) {
    const msg = (error.message || '').toLowerCase();
    const type = (error.__type || error.code || '').toLowerCase();
    return (
        (type.includes('notauthorizedexception') || msg.includes('notauthorizedexception')) &&
        (msg.includes('temporarily locked') || msg.includes('password attempts exceeded'))
    );
}

/**
 * Get login attempt info for a given email (for UI display).
 * Returns null if no history exists for this email.
 */
export function getLoginAttemptInfo(email) {
    const entry = _loginAttempts.get(email);
    if (!entry) return null;

    const threshold = config.maxLoginAttemptsBeforeDelay;
    const isThrottled = entry.count >= threshold;
    let nextRetryMs = 0;

    if (isThrottled) {
        const attemptsOverThreshold = entry.count - threshold;
        const exponentialDelay = config.loginBackoffBaseMs * Math.pow(2, attemptsOverThreshold);
        nextRetryMs = Math.min(exponentialDelay, config.loginBackoffMaxMs);
    }

    return {
        attemptsRemaining: Math.max(0, threshold - entry.count),
        nextRetryMs,
        isThrottled
    };
}

async function cognitoRequest(action, body) {
    requireConfig();
    let lastError;

    for (let attempt = 0; attempt <= RETRY_CONFIG.maxRetries; attempt++) {
        try {
            const res = await fetch('https://cognito-idp.' + config.cognitoRegion + '.amazonaws.com/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-amz-json-1.1',
                    'X-Amz-Target': 'AWSCognitoIdentityProviderService.' + action
                },
                body: JSON.stringify(body)
            });

            if (RETRY_CONFIG.retryableStatusCodes.includes(res.status) && attempt < RETRY_CONFIG.maxRetries) {
                const delay = getBackoffDelay(attempt);
                console.warn(`Cognito request failed with ${res.status}, retrying in ${Math.round(delay)}ms`);
                await sleep(delay);
                continue;
            }

            const data = await res.json();
            if (!res.ok || data.__type) {
                throw new Error(data.message || data.__type || 'Request failed');
            }
            return data;

        } catch (error) {
            lastError = error;

            if (error.name === 'TypeError' && attempt < RETRY_CONFIG.maxRetries) {
                const delay = getBackoffDelay(attempt);
                console.warn(`Cognito network error, retrying in ${Math.round(delay)}ms`);
                await sleep(delay);
                continue;
            }

            throw error;
        }
    }

    throw lastError || new Error('Request failed after retries');
}

// ==================== BASE64URL HELPERS ====================

function b64ToArrayBuffer(b64) {
    const pad = '='.repeat((4 - b64.length % 4) % 4);
    const base64 = b64.replace(/-/g, '+').replace(/_/g, '/') + pad;
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

function arrayBufferToB64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// ==================== LOGIN METHODS ====================

/**
 * Get redirect URI for OAuth flows.
 * @returns {string} Redirect URI
 */
export function getRedirectUri() {
    return config.redirectUri || window.location.origin + '/callback';
}

/**
 * Login with password using direct Cognito API.
 * @param {string} email - User email
 * @param {string} password - User password
 * @returns {Promise<Object>} Authentication result with tokens
 */
export async function loginWithPassword(email, password) {
    requireConfig();
    abortConditionalRequest();
    await checkLoginRateLimit(email);

    try {
        const res = await cognitoRequest('InitiateAuth', {
            AuthFlow: 'USER_PASSWORD_AUTH',
            ClientId: config.clientId,
            AuthParameters: {
                USERNAME: email,
                PASSWORD: password
            }
        });

        if (res.AuthenticationResult) {
            const tokens = {
                access_token: res.AuthenticationResult.AccessToken,
                id_token: res.AuthenticationResult.IdToken,
                refresh_token: res.AuthenticationResult.RefreshToken,
                auth_method: 'password'
            };
            setTokens(tokens);
            await _persistHandlerSession(tokens);
            notifyLogin(tokens, 'password');

            logSecurityEvent({
                class_uid: OCSF_CLASS.AUTHENTICATION,
                activity_id: OCSF_AUTH_ACTIVITY.LOGON,
                activity_name: 'Logon',
                status_id: OCSF_STATUS.SUCCESS,
                severity_id: OCSF_SEVERITY.INFORMATIONAL,
                user_email: email,
                auth_protocol_id: OCSF_AUTH_PROTOCOL.PASSWORD,
                auth_protocol: 'Password',
                message: 'User logged in with password'
            });

            debugLog('auth', 'loginWithPassword:success', { email });
            resetLoginAttempts(email);

            // Non-blocking passkey upgrade offer (fire and forget)
            if (config.autoUpgradeToPasskey) {
                upgradeToPasskey().catch(function() {});
            }

            return tokens;
        } else if (res.ChallengeName) {
            logSecurityEvent({
                class_uid: OCSF_CLASS.AUTHENTICATION,
                activity_id: OCSF_AUTH_ACTIVITY.LOGON,
                activity_name: 'Logon',
                status_id: OCSF_STATUS.FAILURE,
                severity_id: OCSF_SEVERITY.LOW,
                user_email: email,
                auth_protocol_id: OCSF_AUTH_PROTOCOL.PASSWORD,
                auth_protocol: 'Password',
                message: 'MFA challenge required: ' + res.ChallengeName
            });
            throw new Error('Additional verification required: ' + res.ChallengeName);
        }
        throw new Error('Authentication failed');
    } catch (e) {
        if (!e.message.includes('Additional verification required')) {
            logSecurityEvent({
                class_uid: OCSF_CLASS.AUTHENTICATION,
                activity_id: OCSF_AUTH_ACTIVITY.LOGON,
                activity_name: 'Logon',
                status_id: OCSF_STATUS.FAILURE,
                severity_id: OCSF_SEVERITY.MEDIUM,
                user_email: email,
                auth_protocol_id: OCSF_AUTH_PROTOCOL.PASSWORD,
                auth_protocol: 'Password',
                message: 'Password authentication failed: ' + e.message
            });
        }
        debugLog('auth', 'loginWithPassword:failed', { email, error: e.message });
        if (!e.message.includes('Additional verification required')) {
            recordLoginFailure(email);
            if (detectCognitoLockout(e)) {
                logSecurityEvent({
                    class_uid: OCSF_CLASS.AUTHENTICATION,
                    activity_id: OCSF_AUTH_ACTIVITY.LOGON,
                    activity_name: 'Logon',
                    status_id: OCSF_STATUS.FAILURE,
                    severity_id: OCSF_SEVERITY.CRITICAL,
                    user_email: email,
                    auth_protocol_id: OCSF_AUTH_PROTOCOL.PASSWORD,
                    auth_protocol: 'Password',
                    message: 'Cognito account lockout detected for ' + email
                });
                throw new Error('Account temporarily locked by Cognito. Please try again later or reset your password.');
            }
        }
        throw e;
    }
}

/**
 * Login with passkey using direct WebAuthn flow.
 * @param {string} email - User email
 * @returns {Promise<Object>} Authentication result with tokens
 */

/**
 * Format a 16-byte AAGUID as a UUID string (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx).
 * @param {Uint8Array} bytes - 16 bytes of AAGUID
 * @returns {string} UUID-formatted string
 * @private
 */
function formatAaguid(bytes) {
    const hex = Array.from(bytes, function(b) { return b.toString(16).padStart(2, '0'); }).join('');
    return hex.slice(0, 8) + '-' + hex.slice(8, 12) + '-' + hex.slice(12, 16) + '-' + hex.slice(16, 20) + '-' + hex.slice(20, 32);
}

/**
 * Parse authenticatorData from a WebAuthn response to extract flags and optional AAGUID.
 *
 * AuthenticatorData layout (per W3C WebAuthn spec §6.1):
 *   Bytes 0-31:  rpIdHash (SHA-256)
 *   Byte 32:     flags (UP=0x01, UV=0x04, BE=0x08, BS=0x10, AT=0x40, ED=0x80)
 *   Bytes 33-36: signCount (big-endian uint32)
 *   Bytes 37+:   (optional) attestedCredentialData: AAGUID(16) + credIdLen(2) + credId + pubKey
 *
 * @param {ArrayBuffer} authData - Raw authenticatorData
 * @returns {Object|null} Parsed flags, signCount, and optional AAGUID; null if too short
 * @private
 */
function parseAuthenticatorData(authData) {
    var bytes = new Uint8Array(authData);
    if (bytes.length < 37) return null;

    var flags = bytes[32];
    var result = {
        userPresent: !!(flags & 0x01),
        userVerified: !!(flags & 0x04),
        backupEligible: !!(flags & 0x08),
        backupState: !!(flags & 0x10),
        attestedCredentialData: !!(flags & 0x40),
        extensionData: !!(flags & 0x80),
        signCount: new DataView(authData).getUint32(33, false)
    };

    // Extract AAGUID if attested credential data present (AT flag) and enough bytes
    if (result.attestedCredentialData && bytes.length >= 55) {
        var aaguidBytes = bytes.slice(37, 53);
        result.aaguid = formatAaguid(aaguidBytes);
    }

    return result;
}

/**
 * Build a WebAuthn assertion response for Cognito from a navigator.credentials.get() result.
 * @param {PublicKeyCredential} credential - The credential from navigator.credentials.get()
 * @returns {Object} Assertion response formatted for Cognito
 * @private
 */
function buildAssertionResponse(credential) {
    const response = {
        id: credential.id,
        rawId: arrayBufferToB64(credential.rawId),
        response: {
            clientDataJSON: arrayBufferToB64(credential.response.clientDataJSON),
            authenticatorData: arrayBufferToB64(credential.response.authenticatorData),
            signature: arrayBufferToB64(credential.response.signature)
        },
        type: credential.type,
        clientExtensionResults: credential.getClientExtensionResults() || {}
    };

    if (credential.response.userHandle) {
        response.response.userHandle = arrayBufferToB64(credential.response.userHandle);
    }
    if (credential.authenticatorAttachment) {
        response.authenticatorAttachment = credential.authenticatorAttachment;
    }

    // Parse BE/BS flags and sign count from raw authenticatorData
    var metadata = parseAuthenticatorData(credential.response.authenticatorData);
    if (metadata) {
        response.authenticatorMetadata = metadata;
    }

    return response;
}

/**
 * Build a WebAuthn credential response for Cognito from a navigator.credentials.create() result.
 * @param {PublicKeyCredential} credential - The credential from navigator.credentials.create()
 * @returns {Object} Credential response formatted for Cognito
 * @private
 */
function buildCredentialResponse(credential) {
    const response = {
        id: credential.id,
        rawId: arrayBufferToB64(credential.rawId),
        type: credential.type,
        response: {
            clientDataJSON: arrayBufferToB64(credential.response.clientDataJSON),
            attestationObject: arrayBufferToB64(credential.response.attestationObject)
        },
        clientExtensionResults: credential.getClientExtensionResults() || {}
    };

    if (credential.response.getTransports) {
        response.response.transports = credential.response.getTransports();
    }
    if (credential.authenticatorAttachment) {
        response.authenticatorAttachment = credential.authenticatorAttachment;
    }
    if (credential.response.getPublicKey) {
        response.response.publicKey = arrayBufferToB64(credential.response.getPublicKey());
    }
    if (credential.response.getPublicKeyAlgorithm) {
        response.response.publicKeyAlgorithm = credential.response.getPublicKeyAlgorithm();
    }
    if (credential.response.getAuthenticatorData) {
        var rawAuthData = credential.response.getAuthenticatorData();
        response.response.authenticatorData = arrayBufferToB64(rawAuthData);

        // Parse BE/BS flags, AAGUID, and sign count from raw authenticatorData
        var metadata = parseAuthenticatorData(rawAuthData);
        if (metadata) {
            response.authenticatorMetadata = metadata;
        }
    }

    return response;
}

export async function loginWithPasskey(email) {
    requireConfig();
    abortConditionalRequest();
    await checkLoginRateLimit(email);

    try {
        // Step 1: Initiate auth with USER_AUTH and PREFERRED_CHALLENGE=WEB_AUTHN
        const initRes = await cognitoRequest('InitiateAuth', {
            AuthFlow: 'USER_AUTH',
            ClientId: config.clientId,
            AuthParameters: {
                USERNAME: email,
                PREFERRED_CHALLENGE: 'WEB_AUTHN'
            }
        });

        if (initRes.ChallengeName !== 'WEB_AUTHN') {
            logSecurityEvent({
                class_uid: OCSF_CLASS.AUTHENTICATION,
                activity_id: OCSF_AUTH_ACTIVITY.LOGON,
                activity_name: 'Logon',
                status_id: OCSF_STATUS.FAILURE,
                severity_id: OCSF_SEVERITY.LOW,
                user_email: email,
                auth_protocol_id: OCSF_AUTH_PROTOCOL.FIDO2,
                auth_protocol: 'WebAuthn/FIDO2',
                message: 'Passkey not available for user'
            });
            throw new Error('Passkey not available. Register one first or use password.');
        }

        // Step 2: Parse WebAuthn challenge
        const credentialOptions = JSON.parse(initRes.ChallengeParameters.CREDENTIAL_REQUEST_OPTIONS);

        const publicKey = {
            challenge: b64ToArrayBuffer(credentialOptions.challenge),
            timeout: credentialOptions.timeout,
            rpId: credentialOptions.rpId,
            allowCredentials: credentialOptions.allowCredentials.map(function(cred) {
                return {
                    id: b64ToArrayBuffer(cred.id),
                    type: cred.type,
                    transports: cred.transports
                };
            }),
            userVerification: credentialOptions.userVerification
        };

        // Step 3: Get passkey assertion
        const credential = await navigator.credentials.get({ publicKey: publicKey });

        // Step 4: Build response
        const assertionResponse = buildAssertionResponse(credential);

        // Step 5: Complete challenge
        const authRes = await cognitoRequest('RespondToAuthChallenge', {
            ChallengeName: 'WEB_AUTHN',
            ClientId: config.clientId,
            Session: initRes.Session,
            ChallengeResponses: {
                USERNAME: email,
                CREDENTIAL: JSON.stringify(assertionResponse)
            }
        });

        if (authRes.AuthenticationResult) {
            const tokens = {
                access_token: authRes.AuthenticationResult.AccessToken,
                id_token: authRes.AuthenticationResult.IdToken,
                refresh_token: authRes.AuthenticationResult.RefreshToken,
                auth_method: 'passkey'
            };
            setTokens(tokens);
            await _persistHandlerSession(tokens);
            notifyLogin(tokens, 'passkey');

            var loginMeta = {};
            if (assertionResponse.authenticatorMetadata) {
                var lm = assertionResponse.authenticatorMetadata;
                loginMeta.backup_eligible = lm.backupEligible;
                loginMeta.backup_state = lm.backupState;
            }
            logSecurityEvent({
                class_uid: OCSF_CLASS.AUTHENTICATION,
                activity_id: OCSF_AUTH_ACTIVITY.LOGON,
                activity_name: 'Logon',
                status_id: OCSF_STATUS.SUCCESS,
                severity_id: OCSF_SEVERITY.INFORMATIONAL,
                user_email: email,
                auth_protocol_id: OCSF_AUTH_PROTOCOL.FIDO2,
                auth_protocol: 'WebAuthn/FIDO2',
                message: 'User logged in with passkey',
                metadata: loginMeta
            });

            debugLog('auth', 'loginWithPasskey:success', { email });
            resetLoginAttempts(email);
            return tokens;
        }
        throw new Error('Passkey authentication failed');
    } catch (e) {
        // Log failure (if not already logged above)
        if (!e.message.includes('Passkey not available')) {
            logSecurityEvent({
                class_uid: OCSF_CLASS.AUTHENTICATION,
                activity_id: OCSF_AUTH_ACTIVITY.LOGON,
                activity_name: 'Logon',
                status_id: OCSF_STATUS.FAILURE,
                severity_id: e.name === 'NotAllowedError' ? OCSF_SEVERITY.LOW : OCSF_SEVERITY.MEDIUM,
                user_email: email,
                auth_protocol_id: OCSF_AUTH_PROTOCOL.FIDO2,
                auth_protocol: 'WebAuthn/FIDO2',
                message: 'Passkey authentication failed: ' + e.message
            });
        }
        debugLog('auth', 'loginWithPasskey:failed', { email, error: e.message });
        if (!e.message.includes('Passkey not available')) {
            recordLoginFailure(email);
            if (detectCognitoLockout(e)) {
                logSecurityEvent({
                    class_uid: OCSF_CLASS.AUTHENTICATION,
                    activity_id: OCSF_AUTH_ACTIVITY.LOGON,
                    activity_name: 'Logon',
                    status_id: OCSF_STATUS.FAILURE,
                    severity_id: OCSF_SEVERITY.CRITICAL,
                    user_email: email,
                    auth_protocol_id: OCSF_AUTH_PROTOCOL.FIDO2,
                    auth_protocol: 'WebAuthn/FIDO2',
                    message: 'Cognito account lockout detected for ' + email
                });
                throw new Error('Account temporarily locked by Cognito. Please try again later or reset your password.');
            }
        }
        throw e;
    }
}

/**
 * Login via passkey autofill (Conditional UI).
 *
 * Two modes:
 * - With email: Uses Cognito challenge + conditional mediation (single biometric prompt)
 * - Without email: Discovery flow with local challenge, then re-auth via loginWithPasskey
 *   (requires two biometric prompts — Cognito needs a username for its challenge)
 *
 * @param {Object} [options]
 * @param {string} [options.email] - If known, enables single-prompt flow
 * @param {AbortSignal} [options.signal] - AbortController signal for cancellation
 * @returns {Promise<Object>} Token object on success
 * @throws {Error} If conditional mediation is not available
 */
export async function loginWithConditionalUI(options = {}) {
    requireConfig();

    if (!await isConditionalMediationAvailable()) {
        throw new Error('Conditional mediation not available in this browser');
    }

    // Abort any previous conditional request
    abortConditionalRequest();

    var controller = new AbortController();
    _conditionalAbortController = controller;

    // Merge user signal with internal controller
    var signal = options.signal
        ? AbortSignal.any([options.signal, controller.signal])
        : controller.signal;

    var rpId = config.relyingPartyId || window.location.hostname;

    if (options.email) {
        // Mode A: Email known — use Cognito challenge for single-prompt flow
        await checkLoginRateLimit(options.email);
        try {
            var initRes = await cognitoRequest('InitiateAuth', {
                AuthFlow: 'USER_AUTH',
                ClientId: config.clientId,
                AuthParameters: {
                    USERNAME: options.email,
                    PREFERRED_CHALLENGE: 'WEB_AUTHN'
                }
            });

            if (initRes.ChallengeName !== 'WEB_AUTHN') {
                throw new Error('Passkey not available for this user');
            }

            var credOpts = JSON.parse(initRes.ChallengeParameters.CREDENTIAL_REQUEST_OPTIONS);
            var credential = await navigator.credentials.get({
                publicKey: {
                    challenge: b64ToArrayBuffer(credOpts.challenge),
                    rpId: credOpts.rpId,
                    allowCredentials: [],
                    userVerification: credOpts.userVerification || 'preferred',
                    timeout: credOpts.timeout
                },
                mediation: 'conditional',
                signal: signal
            });

            _conditionalAbortController = null;

            var assertionResponse = buildAssertionResponse(credential);

            var authRes = await cognitoRequest('RespondToAuthChallenge', {
                ChallengeName: 'WEB_AUTHN',
                ClientId: config.clientId,
                Session: initRes.Session,
                ChallengeResponses: {
                    USERNAME: options.email,
                    CREDENTIAL: JSON.stringify(assertionResponse)
                }
            });

            if (authRes.AuthenticationResult) {
                var tokens = {
                    access_token: authRes.AuthenticationResult.AccessToken,
                    id_token: authRes.AuthenticationResult.IdToken,
                    refresh_token: authRes.AuthenticationResult.RefreshToken,
                    auth_method: 'passkey'
                };
                setTokens(tokens);
                await _persistHandlerSession(tokens);
                notifyLogin(tokens, 'passkey');

                logSecurityEvent({
                    class_uid: OCSF_CLASS.AUTHENTICATION,
                    activity_id: OCSF_AUTH_ACTIVITY.LOGON,
                    activity_name: 'Logon',
                    status_id: OCSF_STATUS.SUCCESS,
                    severity_id: OCSF_SEVERITY.INFORMATIONAL,
                    user_email: options.email,
                    auth_protocol_id: OCSF_AUTH_PROTOCOL.FIDO2,
                    auth_protocol: 'WebAuthn/FIDO2',
                    message: 'User logged in with conditional UI (passkey autofill)'
                });

                debugLog('auth', 'loginWithConditionalUI:success', { email: options.email, mode: 'email' });
                resetLoginAttempts(options.email);
                return tokens;
            }
            throw new Error('Conditional UI authentication failed');
        } catch (e) {
            _conditionalAbortController = null;
            debugLog('auth', 'loginWithConditionalUI:failed', { email: options.email, error: e.message });
            recordLoginFailure(options.email);
            throw e;
        }
    } else {
        // Mode B: Discovery flow — local challenge, then re-auth
        try {
            var challenge = crypto.getRandomValues(new Uint8Array(32));
            var credential = await navigator.credentials.get({
                publicKey: {
                    challenge: challenge.buffer,
                    rpId: rpId,
                    allowCredentials: [],
                    userVerification: 'preferred'
                },
                mediation: 'conditional',
                signal: signal
            });

            _conditionalAbortController = null;

            // Extract username from userHandle
            var userHandle = credential.response.userHandle;
            if (!userHandle || userHandle.byteLength === 0) {
                throw new Error('No user handle returned — credential may not be discoverable');
            }
            var discoveredUser = new TextDecoder().decode(userHandle);

            debugLog('auth', 'loginWithConditionalUI:discovered', { user: discoveredUser });

            // Complete with full Cognito flow (will prompt biometric again)
            return loginWithPasskey(discoveredUser);
        } catch (e) {
            _conditionalAbortController = null;
            debugLog('auth', 'loginWithConditionalUI:failed', { error: e.message });
            throw e;
        }
    }
}

/**
 * Generate a cryptographically secure random state for OAuth CSRF protection.
 * @returns {string} Random state string
 */
function generateOAuthState() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array, b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Store OAuth state for CSRF protection.
 * Uses localStorage instead of sessionStorage to survive cross-domain navigation
 * (Safari ITP and Firefox ETP can clear sessionStorage during OAuth redirects).
 * State is cleared immediately after verification for security.
 */
function storeOAuthState(state) {
    localStorage.setItem(config.stateKey, state);
}

function verifyOAuthState(state) {
    const stored = localStorage.getItem(config.stateKey);
    localStorage.removeItem(config.stateKey);  // Clear immediately - single use
    return stored && stored === state;
}

// ==================== PKCE (Proof Key for Code Exchange) ====================

const PKCE_VERIFIER_KEY = 'l42_pkce_verifier';

/**
 * Generate a cryptographically secure code verifier for PKCE.
 * RFC 7636 requires 43-128 characters from unreserved URI characters.
 * @returns {string} Random code verifier (64 characters)
 */
function generateCodeVerifier() {
    const array = new Uint8Array(48); // 48 bytes = 64 base64url chars
    crypto.getRandomValues(array);
    // Base64url encoding without padding
    return btoa(String.fromCharCode(...array))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

/**
 * Generate SHA-256 code challenge from verifier for PKCE.
 * @param {string} verifier - Code verifier
 * @returns {Promise<string>} Base64url-encoded SHA-256 hash
 */
async function generateCodeChallenge(verifier) {
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    const hash = await crypto.subtle.digest('SHA-256', data);
    // Base64url encoding without padding
    return btoa(String.fromCharCode(...new Uint8Array(hash)))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

/**
 * Store PKCE code verifier.
 * Uses localStorage to survive cross-domain navigation during OAuth flow.
 * Cleared immediately after token exchange for security.
 */
function storeCodeVerifier(verifier) {
    localStorage.setItem(PKCE_VERIFIER_KEY, verifier);
}

function getAndClearCodeVerifier() {
    const verifier = localStorage.getItem(PKCE_VERIFIER_KEY);
    localStorage.removeItem(PKCE_VERIFIER_KEY);  // Clear immediately - single use
    return verifier;
}

/**
 * Redirect to Cognito Hosted UI for login.
 * Uses PKCE (Proof Key for Code Exchange) for enhanced security.
 * Use this for OAuth flow with full scopes (needed for passkey management).
 *
 * In handler mode, redirects to the backend callback URL (oauthCallbackUrl)
 * which handles the OAuth exchange server-side.
 *
 * @param {string} [email] - Optional email hint
 * @returns {Promise<void>}
 */
export async function loginWithHostedUI(email) {
    requireConfig();
    abortConditionalRequest();

    const state = generateOAuthState();
    storeOAuthState(state);

    // Use backend callback URL if configured, otherwise client-side callback
    const redirectUri = config.oauthCallbackUrl || getRedirectUri();

    // PKCE: Generate code verifier and challenge
    // In handler mode, PKCE is handled by the backend, but we generate for client-side callback
    const codeVerifier = generateCodeVerifier();
    storeCodeVerifier(codeVerifier);
    const codeChallenge = await generateCodeChallenge(codeVerifier);

    const params = new URLSearchParams({
        client_id: config.clientId,
        response_type: 'code',
        scope: config.scopes,
        redirect_uri: redirectUri,
        state: state,
        code_challenge: codeChallenge,
        code_challenge_method: 'S256'
    });
    if (email) {
        params.set('login_hint', email);
    }
    debugLog('auth', 'loginWithHostedUI:redirect', { email: email || null });
    window.location.href = 'https://' + config.cognitoDomain + '/oauth2/authorize?' + params;
}

/**
 * Exchange authorization code for tokens (call from callback page).
 * Uses PKCE code_verifier for enhanced security.
 * @param {string} code - Authorization code from OAuth redirect
 * @param {string} state - State parameter from OAuth redirect (for CSRF verification)
 * @returns {Promise<Object>} Tokens
 * @throws {Error} If state/PKCE verification fails or token exchange fails
 */
export async function exchangeCodeForTokens(code, state) {
    requireConfig();

    if (!state || !verifyOAuthState(state)) {
        logSecurityEvent({
            class_uid: OCSF_CLASS.AUTHENTICATION,
            activity_id: OCSF_AUTH_ACTIVITY.AUTHENTICATION_TICKET,
            activity_name: 'Authentication Ticket',
            status_id: OCSF_STATUS.FAILURE,
            severity_id: OCSF_SEVERITY.HIGH,
            auth_protocol_id: OCSF_AUTH_PROTOCOL.OAUTH2,
            auth_protocol: 'OAuth 2.0/OIDC',
            message: 'Invalid OAuth state - possible CSRF attack'
        });
        throw new Error('Invalid OAuth state - possible CSRF attack');
    }

    // PKCE: Retrieve and clear the code verifier
    const codeVerifier = getAndClearCodeVerifier();
    if (!codeVerifier) {
        logSecurityEvent({
            class_uid: OCSF_CLASS.AUTHENTICATION,
            activity_id: OCSF_AUTH_ACTIVITY.AUTHENTICATION_TICKET,
            activity_name: 'Authentication Ticket',
            status_id: OCSF_STATUS.FAILURE,
            severity_id: OCSF_SEVERITY.MEDIUM,
            auth_protocol_id: OCSF_AUTH_PROTOCOL.OAUTH2,
            auth_protocol: 'OAuth 2.0/OIDC',
            message: 'Missing PKCE code verifier - OAuth flow may have been interrupted'
        });
        throw new Error('Missing PKCE code verifier - OAuth flow may have been interrupted');
    }

    const res = await fetch('https://' + config.cognitoDomain + '/oauth2/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
            grant_type: 'authorization_code',
            client_id: config.clientId,
            code: code,
            redirect_uri: getRedirectUri(),
            code_verifier: codeVerifier
        })
    });

    if (!res.ok) {
        const errorText = await res.text();
        logSecurityEvent({
            class_uid: OCSF_CLASS.AUTHENTICATION,
            activity_id: OCSF_AUTH_ACTIVITY.AUTHENTICATION_TICKET,
            activity_name: 'Authentication Ticket',
            status_id: OCSF_STATUS.FAILURE,
            severity_id: OCSF_SEVERITY.MEDIUM,
            auth_protocol_id: OCSF_AUTH_PROTOCOL.OAUTH2,
            auth_protocol: 'OAuth 2.0/OIDC',
            message: 'Token exchange failed: ' + (errorText || res.status)
        });
        debugLog('auth', 'exchangeCodeForTokens:failed', { error: errorText || String(res.status) });
        throw new Error('Token exchange failed: ' + (errorText || res.status));
    }

    const data = await res.json();
    const tokens = {
        access_token: data.access_token,
        id_token: data.id_token,
        refresh_token: data.refresh_token,
        auth_method: 'oauth'
    };
    setTokens(tokens);
    await _persistHandlerSession(tokens);
    notifyLogin(tokens, 'oauth');

    // Extract email from the new token for logging
    const claims = UNSAFE_decodeJwtPayload(tokens.id_token);

    logSecurityEvent({
        class_uid: OCSF_CLASS.AUTHENTICATION,
        activity_id: OCSF_AUTH_ACTIVITY.AUTHENTICATION_TICKET,
        activity_name: 'Authentication Ticket',
        status_id: OCSF_STATUS.SUCCESS,
        severity_id: OCSF_SEVERITY.INFORMATIONAL,
        user_email: claims?.email,
        auth_protocol_id: OCSF_AUTH_PROTOCOL.OAUTH2,
        auth_protocol: 'OAuth 2.0/OIDC',
        message: 'OAuth token exchange successful'
    });

    debugLog('auth', 'exchangeCodeForTokens:success');
    return tokens;
}

/**
 * Logout - clear tokens and end session.
 *
 * In handler mode, this calls the logout endpoint to destroy the server session.
 * Returns a Promise in handler mode, void in other modes.
 * Existing sync calls continue to work (logout happens in background).
 *
 * @returns {void|Promise<void>}
 */
export function logout() {
    abortConditionalRequest();
    debugLog('auth', 'logout');
    const email = getUserEmail();

    // Clear local cache first (immediate UI update)
    clearTokens();

    // Call server endpoint in background
    return logoutViaHandler(email);
}

/**
 * Logout via Token Handler endpoint.
 * @param {string} email - User email for logging
 * @returns {Promise<void>}
 * @private
 */
async function logoutViaHandler(email) {
    const endpoint = config.logoutEndpoint;

    try {
        const response = await fetch(endpoint, {
            method: 'POST',
            credentials: 'include', // Send session cookies
            headers: {
                'Content-Type': 'application/json',
                'X-L42-CSRF': '1' // CSRF protection for handler endpoints
            }
        });

        // Any response (including 401) means logout succeeded from our perspective
        logSecurityEvent({
            class_uid: OCSF_CLASS.AUTHENTICATION,
            activity_id: OCSF_AUTH_ACTIVITY.LOGOFF,
            activity_name: 'Logoff',
            status_id: OCSF_STATUS.SUCCESS,
            severity_id: OCSF_SEVERITY.INFORMATIONAL,
            user_email: email,
            message: response.ok ? 'User logged out via handler' : 'Handler logout completed (session may have already expired)'
        });
    } catch (e) {
        // Network error - still consider logout successful locally
        console.warn('Handler logout endpoint failed:', e);
        logSecurityEvent({
            class_uid: OCSF_CLASS.AUTHENTICATION,
            activity_id: OCSF_AUTH_ACTIVITY.LOGOFF,
            activity_name: 'Logoff',
            status_id: OCSF_STATUS.SUCCESS,
            severity_id: OCSF_SEVERITY.LOW,
            user_email: email,
            message: 'User logged out locally (handler endpoint unreachable)'
        });
    }
}

// ==================== WEBAUTHN FEATURE DETECTION (v0.9.0) ====================

/**
 * Check if WebAuthn/passkeys are supported by the current browser.
 * Returns false in non-secure contexts (HTTP except localhost).
 *
 * @returns {boolean} True if WebAuthn is available
 *
 * @example
 * if (isPasskeySupported()) {
 *     showPasskeyLoginButton();
 * } else {
 *     hidePasskeyLoginButton();
 * }
 */
export function isPasskeySupported() {
    return typeof window !== 'undefined' &&
        window.isSecureContext === true &&
        typeof window.PublicKeyCredential !== 'undefined' &&
        typeof navigator.credentials !== 'undefined';
}

/**
 * Check if the browser supports conditional mediation (passkey autofill).
 * When available, passkey login can be triggered from the browser's autofill
 * suggestion, providing a seamless login experience without a dedicated button.
 *
 * @returns {Promise<boolean>} True if conditional mediation is available
 *
 * @example
 * if (await isConditionalMediationAvailable()) {
 *     // Set up passkey autofill on the username field
 *     document.getElementById('email').autocomplete = 'username webauthn';
 * }
 */
export async function isConditionalMediationAvailable() {
    if (!isPasskeySupported()) return false;
    try {
        if (typeof PublicKeyCredential.isConditionalMediationAvailable === 'function') {
            return await PublicKeyCredential.isConditionalMediationAvailable();
        }
    } catch {
        // Ignore errors — feature not supported
    }
    return false;
}

/**
 * Check if a platform authenticator (Touch ID, Face ID, Windows Hello) is available.
 * Cross-platform authenticators (security keys, phones) don't require this.
 *
 * @returns {Promise<boolean>} True if platform authenticator exists
 *
 * @example
 * const hasPlatform = await isPlatformAuthenticatorAvailable();
 * if (hasPlatform) {
 *     promptText.textContent = 'Use Touch ID / Face ID to sign in';
 * } else {
 *     promptText.textContent = 'Use your security key to sign in';
 * }
 */
export async function isPlatformAuthenticatorAvailable() {
    if (!isPasskeySupported()) return false;
    try {
        if (typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === 'function') {
            return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
        }
    } catch {
        // Ignore errors — feature not supported
    }
    return false;
}

/**
 * Get a summary of WebAuthn capabilities for the current environment.
 * Useful for debugging integration issues and adapting UI.
 *
 * @returns {Promise<Object>} Capabilities report
 *
 * @example
 * const caps = await getPasskeyCapabilities();
 * // { supported: true, conditionalMediation: true, platformAuthenticator: true, secureContext: true }
 */
/**
 * Detect if the current environment is a WebView (Android, iOS WKWebView, Electron).
 * @returns {boolean}
 * @private
 */
function detectWebView() {
    if (typeof navigator === 'undefined') return false;
    var ua = navigator.userAgent || '';
    // Android WebView
    if (/wv\)/.test(ua)) return true;
    // iOS WKWebView (no Safari in UA)
    if (/iPhone|iPad/.test(ua) && !/Safari/.test(ua)) return true;
    // Electron
    if (/Electron/.test(ua)) return true;
    return false;
}

export async function getPasskeyCapabilities() {
    var supported = isPasskeySupported();
    var secureContext = typeof window !== 'undefined' ? window.isSecureContext === true : false;

    // Try WebAuthn Level 3 getClientCapabilities() first
    if (supported && typeof PublicKeyCredential.getClientCapabilities === 'function') {
        try {
            var caps = await PublicKeyCredential.getClientCapabilities();
            return {
                supported: supported,
                conditionalMediation: caps.conditionalMediation === true
                    || caps['conditional-mediation'] === true,
                conditionalCreate: caps.conditionalCreate === true
                    || caps['conditional-create'] === true,
                platformAuthenticator: supported
                    ? await isPlatformAuthenticatorAvailable()
                    : false,
                secureContext: secureContext,
                hybridTransport: caps.hybridTransport === true
                    || caps['hybrid-transport'] === true,
                passkeyPlatformAuthenticator: caps.passkeyPlatformAuthenticator === true
                    || caps['passkey-platform-authenticator'] === true,
                userVerifyingPlatformAuthenticator: caps.userVerifyingPlatformAuthenticator === true
                    || caps['user-verifying-platform-authenticator'] === true,
                relatedOrigins: caps.relatedOrigins === true
                    || caps['related-origins'] === true,
                signalAllAcceptedCredentials: caps.signalAllAcceptedCredentials === true
                    || caps['signal-all-accepted-credentials'] === true,
                signalCurrentUserDetails: caps.signalCurrentUserDetails === true
                    || caps['signal-current-user-details'] === true,
                signalUnknownCredential: caps.signalUnknownCredential === true
                    || caps['signal-unknown-credential'] === true,
                isWebView: detectWebView(),
                source: 'getClientCapabilities'
            };
        } catch {
            // Fall through to individual checks
        }
    }

    // Fallback: individual feature detection
    return {
        supported: supported,
        conditionalMediation: supported ? await isConditionalMediationAvailable() : false,
        conditionalCreate: false,
        platformAuthenticator: supported ? await isPlatformAuthenticatorAvailable() : false,
        secureContext: secureContext,
        hybridTransport: false,
        passkeyPlatformAuthenticator: false,
        userVerifyingPlatformAuthenticator: supported
            ? await isPlatformAuthenticatorAvailable()
            : false,
        relatedOrigins: false,
        signalAllAcceptedCredentials: false,
        signalCurrentUserDetails: false,
        signalUnknownCredential: false,
        isWebView: detectWebView(),
        source: 'fallback'
    };
}

// ==================== PASSKEY MANAGEMENT ====================

/**
 * List registered passkeys for current user.
 * Requires admin scope (use OAuth login).
 * @returns {Promise<Array>} Array of passkey credentials
 */
export async function listPasskeys() {
    const tokens = await getTokens();
    if (!tokens) throw new Error('Not authenticated');
    if (!hasAdminScope()) {
        throw new Error(
            'Admin scope required for passkey management.\n' +
            'Use loginWithHostedUI() to get aws.cognito.signin.user.admin scope.'
        );
    }

    const res = await cognitoRequest('ListWebAuthnCredentials', {
        AccessToken: tokens.access_token
    });
    return res.Credentials || [];
}

/**
 * Register a new passkey for current user.
 * Requires admin scope (use OAuth login).
 * @returns {Promise<void>}
 */
export async function registerPasskey(options = {}) {
    const tokens = await getTokens();
    const email = getUserEmail();

    if (!tokens) throw new Error('Not authenticated');
    if (!hasAdminScope()) {
        throw new Error(
            'Admin scope required for passkey management.\n' +
            'Use loginWithHostedUI() to get aws.cognito.signin.user.admin scope.'
        );
    }

    try {
        // Step 1: Get credential creation options
        const startRes = await cognitoRequest('StartWebAuthnRegistration', {
            AccessToken: tokens.access_token
        });

        // Step 2: Convert to WebAuthn format
        const credOpts = startRes.CredentialCreationOptions;
        const publicKeyOptions = {
            challenge: b64ToArrayBuffer(credOpts.challenge),
            rp: {
                name: credOpts.rp.name,
                id: credOpts.rp.id
            },
            user: {
                id: b64ToArrayBuffer(credOpts.user.id),
                name: credOpts.user.name,
                displayName: credOpts.user.displayName
            },
            pubKeyCredParams: credOpts.pubKeyCredParams,
            timeout: credOpts.timeout || 60000,
            attestation: options.attestation || credOpts.attestation || 'none',
            authenticatorSelection: {
                // Server options as base, then caller overrides, then defaults
                ...(credOpts.authenticatorSelection || {}),
                ...(options.authenticatorAttachment !== undefined
                    ? { authenticatorAttachment: options.authenticatorAttachment }
                    : {}),
                residentKey: options.residentKey
                    || credOpts.authenticatorSelection?.residentKey
                    || 'required',
                userVerification: options.userVerification
                    || credOpts.authenticatorSelection?.userVerification
                    || 'preferred'
            }
        };

        if (credOpts.excludeCredentials) {
            publicKeyOptions.excludeCredentials = credOpts.excludeCredentials.map(function(c) {
                return {
                    type: c.type,
                    id: b64ToArrayBuffer(c.id),
                    transports: c.transports
                };
            });
        }

        // Step 3: Create credential
        const credential = await navigator.credentials.create({ publicKey: publicKeyOptions });

        // Step 4: Format for Cognito
        const credentialResponse = buildCredentialResponse(credential);

        // Step 5: Validate credential against server policies (if configured)
        await _validateCredential(credentialResponse);

        // Step 6: Complete registration
        await cognitoRequest('CompleteWebAuthnRegistration', {
            AccessToken: tokens.access_token,
            Credential: credentialResponse
        });

        var regMetadata = { credential_id: credential.id };
        if (credentialResponse.authenticatorMetadata) {
            var am = credentialResponse.authenticatorMetadata;
            regMetadata.backup_eligible = am.backupEligible;
            regMetadata.backup_state = am.backupState;
            if (am.aaguid) regMetadata.aaguid = am.aaguid;
            regMetadata.attestation = publicKeyOptions.attestation;
        }
        logSecurityEvent({
            class_uid: OCSF_CLASS.ACCOUNT_CHANGE,
            activity_id: OCSF_ACCOUNT_ACTIVITY.CREATE,
            activity_name: 'Create',
            status_id: OCSF_STATUS.SUCCESS,
            severity_id: OCSF_SEVERITY.INFORMATIONAL,
            user_email: email,
            message: 'Passkey registered successfully',
            metadata: regMetadata
        });
        debugLog('passkey', 'registerPasskey:success');
    } catch (e) {
        logSecurityEvent({
            class_uid: OCSF_CLASS.ACCOUNT_CHANGE,
            activity_id: OCSF_ACCOUNT_ACTIVITY.CREATE,
            activity_name: 'Create',
            status_id: OCSF_STATUS.FAILURE,
            severity_id: e.name === 'NotAllowedError' ? OCSF_SEVERITY.LOW : OCSF_SEVERITY.MEDIUM,
            user_email: email,
            message: 'Passkey registration failed: ' + e.message
        });
        debugLog('passkey', 'registerPasskey:failed', { error: e.message });
        throw e;
    }
}

/**
 * Silently offer passkey upgrade after password login.
 * Uses conditional create (Chrome 136+, Safari 18+).
 * Non-blocking — failures are silent (user just keeps using password).
 *
 * @param {Object} [options]
 * @param {AbortSignal} [options.signal] - AbortController signal
 * @returns {Promise<boolean>} true if passkey was created, false if skipped/failed
 */
export async function upgradeToPasskey(options = {}) {
    requireConfig();

    var tokens = await getTokens();
    if (!tokens || !hasAdminScope()) {
        debugLog('passkey', 'upgradeToPasskey:skipped', { reason: 'not authenticated or no admin scope' });
        return false;
    }

    // Check browser support for conditional create
    if (!isPasskeySupported()) return false;
    if (typeof PublicKeyCredential.isConditionalMediationAvailable !== 'function') return false;
    if (!await PublicKeyCredential.isConditionalMediationAvailable()) return false;

    try {
        // Get creation options from Cognito
        var startRes = await cognitoRequest('StartWebAuthnRegistration', {
            AccessToken: tokens.access_token
        });

        var credOpts = startRes.CredentialCreationOptions;
        var publicKeyOptions = {
            challenge: b64ToArrayBuffer(credOpts.challenge),
            rp: { name: credOpts.rp.name, id: credOpts.rp.id },
            user: {
                id: b64ToArrayBuffer(credOpts.user.id),
                name: credOpts.user.name,
                displayName: credOpts.user.displayName
            },
            pubKeyCredParams: credOpts.pubKeyCredParams,
            timeout: credOpts.timeout || 60000,
            attestation: options.attestation || credOpts.attestation || 'none',
            authenticatorSelection: {
                residentKey: 'required',
                userVerification: 'preferred'
                // No authenticatorAttachment — allow any
            }
        };

        if (credOpts.excludeCredentials) {
            publicKeyOptions.excludeCredentials = credOpts.excludeCredentials.map(function(c) {
                return {
                    type: c.type,
                    id: b64ToArrayBuffer(c.id),
                    transports: c.transports
                };
            });
        }

        // Conditional create — browser may show non-blocking prompt
        var credential = await navigator.credentials.create({
            publicKey: publicKeyOptions,
            mediation: 'conditional',
            signal: options.signal
        });

        if (!credential) {
            debugLog('passkey', 'upgradeToPasskey:skipped', { reason: 'user declined' });
            return false;
        }

        // Validate + complete registration with Cognito
        var credentialResponse = buildCredentialResponse(credential);
        await _validateCredential(credentialResponse);
        await cognitoRequest('CompleteWebAuthnRegistration', {
            AccessToken: tokens.access_token,
            Credential: credentialResponse
        });

        var upgradeMeta = {};
        if (credentialResponse.authenticatorMetadata) {
            var um = credentialResponse.authenticatorMetadata;
            upgradeMeta.backup_eligible = um.backupEligible;
            upgradeMeta.backup_state = um.backupState;
            if (um.aaguid) upgradeMeta.aaguid = um.aaguid;
            upgradeMeta.attestation = publicKeyOptions.attestation;
        }
        logSecurityEvent({
            class_uid: OCSF_CLASS.ACCOUNT_CHANGE,
            activity_id: OCSF_ACCOUNT_ACTIVITY.CREATE,
            activity_name: 'Create',
            status_id: OCSF_STATUS.SUCCESS,
            severity_id: OCSF_SEVERITY.INFORMATIONAL,
            user_email: getUserEmail(),
            message: 'Passkey upgrade completed via conditional create',
            metadata: upgradeMeta
        });

        debugLog('passkey', 'upgradeToPasskey:success');
        return true;
    } catch (e) {
        // Silent failure — don't disrupt user experience
        debugLog('passkey', 'upgradeToPasskey:failed', { error: e.message });
        return false;
    }
}

/**
 * Delete a registered passkey.
 * Requires admin scope (use OAuth login).
 * @param {string} credentialId - Credential ID to delete
 * @returns {Promise<void>}
 */
export async function deletePasskey(credentialId) {
    const tokens = await getTokens();
    const email = getUserEmail();

    if (!tokens) throw new Error('Not authenticated');
    if (!hasAdminScope()) {
        throw new Error(
            'Admin scope required for passkey management.\n' +
            'Use loginWithHostedUI() to get aws.cognito.signin.user.admin scope.'
        );
    }

    try {
        await cognitoRequest('DeleteWebAuthnCredential', {
            AccessToken: tokens.access_token,
            CredentialId: credentialId
        });

        logSecurityEvent({
            class_uid: OCSF_CLASS.ACCOUNT_CHANGE,
            activity_id: OCSF_ACCOUNT_ACTIVITY.DELETE,
            activity_name: 'Delete',
            status_id: OCSF_STATUS.SUCCESS,
            severity_id: OCSF_SEVERITY.INFORMATIONAL,
            user_email: email,
            message: 'Passkey deleted',
            metadata: { credential_id: credentialId }
        });
        debugLog('passkey', 'deletePasskey:success', { credentialId });
    } catch (e) {
        logSecurityEvent({
            class_uid: OCSF_CLASS.ACCOUNT_CHANGE,
            activity_id: OCSF_ACCOUNT_ACTIVITY.DELETE,
            activity_name: 'Delete',
            status_id: OCSF_STATUS.FAILURE,
            severity_id: OCSF_SEVERITY.MEDIUM,
            user_email: email,
            message: 'Passkey deletion failed: ' + e.message,
            metadata: { credential_id: credentialId }
        });
        debugLog('passkey', 'deletePasskey:failed', { credentialId, error: e.message });
        throw e;
    }
}

// ==================== SERVER-SIDE AUTHORIZATION ====================

/**
 * Require server-side authorization for sensitive actions.
 *
 * ⚠️  SECURITY: Client-side role checks are for UI only!
 * ALL authorization decisions MUST be validated on the server.
 *
 * This helper enforces the pattern of server-side validation by making
 * it the easy path. Use this before any sensitive operation.
 *
 * @param {string} action - The action being authorized (e.g., 'admin:delete-user')
 * @param {Object} [options] - Optional configuration
 * @param {string} [options.endpoint='/auth/authorize'] - Authorization endpoint
 * @param {Object} [options.resource] - Resource descriptor { id?, type?, owner? }
 * @param {Object} [options.context={}] - Additional context for authorization
 * @returns {Promise<{authorized: boolean, reason?: string}>} Authorization result
 * @throws {Error} If not authenticated or network error
 *
 * @example
 * // Before sensitive admin action
 * async function deleteUser(userId) {
 *     const authResult = await requireServerAuthorization('admin:delete-user', {
 *         context: { targetUserId: userId }
 *     });
 *
 *     if (!authResult.authorized) {
 *         throw new Error(`Not authorized: ${authResult.reason}`);
 *     }
 *
 *     // Proceed with deletion...
 * }
 *
 * @example
 * // Ownership-scoped action with resource
 * const authResult = await requireServerAuthorization('write:own', {
 *     resource: { id: 'doc-123', type: 'document', owner: currentOwnerSub }
 * });
 */
export async function requireServerAuthorization(action, options = {}) {
    const { endpoint = '/auth/authorize', resource, context = {} } = options;

    const tokens = await ensureValidTokens();
    if (!tokens) {
        throw new Error('Authentication required for this action');
    }

    try {
        const headers = {
            'Content-Type': 'application/json',
            'X-L42-CSRF': '1'
        };
        const fetchOptions = { method: 'POST', headers, credentials: 'include' };

        const body = { action, context };
        if (resource) {
            body.resource = resource;
        }
        fetchOptions.body = JSON.stringify(body);

        const response = await fetch(endpoint, fetchOptions);

        if (response.status === 401) {
            clearTokens();
            throw new Error('Session expired. Please log in again.');
        }

        if (response.status === 403) {
            const data = await response.json().catch(() => ({}));
            return {
                authorized: false,
                reason: data.reason || 'Permission denied'
            };
        }

        if (!response.ok) {
            throw new Error(`Authorization check failed: ${response.status}`);
        }

        const data = await response.json();
        return {
            authorized: data.authorized === true,
            reason: data.reason
        };
    } catch (error) {
        if (error.message.includes('Authentication') || error.message.includes('Session')) {
            throw error;
        }
        throw new Error(`Authorization check failed: ${error.message}`);
    }
}

/**
 * Client-side role check for UI display purposes ONLY.
 *
 * ⚠️  WARNING: This is for UI hints only (showing/hiding buttons).
 * NEVER use this for actual authorization - use requireServerAuthorization().
 *
 * @param {string} requiredRole - Role to check
 * @returns {boolean} True if user appears to have role (UNTRUSTED)
 */
export function UI_ONLY_hasRole(requiredRole) {
    const groups = getUserGroups();
    // Normalize to handle singular/plural variations
    const normalizedGroups = groups.map(g => g.toLowerCase());
    const normalizedRole = requiredRole.toLowerCase();
    return normalizedGroups.includes(normalizedRole) ||
           normalizedGroups.includes(normalizedRole + 's') ||
           normalizedGroups.includes(normalizedRole.replace(/s$/, ''));
}

// ==================== AUTH STATE CHANGE LISTENERS ====================

const authStateListeners = new Set();
const loginListeners = new Set();
const logoutListeners = new Set();

function notifyAuthStateChange(isAuth) {
    debugLog('state', 'authStateChange', { isAuthenticated: isAuth });
    authStateListeners.forEach(callback => {
        try {
            callback(isAuth);
        } catch (e) {
            console.error('Auth state listener error:', e);
        }
    });
}

/**
 * Notify login listeners when a user logs in.
 * @param {Object} tokens - The authentication tokens
 * @param {string} method - The auth method used ('password', 'passkey', 'oauth')
 */
function notifyLogin(tokens, method) {
    debugLog('state', 'login', { method });
    loginListeners.forEach(callback => {
        try {
            callback(tokens, method);
        } catch (e) {
            console.error('Login listener error:', e);
        }
    });
}

/**
 * Notify logout listeners when a user logs out.
 */
function notifyLogout() {
    debugLog('state', 'logout');
    logoutListeners.forEach(callback => {
        try {
            callback();
        } catch (e) {
            console.error('Logout listener error:', e);
        }
    });
}

/**
 * Subscribe to authentication state changes.
 * Note: This fires on login and logout, but NOT on token refresh (v0.5.7+).
 * For more explicit control, use onLogin() and onLogout().
 *
 * @param {Function} callback - Called with boolean isAuthenticated
 * @returns {Function} Unsubscribe function
 */
export function onAuthStateChange(callback) {
    authStateListeners.add(callback);
    return () => authStateListeners.delete(callback);
}

/**
 * Subscribe to login events.
 * Only fires on actual login (password, passkey, or OAuth), never on token refresh.
 *
 * @param {Function} callback - Called with (tokens, method) where method is 'password', 'passkey', or 'oauth'
 * @returns {Function} Unsubscribe function
 *
 * @example
 * const unsubscribe = onLogin((tokens, method) => {
 *     console.log('User logged in via:', method);
 *     window.location.href = '/dashboard';
 * });
 */
export function onLogin(callback) {
    loginListeners.add(callback);
    return () => loginListeners.delete(callback);
}

/**
 * Subscribe to logout events.
 * Fires when the user logs out or tokens are cleared.
 *
 * @param {Function} callback - Called with no arguments
 * @returns {Function} Unsubscribe function
 *
 * @example
 * const unsubscribe = onLogout(() => {
 *     showLoginScreen();
 * });
 */
export function onLogout(callback) {
    logoutListeners.add(callback);
    return () => logoutListeners.delete(callback);
}

// ==================== BACKGROUND TOKEN AUTO-REFRESH (v0.9.0) ====================

let _autoRefreshTimer = null;
let _visibilityHandler = null;
const sessionExpiredListeners = new Set();

/**
 * Default auto-refresh configuration.
 * Can be overridden via startAutoRefresh(options).
 */
const AUTO_REFRESH_DEFAULTS = /*#__PURE__*/ {
    intervalMs: 60000,       // Check every 60 seconds
    pauseWhenHidden: true    // Pause when tab is not visible
};

/**
 * Start automatic background token refresh.
 *
 * Periodically checks token expiry and refreshes proactively.
 * Automatically pauses when the tab is hidden (saves server load)
 * and checks immediately when the tab becomes visible again.
 *
 * Called automatically on login. Call manually if you want to
 * restart with custom options.
 *
 * @param {Object} [options] - Configuration
 * @param {number} [options.intervalMs=60000] - Check interval in milliseconds
 * @param {boolean} [options.pauseWhenHidden=true] - Pause when tab is hidden
 * @returns {Function} Stop function to cancel auto-refresh
 *
 * @example
 * // Auto-starts on login, but you can customize:
 * startAutoRefresh({ intervalMs: 30000 }); // Check every 30s
 *
 * // Stop manually if needed:
 * stopAutoRefresh();
 */
export function startAutoRefresh(options = {}) {
    debugLog('refresh', 'autoRefresh:start', { intervalMs: options.intervalMs || AUTO_REFRESH_DEFAULTS.intervalMs });
    // Clean up any existing timer
    stopAutoRefresh();

    const opts = { ...AUTO_REFRESH_DEFAULTS, ...options };

    async function refreshCheck() {
        try {
            const tokens = await getTokens();
            if (!tokens) {
                stopAutoRefresh();
                return;
            }

            if (isTokenExpired(tokens)) {
                // Token already expired - try to refresh
                try {
                    await refreshTokens();
                } catch (e) {
                    console.warn('Auto-refresh failed (token expired):', e.message);
                    clearTokens();
                    notifySessionExpired(e.message);
                    stopAutoRefresh();
                }
            } else if (shouldRefreshToken(tokens)) {
                // Token approaching expiry - proactive refresh
                try {
                    await refreshTokens();
                } catch (e) {
                    // Proactive refresh failed - not critical yet, will retry
                    console.warn('Proactive auto-refresh failed:', e.message);
                }
            }
        } catch (e) {
            // Handler mode: server returned error
            if (e.message && (e.message.includes('401') || e.message.includes('Session expired'))) {
                clearTokens();
                notifySessionExpired(e.message);
                stopAutoRefresh();
            }
        }
    }

    _autoRefreshTimer = setInterval(refreshCheck, opts.intervalMs);

    // Page visibility handling - pause when hidden, check on return
    if (opts.pauseWhenHidden && typeof document !== 'undefined') {
        _visibilityHandler = () => {
            if (document.visibilityState === 'visible') {
                // Tab became visible - check immediately
                refreshCheck();
            }
        };
        document.addEventListener('visibilitychange', _visibilityHandler);
    }

    return stopAutoRefresh;
}

/**
 * Stop automatic background token refresh.
 */
export function stopAutoRefresh() {
    debugLog('refresh', 'autoRefresh:stop');
    if (_autoRefreshTimer) {
        clearInterval(_autoRefreshTimer);
        _autoRefreshTimer = null;
    }
    if (_visibilityHandler && typeof document !== 'undefined') {
        document.removeEventListener('visibilitychange', _visibilityHandler);
        _visibilityHandler = null;
    }
}

/**
 * Check if auto-refresh is currently running.
 * @returns {boolean} True if auto-refresh timer is active
 */
export function isAutoRefreshActive() {
    return _autoRefreshTimer !== null;
}

// Auto-start on login, auto-stop on logout
loginListeners.add(() => startAutoRefresh());
logoutListeners.add(() => stopAutoRefresh());

// ==================== SESSION EXPIRY (v0.9.0) ====================

/**
 * Notify session expired listeners.
 * @param {string} reason - Why the session expired
 * @private
 */
function notifySessionExpired(reason) {
    debugLog('session', 'sessionExpired', { reason });
    sessionExpiredListeners.forEach(callback => {
        try {
            callback(reason);
        } catch (e) {
            console.error('Session expired listener error:', e);
        }
    });
}

/**
 * Subscribe to session expiry events.
 * Fires when the session cannot be recovered (refresh token expired,
 * server session destroyed, etc.). Use this to redirect to login.
 *
 * @param {Function} callback - Called with (reason: string)
 * @returns {Function} Unsubscribe function
 *
 * @example
 * onSessionExpired((reason) => {
 *     alert('Your session has expired. Please log in again.');
 *     window.location.href = '/login';
 * });
 */
export function onSessionExpired(callback) {
    sessionExpiredListeners.add(callback);
    return () => sessionExpiredListeners.delete(callback);
}

// ==================== FETCH WITH AUTH (v0.9.0) ====================

/**
 * Make an authenticated fetch request.
 *
 * Automatically injects the Bearer token, refreshes if needed,
 * and handles session expiry. Works in all storage modes.
 *
 * @param {string} url - URL to fetch
 * @param {Object} [options={}] - Standard fetch options
 * @returns {Promise<Response>} Fetch response
 * @throws {Error} If not authenticated or session expired
 *
 * @example
 * // Simple GET
 * const res = await fetchWithAuth('/api/content');
 * const data = await res.json();
 *
 * // POST with body
 * const res = await fetchWithAuth('/api/content', {
 *     method: 'POST',
 *     headers: { 'Content-Type': 'application/json' },
 *     body: JSON.stringify({ title: 'New Post' })
 * });
 *
 * // Handles 401 automatically
 * const res = await fetchWithAuth('/api/admin/users');
 * if (!res.ok) {
 *     // If 401, tokens have been cleared and onSessionExpired fired
 *     console.error('Request failed:', res.status);
 * }
 */
export async function fetchWithAuth(url, options = {}) {
    requireConfig();

    const tokens = await ensureValidTokens();
    if (!tokens) {
        throw new Error('Not authenticated. Call login first.');
    }

    const response = await fetch(url, {
        ...options,
        headers: {
            ...options.headers,
            'Authorization': `Bearer ${tokens.access_token}`
        }
    });

    // Handle auth failure - session may have expired server-side
    if (response.status === 401) {
        // Try one more refresh
        try {
            const freshTokens = await refreshTokens();
            // Retry the request with fresh tokens
            return fetch(url, {
                ...options,
                headers: {
                    ...options.headers,
                    'Authorization': `Bearer ${freshTokens.access_token}`
                }
            });
        } catch (e) {
            clearTokens();
            notifySessionExpired('Server returned 401 and refresh failed');
            throw new Error('Session expired. Please log in again.');
        }
    }

    return response;
}

// ==================== DEFAULT EXPORT ====================

export default {
    VERSION,
    configure,
    isConfigured,
    getTokens,
    setTokens,
    clearTokens,
    UNSAFE_decodeJwtPayload,
    isTokenExpired,
    shouldRefreshToken,
    refreshTokens,
    ensureValidTokens,
    getAuthMethod,
    isAuthenticated,
    isAuthenticatedAsync,
    getIdTokenClaims,
    getUserEmail,
    hasAdminScope,
    getUserGroups,
    isAdmin,
    isReadonly,
    getRedirectUri,
    loginWithPassword,
    loginWithPasskey,
    loginWithConditionalUI,
    loginWithHostedUI,
    exchangeCodeForTokens,
    logout,
    listPasskeys,
    registerPasskey,
    upgradeToPasskey,
    deletePasskey,
    onAuthStateChange,
    onLogin,
    onLogout,
    // Server-side authorization (v0.3.0+)
    requireServerAuthorization,
    UI_ONLY_hasRole,
    // Auto-refresh and session management (v0.9.0+)
    startAutoRefresh,
    stopAutoRefresh,
    isAutoRefreshActive,
    onSessionExpired,
    fetchWithAuth,
    // WebAuthn feature detection (v0.9.0+)
    isPasskeySupported,
    isConditionalMediationAvailable,
    isPlatformAuthenticatorAvailable,
    getPasskeyCapabilities,
    // Debug & diagnostics (v0.11.0+)
    getDebugHistory,
    getDiagnostics,
    clearDebugHistory,
    // Login rate limiting (v0.12.1+)
    getLoginAttemptInfo
};
