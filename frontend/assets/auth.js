/* irone — Auth wrapper bridging the l42-cognito-passkey library to the
 * global `auth` API that all pages use.
 *
 * Flow:
 *   1. Page loads → auth.init() fetches /api/auth/config
 *   2. Configures l42 auth library with Cognito passkey client ID
 *   3. Checks session via /auth/me (server-side session cookie)
 *   4. If no session, redirects to /login.html (client-side login form)
 *
 * Login page (login.html) imports l42-auth.js directly as a module for
 * password, passkey, and hosted UI login methods.
 */

const auth = (() => {
    let _user = null;
    let _config = null;
    let _initPromise = null;
    let _redirecting = false;
    let _l42Module = null;

    // ─── Config ──────────────────────────────────────────────────

    async function _fetchConfig() {
        if (_config) return _config;
        const resp = await fetch("/api/auth/config");
        if (!resp.ok) throw new Error(`Auth config fetch failed: ${resp.status}`);
        _config = await resp.json();
        return _config;
    }

    /** Get the fetched auth config (available after init). */
    function getConfig() {
        return _config;
    }

    // ─── L42 integration ────────────────────────────────────────

    /** Lazily import and configure the l42 auth module. */
    async function _initL42() {
        if (_l42Module) return _l42Module;
        const config = await _fetchConfig();
        if (!config.auth_enabled) return null;

        // Set config before importing (l42 reads L42_AUTH_CONFIG at load time)
        window.L42_AUTH_CONFIG = {
            clientId: config.passkey_client_id || config.cognito_client_id,
            domain: config.cognito_domain,
            region: config.cognito_region,
            redirectUri: window.location.origin + '/callback.html',
            tokenEndpoint: '/auth/token',
            refreshEndpoint: '/auth/refresh',
            logoutEndpoint: '/auth/logout',
            sessionEndpoint: '/auth/session',
            validateCredentialEndpoint: '/auth/validate-credential',
            scopes: ['openid', 'email', 'aws.cognito.signin.user.admin'],
        };

        _l42Module = await import('/assets/l42-auth.js');
        return _l42Module;
    }

    // ─── Public API ──────────────────────────────────────────────

    /** Initialize auth — call on every page load. All callers await the same promise. */
    function init() {
        if (!_initPromise) _initPromise = _doInit();
        return _initPromise;
    }

    async function _doInit() {
        try {
            const config = await _fetchConfig();
            if (!config.auth_enabled) return;
        } catch {
            // Config endpoint unreachable — skip auth (local dev)
            return;
        }

        // Skip auth check on login page or if there's an auth error
        const path = window.location.pathname;
        if (path === "/login.html") return;
        if (new URLSearchParams(window.location.search).has("error")) return;

        // Initialize l42 module (sets up auto-refresh, etc.)
        await _initL42();

        // Check session by calling /auth/me
        try {
            const resp = await fetch("/auth/me");
            if (resp.ok) {
                _user = await resp.json();
                return;
            }
        } catch {
            // Network error — fall through to redirect
        }

        // No valid session — redirect to login page
        _redirecting = true;
        window.location.href = "/login.html";
    }

    /** True if a login redirect is in progress. */
    function isRedirecting() {
        return _redirecting;
    }

    /** Handle OAuth callback — exchange code via l42 or fall back. */
    async function handleCallback() {
        window.location.href = "/";
    }

    /** Refresh tokens via server-side session. */
    async function refreshTokens() {
        try {
            const resp = await fetch("/auth/refresh", { method: "POST" });
            if (!resp.ok) {
                window.location.href = "/login.html";
            }
        } catch {
            window.location.href = "/login.html";
        }
    }

    /** Logout — destroy session and redirect. */
    async function logout() {
        _user = null;
        // POST to server to destroy session
        try {
            await fetch("/auth/logout", { method: "POST" });
        } catch { /* best-effort */ }
        window.location.href = "/login.html";
    }

    /** Get Authorization header — not needed with session cookies. */
    function getAuthHeaders() {
        return {};
    }

    /** Check if user is currently authenticated. */
    function isAuthenticated() {
        return _user !== null;
    }

    /** Get current user info. */
    function getUser() {
        return _user;
    }

    /** Check if auth is enabled (after init). */
    function isAuthEnabled() {
        return _config?.auth_enabled === true;
    }

    /** Get the l42 module (for login.html and settings.html). */
    async function getL42() {
        return _initL42();
    }

    return {
        init,
        handleCallback,
        refreshTokens,
        logout,
        getAuthHeaders,
        isAuthenticated,
        isRedirecting,
        getUser,
        isAuthEnabled,
        getConfig,
        getL42,
    };
})();
