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

    // ─── Passkey enrollment gate ─────────────────────────────────

    /**
     * If the user authenticated via password or SSO (not passkey), check
     * whether they have any passkeys registered. If not, redirect to the
     * settings page so they can enroll one before accessing the dashboard.
     */
    async function _enforcePasskeyEnrollment() {
        const l42 = await _initL42();
        if (!l42) return;

        const method = typeof l42.getAuthMethod === 'function'
            ? l42.getAuthMethod()
            : null;

        // Already logged in with passkey — no gate needed
        if (method === 'passkey') return;

        // Check if user has any passkeys registered
        try {
            const passkeys = await l42.listPasskeys();
            if (passkeys && passkeys.length > 0) return; // has passkeys, OK
        } catch {
            // listPasskeys requires admin scope; if it fails, skip the gate
            // rather than locking the user out
            return;
        }

        // No passkeys registered — redirect to settings
        _redirecting = true;
        window.location.href = "/settings.html?enroll=1";
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

                // Passkey enrollment gate: if user logged in without a passkey,
                // redirect to settings to register one (skip if already on settings).
                if (path !== "/settings.html" && path !== "/callback.html") {
                    await _enforcePasskeyEnrollment();
                }
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
