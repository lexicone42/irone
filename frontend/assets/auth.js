/* iris — Session-based authentication via server-side Cognito flow.
 *
 * The Lambda handles OAuth code exchange and session management.
 * This module checks auth status and redirects to login if needed.
 *
 * Flow:
 *   1. Page loads → auth.init() checks session via /auth/me
 *   2. If no session, redirect to /auth/login (Lambda → Cognito)
 *   3. Cognito redirects to /auth/callback (Lambda exchanges code, sets session cookie)
 *   4. Redirect back to / — session cookie authenticates all API calls
 */

const auth = (() => {
    let _user = null;
    let _config = null;
    let _initPromise = null;
    let _redirecting = false;

    // ─── Config ──────────────────────────────────────────────────

    async function _fetchConfig() {
        if (_config) return _config;
        const resp = await fetch("/api/auth/config");
        if (!resp.ok) throw new Error(`Auth config fetch failed: ${resp.status}`);
        _config = await resp.json();
        return _config;
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

        // Skip auth check on login page or if there's an auth error (avoid redirect loop)
        const path = window.location.pathname;
        if (path === "/login.html") return;
        if (new URLSearchParams(window.location.search).has("error")) return;

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

        // No valid session — redirect to server-side login
        _redirecting = true;
        window.location.href = "/auth/login";
    }

    /** True if a login redirect is in progress. */
    function isRedirecting() {
        return _redirecting;
    }

    /** Handle OAuth callback — not needed for server-side flow. */
    async function handleCallback() {
        // Server handles callback at /auth/callback
        window.location.href = "/";
    }

    /** Refresh tokens — server handles this via session. */
    async function refreshTokens() {
        try {
            const resp = await fetch("/auth/refresh", { method: "POST" });
            if (!resp.ok) {
                window.location.href = "/auth/login";
            }
        } catch {
            window.location.href = "/auth/login";
        }
    }

    /** Logout — redirect to server-side logout. */
    async function logout() {
        _user = null;
        sessionStorage.removeItem("iris_auth");
        window.location.href = "/auth/logout";
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
    };
})();
