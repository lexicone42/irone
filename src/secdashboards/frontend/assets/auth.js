/* iris — Client-side Cognito OIDC with PKCE authentication.
 *
 * Tokens are stored in memory only (not localStorage) — a page refresh
 * requires re-authentication.  This is intentional: for a security tool,
 * we prefer short-lived sessions over convenience.
 *
 * Flow:
 *   1. Page loads → auth.init() fetches /api/auth/config
 *   2. If auth disabled, skip — everything works unauthenticated
 *   3. If no token in memory, redirect to Cognito Hosted UI with PKCE
 *   4. Cognito redirects to /callback.html?code=xxx
 *   5. callback.html calls auth.handleCallback() which exchanges code for tokens
 *   6. Tokens stored in auth._tokens (memory), injected into apiFetch() via getAuthHeaders()
 */

const auth = (() => {
    // In-memory token storage — cleared on page refresh
    let _tokens = null;
    let _user = null;
    let _config = null;
    let _initialized = false;

    // ─── PKCE helpers ────────────────────────────────────────────

    function _generateRandomString(length) {
        const array = new Uint8Array(length);
        crypto.getRandomValues(array);
        return Array.from(array, (b) => b.toString(16).padStart(2, "0")).join("");
    }

    async function _generateCodeChallenge(verifier) {
        const encoder = new TextEncoder();
        const data = encoder.encode(verifier);
        const digest = await crypto.subtle.digest("SHA-256", data);
        return btoa(String.fromCharCode(...new Uint8Array(digest)))
            .replace(/\+/g, "-")
            .replace(/\//g, "_")
            .replace(/=+$/, "");
    }

    // ─── Config ──────────────────────────────────────────────────

    async function _fetchConfig() {
        if (_config) return _config;
        const resp = await fetch("/api/auth/config");
        if (!resp.ok) throw new Error(`Auth config fetch failed: ${resp.status}`);
        _config = await resp.json();
        return _config;
    }

    // ─── Token management ────────────────────────────────────────

    function _parseJwtPayload(token) {
        const base64 = token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
        return JSON.parse(atob(base64));
    }

    function _isTokenExpired(token) {
        try {
            const payload = _parseJwtPayload(token);
            return Date.now() >= payload.exp * 1000;
        } catch {
            return true;
        }
    }

    function _getRedirectUri() {
        return window.location.origin + "/callback.html";
    }

    // ─── Public API ──────────────────────────────────────────────

    /** Initialize auth — call on every page load. */
    async function init() {
        if (_initialized) return;
        _initialized = true;

        try {
            const config = await _fetchConfig();
            if (!config.auth_enabled) return;
        } catch {
            // If config endpoint unreachable, skip auth (local dev)
            return;
        }

        // Check for tokens in sessionStorage (survive soft navigations)
        const stored = sessionStorage.getItem("iris_auth");
        if (stored) {
            try {
                const parsed = JSON.parse(stored);
                if (parsed.id_token && !_isTokenExpired(parsed.id_token)) {
                    _tokens = parsed;
                    _user = _parseJwtPayload(parsed.id_token);
                    return;
                }
            } catch {
                sessionStorage.removeItem("iris_auth");
            }
        }

        // No valid token — redirect to login (unless already on auth pages)
        const path = window.location.pathname;
        if (path === "/callback.html" || path === "/login.html") return;

        await _redirectToLogin();
    }

    /** Redirect to Cognito Hosted UI with PKCE. */
    async function _redirectToLogin() {
        const config = await _fetchConfig();
        const verifier = _generateRandomString(64);
        const challenge = await _generateCodeChallenge(verifier);

        // Store verifier for callback
        sessionStorage.setItem("pkce_verifier", verifier);

        const params = new URLSearchParams({
            client_id: config.cognito_client_id,
            response_type: "code",
            scope: "openid email profile",
            redirect_uri: _getRedirectUri(),
            code_challenge: challenge,
            code_challenge_method: "S256",
        });

        window.location.href = `https://${config.cognito_domain}/oauth2/authorize?${params}`;
    }

    /** Handle OAuth callback — exchange code for tokens. */
    async function handleCallback(code) {
        const config = await _fetchConfig();
        const verifier = sessionStorage.getItem("pkce_verifier");
        sessionStorage.removeItem("pkce_verifier");

        if (!verifier) throw new Error("Missing PKCE verifier");

        const resp = await fetch(`https://${config.cognito_domain}/oauth2/token`, {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
                grant_type: "authorization_code",
                client_id: config.cognito_client_id,
                code: code,
                redirect_uri: _getRedirectUri(),
                code_verifier: verifier,
            }),
        });

        if (!resp.ok) {
            const text = await resp.text();
            throw new Error(`Token exchange failed: ${resp.status} ${text}`);
        }

        const tokenData = await resp.json();
        _tokens = {
            access_token: tokenData.access_token,
            id_token: tokenData.id_token,
            refresh_token: tokenData.refresh_token || null,
        };
        _user = _parseJwtPayload(tokenData.id_token);

        // Store in sessionStorage for soft navigations
        sessionStorage.setItem("iris_auth", JSON.stringify(_tokens));

        return _user;
    }

    /** Refresh tokens using the refresh_token grant. */
    async function refreshTokens() {
        if (!_tokens?.refresh_token) {
            await _redirectToLogin();
            return;
        }

        const config = await _fetchConfig();

        try {
            const resp = await fetch(`https://${config.cognito_domain}/oauth2/token`, {
                method: "POST",
                headers: { "Content-Type": "application/x-www-form-urlencoded" },
                body: new URLSearchParams({
                    grant_type: "refresh_token",
                    client_id: config.cognito_client_id,
                    refresh_token: _tokens.refresh_token,
                }),
            });

            if (!resp.ok) {
                await _redirectToLogin();
                return;
            }

            const tokenData = await resp.json();
            _tokens.access_token = tokenData.access_token;
            _tokens.id_token = tokenData.id_token;
            _user = _parseJwtPayload(tokenData.id_token);

            sessionStorage.setItem("iris_auth", JSON.stringify(_tokens));
        } catch {
            await _redirectToLogin();
        }
    }

    /** Logout — clear tokens and redirect to Cognito logout. */
    async function logout() {
        const config = await _fetchConfig();
        _tokens = null;
        _user = null;
        sessionStorage.removeItem("iris_auth");

        if (config.cognito_domain && config.cognito_client_id) {
            const params = new URLSearchParams({
                client_id: config.cognito_client_id,
                logout_uri: window.location.origin + "/login.html",
            });
            window.location.href = `https://${config.cognito_domain}/logout?${params}`;
        } else {
            window.location.href = "/login.html";
        }
    }

    /** Get Authorization header for API calls. Returns {} if no auth. */
    function getAuthHeaders() {
        if (!_tokens?.access_token) return {};
        return { Authorization: `Bearer ${_tokens.access_token}` };
    }

    /** Check if user is currently authenticated. */
    function isAuthenticated() {
        return _tokens !== null && _tokens.id_token && !_isTokenExpired(_tokens.id_token);
    }

    /** Get current user info (from ID token claims). */
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
        getUser,
        isAuthEnabled,
    };
})();
