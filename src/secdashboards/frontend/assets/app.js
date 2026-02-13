/* iris — Alpine.js application components */

const API = "/api";

// ─── Shared helpers ──────────────────────────────────────────────

async function apiFetch(path, opts = {}) {
    const resp = await fetch(`${API}${path}`, {
        headers: { "Content-Type": "application/json" },
        ...opts,
    });
    if (!resp.ok) throw new Error(`API ${resp.status}: ${resp.statusText}`);
    return resp.json();
}

function formatLatency(s) {
    return s != null ? s.toFixed(3) + "s" : "—";
}

function formatAge(minutes) {
    if (minutes == null) return "—";
    if (minutes < 60) return Math.round(minutes) + "m";
    return (minutes / 60).toFixed(1) + "h";
}

function timeAgo(isoString) {
    if (!isoString) return "—";
    const diff = (Date.now() - new Date(isoString).getTime()) / 1000;
    if (diff < 60) return Math.round(diff) + "s ago";
    if (diff < 3600) return Math.round(diff / 60) + "m ago";
    if (diff < 86400) return Math.round(diff / 3600) + "h ago";
    return Math.round(diff / 86400) + "d ago";
}

// ─── Dashboard ───────────────────────────────────────────────────

function dashboardApp() {
    return {
        loading: true,
        data: null,
        error: null,

        async init() {
            try {
                this.data = await apiFetch("/dashboard");
            } catch (e) {
                this.error = e.message;
            } finally {
                this.loading = false;
            }
        },
    };
}

// ─── Health Monitor ──────────────────────────────────────────────

function healthMonitor() {
    return {
        sources: [],
        loading: true,
        refreshing: false,
        error: null,
        lastChecked: null,

        async init() {
            await this.loadCached();
        },

        async loadCached() {
            this.loading = true;
            this.error = null;
            try {
                this.sources = await apiFetch("/sources/health");
                if (this.sources.length > 0) {
                    this.lastChecked = this.sources[0].checked_at;
                }
            } catch (e) {
                this.error = e.message;
            } finally {
                this.loading = false;
            }
        },

        async refresh() {
            this.refreshing = true;
            this.error = null;
            try {
                const resp = await apiFetch("/sources/refresh", { method: "POST" });
                this.sources = resp.results || [];
                if (this.sources.length > 0) {
                    this.lastChecked = this.sources[0].checked_at;
                }
            } catch (e) {
                this.error = e.message;
            } finally {
                this.refreshing = false;
            }
        },

        get healthyCount() {
            return this.sources.filter((s) => s.healthy).length;
        },

        get unhealthyCount() {
            return this.sources.filter((s) => !s.healthy).length;
        },

        formatLatency,
        formatAge,
        timeAgo,
    };
}

// ─── Detections ──────────────────────────────────────────────────

function detectionsApp() {
    return {
        rules: [],
        loading: true,
        error: null,

        // Query explorer state
        sql: "",
        queryResult: null,
        querying: false,
        queryError: null,

        async init() {
            try {
                this.rules = await apiFetch("/rules?enabled_only=false");
            } catch (e) {
                this.error = e.message;
            } finally {
                this.loading = false;
            }
        },

        async runQuery() {
            if (!this.sql.trim()) return;
            this.querying = true;
            this.queryError = null;
            this.queryResult = null;
            try {
                this.queryResult = await apiFetch("/query", {
                    method: "POST",
                    body: JSON.stringify({ sql: this.sql }),
                });
                if (this.queryResult.error) {
                    this.queryError = this.queryResult.error;
                    this.queryResult = null;
                }
            } catch (e) {
                this.queryError = e.message;
            } finally {
                this.querying = false;
            }
        },

        severityClass(severity) {
            if (severity === "critical" || severity === "high") return "badge-error";
            if (severity === "medium") return "badge-warn";
            return "badge-ok";
        },
    };
}

// ─── Sources ─────────────────────────────────────────────────────

function sourcesApp() {
    return {
        sources: [],
        loading: true,
        error: null,

        async init() {
            try {
                this.sources = await apiFetch("/sources");
            } catch (e) {
                this.error = e.message;
            } finally {
                this.loading = false;
            }
        },
    };
}

// ─── Navigation ──────────────────────────────────────────────────

function navApp() {
    return {
        currentPath: window.location.pathname,

        isActive(path) {
            if (path === "/" && this.currentPath === "/") return true;
            if (path !== "/" && this.currentPath.startsWith(path)) return true;
            return false;
        },
    };
}

// ─── Register globals ────────────────────────────────────────────

document.addEventListener("alpine:init", () => {
    Alpine.data("dashboardApp", dashboardApp);
    Alpine.data("healthMonitor", healthMonitor);
    Alpine.data("detectionsApp", detectionsApp);
    Alpine.data("sourcesApp", sourcesApp);
    Alpine.data("navApp", navApp);
});
