/* irone — Alpine.js application components */

const API = "/api";

// ─── Shared helpers ──────────────────────────────────────────────

async function apiFetch(path, opts = {}) {
    // Ensure auth is initialized before any API call
    await auth.init();
    if (auth.isRedirecting()) return {};
    if (auth.isAuthEnabled() && !auth.isAuthenticated()) return {};

    const headers = {
        "Content-Type": "application/json",
        ...auth.getAuthHeaders(),
        ...(opts.headers || {}),
    };
    const resp = await fetch(`${API}${path}`, { ...opts, headers });

    if (resp.status === 401 && auth.isAuthEnabled()) {
        // Try token refresh, then retry once
        await auth.refreshTokens();
        const retryHeaders = {
            "Content-Type": "application/json",
            ...auth.getAuthHeaders(),
            ...(opts.headers || {}),
        };
        const retry = await fetch(`${API}${path}`, { ...opts, headers: retryHeaders });
        if (retry.status === 401) {
            window.location.href = "/auth/login";
            throw new Error("Session expired");
        }
        if (!retry.ok) throw new Error(`API ${retry.status}: ${retry.statusText}`);
        return retry.json();
    }

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
                this.sources = resp;
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

        // Detection run state
        runningRule: null,
        detectionResult: null,
        investigating: false,

        async init() {
            try {
                this.rules = await apiFetch("/rules?enabled_only=false");
            } catch (e) {
                this.error = e.message;
            } finally {
                this.loading = false;
            }
        },

        async runDetection(ruleId) {
            this.runningRule = ruleId;
            this.detectionResult = null;
            this.error = null;
            try {
                this.detectionResult = await apiFetch(`/detections/${ruleId}/run`, {
                    method: "POST",
                    body: JSON.stringify({ lookback_minutes: 15 }),
                });
            } catch (e) {
                this.error = e.message;
            } finally {
                this.runningRule = null;
            }
        },

        async investigate() {
            if (!this.detectionResult || !this.detectionResult.triggered) return;
            this.investigating = true;
            this.error = null;
            try {
                const resp = await apiFetch("/investigations/from-detection", {
                    method: "POST",
                    body: JSON.stringify({
                        rule_id: this.detectionResult.rule_id,
                        lookback_minutes: 15,
                        enrichment_window_minutes: 60,
                    }),
                });
                if (resp.triggered && resp.investigation_id) {
                    window.location.href = `/investigations.html#${resp.investigation_id}`;
                } else if (!resp.triggered) {
                    this.error = "Detection did not trigger \u2014 no investigation created";
                } else {
                    this.error = resp.error || "Investigation not created";
                }
            } catch (e) {
                this.error = e.message;
            } finally {
                this.investigating = false;
            }
        },

        dismissResult() {
            this.detectionResult = null;
        },

        // Extract a dot-path value from nested OCSF objects (e.g. "actor.user.name")
        extractNested(obj, path) {
            return path.split(".").reduce((o, k) => (o && o[k] != null ? o[k] : null), obj);
        },

        // Format match timestamp for display
        formatMatchTime(t) {
            if (!t) return "\u2014";
            try {
                const d = new Date(typeof t === "number" && t > 1e12 ? t : t);
                return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
            } catch {
                return String(t).substring(0, 19);
            }
        },

        // Format execution time nicely
        formatExecTime(ms) {
            if (ms == null) return "\u2014";
            if (ms < 1) return (ms * 1000).toFixed(0) + "\u00b5s";
            if (ms < 1000) return ms.toFixed(1) + "ms";
            return (ms / 1000).toFixed(2) + "s";
        },

        // Extract resource info from OCSF match
        extractResources(m) {
            const resources = m.resources;
            if (Array.isArray(resources) && resources.length > 0) {
                return resources.map(r => r.name || r.uid || r.type || "").filter(Boolean).join(", ");
            }
            const apiOp = this.extractNested(m, "api.operation");
            const svc = this.extractNested(m, "api.service.name");
            if (svc && apiOp) return svc + ":" + apiOp;
            return null;
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

// ─── Investigations ──────────────────────────────────────────────

// Node type → Cytoscape.js style (matches server-side visualization.py)
const NODE_STYLES = {
    Principal:       { color: "#FF6B6B", shape: "ellipse" },
    IPAddress:       { color: "#4ECDC4", shape: "diamond" },
    Resource:        { color: "#45B7D1", shape: "rectangle" },
    APIOperation:    { color: "#96CEB4", shape: "triangle" },
    SecurityFinding: { color: "#FF4757", shape: "star" },
    Event:           { color: "#A8A8A8", shape: "ellipse" },
};

const EDGE_STYLES = {
    AUTHENTICATED_FROM: "#FF6B6B",
    CALLED_API:         "#96CEB4",
    ACCESSED_RESOURCE:  "#45B7D1",
    ORIGINATED_FROM:    "#4ECDC4",
    RELATED_TO:         "#888888",
    TRIGGERED_BY:       "#FF4757",
    PERFORMED_BY:       "#FF6B6B",
    TARGETED:           "#45B7D1",
    COMMUNICATED_WITH:  "#F39C12",
    RESOLVED_TO:        "#9B59B6",
};

function investigationsApp() {
    return {
        investigations: [],
        loading: true,
        error: null,

        // Create form
        newName: "",
        newUsers: "",
        newIps: "",
        creating: false,

        // Detail view
        activeInv: null,
        detailLoading: false,
        graphData: null,
        cy: null,
        detailTab: "graph",   // "graph" | "report"
        reportData: null,
        reportLoading: false,

        async init() {
            await this.loadList();
            // Deep-link: open investigation from URL hash (e.g. #inv-abc123)
            const hash = window.location.hash.slice(1);
            if (hash && hash.startsWith("inv-")) {
                await this.openDetail(hash);
            }
        },

        async loadList() {
            this.loading = true;
            try {
                this.investigations = await apiFetch("/investigations");
            } catch (e) {
                this.error = e.message;
            } finally {
                this.loading = false;
            }
        },

        async create() {
            if (!this.newUsers.trim() && !this.newIps.trim()) return;
            this.creating = true;
            this.error = null;
            try {
                const users = this.newUsers.split(",").map((s) => s.trim()).filter(Boolean);
                const ips = this.newIps.split(",").map((s) => s.trim()).filter(Boolean);
                const inv = await apiFetch("/investigations", {
                    method: "POST",
                    body: JSON.stringify({ name: this.newName, users, ips }),
                });
                this.newName = "";
                this.newUsers = "";
                this.newIps = "";
                await this.loadList();
                await this.openDetail(inv.id);
            } catch (e) {
                this.error = e.message;
            } finally {
                this.creating = false;
            }
        },

        async openDetail(invId) {
            this.detailLoading = true;
            this.detailTab = "graph";
            this.reportData = null;
            this.error = null;
            try {
                this.activeInv = await apiFetch(`/investigations/${invId}`);
                const graphResp = await apiFetch(`/investigations/${invId}/graph`);
                this.graphData = graphResp;
                this.$nextTick(() => this.renderGraph(graphResp.elements));
            } catch (e) {
                this.error = e.message;
            } finally {
                this.detailLoading = false;
            }
        },

        async showTab(tab) {
            this.detailTab = tab;
            if (tab === "graph") {
                this.$nextTick(() => {
                    if (this.graphData) this.renderGraph(this.graphData.elements);
                });
            } else if (tab === "report" && !this.reportData) {
                await this.loadReport();
            }
        },

        async loadReport() {
            if (!this.activeInv) return;
            this.reportLoading = true;
            this.error = null;
            try {
                this.reportData = await apiFetch(`/investigations/${this.activeInv.id}/report`);
            } catch (e) {
                this.error = e.message;
            } finally {
                this.reportLoading = false;
            }
        },

        renderGraph(elements) {
            if (this.cy) {
                this.cy.destroy();
                this.cy = null;
            }

            const container = document.getElementById("cy-graph");
            if (!container || !elements || elements.length === 0) return;

            /* global cytoscape */
            this.cy = cytoscape({
                container,
                elements,
                style: [
                    {
                        selector: "node",
                        style: {
                            label: "data(label)",
                            "text-valign": "bottom",
                            "text-halign": "center",
                            "font-size": "10px",
                            color: "#c9d1d9",
                            "text-outline-color": "#0d1117",
                            "text-outline-width": 1,
                            "background-color": (ele) => {
                                const s = NODE_STYLES[ele.data("node_type")];
                                return s ? s.color : "#888";
                            },
                            shape: (ele) => {
                                const s = NODE_STYLES[ele.data("node_type")];
                                return s ? s.shape : "ellipse";
                            },
                            width: (ele) => Math.max(20, Math.min(60, 15 + ele.data("event_count") * 3)),
                            height: (ele) => Math.max(20, Math.min(60, 15 + ele.data("event_count") * 3)),
                        },
                    },
                    {
                        selector: "edge",
                        style: {
                            width: (ele) => {
                                const ec = ele.data("event_count") || 1;
                                return Math.max(1, Math.min(8, 1 + Math.log2(ec)));
                            },
                            "line-color": (ele) => EDGE_STYLES[ele.data("edge_type")] || "#888",
                            "target-arrow-color": (ele) => EDGE_STYLES[ele.data("edge_type")] || "#888",
                            "target-arrow-shape": "triangle",
                            "curve-style": "bezier",
                            opacity: 0.7,
                        },
                    },
                    {
                        selector: "edge[edge_type='COMMUNICATED_WITH']",
                        style: {
                            "line-style": "solid",
                            "target-arrow-shape": "triangle",
                        },
                    },
                    {
                        selector: "edge[edge_type='RESOLVED_TO']",
                        style: {
                            "line-style": "dashed",
                        },
                    },
                    {
                        selector: "edge:selected",
                        style: {
                            "line-color": "#00ff9c",
                            "target-arrow-color": "#00ff9c",
                            width: (ele) => {
                                const ec = ele.data("event_count") || 1;
                                return Math.max(2, Math.min(10, 2 + Math.log2(ec)));
                            },
                            opacity: 1.0,
                        },
                    },
                    {
                        selector: "node:selected",
                        style: {
                            "border-width": 3,
                            "border-color": "#00ff9c",
                        },
                    },
                ],
                layout: { name: "cose", animate: false, nodeDimensionsIncludeLabels: true },
                wheelSensitivity: 0.3,
            });

            // Click handler: show node details
            this.cy.on("tap", "node", (evt) => {
                const data = evt.target.data();
                this.selectedNode = data;
                this.selectedEdge = null;
            });

            // Click handler: show edge details
            this.cy.on("tap", "edge", (evt) => {
                const data = evt.target.data();
                this.selectedEdge = data;
                this.selectedNode = null;
            });

            // Click background to deselect
            this.cy.on("tap", (evt) => {
                if (evt.target === this.cy) {
                    this.selectedNode = null;
                    this.selectedEdge = null;
                }
            });
        },

        selectedNode: null,
        selectedEdge: null,

        async deleteInv(invId) {
            try {
                await apiFetch(`/investigations/${invId}`, { method: "DELETE" });
                this.activeInv = null;
                this.graphData = null;
                this.selectedNode = null;
                if (this.cy) {
                    this.cy.destroy();
                    this.cy = null;
                }
                await this.loadList();
            } catch (e) {
                this.error = e.message;
            }
        },

        backToList() {
            this.activeInv = null;
            this.graphData = null;
            this.selectedNode = null;
            this.reportData = null;
            this.detailTab = "graph";
            if (this.cy) {
                this.cy.destroy();
                this.cy = null;
            }
            window.location.hash = "";
        },

        timeAgo,
    };
}

// ─── Navigation ──────────────────────────────────────────────────

function navApp() {
    return {
        currentPath: window.location.pathname,
        userEmail: null,
        authEnabled: false,

        async init() {
            // Initialize auth (redirects to login if needed)
            await auth.init();

            this.authEnabled = auth.isAuthEnabled();
            const user = auth.getUser();
            if (user) {
                this.userEmail = user.email || user.sub || "User";
            }
        },

        isActive(path) {
            if (path === "/" && this.currentPath === "/") return true;
            if (path !== "/" && this.currentPath.startsWith(path)) return true;
            return false;
        },

        async doLogout() {
            await auth.logout();
        },
    };
}

// ─── Register globals ────────────────────────────────────────────

document.addEventListener("alpine:init", () => {
    Alpine.data("dashboardApp", dashboardApp);
    Alpine.data("healthMonitor", healthMonitor);
    Alpine.data("detectionsApp", detectionsApp);
    Alpine.data("sourcesApp", sourcesApp);
    Alpine.data("investigationsApp", investigationsApp);
    Alpine.data("navApp", navApp);
});
