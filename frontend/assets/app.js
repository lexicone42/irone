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
            window.location.href = "/login.html";
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
        recentInvestigations: [],

        async init() {
            try {
                const [dashboard, investigations] = await Promise.all([
                    apiFetch("/dashboard"),
                    apiFetch("/investigations").catch(() => []),
                ]);
                this.data = dashboard;
                this.recentInvestigations = (Array.isArray(investigations) ? investigations : []).slice(0, 5);
            } catch (e) {
                this.error = e.message;
            } finally {
                this.loading = false;
            }
        },

        timeAgo,
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

        // Tab state
        activeTab: "rules",

        // Severity group collapse state (medium/low/info start collapsed)
        collapsedGroups: { medium: true, low: true, info: true },

        // Detection run state
        runningRule: null,
        detectionResult: null,
        investigating: false,
        runStatus: {},  // ruleId -> "triggered" | "clean" | "error"

        // History tab state
        history: [],
        historyLoading: false,
        historyTriggeredOnly: false,
        historySeverityFilter: "",
        historySearchQuery: "",

        async init() {
            try {
                this.rules = await apiFetch("/rules?enabled_only=false");
            } catch (e) {
                this.error = e.message;
            } finally {
                this.loading = false;
            }
        },

        // Group rules by severity in display order
        rulesBySeverity() {
            const order = ["critical", "high", "medium", "low", "info"];
            const groups = {};
            for (const sev of order) groups[sev] = [];
            for (const rule of this.rules) {
                const sev = rule.severity || "info";
                if (!groups[sev]) groups[sev] = [];
                groups[sev].push(rule);
            }
            return order
                .filter(sev => groups[sev].length > 0)
                .map(sev => ({ severity: sev, rules: groups[sev] }));
        },

        toggleGroup(severity) {
            this.collapsedGroups[severity] = !this.collapsedGroups[severity];
        },

        async switchToHistory() {
            this.activeTab = "history";
            if (this.history.length === 0) await this.loadHistory();
        },

        async loadHistory() {
            this.historyLoading = true;
            try {
                this.history = await apiFetch("/detections/history?limit=100");
            } catch (e) {
                this.error = e.message;
            } finally {
                this.historyLoading = false;
            }
        },

        filteredHistory() {
            let runs = this.history;
            if (this.historyTriggeredOnly) {
                runs = runs.filter(r => r.triggered);
            }
            if (this.historySeverityFilter) {
                runs = runs.filter(r => r.severity === this.historySeverityFilter);
            }
            if (this.historySearchQuery) {
                const q = this.historySearchQuery.toLowerCase();
                runs = runs.filter(r => r.rule_name.toLowerCase().includes(q));
            }
            return runs;
        },

        async runDetection(ruleId) {
            this.runningRule = ruleId;
            this.detectionResult = null;
            this.error = null;
            try {
                const result = await apiFetch(`/detections/${ruleId}/run`, {
                    method: "POST",
                    body: JSON.stringify({ lookback_minutes: 15 }),
                });
                this.detectionResult = result;
                // Update persistent status indicator
                if (result.error) {
                    this.runStatus[ruleId] = "error";
                } else if (result.triggered) {
                    this.runStatus[ruleId] = "triggered";
                } else {
                    this.runStatus[ruleId] = "clean";
                }
                // Refresh history if already loaded
                if (this.history.length > 0) this.loadHistory();
            } catch (e) {
                this.error = e.message;
                this.runStatus[ruleId] = "error";
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

        async investigateFromHistory(run) {
            window.location.href = `/investigations.html?from_rule=${encodeURIComponent(run.rule_id)}`;
        },

        dismissResult() {
            this.detectionResult = null;
        },

        extractNested(obj, path) {
            return path.split(".").reduce((o, k) => (o && o[k] != null ? o[k] : null), obj);
        },

        formatMatchTime(t) {
            if (!t) return "\u2014";
            try {
                const d = new Date(typeof t === "number" && t > 1e12 ? t : t);
                return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
            } catch {
                return String(t).substring(0, 19);
            }
        },

        formatExecTime(ms) {
            if (ms == null) return "\u2014";
            if (ms < 1) return (ms * 1000).toFixed(0) + "\u00b5s";
            if (ms < 1000) return ms.toFixed(1) + "ms";
            return (ms / 1000).toFixed(2) + "s";
        },

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

        timeAgo,
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

// Tag color mapping (matches server-side TAG_COLORS in timeline.rs)
const TAG_COLORS = {
    unreviewed:          "#636D87",
    important:           "#FFB224",
    suspicious:          "#FF4D6A",
    benign:              "#00D4AA",
    attack_phase:        "#FF4D6A",
    initial_access:      "#FF4D6A",
    persistence:         "#A78BFA",
    privilege_escalation:"#FF4D6A",
    lateral_movement:    "#FB923C",
    data_exfiltration:   "#FF4D6A",
    impact:              "#A78BFA",
};

const SUSPICIOUS_TAGS = new Set([
    "suspicious", "attack_phase", "initial_access", "persistence",
    "privilege_escalation", "lateral_movement", "data_exfiltration", "impact"
]);

// Node type → Cytoscape.js style
const NODE_STYLES = {
    Principal:       { color: "#FF4D6A", shape: "ellipse" },
    IPAddress:       { color: "#00D4AA", shape: "diamond" },
    Resource:        { color: "#4D9BFF", shape: "round-rectangle" },
    APIOperation:    { color: "#7DD3A0", shape: "triangle" },
    SecurityFinding: { color: "#FF4D6A", shape: "star" },
    Event:           { color: "#636D87", shape: "ellipse" },
};

const EDGE_STYLES = {
    AUTHENTICATED_FROM: "#FF4D6A",
    CALLED_API:         "#7DD3A0",
    ACCESSED_RESOURCE:  "#4D9BFF",
    ORIGINATED_FROM:    "#00D4AA",
    RELATED_TO:         "#3D4663",
    TRIGGERED_BY:       "#FF4D6A",
    PERFORMED_BY:       "#FF4D6A",
    TARGETED:           "#4D9BFF",
    COMMUNICATED_WITH:  "#FB923C",
    RESOLVED_TO:        "#A78BFA",
};

function investigationsApp() {
    return {
        investigations: [],
        loading: true,
        error: null,

        // Create form
        createTab: "identifiers",   // "identifiers" | "detection"
        newName: "",
        newUsers: "",
        newIps: "",
        creating: false,

        // From-detection form
        triggeredRuns: [],
        selectedDetectionRunId: "",
        detectionSourceName: "",

        // Detail view
        activeInv: null,
        detailLoading: false,
        graphData: null,
        cy: null,
        detailTab: "graph",   // "graph" | "report"
        reportData: null,
        reportLoading: false,

        // Timeline
        timelineData: null,
        timelineLoading: false,
        timelineFilter: "all",   // "all" | "suspicious" | "unreviewed"
        selectedTimelineEvent: null,

        // Graph display options
        showEventNodes: false,

        // Source dropdown
        availableSources: [],
        newSourceName: "",

        async init() {
            await this.loadList();
            this.loadSources();
            this.loadTriggeredRuns();
            // Deep-link: open investigation from URL hash (e.g. #inv-abc123)
            const hash = window.location.hash.slice(1);
            if (hash && hash.startsWith("inv-")) {
                await this.openDetail(hash);
            }
        },

        async loadSources() {
            try {
                this.availableSources = await apiFetch("/sources");
            } catch {
                // Sources are optional — if endpoint fails, dropdown won't show
                this.availableSources = [];
            }
        },

        async loadTriggeredRuns() {
            try {
                const history = await apiFetch("/detections/history?limit=100");
                this.triggeredRuns = history.filter(r => r.triggered);
            } catch {
                this.triggeredRuns = [];
            }
        },

        get selectedDetectionRun() {
            return this.triggeredRuns.find(r => r.run_id === this.selectedDetectionRunId) || null;
        },

        async loadList() {
            this.loading = true;
            try {
                const resp = await apiFetch("/investigations");
                this.investigations = Array.isArray(resp) ? resp : [];
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
                const payload = { name: this.newName, users, ips };
                if (this.newSourceName) payload.source_name = this.newSourceName;
                const inv = await apiFetch("/investigations", {
                    method: "POST",
                    body: JSON.stringify(payload),
                });
                this.newName = "";
                this.newUsers = "";
                this.newIps = "";
                this.newSourceName = "";
                await this.loadList();
                await this.openDetail(inv.id);
            } catch (e) {
                this.error = e.message;
            } finally {
                this.creating = false;
            }
        },

        async createFromDetection() {
            if (!this.selectedDetectionRunId) return;
            const run = this.selectedDetectionRun;
            if (!run) return;
            this.creating = true;
            this.error = null;
            try {
                const payload = { rule_id: run.rule_id };
                if (this.detectionSourceName) payload.source_name = this.detectionSourceName;
                const resp = await apiFetch("/investigations/from-detection", {
                    method: "POST",
                    body: JSON.stringify(payload),
                });
                this.selectedDetectionRunId = "";
                this.detectionSourceName = "";
                await this.loadList();
                await this.openDetail(resp.investigation_id);
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
            this.timelineData = null;
            this.selectedTimelineEvent = null;
            this.timelineFilter = "all";
            this.error = null;
            try {
                this.activeInv = await apiFetch(`/investigations/${invId}`);
                const [graphResp] = await Promise.all([
                    apiFetch(`/investigations/${invId}/graph`),
                    this.loadTimeline(invId),
                ]);
                this.graphData = graphResp;
                this.$nextTick(() => this.renderGraph(this.filteredGraphElements(graphResp.elements)));
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
                    if (this.graphData) this.renderGraph(this.filteredGraphElements(this.graphData.elements));
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

        filteredGraphElements(elements) {
            if (!elements) return [];
            if (this.showEventNodes) return elements;
            // Collect IDs of Event nodes to exclude
            const eventIds = new Set();
            for (const el of elements) {
                if (el.group === "nodes" && el.data?.node_type === "Event") {
                    eventIds.add(el.data.id);
                }
            }
            // Filter out Event nodes and any edges touching them
            return elements.filter(el => {
                if (el.group === "nodes") return !eventIds.has(el.data.id);
                if (el.group === "edges") return !eventIds.has(el.data.source) && !eventIds.has(el.data.target);
                return true;
            });
        },

        toggleEventNodes() {
            this.showEventNodes = !this.showEventNodes;
            if (this.graphData) {
                this.$nextTick(() => this.renderGraph(this.filteredGraphElements(this.graphData.elements)));
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
                            "font-family": "Inter, sans-serif",
                            "font-size": "10px",
                            color: "#E1E4ED",
                            "text-outline-color": "#0B0E14",
                            "text-outline-width": 2,
                            "background-color": (ele) => {
                                const s = NODE_STYLES[ele.data("node_type")];
                                return s ? s.color : "#636D87";
                            },
                            shape: (ele) => {
                                const s = NODE_STYLES[ele.data("node_type")];
                                return s ? s.shape : "ellipse";
                            },
                            "border-width": 2,
                            "border-color": (ele) => {
                                const s = NODE_STYLES[ele.data("node_type")];
                                return s ? s.color + "66" : "#636D8766";
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
                            "line-color": (ele) => EDGE_STYLES[ele.data("edge_type")] || "#3D4663",
                            "target-arrow-color": (ele) => EDGE_STYLES[ele.data("edge_type")] || "#3D4663",
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
                            "line-color": "#4D9BFF",
                            "target-arrow-color": "#4D9BFF",
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
                            "border-color": "#4D9BFF",
                            "overlay-color": "#4D9BFF",
                            "overlay-opacity": 0.1,
                        },
                    },
                ],
                layout: { name: "cose", animate: false, nodeDimensionsIncludeLabels: true },
                wheelSensitivity: 0.3,
            });

            // Click handler: show node details + sync timeline
            this.cy.on("tap", "node", (evt) => {
                const data = evt.target.data();
                this.selectedNode = data;
                this.selectedEdge = null;
                // Find matching timeline events for this node
                if (this.timelineData?.events && data.id) {
                    const match = this.timelineData.events.find(
                        e => e.entity_id === data.id
                    );
                    if (match) {
                        this.selectedTimelineEvent = match;
                    }
                }
            });

            // Click handler: show edge details + sync timeline
            this.cy.on("tap", "edge", (evt) => {
                const data = evt.target.data();
                this.selectedEdge = data;
                this.selectedNode = null;
                // Find matching timeline events for this edge
                if (this.timelineData?.events && data.id) {
                    const match = this.timelineData.events.find(
                        e => e.entity_id === data.id
                    );
                    if (match) {
                        this.selectedTimelineEvent = match;
                    }
                }
            });

            // Click background to deselect
            this.cy.on("tap", (evt) => {
                if (evt.target === this.cy) {
                    this.selectedNode = null;
                    this.selectedEdge = null;
                    this.selectedTimelineEvent = null;
                }
            });
        },

        // ─── Timeline methods ──────────────────────────

        async loadTimeline(invId) {
            this.timelineLoading = true;
            try {
                this.timelineData = await apiFetch(`/investigations/${invId || this.activeInv?.id}/timeline`);
            } catch (e) {
                console.warn("Timeline load failed:", e);
                this.timelineData = null;
            } finally {
                this.timelineLoading = false;
            }
        },

        filteredTimeline() {
            if (!this.timelineData?.events) return [];
            const events = this.timelineData.events;
            if (this.timelineFilter === "all") return events;
            if (this.timelineFilter === "suspicious") {
                return events.filter(e => SUSPICIOUS_TAGS.has(e.tag));
            }
            if (this.timelineFilter === "unreviewed") {
                return events.filter(e => !e.tag || e.tag === "unreviewed");
            }
            return events;
        },

        selectTimelineEvent(evt) {
            this.selectedTimelineEvent = evt;
            // Highlight corresponding graph node
            if (this.cy && evt.entity_id) {
                this.cy.elements().unselect();
                const node = this.cy.getElementById(evt.entity_id);
                if (node.length > 0) {
                    node.select();
                    this.cy.animate({ center: { eles: node }, duration: 300 });
                    this.selectedNode = node.data();
                    this.selectedEdge = null;
                }
            }
        },

        tagColor(tag) {
            return TAG_COLORS[tag] || TAG_COLORS.unreviewed;
        },

        formatTimelineTime(ts) {
            if (!ts) return "—";
            try {
                const d = new Date(ts);
                const h = String(d.getHours()).padStart(2, "0");
                const m = String(d.getMinutes()).padStart(2, "0");
                const s = String(d.getSeconds()).padStart(2, "0");
                const mon = d.toLocaleString("en", { month: "short" });
                const day = d.getDate();
                return `${h}:${m}:${s} ${mon} ${day}`;
            } catch {
                return String(ts).substring(11, 19);
            }
        },

        formatTimelineClock(ts) {
            if (!ts) return "—";
            try {
                const d = new Date(ts);
                const h = String(d.getHours()).padStart(2, "0");
                const m = String(d.getMinutes()).padStart(2, "0");
                const s = String(d.getSeconds()).padStart(2, "0");
                return `${h}:${m}:${s}`;
            } catch {
                return String(ts).substring(11, 19);
            }
        },

        formatTimelineDate(ts) {
            if (!ts) return "";
            try {
                const d = new Date(ts);
                const mon = d.toLocaleString("en", { month: "short" });
                const day = d.getDate();
                return `${mon} ${day}`;
            } catch {
                return "";
            }
        },

        // Scroll a timeline event into view
        scrollTimelineToEvent(eventId) {
            const el = document.querySelector(`[data-timeline-id="${eventId}"]`);
            if (el) el.scrollIntoView({ behavior: "smooth", block: "center" });
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
            this.selectedEdge = null;
            this.reportData = null;
            this.timelineData = null;
            this.selectedTimelineEvent = null;
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

// ─── Settings (passkey management) ──────────────────────────────

function settingsApp() {
    return {
        userEmail: "",
        userGroups: [],
        passkeys: [],
        loading: true,
        registering: false,
        deleting: null,
        passkeyError: "",
        passkeySuccess: "",
        passkeySupported: true,
        enrollmentRequired: new URLSearchParams(window.location.search).has(
            "enroll"
        ),
        _l42: null,

        async init() {
            await auth.init();
            if (!auth.isAuthenticated()) return;

            const user = auth.getUser();
            this.userEmail = user?.email || "";
            this.userGroups = user?.groups || [];

            // Dynamic import — l42-auth.js is an ES module
            this._l42 = await import("/assets/l42-auth.js");

            this.passkeySupported = await this._l42.isPasskeySupported();
            if (this.passkeySupported) {
                // Fetch tokens from server session to populate l42 cache
                await this._l42.getTokens();
                await this.loadPasskeys();
            } else {
                this.loading = false;
            }
        },

        async loadPasskeys() {
            this.loading = true;
            try {
                this.passkeys = await this._l42.listPasskeys();
            } catch (err) {
                this.passkeyError = "Failed to load passkeys: " + err.message;
            } finally {
                this.loading = false;
            }
        },

        async registerNewPasskey() {
            this.registering = true;
            this.passkeyError = "";
            this.passkeySuccess = "";
            try {
                await this._l42.registerPasskey();
                this.passkeySuccess = "Passkey registered successfully!";
                await this.loadPasskeys();
            } catch (err) {
                if (err.name !== "NotAllowedError") {
                    this.passkeyError =
                        "Failed to register passkey: " + err.message;
                }
            } finally {
                this.registering = false;
            }
        },

        async deleteKey(credentialId) {
            if (
                !confirm(
                    "Delete this passkey? You will no longer be able to sign in with it."
                )
            ) {
                return;
            }
            this.deleting = credentialId;
            this.passkeyError = "";
            this.passkeySuccess = "";
            try {
                await this._l42.deletePasskey(credentialId);
                this.passkeySuccess = "Passkey deleted.";
                await this.loadPasskeys();
            } catch (err) {
                this.passkeyError =
                    "Failed to delete passkey: " + err.message;
            } finally {
                this.deleting = null;
            }
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
    Alpine.data("settingsApp", settingsApp);
    Alpine.data("navApp", navApp);
});
