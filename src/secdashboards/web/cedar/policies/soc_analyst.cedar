// SOC Analyst: view dashboards, investigate alerts, use AI analysis.
@id("soc-analyst-view")
permit(
    principal in Secdash::UserGroup::"soc-analyst",
    action in [
        Secdash::Action::"view:dashboard",
        Secdash::Action::"view:monitoring",
        Secdash::Action::"view:security_lake",
        Secdash::Action::"view:detections",
        Secdash::Action::"view:investigations",
        Secdash::Action::"view:deploy"
    ],
    resource
);

@id("soc-analyst-investigate")
permit(
    principal in Secdash::UserGroup::"soc-analyst",
    action in [
        Secdash::Action::"create:investigation",
        Secdash::Action::"view:investigation",
        Secdash::Action::"enrich:investigation",
        Secdash::Action::"ai:analyze",
        Secdash::Action::"api:read"
    ],
    resource
);
