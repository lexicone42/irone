// Incident Responder: focused investigation with export and AI analysis.
@id("incident-responder-view")
permit(
    principal in Secdash::UserGroup::"incident-responder",
    action in [
        Secdash::Action::"view:dashboard",
        Secdash::Action::"view:monitoring",
        Secdash::Action::"view:detections",
        Secdash::Action::"view:investigations"
    ],
    resource
);

@id("incident-responder-investigate")
permit(
    principal in Secdash::UserGroup::"incident-responder",
    action in [
        Secdash::Action::"create:investigation",
        Secdash::Action::"view:investigation",
        Secdash::Action::"enrich:investigation",
        Secdash::Action::"ai:analyze",
        Secdash::Action::"export:investigation",
        Secdash::Action::"api:read",
        Secdash::Action::"api:query"
    ],
    resource
);
