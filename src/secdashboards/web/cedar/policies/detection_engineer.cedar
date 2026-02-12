// Detection Engineer: create/manage detections, query data, investigate, use AI.
@id("detection-engineer-view")
permit(
    principal in Secdash::UserGroup::"detection-engineer",
    action in [
        Secdash::Action::"view:dashboard",
        Secdash::Action::"view:monitoring",
        Secdash::Action::"view:security_lake",
        Secdash::Action::"test:security_lake",
        Secdash::Action::"view:detections",
        Secdash::Action::"view:investigations",
        Secdash::Action::"view:deploy"
    ],
    resource
);

@id("detection-engineer-create")
permit(
    principal in Secdash::UserGroup::"detection-engineer",
    action in [
        Secdash::Action::"create:detection",
        Secdash::Action::"test:detection",
        Secdash::Action::"query:data",
        Secdash::Action::"ai:generate_rule",
        Secdash::Action::"create:investigation",
        Secdash::Action::"view:investigation",
        Secdash::Action::"enrich:investigation",
        Secdash::Action::"api:read",
        Secdash::Action::"api:query"
    ],
    resource
);
