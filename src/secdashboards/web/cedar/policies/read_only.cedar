// Read-Only: view dashboard and monitoring only.
@id("read-only-view")
permit(
    principal in Secdash::UserGroup::"read-only",
    action in [
        Secdash::Action::"view:dashboard",
        Secdash::Action::"view:monitoring"
    ],
    resource
);
