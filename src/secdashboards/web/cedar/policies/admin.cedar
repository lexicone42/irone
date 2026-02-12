// Admin: full access to all actions on all resources.
@id("admin-permit-all")
permit(
    principal in Secdash::UserGroup::"admin",
    action,
    resource
);
