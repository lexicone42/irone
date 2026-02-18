use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Authenticated user extracted from session/token.
/// Real implementation comes from `l42-cognito-passkey`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticatedUser {
    /// Cognito subject UUID.
    pub sub: String,
    pub email: Option<String>,
    /// Cognito groups (used for Cedar RBAC).
    pub groups: Vec<String>,
}

/// Server-side session data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub session_id: String,
    pub user: Option<AuthenticatedUser>,
    pub data: HashMap<String, serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticated_user_construction() {
        let user = AuthenticatedUser {
            sub: "abc-123".into(),
            email: Some("test@example.com".into()),
            groups: vec!["admin".into(), "analysts".into()],
        };
        assert_eq!(user.sub, "abc-123");
        assert_eq!(user.groups.len(), 2);
    }
}
