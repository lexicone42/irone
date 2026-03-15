use aws_sdk_iam::Client as IamClient;
use irone_core::graph::{ExtractedIdentifiers, NodeType, SecurityGraph};
use serde_json::Value;
use tracing::debug;

/// Context about an IAM user's permissions and MFA status.
#[derive(Debug, Clone)]
pub struct IamUserContext {
    pub attached_policies: Vec<String>,
    pub inline_policy_names: Vec<String>,
    pub has_admin_access: bool,
    pub mfa_devices: usize,
}

/// Context about an IAM role's permissions and trust relationships.
#[derive(Debug, Clone)]
pub struct IamRoleContext {
    pub attached_policies: Vec<String>,
    pub inline_policy_names: Vec<String>,
    pub has_admin_access: bool,
    pub trust_policy: Value,
    pub trust_principals: Vec<String>,
}

/// Enriches investigation graphs with IAM context (policies, trust, admin access).
pub struct IamEnricher {
    client: IamClient,
}

/// Maximum number of users/roles to enrich per graph to avoid API throttling.
const MAX_ENRICHMENT_ENTITIES: usize = 20;

impl IamEnricher {
    pub fn new(sdk_config: &aws_config::SdkConfig) -> Self {
        Self {
            client: IamClient::new(sdk_config),
        }
    }

    /// Look up IAM user context: attached policies, inline policies, admin check, MFA.
    pub async fn get_user_context(&self, user_name: &str) -> Option<IamUserContext> {
        // Attached managed policies
        let attached = match self
            .client
            .list_attached_user_policies()
            .user_name(user_name)
            .send()
            .await
        {
            Ok(resp) => resp
                .attached_policies()
                .iter()
                .filter_map(|p| p.policy_arn().map(String::from))
                .collect::<Vec<_>>(),
            Err(e) => {
                debug!(user = user_name, error = %e, "failed to list attached user policies");
                return None;
            }
        };

        // Inline policy names
        let inline = match self
            .client
            .list_user_policies()
            .user_name(user_name)
            .send()
            .await
        {
            Ok(resp) => resp.policy_names().to_vec(),
            Err(e) => {
                debug!(user = user_name, error = %e, "failed to list inline user policies");
                Vec::new()
            }
        };

        let has_admin = attached
            .iter()
            .any(|arn| arn.contains("AdministratorAccess"));

        // MFA devices
        let mfa_count = match self
            .client
            .list_mfa_devices()
            .user_name(user_name)
            .send()
            .await
        {
            Ok(resp) => resp.mfa_devices().len(),
            Err(_) => 0,
        };

        Some(IamUserContext {
            attached_policies: attached,
            inline_policy_names: inline,
            has_admin_access: has_admin,
            mfa_devices: mfa_count,
        })
    }

    /// Look up IAM role context: attached policies, inline policies, trust policy.
    pub async fn get_role_context(&self, role_name: &str) -> Option<IamRoleContext> {
        // Get role (includes trust policy)
        let role = match self.client.get_role().role_name(role_name).send().await {
            Ok(resp) => resp.role,
            Err(e) => {
                debug!(role = role_name, error = %e, "failed to get role");
                return None;
            }
        };

        let role = role?;

        let trust_doc_str = role.assume_role_policy_document().unwrap_or_default();

        // Trust policy is URL-encoded JSON — percent-decode it
        let trust_decoded = percent_decode(trust_doc_str);
        let trust_policy: Value = serde_json::from_str(&trust_decoded).unwrap_or(Value::Null);

        // Extract principal ARNs from trust policy
        let trust_principals = extract_trust_principals(&trust_policy);

        // Attached managed policies
        let attached = match self
            .client
            .list_attached_role_policies()
            .role_name(role_name)
            .send()
            .await
        {
            Ok(resp) => resp
                .attached_policies()
                .iter()
                .filter_map(|p| p.policy_arn().map(String::from))
                .collect::<Vec<_>>(),
            Err(e) => {
                debug!(role = role_name, error = %e, "failed to list attached role policies");
                Vec::new()
            }
        };

        // Inline policy names
        let inline = match self
            .client
            .list_role_policies()
            .role_name(role_name)
            .send()
            .await
        {
            Ok(resp) => resp.policy_names().to_vec(),
            Err(e) => {
                debug!(role = role_name, error = %e, "failed to list inline role policies");
                Vec::new()
            }
        };

        let has_admin = attached
            .iter()
            .any(|arn| arn.contains("AdministratorAccess"));

        Some(IamRoleContext {
            attached_policies: attached,
            inline_policy_names: inline,
            has_admin_access: has_admin,
            trust_policy,
            trust_principals,
        })
    }

    /// Enrich a `SecurityGraph` with IAM context for principals found in the identifiers.
    pub async fn enrich_graph(
        &self,
        graph: &mut SecurityGraph,
        identifiers: &ExtractedIdentifiers,
    ) {
        let mut enriched = 0;

        // Enrich IAM users
        for user_name in identifiers.users.iter().take(MAX_ENRICHMENT_ENTITIES) {
            if let Some(ctx) = self.get_user_context(user_name).await {
                // Find matching Principal nodes in the graph
                for node in graph.nodes.values_mut() {
                    if node.node_type == NodeType::Principal && node.label == *user_name {
                        inject_user_context(&mut node.properties, &ctx);
                        enriched += 1;
                    }
                }
            }
        }

        // Enrich IAM roles (extracted from ARNs matching `:role/`)
        let role_names: Vec<String> = identifiers
            .resource_ids
            .iter()
            .filter_map(|arn: &String| {
                let role_part = arn.split(":role/").nth(1)?;
                // Strip any path prefix (e.g., "service-role/MyRole" → "MyRole")
                Some(
                    role_part
                        .rsplit('/')
                        .next()
                        .unwrap_or(role_part)
                        .to_string(),
                )
            })
            .take(MAX_ENRICHMENT_ENTITIES)
            .collect();

        for role_name in &role_names {
            if let Some(ctx) = self.get_role_context(role_name).await {
                for node in graph.nodes.values_mut() {
                    let is_match = (node.node_type == NodeType::Principal
                        || node.node_type == NodeType::Resource)
                        && (node.label == *role_name
                            || node.label.ends_with(&format!("/{role_name}")));
                    if is_match {
                        inject_role_context(&mut node.properties, &ctx);
                        enriched += 1;
                    }
                }
            }
        }

        if enriched > 0 {
            tracing::info!(enriched, "IAM context enrichment complete");
        } else {
            debug!("no IAM context enriched (no matching principals found)");
        }
    }
}

/// Inject IAM user context into a node's properties map.
fn inject_user_context(
    properties: &mut std::collections::HashMap<String, Value>,
    ctx: &IamUserContext,
) {
    properties.insert(
        "iam_attached_policies".into(),
        serde_json::to_value(&ctx.attached_policies).unwrap_or_default(),
    );
    properties.insert(
        "iam_inline_policies".into(),
        serde_json::to_value(&ctx.inline_policy_names).unwrap_or_default(),
    );
    properties.insert("admin_access".into(), Value::Bool(ctx.has_admin_access));
    properties.insert("mfa_devices".into(), serde_json::json!(ctx.mfa_devices));
}

/// Inject IAM role context into a node's properties map.
fn inject_role_context(
    properties: &mut std::collections::HashMap<String, Value>,
    ctx: &IamRoleContext,
) {
    properties.insert(
        "iam_attached_policies".into(),
        serde_json::to_value(&ctx.attached_policies).unwrap_or_default(),
    );
    properties.insert(
        "iam_inline_policies".into(),
        serde_json::to_value(&ctx.inline_policy_names).unwrap_or_default(),
    );
    properties.insert("admin_access".into(), Value::Bool(ctx.has_admin_access));
    properties.insert("trust_policy".into(), ctx.trust_policy.clone());
    properties.insert(
        "trust_principals".into(),
        serde_json::to_value(&ctx.trust_principals).unwrap_or_default(),
    );
}

/// Simple percent-decoding for URL-encoded strings (e.g., IAM trust policy documents).
fn percent_decode(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.bytes();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let hi = chars.next().unwrap_or(b'0');
            let lo = chars.next().unwrap_or(b'0');
            let decoded =
                u8::from_str_radix(&format!("{}{}", hi as char, lo as char), 16).unwrap_or(b'?');
            result.push(decoded as char);
        } else if b == b'+' {
            result.push(' ');
        } else {
            result.push(b as char);
        }
    }
    result
}

/// Extract principal ARNs from an IAM trust policy document.
fn extract_trust_principals(trust_policy: &Value) -> Vec<String> {
    let mut principals = Vec::new();

    let statements = match trust_policy.get("Statement") {
        Some(Value::Array(stmts)) => stmts.as_slice(),
        _ => return principals,
    };

    for stmt in statements {
        if let Some(principal) = stmt.get("Principal") {
            match principal {
                Value::String(s) => principals.push(s.clone()),
                Value::Object(map) => {
                    for (_, value) in map {
                        match value {
                            Value::String(s) => principals.push(s.clone()),
                            Value::Array(arr) => {
                                for v in arr {
                                    if let Value::String(s) = v {
                                        principals.push(s.clone());
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
    }

    principals
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde_json::json;

    use super::*;

    #[test]
    fn extract_trust_principals_single_service() {
        let policy = json!({
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole"
            }]
        });
        let principals = extract_trust_principals(&policy);
        assert_eq!(principals, vec!["lambda.amazonaws.com"]);
    }

    #[test]
    fn extract_trust_principals_multiple_aws() {
        let policy = json!({
            "Statement": [{
                "Effect": "Allow",
                "Principal": {
                    "AWS": [
                        "arn:aws:iam::123456789012:root",
                        "arn:aws:iam::987654321098:role/CrossAccountRole"
                    ]
                },
                "Action": "sts:AssumeRole"
            }]
        });
        let principals = extract_trust_principals(&policy);
        assert_eq!(principals.len(), 2);
        assert!(principals[0].contains("123456789012"));
        assert!(principals[1].contains("CrossAccountRole"));
    }

    #[test]
    fn extract_trust_principals_star() {
        let policy = json!({
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "sts:AssumeRole"
            }]
        });
        let principals = extract_trust_principals(&policy);
        assert_eq!(principals, vec!["*"]);
    }

    #[test]
    fn extract_trust_principals_empty() {
        let policy = json!({});
        let principals = extract_trust_principals(&policy);
        assert!(principals.is_empty());
    }

    #[test]
    fn inject_user_context_sets_properties() {
        let ctx = IamUserContext {
            attached_policies: vec!["arn:aws:iam::aws:policy/ReadOnlyAccess".into()],
            inline_policy_names: vec!["custom-s3".into()],
            has_admin_access: false,
            mfa_devices: 1,
        };
        let mut props: HashMap<String, serde_json::Value> = HashMap::new();
        inject_user_context(&mut props, &ctx);

        assert_eq!(props["admin_access"], json!(false));
        assert_eq!(props["mfa_devices"], json!(1));
        assert!(props["iam_attached_policies"].as_array().unwrap().len() == 1);
    }

    #[test]
    fn inject_role_context_includes_trust() {
        let trust = json!({"Statement": []});
        let ctx = IamRoleContext {
            attached_policies: vec!["arn:aws:iam::aws:policy/AdministratorAccess".into()],
            inline_policy_names: Vec::new(),
            has_admin_access: true,
            trust_policy: trust.clone(),
            trust_principals: vec!["lambda.amazonaws.com".into()],
        };
        let mut props: HashMap<String, serde_json::Value> = HashMap::new();
        inject_role_context(&mut props, &ctx);

        assert_eq!(props["admin_access"], json!(true));
        assert_eq!(props["trust_policy"], trust);
        assert_eq!(props["trust_principals"], json!(["lambda.amazonaws.com"]));
    }
}
