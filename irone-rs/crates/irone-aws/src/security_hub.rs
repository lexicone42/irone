use aws_sdk_securityhub::Client as SecurityHubClient;
use aws_sdk_securityhub::types::{AwsSecurityFinding, Resource, Severity as AsffSeverity};
use chrono::Utc;
use irone_core::detections::Severity;
use irone_core::notifications::{NotificationChannel, SecurityAlert};
use tracing::info;

/// Pushes irone detection findings to AWS Security Hub via `BatchImportFindings`.
pub struct SecurityHubNotifier {
    client: SecurityHubClient,
    account_id: String,
    region: String,
}

impl SecurityHubNotifier {
    pub fn new(sdk_config: &aws_config::SdkConfig, account_id: String, region: String) -> Self {
        Self {
            client: SecurityHubClient::new(sdk_config),
            account_id,
            region,
        }
    }

    /// Map irone severity to ASFF severity label.
    fn asff_severity_label(severity: &Severity) -> aws_sdk_securityhub::types::SeverityLabel {
        use aws_sdk_securityhub::types::SeverityLabel;
        match severity {
            Severity::Info => SeverityLabel::Informational,
            Severity::Low => SeverityLabel::Low,
            Severity::Medium => SeverityLabel::Medium,
            Severity::High => SeverityLabel::High,
            Severity::Critical => SeverityLabel::Critical,
        }
    }

    /// Build an ASFF finding from a `SecurityAlert`.
    fn build_finding(&self, alert: &SecurityAlert) -> AwsSecurityFinding {
        let now = Utc::now().to_rfc3339();
        let epoch = Utc::now().timestamp();
        let product_arn = format!(
            "arn:aws:securityhub:{}:{}:product/{}/default",
            self.region, self.account_id, self.account_id,
        );

        AwsSecurityFinding::builder()
            .schema_version("2018-10-08")
            .product_arn(&product_arn)
            .id(format!("irone-{}-{epoch}", alert.rule_id))
            .generator_id(format!("irone/{}", alert.rule_id))
            .aws_account_id(&self.account_id)
            .title(&alert.rule_name)
            .description(&alert.message)
            .severity(
                AsffSeverity::builder()
                    .label(Self::asff_severity_label(&alert.severity))
                    .build(),
            )
            .types("Software and Configuration Checks")
            .created_at(&now)
            .updated_at(&now)
            .resources(
                Resource::builder()
                    .r#type("Other")
                    .id("irone-detection")
                    .region(&self.region)
                    .build(),
            )
            .product_fields("irone/rule_id", &alert.rule_id)
            .product_fields("irone/match_count", alert.match_count.to_string())
            .build()
    }
}

impl NotificationChannel for SecurityHubNotifier {
    async fn send_alert(
        &self,
        alert: &SecurityAlert,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let finding = self.build_finding(alert);

        let response = self
            .client
            .batch_import_findings()
            .findings(finding)
            .send()
            .await
            .map_err(|e| {
                Box::new(std::io::Error::other(format!(
                    "Security Hub BatchImportFindings failed: {e}"
                ))) as Box<dyn std::error::Error + Send + Sync>
            })?;

        if response.failed_count() > Some(0) {
            let failures: Vec<String> = response
                .failed_findings()
                .iter()
                .map(|f| {
                    format!(
                        "{}: {}",
                        f.id().unwrap_or("?"),
                        f.error_message().unwrap_or("unknown error")
                    )
                })
                .collect();
            tracing::warn!(
                rule_id = %alert.rule_id,
                failures = ?failures,
                "some Security Hub findings failed to import"
            );
        } else {
            info!(
                rule_id = %alert.rule_id,
                success_count = response.success_count(),
                "finding imported to Security Hub"
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use irone_core::detections::Severity;
    use irone_core::notifications::SecurityAlert;

    use super::SecurityHubNotifier;

    fn notifier() -> SecurityHubNotifier {
        // Build a fake config — we only test finding construction, not actual API calls.
        let config = aws_config::SdkConfig::builder()
            .behavior_version(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new("us-west-2"))
            .build();
        SecurityHubNotifier::new(&config, "123456789012".into(), "us-west-2".into())
    }

    fn sample_alert(severity: Severity) -> SecurityAlert {
        SecurityAlert {
            rule_id: "DETECT-IAM-001".into(),
            rule_name: "IAM Privilege Escalation".into(),
            severity,
            message: "AttachRolePolicy called on admin role".into(),
            match_count: 2,
            details: HashMap::new(),
        }
    }

    #[test]
    fn finding_has_correct_schema_version() {
        let n = notifier();
        let alert = sample_alert(Severity::High);
        let finding = n.build_finding(&alert);
        assert_eq!(finding.schema_version(), Some("2018-10-08"));
    }

    #[test]
    fn finding_product_arn_uses_account_and_region() {
        let n = notifier();
        let alert = sample_alert(Severity::High);
        let finding = n.build_finding(&alert);
        assert_eq!(
            finding.product_arn(),
            Some("arn:aws:securityhub:us-west-2:123456789012:product/123456789012/default")
        );
    }

    #[test]
    fn finding_id_includes_rule_id() {
        let n = notifier();
        let alert = sample_alert(Severity::Critical);
        let finding = n.build_finding(&alert);
        let id = finding.id().unwrap_or("");
        assert!(id.starts_with("irone-DETECT-IAM-001-"));
    }

    #[test]
    fn finding_severity_maps_correctly() {
        use aws_sdk_securityhub::types::SeverityLabel;
        let cases = [
            (Severity::Info, SeverityLabel::Informational),
            (Severity::Low, SeverityLabel::Low),
            (Severity::Medium, SeverityLabel::Medium),
            (Severity::High, SeverityLabel::High),
            (Severity::Critical, SeverityLabel::Critical),
        ];
        for (irone_sev, expected_label) in cases {
            let label = SecurityHubNotifier::asff_severity_label(&irone_sev);
            assert_eq!(label, expected_label);
        }
    }

    #[test]
    fn finding_title_and_description() {
        let n = notifier();
        let alert = sample_alert(Severity::High);
        let finding = n.build_finding(&alert);
        assert_eq!(finding.title(), Some("IAM Privilege Escalation"));
        assert_eq!(
            finding.description(),
            Some("AttachRolePolicy called on admin role")
        );
    }

    #[test]
    fn finding_product_fields_contain_irone_metadata() {
        let n = notifier();
        let alert = sample_alert(Severity::Medium);
        let finding = n.build_finding(&alert);
        let fields = finding.product_fields().unwrap();
        assert_eq!(
            fields.get("irone/rule_id").map(String::as_str),
            Some("DETECT-IAM-001")
        );
        assert_eq!(
            fields.get("irone/match_count").map(String::as_str),
            Some("2")
        );
    }

    #[test]
    fn finding_has_resource() {
        let n = notifier();
        let alert = sample_alert(Severity::Low);
        let finding = n.build_finding(&alert);
        assert_eq!(finding.resources().len(), 1);
        let resource_type = finding.resources()[0].r#type().unwrap_or("");
        assert_eq!(resource_type, "Other");
    }
}
