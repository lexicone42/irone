use std::fmt::Write;

use aws_sdk_sns::Client as SnsClient;
use iris_core::detections::Severity;
use iris_core::notifications::{NotificationChannel, SecurityAlert};
use tracing::info;

use crate::error::AwsError;

/// SNS-backed notification channel.
///
/// Publishes formatted security alerts to an SNS topic.
pub struct SnsNotifier {
    client: SnsClient,
    topic_arn: String,
}

impl SnsNotifier {
    pub fn new(config: &aws_config::SdkConfig, topic_arn: String) -> Self {
        Self {
            client: SnsClient::new(config),
            topic_arn,
        }
    }

    /// Format the subject line (max 100 chars for SNS).
    fn format_subject(alert: &SecurityAlert) -> String {
        let severity_tag = match alert.severity {
            Severity::Critical => "[CRITICAL]",
            Severity::High => "[HIGH]",
            Severity::Medium => "[MEDIUM]",
            Severity::Low => "[LOW]",
            Severity::Info => "[INFO]",
        };
        let subject = format!("{severity_tag} {}", alert.rule_name);
        if subject.len() > 100 {
            format!("{}...", &subject[..97])
        } else {
            subject
        }
    }

    /// Format the message body.
    fn format_message(alert: &SecurityAlert) -> String {
        let mut msg = format!(
            "Security Alert: {}\n\
             Severity: {:?}\n\
             Rule: {} ({})\n\
             Matches: {}\n\n\
             {}",
            alert.rule_name,
            alert.severity,
            alert.rule_name,
            alert.rule_id,
            alert.match_count,
            alert.message,
        );

        if !alert.details.is_empty() {
            msg.push_str("\n\nDetails:\n");
            for (key, value) in &alert.details {
                let _ = writeln!(msg, "  {key}: {value}");
            }
        }

        msg
    }
}

impl NotificationChannel for SnsNotifier {
    async fn send_alert(
        &self,
        alert: &SecurityAlert,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let subject = Self::format_subject(alert);
        let message = Self::format_message(alert);

        self.client
            .publish()
            .topic_arn(&self.topic_arn)
            .subject(&subject)
            .message(&message)
            .send()
            .await
            .map_err(|e| AwsError::Sns(e.to_string()).boxed())?;

        info!(rule_id = %alert.rule_id, topic = %self.topic_arn, "alert published to SNS");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde_json::json;

    use super::*;

    fn sample_alert(severity: Severity) -> SecurityAlert {
        SecurityAlert {
            rule_id: "RULE-001".into(),
            rule_name: "Suspicious API Activity".into(),
            severity,
            message: "Multiple failed auth attempts detected".into(),
            match_count: 5,
            details: HashMap::from([
                ("source_ip".into(), json!("10.0.0.1")),
                ("user".into(), json!("admin")),
            ]),
        }
    }

    #[test]
    fn subject_severity_prefix() {
        let cases = [
            (Severity::Critical, "[CRITICAL] Suspicious API Activity"),
            (Severity::High, "[HIGH] Suspicious API Activity"),
            (Severity::Medium, "[MEDIUM] Suspicious API Activity"),
            (Severity::Low, "[LOW] Suspicious API Activity"),
            (Severity::Info, "[INFO] Suspicious API Activity"),
        ];
        for (severity, expected) in cases {
            let alert = sample_alert(severity);
            assert_eq!(SnsNotifier::format_subject(&alert), expected);
        }
    }

    #[test]
    fn subject_truncated_at_100_chars() {
        let alert = SecurityAlert {
            rule_id: "R".into(),
            rule_name: "A".repeat(120),
            severity: Severity::Critical,
            message: String::new(),
            match_count: 0,
            details: HashMap::new(),
        };
        let subject = SnsNotifier::format_subject(&alert);
        assert!(subject.len() <= 100);
        assert!(subject.ends_with("..."));
    }

    #[test]
    fn message_contains_all_fields() {
        let alert = sample_alert(Severity::High);
        let msg = SnsNotifier::format_message(&alert);
        assert!(msg.contains("Suspicious API Activity"));
        assert!(msg.contains("High"));
        assert!(msg.contains("RULE-001"));
        assert!(msg.contains("Matches: 5"));
        assert!(msg.contains("Multiple failed auth attempts"));
        assert!(msg.contains("Details:"));
        assert!(msg.contains("source_ip"));
    }

    #[test]
    fn message_no_details_when_empty() {
        let mut alert = sample_alert(Severity::Low);
        alert.details.clear();
        let msg = SnsNotifier::format_message(&alert);
        assert!(!msg.contains("Details:"));
    }
}
