// Notification types — SecurityAlert + NotificationChannel trait
// The Python version never had a models.py for this; we define the trait here.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::detections::Severity;

/// A security alert ready to be sent via a notification channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAlert {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub message: String,
    pub match_count: usize,
    pub details: HashMap<String, Value>,
}

/// Trait for notification delivery channels (SNS, Slack, etc.).
///
/// Concrete implementations live in `irone-aws` (SNS) or separate crates.
#[allow(async_fn_in_trait)]
pub trait NotificationChannel: Send + Sync {
    /// Send an alert. Returns Ok(()) on success.
    async fn send_alert(
        &self,
        alert: &SecurityAlert,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}
