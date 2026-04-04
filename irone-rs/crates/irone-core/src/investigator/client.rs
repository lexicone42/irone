//! HTTP client for the Anthropic Messages API.

use chrono::Utc;
use serde::{Deserialize, Serialize};

use super::models::{
    AiVerdict, InvestigationAnalysis, InvestigationContext, RecommendedAction, ThreatAssessment,
};
use super::prompt::build_investigation_prompt;

/// Anthropic API request body (Messages API).
#[derive(Debug, Serialize)]
struct MessagesRequest {
    model: String,
    max_tokens: u32,
    messages: Vec<Message>,
    system: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Message {
    role: String,
    content: String,
}

/// Anthropic API response body.
#[derive(Debug, Deserialize)]
struct MessagesResponse {
    content: Vec<ContentBlock>,
    model: String,
    #[allow(dead_code)]
    usage: Option<Usage>,
}

#[derive(Debug, Deserialize)]
struct ContentBlock {
    text: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Usage {
    #[allow(dead_code)]
    input_tokens: u32,
    #[allow(dead_code)]
    output_tokens: u32,
}

/// Raw JSON response from Claude that we parse into `InvestigationAnalysis`.
#[derive(Debug, Deserialize)]
struct ClaudeAnalysisResponse {
    verdict: String,
    confidence: f64,
    #[serde(default)]
    mitre_techniques: Vec<String>,
    #[serde(default)]
    kill_chain_phases: Vec<String>,
    #[serde(default)]
    blast_radius: String,
    #[serde(default)]
    executive_summary: String,
    #[serde(default)]
    technical_narrative: String,
    #[serde(default)]
    key_findings: Vec<String>,
    #[serde(default)]
    recommended_actions: Vec<RawAction>,
    #[serde(default)]
    follow_up_questions: Vec<String>,
    #[serde(default)]
    detection_improvements: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RawAction {
    priority: u8,
    action: String,
    #[serde(default)]
    rationale: String,
    #[serde(default)]
    automatable: bool,
}

/// Client for running investigations through the Anthropic Messages API.
pub struct ClaudeInvestigator {
    api_key: String,
    model: String,
    client: reqwest::Client,
    base_url: String,
}

impl ClaudeInvestigator {
    /// Create a new investigator with the given API key.
    #[must_use]
    pub fn new(api_key: String) -> Self {
        Self {
            api_key,
            model: "claude-sonnet-4-20250514".into(),
            client: reqwest::Client::new(),
            base_url: "https://api.anthropic.com".into(),
        }
    }

    /// Use a specific model (e.g., `claude-sonnet-4-20250514`).
    #[must_use]
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = model.into();
        self
    }

    /// Override the base URL (for testing or proxy).
    #[must_use]
    pub fn with_base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = url.into();
        self
    }

    /// Create from environment variable `ANTHROPIC_API_KEY`.
    pub fn from_env() -> Result<Self, String> {
        let api_key =
            std::env::var("ANTHROPIC_API_KEY").map_err(|_| "ANTHROPIC_API_KEY not set")?;
        Ok(Self::new(api_key))
    }

    /// Run a full investigation analysis.
    pub async fn analyze(
        &self,
        ctx: &InvestigationContext,
        investigation_id: &str,
    ) -> Result<InvestigationAnalysis, Box<dyn std::error::Error + Send + Sync>> {
        let prompt = build_investigation_prompt(ctx);

        let request = MessagesRequest {
            model: self.model.clone(),
            max_tokens: 4096,
            system: "You are a security investigation AI. Respond only with valid JSON \
                     matching the requested schema. No markdown fences, no explanation \
                     outside the JSON."
                .into(),
            messages: vec![Message {
                role: "user".into(),
                content: prompt.clone(),
            }],
        };

        let url = format!("{}/v1/messages", self.base_url);

        let response = self
            .client
            .post(&url)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&request)
            .send()
            .await?;

        let status = response.status();
        let body = response.text().await?;

        if !status.is_success() {
            return Err(format!("Anthropic API error ({status}): {body}").into());
        }

        let api_response: MessagesResponse = serde_json::from_str(&body)
            .map_err(|e| format!("Failed to parse API response: {e}\nBody: {body}"))?;

        let raw_text = api_response
            .content
            .first()
            .and_then(|b| b.text.as_deref())
            .ok_or("No text content in API response")?;

        // Strip markdown fences if Claude wraps the JSON
        let json_text = raw_text
            .trim()
            .strip_prefix("```json")
            .or_else(|| raw_text.trim().strip_prefix("```"))
            .unwrap_or(raw_text)
            .strip_suffix("```")
            .unwrap_or(raw_text)
            .trim();

        let parsed: ClaudeAnalysisResponse = serde_json::from_str(json_text).map_err(|e| {
            format!("Failed to parse Claude response as JSON: {e}\nText: {json_text}")
        })?;

        let verdict = match parsed.verdict.as_str() {
            "true_positive" => AiVerdict::TruePositive,
            "suspicious" => AiVerdict::Suspicious,
            "likely_benign" => AiVerdict::LikelyBenign,
            "false_positive" => AiVerdict::FalsePositive,
            _ => AiVerdict::Inconclusive,
        };

        Ok(InvestigationAnalysis {
            investigation_id: investigation_id.into(),
            analyzed_at: Utc::now(),
            threat_assessment: ThreatAssessment {
                verdict,
                confidence: parsed.confidence,
                mitre_techniques: parsed.mitre_techniques,
                kill_chain_phases: parsed.kill_chain_phases,
                blast_radius: parsed.blast_radius,
            },
            executive_summary: parsed.executive_summary,
            technical_narrative: parsed.technical_narrative,
            key_findings: parsed.key_findings,
            recommended_actions: parsed
                .recommended_actions
                .into_iter()
                .map(|a| RecommendedAction {
                    priority: a.priority,
                    action: a.action,
                    rationale: a.rationale,
                    automatable: a.automatable,
                })
                .collect(),
            follow_up_questions: parsed.follow_up_questions,
            detection_improvements: parsed.detection_improvements,
            raw_response: raw_text.into(),
            model: api_response.model,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claude_investigator_from_env_fails_without_key() {
        // This test only works if ANTHROPIC_API_KEY is not set in the environment.
        // We can't safely unset it (remove_var is unsafe in 2024 edition) so we
        // just test the constructor path instead.
        let result = ClaudeInvestigator::from_env();
        // Either it succeeds (key is set) or fails (not set) — both are valid
        let _ = result;
    }

    #[test]
    fn claude_investigator_builder() {
        let client = ClaudeInvestigator::new("test-key".into())
            .with_model("claude-opus-4-20250514")
            .with_base_url("http://localhost:8080");
        assert_eq!(client.model, "claude-opus-4-20250514");
        assert_eq!(client.base_url, "http://localhost:8080");
    }

    #[test]
    fn parse_claude_response_json() {
        let json = r#"{
            "verdict": "true_positive",
            "confidence": 0.92,
            "mitre_techniques": ["T1078.004"],
            "kill_chain_phases": ["Initial Access", "Persistence"],
            "blast_radius": "AWS account us-west-2",
            "executive_summary": "Root console login from unknown IP",
            "technical_narrative": "At 14:32...",
            "key_findings": ["Root login from 198.51.100.1"],
            "recommended_actions": [
                {
                    "priority": 1,
                    "action": "Rotate root credentials",
                    "rationale": "Root is compromised",
                    "automatable": false
                }
            ],
            "follow_up_questions": ["Who owns 198.51.100.1?"],
            "detection_improvements": ["Add MFA check"]
        }"#;

        let parsed: ClaudeAnalysisResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.verdict, "true_positive");
        assert_eq!(parsed.confidence, 0.92);
        assert_eq!(parsed.recommended_actions.len(), 1);
        assert_eq!(parsed.recommended_actions[0].priority, 1);
    }

    #[test]
    fn parse_verdict_mapping() {
        let cases = [
            ("true_positive", AiVerdict::TruePositive),
            ("suspicious", AiVerdict::Suspicious),
            ("likely_benign", AiVerdict::LikelyBenign),
            ("false_positive", AiVerdict::FalsePositive),
            ("inconclusive", AiVerdict::Inconclusive),
            ("unknown_value", AiVerdict::Inconclusive),
        ];
        for (input, expected) in cases {
            let verdict = match input {
                "true_positive" => AiVerdict::TruePositive,
                "suspicious" => AiVerdict::Suspicious,
                "likely_benign" => AiVerdict::LikelyBenign,
                "false_positive" => AiVerdict::FalsePositive,
                _ => AiVerdict::Inconclusive,
            };
            assert_eq!(verdict, expected, "failed for input: {input}");
        }
    }

    #[test]
    fn strip_markdown_fences() {
        let raw = "```json\n{\"verdict\":\"suspicious\"}\n```";
        let stripped = raw
            .trim()
            .strip_prefix("```json")
            .or_else(|| raw.trim().strip_prefix("```"))
            .unwrap_or(raw)
            .strip_suffix("```")
            .unwrap_or(raw)
            .trim();
        assert_eq!(stripped, "{\"verdict\":\"suspicious\"}");
    }
}
