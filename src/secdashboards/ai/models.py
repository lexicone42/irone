"""Bedrock model configurations and pricing.

This module defines available Claude 4.5 models on AWS Bedrock with their
pricing information for cost estimation.

Pricing is based on Anthropic's published rates. AWS Bedrock pricing
may vary slightly - check https://aws.amazon.com/bedrock/pricing/ for
current rates.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class BedrockModel(StrEnum):
    """Available Claude 4.5 models on AWS Bedrock."""

    # Claude 4.5 family - the only models we use
    CLAUDE_SONNET_4_5 = "anthropic.claude-sonnet-4-5-20250929-v1:0"
    CLAUDE_OPUS_4_5 = "anthropic.claude-opus-4-5-20251101-v1:0"
    CLAUDE_HAIKU_4_5 = "anthropic.claude-haiku-4-5-20251001-v1:0"

    # Convenience aliases
    SONNET = CLAUDE_SONNET_4_5
    HAIKU = CLAUDE_HAIKU_4_5
    OPUS = CLAUDE_OPUS_4_5


@dataclass(frozen=True)
class ModelPricing:
    """Pricing information for a model.

    All prices are in USD per million tokens (MTok).
    """

    input_price_per_mtok: float
    output_price_per_mtok: float
    batch_input_price_per_mtok: float | None = None
    batch_output_price_per_mtok: float | None = None
    description: str = ""
    context_window: int = 200000
    recommended_for: list[str] | None = None

    @property
    def input_price_per_1k(self) -> float:
        """Price per 1,000 input tokens."""
        return self.input_price_per_mtok / 1000

    @property
    def output_price_per_1k(self) -> float:
        """Price per 1,000 output tokens."""
        return self.output_price_per_mtok / 1000

    def estimate_cost(
        self,
        input_tokens: int,
        output_tokens: int,
        use_batch: bool = False,
    ) -> float:
        """Estimate cost for a request.

        Args:
            input_tokens: Number of input tokens
            output_tokens: Number of output tokens
            use_batch: Whether to use batch pricing (50% discount)

        Returns:
            Estimated cost in USD
        """
        if use_batch and self.batch_input_price_per_mtok:
            input_cost = (input_tokens / 1_000_000) * self.batch_input_price_per_mtok
            output_cost = (output_tokens / 1_000_000) * (
                self.batch_output_price_per_mtok or self.output_price_per_mtok / 2
            )
        else:
            input_cost = (input_tokens / 1_000_000) * self.input_price_per_mtok
            output_cost = (output_tokens / 1_000_000) * self.output_price_per_mtok

        return input_cost + output_cost


# Model pricing database - Claude 4.5 only
# Source: https://aws.amazon.com/bedrock/pricing/
MODEL_PRICING: dict[BedrockModel, ModelPricing] = {
    BedrockModel.CLAUDE_SONNET_4_5: ModelPricing(
        input_price_per_mtok=3.0,
        output_price_per_mtok=15.0,
        batch_input_price_per_mtok=1.5,
        batch_output_price_per_mtok=7.5,
        description="Best balance of speed, cost, and capability - default for all tasks",
        context_window=200000,
        recommended_for=["detection_generation", "alert_analysis", "general", "investigation"],
    ),
    BedrockModel.CLAUDE_HAIKU_4_5: ModelPricing(
        input_price_per_mtok=1.0,
        output_price_per_mtok=5.0,
        batch_input_price_per_mtok=0.5,
        batch_output_price_per_mtok=2.5,
        description="Fast and cost-effective for high-volume tasks",
        context_window=200000,
        recommended_for=["quick_triage", "simple_queries", "high_volume", "bulk_processing"],
    ),
    BedrockModel.CLAUDE_OPUS_4_5: ModelPricing(
        input_price_per_mtok=15.0,
        output_price_per_mtok=75.0,
        batch_input_price_per_mtok=7.5,
        batch_output_price_per_mtok=37.5,
        description="Most capable for complex analysis and deep investigation",
        context_window=200000,
        recommended_for=["complex_investigation", "detailed_reports", "attack_chain_analysis"],
    ),
}


def get_pricing(model: BedrockModel | str) -> ModelPricing:
    """Get pricing for a model.

    Args:
        model: Model enum or model ID string

    Returns:
        ModelPricing for the specified model

    Raises:
        KeyError: If model is not found
    """
    if isinstance(model, str):
        model = BedrockModel(model)
    return MODEL_PRICING[model]


def estimate_request_cost(
    model: BedrockModel | str,
    input_tokens: int,
    output_tokens: int,
    use_batch: bool = False,
) -> dict[str, Any]:
    """Estimate cost for a Bedrock request.

    Args:
        model: Model to use
        input_tokens: Estimated input tokens
        output_tokens: Estimated output tokens
        use_batch: Whether batch pricing applies

    Returns:
        Dict with cost breakdown
    """
    pricing = get_pricing(model)
    total_cost = pricing.estimate_cost(input_tokens, output_tokens, use_batch)

    return {
        "model": model if isinstance(model, str) else model.value,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "input_cost_usd": (input_tokens / 1_000_000) * pricing.input_price_per_mtok,
        "output_cost_usd": (output_tokens / 1_000_000) * pricing.output_price_per_mtok,
        "total_cost_usd": total_cost,
        "batch_discount_applied": use_batch,
        "pricing_source": "https://aws.amazon.com/bedrock/pricing/",
    }


# Task-specific model recommendations - all Claude 4.5
TASK_MODEL_RECOMMENDATIONS: dict[str, BedrockModel] = {
    # Detection engineering
    "detection_generation": BedrockModel.CLAUDE_SONNET_4_5,
    "rule_explanation": BedrockModel.CLAUDE_HAIKU_4_5,
    "rule_optimization": BedrockModel.CLAUDE_SONNET_4_5,
    # Alert analysis
    "alert_triage": BedrockModel.CLAUDE_HAIKU_4_5,
    "alert_analysis": BedrockModel.CLAUDE_SONNET_4_5,
    "severity_assessment": BedrockModel.CLAUDE_HAIKU_4_5,
    # Investigation
    "graph_analysis": BedrockModel.CLAUDE_SONNET_4_5,
    "attack_chain_analysis": BedrockModel.CLAUDE_OPUS_4_5,
    "incident_report": BedrockModel.CLAUDE_SONNET_4_5,
    "timeline_summary": BedrockModel.CLAUDE_SONNET_4_5,
    # Query generation
    "natural_language_to_sql": BedrockModel.CLAUDE_SONNET_4_5,
    "query_explanation": BedrockModel.CLAUDE_HAIKU_4_5,
    # General
    "general": BedrockModel.CLAUDE_SONNET_4_5,
    "quick": BedrockModel.CLAUDE_HAIKU_4_5,
    "complex": BedrockModel.CLAUDE_OPUS_4_5,
}


def get_recommended_model(task: str) -> BedrockModel:
    """Get recommended model for a task.

    Args:
        task: Task identifier (e.g., 'detection_generation', 'alert_triage')

    Returns:
        Recommended BedrockModel for the task (defaults to Sonnet 4.5)
    """
    return TASK_MODEL_RECOMMENDATIONS.get(task, BedrockModel.CLAUDE_SONNET_4_5)
