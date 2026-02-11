"""AI-assisted security analysis module using AWS Bedrock.

This module provides AI-powered capabilities for security workflows:
- Detection rule generation from natural language
- Alert analysis and triage
- Investigation graph analysis
- Natural language to SQL conversion
- Incident report generation

Example usage:
    ```python
    from secdashboards.ai import BedrockAssistant, BedrockModel, TaskConfig

    # Initialize assistant
    assistant = BedrockAssistant(region="us-west-2")

    # Generate a detection rule
    response = assistant.generate_detection_rule(
        "Detect when root user logs in from an IP not in our corporate range"
    )
    print(response.content)
    print(f"Cost: ${response.cost_usd:.4f}")

    # Configure specific model for a task
    config = TaskConfig(model=BedrockModel.CLAUDE_OPUS_4_5)
    response = assistant.analyze_attack_chain(events, config=config)

    # Check session costs
    print(assistant.get_usage_summary())
    ```

Pricing information is sourced from AWS Bedrock pricing pages and may
vary by region. Always check current pricing at:
https://aws.amazon.com/bedrock/pricing/
"""

from secdashboards.ai.assistant import (
    AssistantResponse,
    BedrockAssistant,
    TaskConfig,
)
from secdashboards.ai.models import (
    MODEL_PRICING,
    TASK_MODEL_RECOMMENDATIONS,
    BedrockModel,
    ModelPricing,
    estimate_request_cost,
    get_pricing,
    get_recommended_model,
)
from secdashboards.ai.prompts import PROMPTS, get_prompt
from secdashboards.ai.tools import (
    ALL_TOOLS,
    ToolExecutor,
    get_tool_config,
)

__all__ = [
    # Assistant
    "BedrockAssistant",
    "AssistantResponse",
    "TaskConfig",
    # Models
    "BedrockModel",
    "ModelPricing",
    "MODEL_PRICING",
    "TASK_MODEL_RECOMMENDATIONS",
    "get_pricing",
    "get_recommended_model",
    "estimate_request_cost",
    # Prompts
    "PROMPTS",
    "get_prompt",
    # Tools (skeleton)
    "ToolExecutor",
    "get_tool_config",
    "ALL_TOOLS",
]
