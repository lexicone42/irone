"""Bedrock AI Assistant for security analysis.

This module provides the main BedrockAssistant class for AI-assisted
security workflows including detection generation, alert analysis,
investigation support, and natural language querying.
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any

import boto3
from botocore.exceptions import ClientError

from secdashboards.ai.models import (
    MODEL_PRICING,
    BedrockModel,
    get_pricing,
    get_recommended_model,
)
from secdashboards.ai.prompts import get_prompt

if TYPE_CHECKING:
    from secdashboards.detections.rule import DetectionResult
    from secdashboards.graph.models import SecurityGraph

logger = logging.getLogger(__name__)


@dataclass
class AssistantResponse:
    """Response from the Bedrock assistant.

    Attributes:
        content: The text response from the model
        model: Model used for the response
        input_tokens: Number of input tokens used
        output_tokens: Number of output tokens used
        cost_usd: Estimated cost in USD
        latency_ms: Response latency in milliseconds
        stop_reason: Why the model stopped generating
        metadata: Additional response metadata
    """

    content: str
    model: str
    input_tokens: int
    output_tokens: int
    cost_usd: float
    latency_ms: float
    stop_reason: str = "end_turn"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "content": self.content,
            "model": self.model,
            "usage": {
                "input_tokens": self.input_tokens,
                "output_tokens": self.output_tokens,
            },
            "cost_usd": self.cost_usd,
            "latency_ms": self.latency_ms,
            "stop_reason": self.stop_reason,
            "metadata": self.metadata,
        }


@dataclass
class TaskConfig:
    """Configuration for a specific task.

    Attributes:
        model: Model to use (or None for recommended)
        max_tokens: Maximum output tokens
        temperature: Sampling temperature (0-1)
        system_prompt_override: Custom system prompt (or None for default)
    """

    model: BedrockModel | None = None
    max_tokens: int = 4096
    temperature: float = 0.3
    system_prompt_override: str | None = None


class BedrockAssistant:
    """AI assistant powered by AWS Bedrock Claude models.

    This class provides security-focused AI capabilities including:
    - Detection rule generation from natural language
    - Alert analysis and triage
    - Investigation graph analysis
    - Natural language to SQL conversion
    - Incident report generation

    Example:
        ```python
        assistant = BedrockAssistant(region="us-west-2")

        # Generate a detection rule
        response = assistant.generate_detection_rule(
            "Detect when a root user logs in from an unusual IP"
        )
        print(response.content)
        print(f"Cost: ${response.cost_usd:.4f}")
        ```
    """

    def __init__(
        self,
        region: str = "us-west-2",
        default_model: BedrockModel = BedrockModel.CLAUDE_3_5_SONNET,
        task_configs: dict[str, TaskConfig] | None = None,
    ) -> None:
        """Initialize the Bedrock assistant.

        Args:
            region: AWS region for Bedrock
            default_model: Default model for tasks without specific config
            task_configs: Per-task configuration overrides
        """
        self.region = region
        self.default_model = default_model
        self.task_configs = task_configs or {}

        # Initialize Bedrock client
        self._client = boto3.client("bedrock-runtime", region_name=region)

        # Track usage for cost monitoring
        self._total_input_tokens = 0
        self._total_output_tokens = 0
        self._total_cost_usd = 0.0
        self._request_count = 0

    def _get_task_config(self, task: str) -> TaskConfig:
        """Get configuration for a task."""
        return self.task_configs.get(task, TaskConfig())

    def _get_model_for_task(self, task: str, config: TaskConfig) -> BedrockModel:
        """Determine which model to use for a task."""
        if config.model:
            return config.model
        return get_recommended_model(task)

    def _invoke_model(
        self,
        task: str,
        user_message: str,
        config: TaskConfig | None = None,
    ) -> AssistantResponse:
        """Invoke Bedrock model with proper configuration.

        Args:
            task: Task identifier for prompt selection
            user_message: User's input message
            config: Optional task configuration override

        Returns:
            AssistantResponse with model output and usage info
        """
        config = config or self._get_task_config(task)
        model = self._get_model_for_task(task, config)
        pricing = get_pricing(model)

        # Get system prompt
        system_prompt = config.system_prompt_override or get_prompt(task)

        # Build request
        request_body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": config.max_tokens,
            "temperature": config.temperature,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_message}],
        }

        # Invoke model and measure latency
        start_time = datetime.now()
        try:
            response = self._client.invoke_model(
                modelId=model.value,
                body=json.dumps(request_body),
            )
        except ClientError as e:
            logger.error(f"Bedrock invocation failed: {e}")
            raise

        latency_ms = (datetime.now() - start_time).total_seconds() * 1000

        # Parse response
        response_body = json.loads(response["body"].read())

        content = ""
        for block in response_body.get("content", []):
            if block.get("type") == "text":
                content += block.get("text", "")

        input_tokens = response_body.get("usage", {}).get("input_tokens", 0)
        output_tokens = response_body.get("usage", {}).get("output_tokens", 0)
        stop_reason = response_body.get("stop_reason", "end_turn")

        # Calculate cost
        cost = pricing.estimate_cost(input_tokens, output_tokens)

        # Update tracking
        self._total_input_tokens += input_tokens
        self._total_output_tokens += output_tokens
        self._total_cost_usd += cost
        self._request_count += 1

        return AssistantResponse(
            content=content,
            model=model.value,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=cost,
            latency_ms=latency_ms,
            stop_reason=stop_reason,
            metadata={
                "task": task,
                "region": self.region,
            },
        )

    # =========================================================================
    # Detection Engineering
    # =========================================================================

    def generate_detection_rule(
        self,
        description: str,
        context: str | None = None,
        config: TaskConfig | None = None,
    ) -> AssistantResponse:
        """Generate a detection rule from a natural language description.

        Args:
            description: What the rule should detect
            context: Additional context (e.g., environment details)
            config: Optional task configuration

        Returns:
            AssistantResponse containing the YAML detection rule
        """
        message = f"Generate a detection rule for: {description}"
        if context:
            message += f"\n\nAdditional context:\n{context}"

        return self._invoke_model("detection_generation", message, config)

    def optimize_detection_rule(
        self,
        rule_yaml: str,
        issues: str | None = None,
        config: TaskConfig | None = None,
    ) -> AssistantResponse:
        """Optimize an existing detection rule.

        Args:
            rule_yaml: The current rule in YAML format
            issues: Known issues or goals for optimization
            config: Optional task configuration

        Returns:
            AssistantResponse containing the optimized rule
        """
        message = f"Optimize this detection rule:\n\n```yaml\n{rule_yaml}\n```"
        if issues:
            message += f"\n\nKnown issues or goals:\n{issues}"

        return self._invoke_model("rule_optimization", message, config)

    def explain_detection_rule(
        self,
        rule_yaml: str,
        config: TaskConfig | None = None,
    ) -> AssistantResponse:
        """Explain what a detection rule does.

        Args:
            rule_yaml: The rule to explain
            config: Optional task configuration

        Returns:
            AssistantResponse with explanation
        """
        message = f"Explain this detection rule:\n\n```yaml\n{rule_yaml}\n```"
        return self._invoke_model("rule_explanation", message, config)

    # =========================================================================
    # Alert Analysis
    # =========================================================================

    def triage_alert(
        self,
        detection_result: "DetectionResult",
        config: TaskConfig | None = None,
    ) -> AssistantResponse:
        """Triage a triggered alert.

        Args:
            detection_result: The detection result to triage
            config: Optional task configuration

        Returns:
            AssistantResponse with triage assessment
        """
        # Format detection result for analysis
        alert_data = detection_result.to_alert_dict()
        message = f"Triage this security alert:\n\n```json\n{json.dumps(alert_data, indent=2, default=str)}\n```"

        return self._invoke_model("alert_triage", message, config)

    def analyze_alert(
        self,
        detection_result: "DetectionResult",
        include_events: bool = True,
        config: TaskConfig | None = None,
    ) -> AssistantResponse:
        """Perform detailed analysis of an alert.

        Args:
            detection_result: The detection result to analyze
            include_events: Whether to include matched events
            config: Optional task configuration

        Returns:
            AssistantResponse with detailed analysis
        """
        alert_data = detection_result.to_alert_dict()

        if include_events and detection_result.matches:
            # Include sample events (limit to avoid token overflow)
            alert_data["matched_events_sample"] = detection_result.matches[:20]

        message = f"Analyze this security alert in detail:\n\n```json\n{json.dumps(alert_data, indent=2, default=str)}\n```"

        return self._invoke_model("alert_analysis", message, config)

    # =========================================================================
    # Investigation
    # =========================================================================

    def analyze_graph(
        self,
        graph: "SecurityGraph",
        focus_area: str | None = None,
        config: TaskConfig | None = None,
    ) -> AssistantResponse:
        """Analyze a security investigation graph.

        Args:
            graph: The SecurityGraph to analyze
            focus_area: Specific area to focus on
            config: Optional task configuration

        Returns:
            AssistantResponse with graph analysis
        """
        # Convert graph to summary format
        summary = graph.summary()
        graph_data = {
            "summary": summary,
            "nodes": [
                {
                    "id": node.id,
                    "type": node.node_type.value,
                    "label": node.label,
                    "properties": node.properties,
                }
                for node in graph.nodes.values()
            ][:50],  # Limit nodes
            "edges": [
                {
                    "source": edge.source_id,
                    "target": edge.target_id,
                    "type": edge.edge_type.value,
                }
                for edge in graph.edges
            ][:100],  # Limit edges
        }

        message = f"Analyze this security investigation graph:\n\n```json\n{json.dumps(graph_data, indent=2, default=str)}\n```"
        if focus_area:
            message += f"\n\nFocus on: {focus_area}"

        return self._invoke_model("graph_analysis", message, config)

    def analyze_attack_chain(
        self,
        events: list[dict[str, Any]],
        config: TaskConfig | None = None,
    ) -> AssistantResponse:
        """Analyze events for attack chain patterns.

        Args:
            events: List of security events to analyze
            config: Optional task configuration

        Returns:
            AssistantResponse with attack chain analysis
        """
        # Limit events to avoid token overflow
        events = events[:50]

        message = f"Analyze these events for attack chain patterns:\n\n```json\n{json.dumps(events, indent=2, default=str)}\n```"

        return self._invoke_model("attack_chain_analysis", message, config)

    def generate_incident_report(
        self,
        summary: str,
        timeline: list[dict[str, Any]],
        indicators: list[str] | None = None,
        actions_taken: list[str] | None = None,
        config: TaskConfig | None = None,
    ) -> AssistantResponse:
        """Generate an incident report.

        Args:
            summary: Brief incident summary
            timeline: List of timeline events
            indicators: IOCs identified
            actions_taken: Actions already taken
            config: Optional task configuration

        Returns:
            AssistantResponse with incident report
        """
        incident_data = {
            "summary": summary,
            "timeline": timeline[:30],
            "indicators": indicators or [],
            "actions_taken": actions_taken or [],
        }

        message = f"Generate an incident report from this data:\n\n```json\n{json.dumps(incident_data, indent=2, default=str)}\n```"

        return self._invoke_model("incident_report", message, config)

    # =========================================================================
    # Query Generation
    # =========================================================================

    def natural_language_to_sql(
        self,
        question: str,
        database: str = "amazon_security_lake_glue_db_us_west_2",
        table: str = "amazon_security_lake_table_us_west_2_cloud_trail_mgmt_2_0",
        config: TaskConfig | None = None,
    ) -> AssistantResponse:
        """Convert a natural language question to SQL.

        Args:
            question: The question to convert
            database: Target Glue database
            table: Target table
            config: Optional task configuration

        Returns:
            AssistantResponse containing the SQL query
        """
        message = f"""Convert this question to a SQL query for Security Lake:

Question: {question}

Target database: {database}
Target table: {table}

Generate only the SQL query."""

        return self._invoke_model("natural_language_to_sql", message, config)

    def explain_query(
        self,
        sql: str,
        config: TaskConfig | None = None,
    ) -> AssistantResponse:
        """Explain what a SQL query does.

        Args:
            sql: The SQL query to explain
            config: Optional task configuration

        Returns:
            AssistantResponse with explanation
        """
        message = f"Explain this Security Lake query:\n\n```sql\n{sql}\n```"
        return self._invoke_model("query_explanation", message, config)

    # =========================================================================
    # Cost Tracking
    # =========================================================================

    def get_usage_summary(self) -> dict[str, Any]:
        """Get usage summary for this session.

        Returns:
            Dict with usage statistics
        """
        return {
            "total_input_tokens": self._total_input_tokens,
            "total_output_tokens": self._total_output_tokens,
            "total_cost_usd": self._total_cost_usd,
            "request_count": self._request_count,
            "avg_cost_per_request": (
                self._total_cost_usd / self._request_count
                if self._request_count > 0
                else 0
            ),
        }

    def estimate_task_cost(
        self,
        task: str,
        estimated_input_tokens: int = 2000,
        estimated_output_tokens: int = 1000,
    ) -> dict[str, Any]:
        """Estimate cost for a task before running it.

        Args:
            task: Task identifier
            estimated_input_tokens: Expected input tokens
            estimated_output_tokens: Expected output tokens

        Returns:
            Cost estimate with model recommendation
        """
        model = get_recommended_model(task)
        pricing = get_pricing(model)

        return {
            "task": task,
            "recommended_model": model.value,
            "model_description": pricing.description,
            "estimated_input_tokens": estimated_input_tokens,
            "estimated_output_tokens": estimated_output_tokens,
            "estimated_cost_usd": pricing.estimate_cost(
                estimated_input_tokens, estimated_output_tokens
            ),
            "input_price_per_1k": pricing.input_price_per_1k,
            "output_price_per_1k": pricing.output_price_per_1k,
        }

    @staticmethod
    def list_available_models() -> list[dict[str, Any]]:
        """List all available models with pricing.

        Returns:
            List of model information dicts
        """
        return [
            {
                "model_id": model.value,
                "name": model.name,
                "input_price_per_mtok": pricing.input_price_per_mtok,
                "output_price_per_mtok": pricing.output_price_per_mtok,
                "description": pricing.description,
                "recommended_for": pricing.recommended_for,
            }
            for model, pricing in MODEL_PRICING.items()
        ]
