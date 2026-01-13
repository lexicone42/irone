"""Tests for the AI/Bedrock module."""

import pytest

from secdashboards.ai import (
    BedrockModel,
    ModelPricing,
    PROMPTS,
    TASK_MODEL_RECOMMENDATIONS,
    estimate_request_cost,
    get_pricing,
    get_prompt,
    get_recommended_model,
)
from secdashboards.ai.tools import ALL_TOOLS, get_tool_config


class TestBedrockModel:
    """Tests for BedrockModel enum."""

    def test_all_models_defined(self) -> None:
        """Test that all expected models are defined."""
        expected_models = [
            "CLAUDE_3_5_SONNET",
            "CLAUDE_3_5_HAIKU",
            "CLAUDE_3_OPUS",
            "CLAUDE_3_SONNET",
            "CLAUDE_3_HAIKU",
            "CLAUDE_SONNET_4",
            "CLAUDE_OPUS_4",
        ]
        for model_name in expected_models:
            assert hasattr(BedrockModel, model_name)

    def test_model_values_are_valid_bedrock_ids(self) -> None:
        """Test that model values look like Bedrock model IDs."""
        for model in BedrockModel:
            assert model.value.startswith("anthropic.claude")
            assert ":" in model.value or "v1" in model.value

    def test_aliases_work(self) -> None:
        """Test that convenience aliases work."""
        assert BedrockModel.SONNET == BedrockModel.CLAUDE_3_5_SONNET
        assert BedrockModel.HAIKU == BedrockModel.CLAUDE_3_5_HAIKU
        assert BedrockModel.OPUS == BedrockModel.CLAUDE_3_OPUS


class TestModelPricing:
    """Tests for ModelPricing dataclass."""

    def test_pricing_calculation(self) -> None:
        """Test pricing estimation calculation."""
        pricing = ModelPricing(
            input_price_per_mtok=3.0,
            output_price_per_mtok=15.0,
        )

        # 1M input + 1M output = $3 + $15 = $18
        cost = pricing.estimate_cost(1_000_000, 1_000_000)
        assert cost == pytest.approx(18.0)

    def test_pricing_per_1k(self) -> None:
        """Test per-1k token pricing properties."""
        pricing = ModelPricing(
            input_price_per_mtok=3.0,
            output_price_per_mtok=15.0,
        )

        assert pricing.input_price_per_1k == pytest.approx(0.003)
        assert pricing.output_price_per_1k == pytest.approx(0.015)

    def test_batch_pricing(self) -> None:
        """Test batch pricing (50% discount)."""
        pricing = ModelPricing(
            input_price_per_mtok=3.0,
            output_price_per_mtok=15.0,
            batch_input_price_per_mtok=1.5,
            batch_output_price_per_mtok=7.5,
        )

        # Regular cost
        regular_cost = pricing.estimate_cost(1_000_000, 1_000_000, use_batch=False)
        # Batch cost
        batch_cost = pricing.estimate_cost(1_000_000, 1_000_000, use_batch=True)

        assert batch_cost == pytest.approx(regular_cost / 2)


class TestGetPricing:
    """Tests for get_pricing function."""

    def test_get_pricing_by_enum(self) -> None:
        """Test getting pricing by enum."""
        pricing = get_pricing(BedrockModel.CLAUDE_3_5_SONNET)
        assert isinstance(pricing, ModelPricing)
        assert pricing.input_price_per_mtok > 0

    def test_get_pricing_by_string(self) -> None:
        """Test getting pricing by model ID string."""
        pricing = get_pricing(BedrockModel.CLAUDE_3_5_SONNET.value)
        assert isinstance(pricing, ModelPricing)

    def test_all_models_have_pricing(self) -> None:
        """Test that all models have pricing defined."""
        for model in BedrockModel:
            pricing = get_pricing(model)
            assert pricing is not None
            assert pricing.input_price_per_mtok > 0
            assert pricing.output_price_per_mtok > 0


class TestEstimateRequestCost:
    """Tests for estimate_request_cost function."""

    def test_estimate_includes_breakdown(self) -> None:
        """Test that estimate includes cost breakdown."""
        estimate = estimate_request_cost(
            BedrockModel.CLAUDE_3_5_SONNET,
            input_tokens=2000,
            output_tokens=1000,
        )

        assert "model" in estimate
        assert "input_tokens" in estimate
        assert "output_tokens" in estimate
        assert "input_cost_usd" in estimate
        assert "output_cost_usd" in estimate
        assert "total_cost_usd" in estimate

    def test_estimate_values_are_reasonable(self) -> None:
        """Test that estimates are in reasonable range."""
        estimate = estimate_request_cost(
            BedrockModel.CLAUDE_3_5_SONNET,
            input_tokens=2000,
            output_tokens=1000,
        )

        # For 3k tokens, cost should be in cents range
        assert estimate["total_cost_usd"] < 1.0  # Less than $1
        assert estimate["total_cost_usd"] > 0.001  # More than $0.001


class TestTaskModelRecommendations:
    """Tests for task model recommendations."""

    def test_all_tasks_have_recommendations(self) -> None:
        """Test that all known tasks have model recommendations."""
        expected_tasks = [
            "detection_generation",
            "alert_triage",
            "alert_analysis",
            "graph_analysis",
            "natural_language_to_sql",
        ]
        for task in expected_tasks:
            assert task in TASK_MODEL_RECOMMENDATIONS

    def test_get_recommended_model(self) -> None:
        """Test getting recommended model for a task."""
        model = get_recommended_model("detection_generation")
        assert isinstance(model, BedrockModel)

    def test_unknown_task_returns_default(self) -> None:
        """Test that unknown tasks return default model."""
        model = get_recommended_model("unknown_task_xyz")
        assert model == BedrockModel.CLAUDE_3_5_SONNET


class TestPrompts:
    """Tests for prompt templates."""

    def test_all_prompts_defined(self) -> None:
        """Test that all expected prompts are defined."""
        expected_prompts = [
            "detection_generation",
            "rule_optimization",
            "alert_triage",
            "alert_analysis",
            "graph_analysis",
            "attack_chain_analysis",
            "incident_report",
            "natural_language_to_sql",
            "query_explanation",
        ]
        for prompt_name in expected_prompts:
            assert prompt_name in PROMPTS

    def test_get_prompt(self) -> None:
        """Test getting a prompt by name."""
        prompt = get_prompt("detection_generation")
        assert isinstance(prompt, str)
        assert len(prompt) > 100  # Should be substantial

    def test_get_prompt_unknown_raises(self) -> None:
        """Test that unknown prompt raises KeyError."""
        with pytest.raises(KeyError):
            get_prompt("unknown_prompt_xyz")

    def test_prompts_contain_security_context(self) -> None:
        """Test that prompts include security context."""
        for prompt_name, prompt in PROMPTS.items():
            assert "security" in prompt.lower() or "Security" in prompt


class TestTools:
    """Tests for agent tools skeleton."""

    def test_all_tools_defined(self) -> None:
        """Test that all expected tools are defined."""
        assert len(ALL_TOOLS) >= 5

    def test_tools_have_valid_structure(self) -> None:
        """Test that tools have valid Bedrock tool spec structure."""
        for tool in ALL_TOOLS:
            assert "toolSpec" in tool
            spec = tool["toolSpec"]
            assert "name" in spec
            assert "description" in spec
            assert "inputSchema" in spec
            assert "json" in spec["inputSchema"]

    def test_get_tool_config_all(self) -> None:
        """Test getting all tools."""
        config = get_tool_config()
        assert "tools" in config
        assert len(config["tools"]) == len(ALL_TOOLS)

    def test_get_tool_config_filtered(self) -> None:
        """Test getting filtered tools."""
        config = get_tool_config(["query_security_lake"])
        assert "tools" in config
        assert len(config["tools"]) == 1
        assert config["tools"][0]["toolSpec"]["name"] == "query_security_lake"

    def test_get_tool_config_empty(self) -> None:
        """Test getting empty tool list."""
        config = get_tool_config([])
        assert "tools" in config
        assert len(config["tools"]) == 0


class TestIntegration:
    """Integration tests for AI module imports."""

    def test_all_public_imports(self) -> None:
        """Test that all public API imports work."""
        from secdashboards.ai import (
            ALL_TOOLS,
            MODEL_PRICING,
            PROMPTS,
            TASK_MODEL_RECOMMENDATIONS,
            AssistantResponse,
            BedrockAssistant,
            BedrockModel,
            ModelPricing,
            TaskConfig,
            ToolExecutor,
            estimate_request_cost,
            get_pricing,
            get_prompt,
            get_recommended_model,
            get_tool_config,
        )

        # Just verify they imported without error
        assert BedrockAssistant is not None
        assert BedrockModel is not None
        assert ModelPricing is not None

    def test_assistant_response_dataclass(self) -> None:
        """Test AssistantResponse dataclass."""
        from secdashboards.ai import AssistantResponse

        response = AssistantResponse(
            content="Test content",
            model="test-model",
            input_tokens=100,
            output_tokens=50,
            cost_usd=0.01,
            latency_ms=500.0,
        )

        assert response.content == "Test content"
        assert response.input_tokens == 100

        # Test to_dict
        d = response.to_dict()
        assert d["content"] == "Test content"
        assert d["usage"]["input_tokens"] == 100

    def test_task_config_dataclass(self) -> None:
        """Test TaskConfig dataclass."""
        from secdashboards.ai import TaskConfig

        config = TaskConfig(
            model=BedrockModel.CLAUDE_3_5_SONNET,
            max_tokens=2048,
            temperature=0.5,
        )

        assert config.model == BedrockModel.CLAUDE_3_5_SONNET
        assert config.max_tokens == 2048
        assert config.temperature == 0.5
