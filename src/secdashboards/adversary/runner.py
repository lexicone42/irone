"""Adversary test runner for validating detection rules.

This module orchestrates adversary emulation tests against detection rules,
providing a framework for validating detection coverage.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from secdashboards.adversary.events import OCSFEventGenerator, SyntheticEvent
from secdashboards.adversary.network import NetworkEmulator
from secdashboards.adversary.scenarios import AttackScenario, ScenarioRunner
from secdashboards.connectors.result import QueryResult
from secdashboards.detections.rule import DetectionResult, DetectionRule

logger = logging.getLogger(__name__)


class TestOutcome(StrEnum):
    """Outcome of a detection test."""

    PASS = "pass"  # Detection triggered as expected
    FAIL = "fail"  # Detection did not trigger when it should
    SKIP = "skip"  # Test was skipped
    ERROR = "error"  # Error during test execution


@dataclass
class TestResult:
    """Result of testing a single detection rule."""

    rule_id: str
    rule_name: str
    outcome: TestOutcome
    scenario_id: str
    detection_result: DetectionResult | None = None
    events_generated: int = 0
    expected_triggered: bool = True
    actual_triggered: bool = False
    error_message: str | None = None
    execution_time_ms: float = 0.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "outcome": self.outcome.value,
            "scenario_id": self.scenario_id,
            "events_generated": self.events_generated,
            "expected_triggered": self.expected_triggered,
            "actual_triggered": self.actual_triggered,
            "error_message": self.error_message,
            "execution_time_ms": self.execution_time_ms,
            "timestamp": self.timestamp.isoformat(),
        }


class TestSuite(BaseModel):
    """A collection of test results for a test run."""

    suite_id: str = Field(default_factory=lambda: datetime.now(UTC).strftime("%Y%m%d_%H%M%S"))
    start_time: datetime = Field(default_factory=lambda: datetime.now(UTC))
    end_time: datetime | None = None
    results: list[dict[str, Any]] = Field(default_factory=list)
    scenarios_run: list[str] = Field(default_factory=list)
    rules_tested: list[str] = Field(default_factory=list)

    def add_result(self, result: TestResult) -> None:
        self.results.append(result.to_dict())

    def complete(self) -> None:
        self.end_time = datetime.now(UTC)

    @property
    def total_tests(self) -> int:
        return len(self.results)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r["outcome"] == "pass")

    @property
    def failed(self) -> int:
        return sum(1 for r in self.results if r["outcome"] == "fail")

    @property
    def errors(self) -> int:
        return sum(1 for r in self.results if r["outcome"] == "error")

    @property
    def pass_rate(self) -> float:
        if self.total_tests == 0:
            return 0.0
        return self.passed / self.total_tests * 100

    def summary(self) -> dict[str, Any]:
        return {
            "suite_id": self.suite_id,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "total_tests": self.total_tests,
            "passed": self.passed,
            "failed": self.failed,
            "errors": self.errors,
            "pass_rate": f"{self.pass_rate:.1f}%",
            "scenarios_run": self.scenarios_run,
            "rules_tested": self.rules_tested,
        }


class AdversaryTestRunner:
    """Runner for validating detection rules against adversary scenarios.

    This class provides methods to test detection rules using synthetic
    events generated from attack scenarios, verifying that detections
    trigger correctly.

    Example usage:
        # Setup
        runner = AdversaryTestRunner()

        # Test single rule against scenario
        result = runner.test_rule_against_scenario(
            rule=my_detection_rule,
            scenario=MITRE_SCENARIOS["root-account-compromise"],
        )

        # Run full test suite
        suite = runner.run_test_suite(
            rules=[rule1, rule2, rule3],
            scenarios=list(MITRE_SCENARIOS.values()),
        )
        print(suite.summary())
    """

    def __init__(
        self,
        event_generator: OCSFEventGenerator | None = None,
        network_emulator: NetworkEmulator | None = None,
        enable_network_tests: bool = False,
    ) -> None:
        """Initialize the test runner.

        Args:
            event_generator: Custom event generator (optional)
            network_emulator: Network emulator for live traffic tests (optional)
            enable_network_tests: Enable tests that generate real network traffic
        """
        self.event_generator = event_generator or OCSFEventGenerator()
        self.network_emulator = network_emulator if enable_network_tests else None
        self.scenario_runner = ScenarioRunner(
            event_generator=self.event_generator,
            network_emulator=self.network_emulator,
        )

    def generate_test_events(
        self,
        scenario: AttackScenario,
    ) -> tuple[list[SyntheticEvent], QueryResult]:
        """Generate synthetic events for a scenario.

        Returns:
            Tuple of (events list, DataFrame for detection testing)
        """
        result = self.scenario_runner.run_scenario(
            scenario,
            generate_network_traffic=self.network_emulator is not None,
        )
        events = result["events"]
        df = self.scenario_runner.events_to_dataframe(events)
        return events, df

    def test_rule_against_events(
        self,
        rule: DetectionRule,
        events_df: QueryResult,
    ) -> DetectionResult:
        """Test a detection rule against a DataFrame of events."""
        return rule.evaluate(events_df)

    def test_rule_against_scenario(
        self,
        rule: DetectionRule,
        scenario: AttackScenario,
        expect_triggered: bool | None = None,
    ) -> TestResult:
        """Test a single rule against an attack scenario.

        Args:
            rule: The detection rule to test
            scenario: The attack scenario to use
            expect_triggered: Override whether detection should trigger
                            (defaults to True if rule is in expected_detections)

        Returns:
            TestResult with outcome and details
        """
        start_time = datetime.now(UTC)

        # Determine expected outcome
        if expect_triggered is None:
            expect_triggered = rule.id in scenario.expected_detections

        try:
            # Generate events
            events, events_df = self.generate_test_events(scenario)

            if events_df.is_empty():
                return TestResult(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    outcome=TestOutcome.SKIP,
                    scenario_id=scenario.id,
                    events_generated=0,
                    expected_triggered=expect_triggered,
                    error_message="No events generated",
                    execution_time_ms=(datetime.now(UTC) - start_time).total_seconds() * 1000,
                )

            # Run detection
            detection_result = self.test_rule_against_events(rule, events_df)

            # Determine outcome
            actual_triggered = detection_result.triggered
            if (
                expect_triggered
                and actual_triggered
                or not expect_triggered
                and not actual_triggered
            ):
                outcome = TestOutcome.PASS
            else:
                outcome = TestOutcome.FAIL

            return TestResult(
                rule_id=rule.id,
                rule_name=rule.name,
                outcome=outcome,
                scenario_id=scenario.id,
                detection_result=detection_result,
                events_generated=len(events),
                expected_triggered=expect_triggered,
                actual_triggered=actual_triggered,
                execution_time_ms=(datetime.now(UTC) - start_time).total_seconds() * 1000,
            )

        except Exception as e:
            logger.exception(f"Error testing rule {rule.id} against {scenario.id}")
            return TestResult(
                rule_id=rule.id,
                rule_name=rule.name,
                outcome=TestOutcome.ERROR,
                scenario_id=scenario.id,
                expected_triggered=expect_triggered,
                error_message=str(e),
                execution_time_ms=(datetime.now(UTC) - start_time).total_seconds() * 1000,
            )

    def test_scenario_coverage(
        self,
        rules: list[DetectionRule],
        scenario: AttackScenario,
    ) -> dict[str, Any]:
        """Test which rules detect events from a scenario.

        Returns detailed coverage information for the scenario.
        """
        events, events_df = self.generate_test_events(scenario)

        detections_triggered = []
        detections_not_triggered = []

        for rule in rules:
            try:
                result = self.test_rule_against_events(rule, events_df)
                if result.triggered:
                    detections_triggered.append(
                        {
                            "rule_id": rule.id,
                            "rule_name": rule.name,
                            "match_count": result.match_count,
                        }
                    )
                else:
                    detections_not_triggered.append(
                        {
                            "rule_id": rule.id,
                            "rule_name": rule.name,
                        }
                    )
            except Exception as e:
                logger.warning(f"Error testing rule {rule.id}: {e}")

        # Calculate coverage
        expected_detections = set(scenario.expected_detections)
        triggered_ids = {d["rule_id"] for d in detections_triggered}
        coverage_hits = expected_detections & triggered_ids
        coverage_misses = expected_detections - triggered_ids

        return {
            "scenario_id": scenario.id,
            "scenario_name": scenario.name,
            "techniques": scenario.get_technique_ids(),
            "events_generated": len(events),
            "expected_detections": list(expected_detections),
            "detections_triggered": detections_triggered,
            "detections_not_triggered": detections_not_triggered,
            "coverage_hits": list(coverage_hits),
            "coverage_misses": list(coverage_misses),
            "coverage_rate": len(coverage_hits) / len(expected_detections) * 100
            if expected_detections
            else 100.0,
        }

    def run_test_suite(
        self,
        rules: list[DetectionRule],
        scenarios: list[AttackScenario],
        stop_on_failure: bool = False,
    ) -> TestSuite:
        """Run a complete test suite across multiple rules and scenarios.

        Args:
            rules: List of detection rules to test
            scenarios: List of attack scenarios to run
            stop_on_failure: Stop execution on first failure

        Returns:
            TestSuite with all results
        """
        suite = TestSuite()
        suite.scenarios_run = [s.id for s in scenarios]
        suite.rules_tested = [r.id for r in rules]

        for scenario in scenarios:
            logger.info(f"Running scenario: {scenario.name}")

            # Find rules expected to trigger for this scenario
            expected_rules = {r for r in rules if r.id in scenario.expected_detections}

            for rule in expected_rules:
                result = self.test_rule_against_scenario(
                    rule=rule,
                    scenario=scenario,
                    expect_triggered=True,
                )
                suite.add_result(result)

                if stop_on_failure and result.outcome == TestOutcome.FAIL:
                    logger.warning(f"Stopping on failure: {rule.id}")
                    suite.complete()
                    return suite

        suite.complete()
        return suite

    def generate_coverage_report(
        self,
        rules: list[DetectionRule],
        scenarios: list[AttackScenario],
    ) -> dict[str, Any]:
        """Generate a comprehensive coverage report.

        Analyzes which MITRE techniques are covered by the detection rules.
        """
        technique_coverage: dict[str, dict[str, Any]] = {}

        for scenario in scenarios:
            coverage = self.test_scenario_coverage(rules, scenario)

            for technique_id in scenario.get_technique_ids():
                if technique_id not in technique_coverage:
                    technique_coverage[technique_id] = {
                        "scenarios": [],
                        "detections": set(),
                        "covered": False,
                    }

                technique_coverage[technique_id]["scenarios"].append(scenario.id)

                if coverage["coverage_rate"] > 0:
                    technique_coverage[technique_id]["covered"] = True
                    technique_coverage[technique_id]["detections"].update(coverage["coverage_hits"])

        # Convert sets to lists for JSON serialization
        for tech_id in technique_coverage:
            technique_coverage[tech_id]["detections"] = list(
                technique_coverage[tech_id]["detections"]
            )

        covered_techniques = sum(1 for t in technique_coverage.values() if t["covered"])
        total_techniques = len(technique_coverage)

        return {
            "total_rules": len(rules),
            "total_scenarios": len(scenarios),
            "total_techniques": total_techniques,
            "covered_techniques": covered_techniques,
            "technique_coverage_rate": covered_techniques / total_techniques * 100
            if total_techniques
            else 0,
            "technique_details": technique_coverage,
        }


class LocalDetectionTester:
    """Helper class for testing detections locally without AWS.

    Provides a simplified interface for running detection rules
    against synthetic data without requiring actual Security Lake access.
    """

    def __init__(self) -> None:
        self.event_generator = OCSFEventGenerator()
        self.test_runner = AdversaryTestRunner(
            event_generator=self.event_generator,
        )

    def quick_test(
        self,
        rule: DetectionRule,
        event_type: str,
        **kwargs: Any,
    ) -> DetectionResult:
        """Quick test a rule against a single event type.

        Args:
            rule: Detection rule to test
            event_type: Type of event to generate (e.g., "root_login", "brute_force")
            **kwargs: Additional arguments for event generation

        Returns:
            DetectionResult from the rule evaluation
        """
        generators = {
            "root_login": self.event_generator.generate_root_login,
            "iam_policy_change": self.event_generator.generate_iam_policy_change,
            "security_group_change": self.event_generator.generate_security_group_change,
            "access_key_creation": self.event_generator.generate_access_key_creation,
            "brute_force": self.event_generator.generate_failed_login_attempts,
            "api_abuse": self.event_generator.generate_unusual_api_volume,
            "port_scan": self.event_generator.generate_port_scan,
            "dns_query": self.event_generator.generate_dns_query,
        }

        if event_type not in generators:
            raise ValueError(
                f"Unknown event type: {event_type}. Available: {list(generators.keys())}"
            )

        # Generate events
        result = generators[event_type](**kwargs)
        events = result if isinstance(result, list) else [result]

        # Convert to DataFrame
        df = self.event_generator.events_to_dataframe(events)  # type: ignore[arg-type]

        # Evaluate rule
        return rule.evaluate(df)

    def test_detection_coverage(
        self,
        rule: DetectionRule,
    ) -> dict[str, bool]:
        """Test a detection rule against all available event types.

        Returns a dict mapping event types to whether they triggered.
        """
        results = {}

        # Map of event types to detection patterns
        test_cases = {
            "root_login": {"count": 1},
            "iam_policy_change": {},
            "security_group_change": {},
            "access_key_creation": {},
            "brute_force": {"count": 10},
            "api_abuse": {"count": 150},
        }

        for event_type, kwargs in test_cases.items():
            try:
                result = self.quick_test(rule, event_type, **kwargs)
                results[event_type] = result.triggered
            except Exception as e:
                logger.warning(f"Failed to test {event_type}: {e}")
                results[event_type] = False

        return results
