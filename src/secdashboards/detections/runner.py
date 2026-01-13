"""Detection rule runner for executing rules against data sources."""

import importlib
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import structlog
import yaml

from secdashboards.catalog.registry import DataCatalog
from secdashboards.connectors.base import DataConnector
from secdashboards.detections.rule import (
    DetectionMetadata,
    DetectionResult,
    DetectionRule,
    Severity,
    SQLDetectionRule,
)

logger = structlog.get_logger()

# Environment variable to control Python rule loading
# Set SECDASH_ALLOW_PYTHON_RULES=1 to enable (NOT recommended in production)
ALLOW_PYTHON_RULES = os.environ.get("SECDASH_ALLOW_PYTHON_RULES", "").lower() in (
    "1",
    "true",
    "yes",
)


class DetectionRunner:
    """Runs detection rules against data sources.

    Security Notes:
    - By default, only YAML rules are loaded from filesystem
    - Python rule loading is disabled unless SECDASH_ALLOW_PYTHON_RULES=1
    - For production, use S3RuleStore for secure rule management
    """

    def __init__(
        self,
        catalog: DataCatalog,
        allow_python_rules: bool | None = None,
    ) -> None:
        """Initialize the detection runner.

        Args:
            catalog: Data catalog for source resolution
            allow_python_rules: Override env var for Python rules (None = use env)
        """
        self.catalog = catalog
        self._rules: dict[str, DetectionRule] = {}
        self._allow_python_rules = (
            allow_python_rules if allow_python_rules is not None else ALLOW_PYTHON_RULES
        )

        if self._allow_python_rules:
            logger.warning(
                "python_rules_enabled",
                message="Python rule loading is enabled. This allows arbitrary code execution.",
            )

    def register_rule(self, rule: DetectionRule) -> None:
        """Register a detection rule."""
        self._rules[rule.id] = rule
        logger.info("Registered detection rule", rule_id=rule.id, rule_name=rule.name)

    def get_rule(self, rule_id: str) -> DetectionRule | None:
        """Get a rule by ID."""
        return self._rules.get(rule_id)

    def list_rules(self, enabled_only: bool = True) -> list[DetectionRule]:
        """List all registered rules."""
        rules = list(self._rules.values())
        if enabled_only:
            rules = [r for r in rules if r.metadata.enabled]
        return rules

    def run_rule(
        self,
        rule_id: str,
        connector: DataConnector,
        start: datetime | None = None,
        end: datetime | None = None,
        lookback_minutes: int = 15,
    ) -> DetectionResult:
        """Run a single detection rule."""
        rule = self._rules.get(rule_id)
        if not rule:
            return DetectionResult(
                rule_id=rule_id,
                rule_name="Unknown",
                triggered=False,
                error=f"Rule not found: {rule_id}",
            )

        # Set time window
        end = end or datetime.now(UTC)
        start = start or (end - timedelta(minutes=lookback_minutes))

        try:
            # Get and execute query
            query = rule.get_query(start, end)
            logger.debug("Executing detection query", rule_id=rule_id, query=query[:200])

            df = connector.query(query)

            # Evaluate results
            result = rule.evaluate(df)
            logger.info(
                "Detection completed",
                rule_id=rule_id,
                triggered=result.triggered,
                match_count=result.match_count,
            )
            return result

        except Exception as e:
            logger.exception("Detection rule failed", rule_id=rule_id)
            return DetectionResult(
                rule_id=rule_id,
                rule_name=rule.name,
                triggered=False,
                error=str(e),
            )

    def run_all(
        self,
        connector: DataConnector,
        start: datetime | None = None,
        end: datetime | None = None,
        lookback_minutes: int = 15,
    ) -> list[DetectionResult]:
        """Run all enabled detection rules."""
        results = []
        for rule_id in self._rules:
            rule = self._rules[rule_id]
            if rule.metadata.enabled:
                result = self.run_rule(rule_id, connector, start, end, lookback_minutes)
                results.append(result)
        return results

    def load_rules_from_directory(self, rules_dir: Path) -> int:
        """Load detection rules from YAML files in a directory.

        Security Note: Python rules are only loaded if explicitly enabled
        via SECDASH_ALLOW_PYTHON_RULES=1 or allow_python_rules=True.
        """
        loaded = 0

        # Always load YAML rules (safe)
        for yaml_file in rules_dir.glob("*.yaml"):
            try:
                rules = self._load_yaml_rules(yaml_file)
                for rule in rules:
                    self.register_rule(rule)
                    loaded += 1
            except Exception as e:
                logger.exception(
                    "Failed to load rules from file", file=str(yaml_file), error=str(e)
                )

        # Only load Python rules if explicitly enabled
        if self._allow_python_rules:
            for py_file in rules_dir.glob("*.py"):
                if py_file.name.startswith("_"):
                    continue
                try:
                    rules = self._load_python_rules(py_file)
                    for rule in rules:
                        self.register_rule(rule)
                        loaded += 1
                except Exception as e:
                    logger.exception(
                        "Failed to load rules from file", file=str(py_file), error=str(e)
                    )
        else:
            # Log skipped Python files for visibility
            py_files = list(rules_dir.glob("*.py"))
            if py_files:
                logger.info(
                    "skipped_python_rules",
                    count=len(py_files),
                    message="Python rules disabled. Set SECDASH_ALLOW_PYTHON_RULES=1 to enable.",
                )

        return loaded

    def _load_yaml_rules(self, file_path: Path) -> list[DetectionRule]:
        """Load SQL-based detection rules from a YAML file."""
        with file_path.open() as f:
            data = yaml.safe_load(f)

        rules = []
        rule_defs = data if isinstance(data, list) else [data]

        for rule_def in rule_defs:
            metadata = DetectionMetadata(
                id=rule_def["id"],
                name=rule_def["name"],
                description=rule_def.get("description", ""),
                author=rule_def.get("author", ""),
                severity=Severity(rule_def.get("severity", "medium")),
                tags=rule_def.get("tags", []),
                mitre_attack=rule_def.get("mitre_attack", []),
                data_sources=rule_def.get("data_sources", []),
                schedule=rule_def.get("schedule", "rate(5 minutes)"),
                enabled=rule_def.get("enabled", True),
            )

            rule = SQLDetectionRule(
                metadata=metadata,
                query_template=rule_def["query"],
                threshold=rule_def.get("threshold", 1),
                group_by_fields=rule_def.get("group_by", []),
            )
            rules.append(rule)

        return rules

    def _load_python_rules(self, file_path: Path) -> list[DetectionRule]:
        """Load custom detection rules from a Python file."""
        # Add parent directory to path for imports
        sys.path.insert(0, str(file_path.parent))

        try:
            spec = importlib.util.spec_from_file_location(file_path.stem, file_path)
            if not spec or not spec.loader:
                return []

            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            # Find all DetectionRule subclasses in the module
            rules = []
            for name in dir(module):
                obj = getattr(module, name)
                if (
                    isinstance(obj, type)
                    and issubclass(obj, DetectionRule)
                    and obj is not DetectionRule
                    and obj is not SQLDetectionRule
                ):
                    # Check if there's a corresponding instance or factory
                    instance_name = name.lower().replace("rule", "") + "_rule"
                    if hasattr(module, instance_name):
                        rules.append(getattr(module, instance_name))

            # Also check for rule instances directly
            for name in dir(module):
                obj = getattr(module, name)
                if isinstance(obj, DetectionRule):
                    rules.append(obj)

            return rules

        finally:
            sys.path.pop(0)

    def export_rules_to_dict(self) -> list[dict[str, Any]]:
        """Export all rules to a list of dictionaries."""
        return [rule.to_dict() for rule in self._rules.values()]
