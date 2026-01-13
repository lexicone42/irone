"""Health monitoring for data sources and detections."""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import structlog

from secdashboards.catalog.registry import DataCatalog
from secdashboards.connectors.base import HealthCheckResult
from secdashboards.detections.runner import DetectionRunner

logger = structlog.get_logger()


@dataclass
class HealthReport:
    """Comprehensive health report for data sources and detections."""

    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    source_health: list[HealthCheckResult] = field(default_factory=list)
    detection_status: list[dict[str, Any]] = field(default_factory=list)
    overall_healthy: bool = True
    issues: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "generated_at": self.generated_at.isoformat(),
            "overall_healthy": self.overall_healthy,
            "issues": self.issues,
            "source_health": [h.to_dict() for h in self.source_health],
            "detection_status": self.detection_status,
            "summary": {
                "total_sources": len(self.source_health),
                "healthy_sources": sum(1 for h in self.source_health if h.healthy),
                "unhealthy_sources": sum(1 for h in self.source_health if not h.healthy),
                "total_detections": len(self.detection_status),
            },
        }

    def add_issue(self, issue: str) -> None:
        """Add an issue and mark report as unhealthy."""
        self.issues.append(issue)
        self.overall_healthy = False


class HealthMonitor:
    """Monitors health of data sources and detection rules."""

    def __init__(self, catalog: DataCatalog, runner: DetectionRunner | None = None) -> None:
        self.catalog = catalog
        self.runner = runner

    def check_source(self, source_name: str) -> HealthCheckResult:
        """Check health of a single data source."""
        try:
            connector = self.catalog.get_connector(source_name)
            return connector.check_health()
        except Exception as e:
            logger.exception("Failed to check source health", source=source_name)
            return HealthCheckResult(
                source_name=source_name,
                healthy=False,
                error=str(e),
            )

    def check_all_sources(self) -> list[HealthCheckResult]:
        """Check health of all registered data sources."""
        results = []
        for source in self.catalog.list_sources():
            result = self.check_source(source.name)
            results.append(result)
        return results

    def check_detection_health(self) -> list[dict[str, Any]]:
        """Check that detections are configured correctly."""
        if not self.runner:
            return []

        status = []
        for rule in self.runner.list_rules(enabled_only=False):
            rule_status: dict[str, Any] = {
                "rule_id": rule.id,
                "rule_name": rule.name,
                "enabled": rule.metadata.enabled,
                "severity": rule.metadata.severity,
                "schedule": rule.metadata.schedule,
                "data_sources": rule.metadata.data_sources,
                "issues": [],
            }

            # Check if required data sources exist
            for ds_name in rule.metadata.data_sources:
                if not self.catalog.get_source(ds_name):
                    rule_status["issues"].append(f"Data source not found: {ds_name}")

            rule_status["healthy"] = len(rule_status["issues"]) == 0
            status.append(rule_status)

        return status

    def generate_report(self) -> HealthReport:
        """Generate a comprehensive health report."""
        report = HealthReport()

        # Check data sources
        logger.info("Checking data source health...")
        report.source_health = self.check_all_sources()

        for health in report.source_health:
            if not health.healthy:
                if health.error:
                    report.add_issue(f"Source '{health.source_name}' error: {health.error}")
                elif health.data_age_minutes:
                    source = self.catalog.get_source(health.source_name)
                    expected = source.expected_freshness_minutes if source else 60
                    report.add_issue(
                        f"Source '{health.source_name}' data is stale "
                        f"({health.data_age_minutes:.0f} min old, expected < {expected} min)"
                    )
                else:
                    report.add_issue(f"Source '{health.source_name}' is unhealthy")

        # Check detections
        if self.runner:
            logger.info("Checking detection health...")
            report.detection_status = self.check_detection_health()

            for status in report.detection_status:
                for issue in status.get("issues", []):
                    report.add_issue(f"Detection '{status['rule_name']}': {issue}")

        logger.info(
            "Health report generated",
            overall_healthy=report.overall_healthy,
            issue_count=len(report.issues),
        )

        return report

    def get_freshness_summary(self) -> dict[str, Any]:
        """Get a summary of data freshness across all sources."""
        summary: dict[str, Any] = {
            "checked_at": datetime.now(UTC).isoformat(),
            "sources": {},
        }

        for source in self.catalog.list_sources():
            try:
                connector = self.catalog.get_connector(source.name)
                health = connector.check_health()

                last_data = (
                    health.last_data_time.isoformat() if health.last_data_time else None
                )
                summary["sources"][source.name] = {
                    "healthy": health.healthy,
                    "last_data_time": last_data,
                    "data_age_minutes": health.data_age_minutes,
                    "expected_freshness_minutes": source.expected_freshness_minutes,
                    "record_count_last_hour": health.record_count,
                }
            except Exception as e:
                summary["sources"][source.name] = {
                    "healthy": False,
                    "error": str(e),
                }

        return summary
