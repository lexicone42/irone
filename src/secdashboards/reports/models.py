"""Report data models for LaTeX export."""

from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class ReportType(StrEnum):
    """Types of reports that can be generated."""

    INVESTIGATION = "investigation"
    DETECTION = "detection"
    EXECUTIVE_SUMMARY = "executive_summary"


class ReportSection(BaseModel):
    """Base class for report sections."""

    title: str
    content: str = ""
    subsections: list["ReportSection"] = Field(default_factory=list)


class TableData(BaseModel):
    """Tabular data for LaTeX tables."""

    headers: list[str]
    rows: list[list[str]]
    caption: str = ""
    label: str = ""
    column_alignments: str = ""  # e.g., "l|c|r" for left, center, right

    def __len__(self) -> int:
        return len(self.rows)


class CodeBlock(BaseModel):
    """Code block for syntax-highlighted content."""

    code: str
    language: str = "sql"
    caption: str = ""
    label: str = ""


class Figure(BaseModel):
    """Figure/image reference for the report."""

    path: Path | str
    caption: str = ""
    label: str = ""
    width: str = "0.8\\textwidth"


class EntitySummary(BaseModel):
    """Summary of entities in an investigation graph."""

    entity_type: str
    count: int
    examples: list[str] = Field(default_factory=list, max_length=5)


class DetectionResultSummary(BaseModel):
    """Summary of a detection rule execution."""

    rule_id: str
    rule_name: str
    severity: str
    triggered: bool
    match_count: int
    sample_matches: list[dict[str, Any]] = Field(default_factory=list)
    query: str = ""


class InvestigationReportData(BaseModel):
    """Data model for investigation reports."""

    title: str = "Security Investigation Report"
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    investigation_id: str = ""

    # Executive summary
    executive_summary: str = ""

    # Graph data
    entity_summaries: list[EntitySummary] = Field(default_factory=list)
    total_nodes: int = 0
    total_edges: int = 0

    # Entity details
    principals: list[dict[str, Any]] = Field(default_factory=list)
    ip_addresses: list[dict[str, Any]] = Field(default_factory=list)
    resources: list[dict[str, Any]] = Field(default_factory=list)
    api_operations: list[dict[str, Any]] = Field(default_factory=list)
    findings: list[dict[str, Any]] = Field(default_factory=list)

    # AI analysis
    ai_analysis: str = ""

    # Graph visualization
    graph_image_path: Path | str | None = None

    # Metadata
    time_range_start: datetime | None = None
    time_range_end: datetime | None = None
    data_sources: list[str] = Field(default_factory=list)


class DetectionReportData(BaseModel):
    """Data model for detection engineering reports."""

    title: str = "Detection Engineering Report"
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    # Detection rules
    detection_results: list[DetectionResultSummary] = Field(default_factory=list)

    # Coverage metrics
    total_rules: int = 0
    rules_triggered: int = 0
    rules_by_severity: dict[str, int] = Field(default_factory=dict)
    mitre_coverage: list[str] = Field(default_factory=list)

    # AI-generated rules
    ai_suggested_rules: list[dict[str, Any]] = Field(default_factory=list)

    # Test summary
    test_summary: str = ""


class Report(BaseModel):
    """Complete report ready for rendering."""

    report_type: ReportType
    title: str
    subtitle: str = ""
    author: str = "SecDashboards"
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    sections: list[ReportSection] = Field(default_factory=list)
    tables: list[TableData] = Field(default_factory=list)
    figures: list[Figure] = Field(default_factory=list)
    code_blocks: list[CodeBlock] = Field(default_factory=list)

    # Raw data for template rendering
    data: InvestigationReportData | DetectionReportData | None = None
