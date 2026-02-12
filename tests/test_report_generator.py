"""Tests for HTML report generator."""

from datetime import UTC, datetime

import pytest

from secdashboards.reports.models import (
    CodeBlock,
    Report,
    ReportSection,
    ReportType,
    TableData,
)
from secdashboards.web.report_generator import (
    render_health_report,
    render_report,
    save_report,
)


@pytest.fixture
def sample_report():
    return Report(
        report_type=ReportType.DETECTION,
        title="Test Detection Report",
        subtitle="Weekly summary",
        author="Test Suite",
        generated_at=datetime(2024, 6, 1, 12, 0, tzinfo=UTC),
        sections=[
            ReportSection(title="Overview", content="This is a test report."),
            ReportSection(title="Findings", content="No findings."),
        ],
        tables=[
            TableData(
                caption="Detection Results",
                headers=["Rule", "Triggered", "Matches"],
                rows=[
                    ["brute-force", "Yes", "12"],
                    ["data-exfil", "No", "0"],
                ],
            ),
        ],
        code_blocks=[
            CodeBlock(
                caption="Sample Query",
                code="SELECT * FROM events WHERE severity = 'critical'",
            ),
        ],
    )


@pytest.fixture
def health_data():
    return [
        {
            "source_name": "duckdb-local",
            "healthy": True,
            "record_count": 100,
            "latency_seconds": 0.005,
            "error": None,
        },
        {
            "source_name": "athena-prod",
            "healthy": False,
            "record_count": 0,
            "latency_seconds": 0,
            "error": "Connection timeout",
        },
    ]


class TestRenderReport:
    def test_returns_html(self, sample_report) -> None:
        html = render_report(sample_report)
        assert "<!DOCTYPE html>" in html
        assert "</html>" in html

    def test_contains_title(self, sample_report) -> None:
        html = render_report(sample_report)
        assert "Test Detection Report" in html

    def test_contains_subtitle(self, sample_report) -> None:
        html = render_report(sample_report)
        assert "Weekly summary" in html

    def test_contains_sections(self, sample_report) -> None:
        html = render_report(sample_report)
        assert "Overview" in html
        assert "This is a test report." in html

    def test_contains_table_data(self, sample_report) -> None:
        html = render_report(sample_report)
        assert "brute-force" in html
        assert "data-exfil" in html

    def test_contains_code_block(self, sample_report) -> None:
        html = render_report(sample_report)
        assert "Sample Query" in html
        assert "SELECT * FROM events" in html

    def test_contains_table_caption(self, sample_report) -> None:
        html = render_report(sample_report)
        assert "Detection Results" in html

    def test_self_contained_css(self, sample_report) -> None:
        html = render_report(sample_report)
        assert "<style>" in html
        # No external stylesheet links
        assert 'rel="stylesheet"' not in html

    def test_contains_metadata(self, sample_report) -> None:
        html = render_report(sample_report)
        assert "2024-06-01" in html
        assert "Test Suite" in html


class TestRenderHealthReport:
    def test_returns_html(self, health_data) -> None:
        html = render_health_report(health_data)
        assert "<!DOCTYPE html>" in html

    def test_contains_sources(self, health_data) -> None:
        html = render_health_report(health_data)
        assert "duckdb-local" in html
        assert "athena-prod" in html

    def test_shows_status(self, health_data) -> None:
        html = render_health_report(health_data)
        assert "OK" in html
        assert "FAIL" in html

    def test_shows_error(self, health_data) -> None:
        html = render_health_report(health_data)
        assert "Connection timeout" in html

    def test_summary_counts(self, health_data) -> None:
        html = render_health_report(health_data)
        # 1 healthy, 1 unhealthy, 2 total
        assert ">1<" in html  # healthy count
        assert ">2<" in html  # total count


class TestSaveReport:
    def test_save_to_file(self, tmp_path, sample_report) -> None:
        html = render_report(sample_report)
        out = tmp_path / "report.html"
        result = save_report(html, out)
        assert result == out
        assert out.exists()
        assert "Test Detection Report" in out.read_text()

    def test_creates_parent_dirs(self, tmp_path, sample_report) -> None:
        html = render_report(sample_report)
        out = tmp_path / "nested" / "dir" / "report.html"
        save_report(html, out)
        assert out.exists()
