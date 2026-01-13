"""Tests for report generation with sample data.

These tests generate sample reports and verify:
1. LaTeX content is generated correctly
2. PDF compilation works (if pdflatex available)
3. Report structure is valid

Run with:
    uv run pytest tests/test_report_generation.py -v

To generate PDF samples for visual inspection:
    uv run python scripts/generate_sample_reports.py
"""

import os
import tempfile
from datetime import datetime, UTC
from pathlib import Path

import pytest

from secdashboards.graph import (
    APIOperationNode,
    EdgeType,
    GraphEdge,
    IPAddressNode,
    NodeType,
    PrincipalNode,
    ResourceNode,
    SecurityFindingNode,
    SecurityGraph,
)
from secdashboards.reports import (
    LaTeXRenderer,
    compile_latex_to_pdf,
    detection_results_to_report_data,
    graph_to_report_data,
)


@pytest.fixture
def sample_graph() -> SecurityGraph:
    """Create a sample investigation graph."""
    graph = SecurityGraph()

    # Add principals
    principal = PrincipalNode(
        id=PrincipalNode.create_id("test-user"),
        label="test-user",
        user_name="test-user",
        user_type="IAMUser",
        event_count=50,
    )
    graph.add_node(principal)

    # Add IP
    ip_node = IPAddressNode(
        id=IPAddressNode.create_id("10.0.0.1"),
        label="10.0.0.1",
        ip_address="10.0.0.1",
        is_internal=True,
        event_count=25,
    )
    graph.add_node(ip_node)

    # Add API operation
    api_node = APIOperationNode(
        id=APIOperationNode.create_id("s3", "GetObject"),
        label="s3:GetObject",
        service="s3",
        operation="GetObject",
        success_count=100,
        failure_count=5,
        event_count=105,
    )
    graph.add_node(api_node)

    # Add resource
    resource = ResourceNode(
        id=ResourceNode.create_id("s3", "test-bucket"),
        label="test-bucket",
        resource_type="s3",
        resource_id="test-bucket",
        event_count=105,
    )
    graph.add_node(resource)

    # Add finding
    triggered_time = datetime.now(UTC)
    finding = SecurityFindingNode(
        id=SecurityFindingNode.create_id("test-rule", triggered_time),
        label="Test Detection",
        rule_id="test-rule",
        rule_name="Test Detection",
        severity="high",
        triggered_at=triggered_time,
        match_count=10,
        event_count=10,
    )
    graph.add_node(finding)

    # Add edges
    edges = [
        (principal.id, ip_node.id, EdgeType.AUTHENTICATED_FROM),
        (principal.id, api_node.id, EdgeType.CALLED_API),
        (api_node.id, resource.id, EdgeType.TARGETED),
        (finding.id, principal.id, EdgeType.RELATED_TO),
    ]
    for source, target, edge_type in edges:
        edge = GraphEdge(
            id=GraphEdge.create_id(edge_type, source, target),
            edge_type=edge_type,
            source_id=source,
            target_id=target,
        )
        graph.add_edge(edge)

    return graph


@pytest.fixture
def sample_detection_results() -> list[dict]:
    """Create sample detection results."""
    return [
        {
            "rule_id": "test-rule-1",
            "rule_name": "Test Rule 1 - Critical Finding",
            "severity": "critical",
            "triggered": True,
            "match_count": 5,
            "query": "SELECT * FROM cloudtrail WHERE status = 'Failure'",
            "sample_matches": [{"user": "admin", "action": "DeleteBucket"}],
        },
        {
            "rule_id": "test-rule-2",
            "rule_name": "Test Rule 2 - High Severity",
            "severity": "high",
            "triggered": True,
            "match_count": 25,
            "query": "SELECT * FROM cloudtrail WHERE api.operation = 'CreateAccessKey'",
        },
        {
            "rule_id": "test-rule-3",
            "rule_name": "Test Rule 3 - No Matches",
            "severity": "medium",
            "triggered": False,
            "match_count": 0,
            "query": "SELECT * FROM cloudtrail WHERE something = 'rare'",
        },
    ]


class TestInvestigationReport:
    """Test investigation report generation."""

    def test_graph_to_report_data(self, sample_graph: SecurityGraph) -> None:
        """Test converting graph to report data."""
        report_data = graph_to_report_data(
            graph=sample_graph,
            investigation_id="TEST-001",
            ai_analysis="This is a test analysis.",
        )

        assert report_data.investigation_id == "TEST-001"
        assert report_data.total_nodes == sample_graph.node_count()
        assert report_data.total_edges == sample_graph.edge_count()
        assert len(report_data.entity_summaries) > 0
        assert report_data.ai_analysis == "This is a test analysis."

    def test_render_investigation_report_latex(self, sample_graph: SecurityGraph) -> None:
        """Test rendering investigation report to LaTeX."""
        report_data = graph_to_report_data(graph=sample_graph)
        report_data.title = "Test Investigation Report"

        renderer = LaTeXRenderer()
        latex = renderer.render_investigation_report(report_data)

        # Verify LaTeX structure
        assert r"\documentclass" in latex
        assert r"\begin{document}" in latex
        assert r"\end{document}" in latex
        assert "Test Investigation Report" in latex
        assert "Executive Summary" in latex
        assert "Investigation Graph Overview" in latex

    def test_investigation_report_escapes_special_chars(self, sample_graph: SecurityGraph) -> None:
        """Test that special characters are properly escaped."""
        report_data = graph_to_report_data(
            graph=sample_graph,
            ai_analysis="Special chars: $100 & 50% of users use _ underscores #hashtag",
        )

        renderer = LaTeXRenderer()
        latex = renderer.render_investigation_report(report_data)

        # These chars should be escaped
        assert r"\$" in latex or "$100" not in latex  # Dollar escaped
        assert r"\&" in latex  # Ampersand escaped
        assert r"\%" in latex  # Percent escaped


class TestDetectionReport:
    """Test detection report generation."""

    def test_detection_results_to_report_data(
        self, sample_detection_results: list[dict]
    ) -> None:
        """Test converting detection results to report data."""
        report_data = detection_results_to_report_data(
            results=sample_detection_results,
            mitre_techniques=["T1078", "T1530"],
            test_summary="Test summary",
        )

        assert report_data.total_rules == 3
        assert report_data.rules_triggered == 2
        assert len(report_data.mitre_coverage) == 2
        assert report_data.test_summary == "Test summary"

    def test_render_detection_report_latex(
        self, sample_detection_results: list[dict]
    ) -> None:
        """Test rendering detection report to LaTeX."""
        report_data = detection_results_to_report_data(results=sample_detection_results)
        report_data.title = "Test Detection Report"

        renderer = LaTeXRenderer()
        latex = renderer.render_detection_report(report_data)

        # Verify LaTeX structure
        assert r"\documentclass" in latex
        assert r"\begin{document}" in latex
        assert r"\end{document}" in latex
        assert "Test Detection Report" in latex
        assert "Detection Results Overview" in latex
        assert "test-rule-1" in latex
        assert "test-rule-2" in latex

    def test_detection_report_severity_colors(
        self, sample_detection_results: list[dict]
    ) -> None:
        """Test that severity levels have proper colors."""
        report_data = detection_results_to_report_data(results=sample_detection_results)

        renderer = LaTeXRenderer()
        latex = renderer.render_detection_report(report_data)

        # Check severity commands are used
        assert r"\severitycritical" in latex
        assert r"\severityhigh" in latex
        assert r"\severitymedium" in latex


class TestPDFCompilation:
    """Test PDF compilation (skipped if pdflatex not available)."""

    @pytest.fixture
    def check_pdflatex(self) -> bool:
        """Check if pdflatex is available."""
        import shutil

        return shutil.which("pdflatex") is not None

    def test_compile_simple_latex(self, check_pdflatex: bool) -> None:
        """Test compiling simple LaTeX to PDF."""
        if not check_pdflatex:
            pytest.skip("pdflatex not available")

        latex_content = r"""
\documentclass{article}
\begin{document}
Hello World
\end{document}
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "test.pdf"
            result = compile_latex_to_pdf(latex_content, output_path)

            assert result is not None
            assert result.exists()
            assert result.stat().st_size > 0

    def test_compile_investigation_report(
        self, sample_graph: SecurityGraph, check_pdflatex: bool
    ) -> None:
        """Test compiling investigation report to PDF."""
        if not check_pdflatex:
            pytest.skip("pdflatex not available")

        report_data = graph_to_report_data(graph=sample_graph)
        renderer = LaTeXRenderer()
        latex = renderer.render_investigation_report(report_data)

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "investigation.pdf"
            result = compile_latex_to_pdf(latex, output_path)

            assert result is not None
            assert result.exists()
            assert result.stat().st_size > 1000  # Should be a real PDF

    def test_compile_detection_report(
        self, sample_detection_results: list[dict], check_pdflatex: bool
    ) -> None:
        """Test compiling detection report to PDF."""
        if not check_pdflatex:
            pytest.skip("pdflatex not available")

        report_data = detection_results_to_report_data(results=sample_detection_results)
        renderer = LaTeXRenderer()
        latex = renderer.render_detection_report(report_data)

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "detection.pdf"
            result = compile_latex_to_pdf(latex, output_path)

            assert result is not None
            assert result.exists()
            assert result.stat().st_size > 1000  # Should be a real PDF


class TestReportContent:
    """Test report content validation."""

    def test_investigation_report_has_all_sections(
        self, sample_graph: SecurityGraph
    ) -> None:
        """Test that investigation report has all required sections."""
        report_data = graph_to_report_data(graph=sample_graph)
        renderer = LaTeXRenderer()
        latex = renderer.render_investigation_report(report_data)

        required_sections = [
            "Executive Summary",
            "Investigation Graph Overview",
            "Detailed Findings",
            "Appendix",
        ]

        for section in required_sections:
            assert section in latex, f"Missing section: {section}"

    def test_detection_report_has_all_sections(
        self, sample_detection_results: list[dict]
    ) -> None:
        """Test that detection report has all required sections."""
        report_data = detection_results_to_report_data(
            results=sample_detection_results,
            mitre_techniques=["T1078"],
        )
        renderer = LaTeXRenderer()
        latex = renderer.render_detection_report(report_data)

        required_sections = [
            "Executive Summary",
            "Detection Results Overview",
            "Detailed Detection Results",
            "MITRE ATT&CK Coverage",
            "Appendix",
        ]

        for section in required_sections:
            # Handle LaTeX escaping of &
            escaped_section = section.replace("&", r"\&")
            assert (
                section in latex or escaped_section in latex
            ), f"Missing section: {section}"

    def test_report_metadata_included(self, sample_graph: SecurityGraph) -> None:
        """Test that report metadata is included."""
        report_data = graph_to_report_data(
            graph=sample_graph,
            investigation_id="META-TEST-001",
        )
        renderer = LaTeXRenderer()
        latex = renderer.render_investigation_report(report_data)

        assert "META-TEST-001" in latex
        assert "Generated by SecDashboards" in latex
