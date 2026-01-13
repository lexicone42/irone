"""Tests for the LaTeX report generation module."""

from datetime import datetime
from pathlib import Path

import pytest

from secdashboards.reports import (
    CodeBlock,
    DetectionReportData,
    DetectionResultSummary,
    EntitySummary,
    Figure,
    InvestigationReportData,
    LaTeXRenderer,
    Report,
    ReportSection,
    ReportType,
    TableData,
    escape_latex,
    escape_latex_url,
    format_code_block,
    format_figure,
    format_table,
)


class TestEscapeLatex:
    """Tests for LaTeX escaping utilities."""

    def test_escape_special_characters(self) -> None:
        """Test escaping of LaTeX special characters."""
        assert escape_latex("&") == r"\&"
        assert escape_latex("%") == r"\%"
        assert escape_latex("$") == r"\$"
        assert escape_latex("#") == r"\#"
        assert escape_latex("_") == r"\_"
        assert escape_latex("{") == r"\{"
        assert escape_latex("}") == r"\}"

    def test_escape_multiple_characters(self) -> None:
        """Test escaping string with multiple special characters."""
        text = "Price: $100 & 50% off"
        expected = r"Price: \$100 \& 50\% off"
        assert escape_latex(text) == expected

    def test_escape_none(self) -> None:
        """Test escaping None returns empty string."""
        assert escape_latex(None) == ""

    def test_escape_non_string(self) -> None:
        """Test escaping non-string values."""
        assert escape_latex(123) == "123"
        assert escape_latex(12.5) == "12.5"

    def test_escape_preserves_normal_text(self) -> None:
        """Test that normal text is preserved."""
        text = "Normal text without special chars"
        assert escape_latex(text) == text

    def test_escape_tilde_and_caret(self) -> None:
        """Test escaping tilde and caret."""
        assert escape_latex("~") == r"\textasciitilde{}"
        assert escape_latex("^") == r"\textasciicircum{}"

    def test_escape_backslash(self) -> None:
        """Test escaping backslash."""
        assert escape_latex("\\") == r"\textbackslash{}"


class TestEscapeLatexUrl:
    """Tests for URL escaping."""

    def test_escape_url_preserves_structure(self) -> None:
        """Test that URL structure is preserved."""
        url = "https://example.com/path?query=value"
        escaped = escape_latex_url(url)
        assert "https://example.com/path?query=value" in escaped

    def test_escape_url_special_chars(self) -> None:
        """Test escaping URL special characters."""
        url = "https://example.com/search?q=foo%20bar&sort=asc#section"
        escaped = escape_latex_url(url)
        assert r"\%" in escaped
        assert r"\&" in escaped
        assert r"\#" in escaped


class TestTableData:
    """Tests for TableData model."""

    def test_create_table(self) -> None:
        """Test creating a table data object."""
        table = TableData(
            headers=["Name", "Value"],
            rows=[["foo", "bar"], ["baz", "qux"]],
            caption="Test table",
        )
        assert len(table) == 2
        assert table.headers == ["Name", "Value"]

    def test_empty_table(self) -> None:
        """Test empty table."""
        table = TableData(headers=[], rows=[])
        assert len(table) == 0


class TestFormatTable:
    """Tests for table formatting."""

    def test_format_basic_table(self) -> None:
        """Test formatting a basic table."""
        table = TableData(
            headers=["Col1", "Col2"],
            rows=[["a", "b"], ["c", "d"]],
        )
        latex = format_table(table)
        assert r"\begin{longtable}" in latex
        assert r"\end{longtable}" in latex
        assert "Col1" in latex
        assert "Col2" in latex

    def test_format_table_escapes_content(self) -> None:
        """Test that table content is escaped."""
        table = TableData(
            headers=["Name & Value"],
            rows=[["$100"]],
        )
        latex = format_table(table)
        assert r"Name \& Value" in latex
        assert r"\$100" in latex

    def test_format_empty_table(self) -> None:
        """Test formatting empty table returns empty string."""
        table = TableData(headers=[], rows=[])
        assert format_table(table) == ""

    def test_format_table_with_caption(self) -> None:
        """Test table with caption."""
        table = TableData(
            headers=["A"],
            rows=[["1"]],
            caption="My caption",
            label="tab:test",
        )
        latex = format_table(table)
        assert r"\caption{My caption}" in latex
        assert r"\label{tab:test}" in latex


class TestCodeBlock:
    """Tests for code block model and formatting."""

    def test_create_code_block(self) -> None:
        """Test creating a code block."""
        code = CodeBlock(
            code="SELECT * FROM users",
            language="sql",
            caption="User query",
        )
        assert code.code == "SELECT * FROM users"
        assert code.language == "sql"

    def test_format_code_block(self) -> None:
        """Test formatting code block."""
        code = CodeBlock(
            code="SELECT * FROM table",
            language="sql",
        )
        latex = format_code_block(code)
        assert r"\begin{lstlisting}[language=sql]" in latex
        assert "SELECT * FROM table" in latex
        assert r"\end{lstlisting}" in latex

    def test_format_code_block_with_caption(self) -> None:
        """Test code block with caption."""
        code = CodeBlock(
            code="SELECT 1",
            caption="Test query",
            label="lst:test",
        )
        latex = format_code_block(code)
        assert "caption={Test query}" in latex
        assert "label=lst:test" in latex


class TestFigure:
    """Tests for figure model and formatting."""

    def test_create_figure(self) -> None:
        """Test creating a figure."""
        fig = Figure(
            path="images/graph.png",
            caption="Investigation graph",
            label="fig:graph",
        )
        assert str(fig.path) == "images/graph.png"

    def test_format_figure(self) -> None:
        """Test formatting figure."""
        fig = Figure(
            path="graph.png",
            caption="My graph",
        )
        latex = format_figure(fig)
        assert r"\begin{figure}[htbp]" in latex
        assert r"\includegraphics" in latex
        assert "graph.png" in latex
        assert r"\caption{My graph}" in latex
        assert r"\end{figure}" in latex


class TestReportModels:
    """Tests for report data models."""

    def test_entity_summary(self) -> None:
        """Test EntitySummary model."""
        summary = EntitySummary(
            entity_type="Principal",
            count=5,
            examples=["user1", "user2", "user3"],
        )
        assert summary.entity_type == "Principal"
        assert summary.count == 5
        assert len(summary.examples) == 3

    def test_detection_result_summary(self) -> None:
        """Test DetectionResultSummary model."""
        result = DetectionResultSummary(
            rule_id="high-api-calls",
            rule_name="High API Call Volume",
            severity="high",
            triggered=True,
            match_count=42,
        )
        assert result.triggered is True
        assert result.match_count == 42

    def test_investigation_report_data(self) -> None:
        """Test InvestigationReportData model."""
        data = InvestigationReportData(
            title="Test Investigation",
            investigation_id="INV-001",
            total_nodes=10,
            total_edges=25,
            executive_summary="Summary here",
        )
        assert data.title == "Test Investigation"
        assert data.total_nodes == 10
        assert isinstance(data.generated_at, datetime)

    def test_detection_report_data(self) -> None:
        """Test DetectionReportData model."""
        data = DetectionReportData(
            total_rules=5,
            rules_triggered=2,
            rules_by_severity={"high": 1, "medium": 1},
        )
        assert data.total_rules == 5
        assert data.rules_triggered == 2

    def test_report_section(self) -> None:
        """Test ReportSection model."""
        section = ReportSection(
            title="Introduction",
            content="This is the intro.",
            subsections=[
                ReportSection(title="Background", content="Background info"),
            ],
        )
        assert section.title == "Introduction"
        assert len(section.subsections) == 1

    def test_report_model(self) -> None:
        """Test Report model."""
        report = Report(
            report_type=ReportType.INVESTIGATION,
            title="Security Report",
            author="Test Author",
        )
        assert report.report_type == ReportType.INVESTIGATION
        assert report.author == "Test Author"


class TestLaTeXRenderer:
    """Tests for LaTeX renderer."""

    @pytest.fixture
    def renderer(self) -> LaTeXRenderer:
        """Create a renderer instance."""
        return LaTeXRenderer()

    def test_renderer_initialization(self, renderer: LaTeXRenderer) -> None:
        """Test renderer initializes correctly."""
        assert renderer.template_dir.exists()
        assert renderer.env is not None

    def test_render_investigation_report(self, renderer: LaTeXRenderer) -> None:
        """Test rendering an investigation report."""
        data = InvestigationReportData(
            title="Test Investigation",
            investigation_id="INV-001",
            executive_summary="Executive summary text here.",
            total_nodes=15,
            total_edges=42,
            entity_summaries=[
                EntitySummary(entity_type="Principal", count=5, examples=["user1"]),
                EntitySummary(entity_type="IPAddress", count=10, examples=["1.2.3.4"]),
            ],
            principals=[{"user_name": "admin", "user_type": "IAMUser"}],
            ai_analysis="AI analysis findings here.",
        )

        latex = renderer.render_investigation_report(data)

        # Check document structure
        assert r"\documentclass" in latex
        assert r"\begin{document}" in latex
        assert r"\end{document}" in latex

        # Check content
        assert "Test Investigation" in latex or "Security Investigation Report" in latex
        assert "INV-001" in latex
        assert "15" in latex  # total_nodes
        assert "42" in latex  # total_edges
        assert "Principal" in latex
        assert "IPAddress" in latex
        assert "AI analysis findings here" in latex

    def test_render_detection_report(self, renderer: LaTeXRenderer) -> None:
        """Test rendering a detection report."""
        data = DetectionReportData(
            total_rules=3,
            rules_triggered=1,
            rules_by_severity={"high": 1, "medium": 2},
            detection_results=[
                DetectionResultSummary(
                    rule_id="test-rule",
                    rule_name="Test Rule",
                    severity="high",
                    triggered=True,
                    match_count=5,
                    query="SELECT * FROM events",
                ),
            ],
            mitre_coverage=["T1078", "T1110"],
        )

        latex = renderer.render_detection_report(data)

        # Check document structure
        assert r"\documentclass" in latex
        assert r"\begin{document}" in latex

        # Check content
        assert "Detection" in latex
        assert "test-rule" in latex
        assert "Test Rule" in latex
        assert "T1078" in latex
        assert "SELECT * FROM events" in latex

    def test_render_to_file(self, renderer: LaTeXRenderer, tmp_path: Path) -> None:
        """Test rendering report to file."""
        data = InvestigationReportData(
            title="File Test",
            total_nodes=1,
            total_edges=1,
        )

        report = Report(
            report_type=ReportType.INVESTIGATION,
            title="File Test",
            data=data,
        )

        output_path = tmp_path / "output" / "test_report.tex"
        result_path = renderer.render_to_file(report, output_path)

        assert result_path.exists()
        content = result_path.read_text()
        assert r"\documentclass" in content

    def test_custom_jinja_delimiters(self, renderer: LaTeXRenderer) -> None:
        """Test that custom Jinja delimiters work for LaTeX."""
        # The renderer should use \VAR{} and \BLOCK{} instead of {{ }} and {% %}
        # to avoid conflicts with LaTeX syntax
        assert renderer.env.variable_start_string == r"\VAR{"
        assert renderer.env.variable_end_string == "}"
        assert renderer.env.block_start_string == r"\BLOCK{"
        assert renderer.env.block_end_string == "}"

    def test_escape_latex_filter_registered(self, renderer: LaTeXRenderer) -> None:
        """Test that escape_latex filter is registered."""
        assert "escape_latex" in renderer.env.filters


class TestReportTypes:
    """Tests for report type enumeration."""

    def test_report_types(self) -> None:
        """Test report type values."""
        assert ReportType.INVESTIGATION == "investigation"
        assert ReportType.DETECTION == "detection"
        assert ReportType.EXECUTIVE_SUMMARY == "executive_summary"


class TestExporters:
    """Tests for high-level export functions."""

    @pytest.fixture
    def sample_graph(self):
        """Create a sample SecurityGraph for testing."""
        from secdashboards.graph import SecurityGraph
        from secdashboards.graph.models import EdgeType, GraphEdge, GraphNode, NodeType

        graph = SecurityGraph()

        # Add sample nodes
        graph.add_node(
            GraphNode(
                id="Principal:admin",
                node_type=NodeType.PRINCIPAL,
                label="admin",
                properties={"user_name": "admin", "user_type": "IAMUser"},
            )
        )
        graph.add_node(
            GraphNode(
                id="IPAddress:10.0.0.1",
                node_type=NodeType.IP_ADDRESS,
                label="10.0.0.1",
                properties={"ip_address": "10.0.0.1", "is_internal": True},
            )
        )
        graph.add_node(
            GraphNode(
                id="APIOperation:s3:GetObject",
                node_type=NodeType.API_OPERATION,
                label="s3:GetObject",
                properties={"service": "s3", "operation": "GetObject"},
            )
        )

        # Add sample edge
        graph.add_edge(
            GraphEdge(
                id=GraphEdge.create_id(
                    EdgeType.CALLED_API,
                    "Principal:admin",
                    "APIOperation:s3:GetObject",
                ),
                source_id="Principal:admin",
                target_id="APIOperation:s3:GetObject",
                edge_type=EdgeType.CALLED_API,
            )
        )

        return graph

    def test_graph_to_report_data(self, sample_graph) -> None:
        """Test converting graph to report data."""
        from secdashboards.reports import graph_to_report_data

        report_data = graph_to_report_data(
            graph=sample_graph,
            investigation_id="TEST-001",
            executive_summary="Test summary",
            ai_analysis="AI findings here",
        )

        assert report_data.investigation_id == "TEST-001"
        assert report_data.executive_summary == "Test summary"
        assert report_data.ai_analysis == "AI findings here"
        assert report_data.total_nodes == 3
        assert report_data.total_edges == 1
        assert len(report_data.entity_summaries) > 0
        assert len(report_data.principals) == 1
        assert len(report_data.ip_addresses) == 1
        assert len(report_data.api_operations) == 1

    def test_export_investigation_report(self, sample_graph, tmp_path: Path) -> None:
        """Test exporting investigation report to file."""
        from secdashboards.reports import export_investigation_report

        output_path = tmp_path / "test_report.tex"

        result = export_investigation_report(
            graph=sample_graph,
            output_path=output_path,
            investigation_id="TEST-002",
        )

        assert result.exists()
        content = result.read_text()
        assert r"\documentclass" in content
        assert "TEST-002" in content
        assert "admin" in content

    def test_detection_results_to_report_data(self) -> None:
        """Test converting detection results to report data."""
        from secdashboards.reports import detection_results_to_report_data

        results = [
            {
                "rule_id": "rule-1",
                "rule_name": "Test Rule 1",
                "severity": "high",
                "triggered": True,
                "match_count": 5,
            },
            {
                "rule_id": "rule-2",
                "rule_name": "Test Rule 2",
                "severity": "medium",
                "triggered": False,
                "match_count": 0,
            },
        ]

        report_data = detection_results_to_report_data(
            results=results,
            mitre_techniques=["T1078", "T1110"],
            test_summary="Test complete",
        )

        assert report_data.total_rules == 2
        assert report_data.rules_triggered == 1
        assert report_data.rules_by_severity["high"] == 1
        assert report_data.rules_by_severity["medium"] == 1
        assert len(report_data.detection_results) == 2
        assert "T1078" in report_data.mitre_coverage

    def test_export_detection_report(self, tmp_path: Path) -> None:
        """Test exporting detection report to file."""
        from secdashboards.reports import export_detection_report

        results = [
            {
                "rule_id": "test-rule",
                "rule_name": "Test Rule",
                "severity": "high",
                "triggered": True,
                "match_count": 3,
                "query": "SELECT * FROM events",
            },
        ]

        output_path = tmp_path / "detection_report.tex"

        result = export_detection_report(
            results=results,
            output_path=output_path,
            mitre_techniques=["T1078"],
        )

        assert result.exists()
        content = result.read_text()
        assert r"\documentclass" in content
        assert "test-rule" in content
        assert "T1078" in content
