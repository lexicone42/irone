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
from secdashboards.reports.latex_renderer import (
    _calculate_column_widths,
    truncate_text,
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


class TestTruncateText:
    """Tests for text truncation utility."""

    def test_truncate_short_text(self) -> None:
        """Test that short text is not truncated."""
        text = "Short text"
        assert truncate_text(text, 50) == text

    def test_truncate_long_text(self) -> None:
        """Test truncation of long text."""
        text = "This is a very long text that should be truncated"
        result = truncate_text(text, 20)
        assert len(result) == 20
        assert result.endswith("...")

    def test_truncate_exact_length(self) -> None:
        """Test text at exact max length."""
        text = "Exact"
        assert truncate_text(text, 5) == "Exact"

    def test_truncate_none(self) -> None:
        """Test truncating None returns empty string."""
        assert truncate_text(None, 50) == ""

    def test_truncate_non_string(self) -> None:
        """Test truncating non-string values."""
        assert truncate_text(12345, 3) == "..."

    def test_truncate_custom_suffix(self) -> None:
        """Test truncation with custom suffix."""
        text = "Long text here"
        result = truncate_text(text, 10, suffix="[...]")
        assert result.endswith("[...]")

    def test_truncate_arn(self) -> None:
        """Test truncating AWS ARN."""
        arn = "arn:aws:iam::123456789012:user/very-long-username-that-exceeds-limits"
        result = truncate_text(arn, 40)
        assert len(result) == 40
        assert result.startswith("arn:aws:iam")
        assert result.endswith("...")


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

    def test_format_table_truncates_long_cells(self) -> None:
        """Test that long cell content is truncated."""
        long_arn = "arn:aws:iam::123456789012:user/" + "x" * 100
        table = TableData(
            headers=["ARN"],
            rows=[[long_arn]],
        )
        latex = format_table(table, max_cell_width=40)
        # The truncated value should be shorter and end with ...
        assert "..." in latex
        # Original full ARN should not be present
        assert "x" * 100 not in latex

    def test_format_table_small_font(self) -> None:
        """Test table with small font option."""
        table = TableData(
            headers=["A"],
            rows=[["1"]],
        )
        latex = format_table(table, use_small_font=True)
        assert r"{\small" in latex

    def test_format_table_respects_custom_alignments(self) -> None:
        """Test that custom column alignments are respected."""
        table = TableData(
            headers=["Name", "Count"],
            rows=[["test", "5"]],
            column_alignments="|l|r|",
        )
        latex = format_table(table)
        assert r"\begin{longtable}{|l|r|}" in latex


class TestCalculateColumnWidths:
    """Tests for column width calculation."""

    def test_short_columns_use_auto_width(self) -> None:
        """Test that short columns use auto width (l alignment)."""
        headers = ["ID", "Name"]
        rows = [["1", "Joe"], ["2", "Amy"]]
        widths = _calculate_column_widths(headers, rows, 2)
        # Short columns should use 'l' alignment
        assert all(w == "l" for w in widths)

    def test_numeric_columns_right_aligned(self) -> None:
        """Test that numeric columns are right-aligned."""
        headers = ["Name", "Count", "Total Matches"]
        rows = [["test", "5", "100"]]
        widths = _calculate_column_widths(headers, rows, 3)
        # "Count" and "Total Matches" headers should trigger right alignment
        assert widths[1] == "r"
        assert widths[2] == "r"

    def test_long_content_uses_p_column(self) -> None:
        """Test that long content triggers p{} column specification."""
        headers = ["Short", "Very Long Description Column"]
        rows = [["x", "This is a very long description that needs wrapping"]]
        widths = _calculate_column_widths(headers, rows, 2)
        # Second column should use p{} for wrapping
        assert widths[1].startswith("p{")
        assert r"\textwidth" in widths[1]

    def test_handles_empty_cells(self) -> None:
        """Test handling of empty cells."""
        headers = ["A", "B"]
        rows = [["x", ""], [None, "y"]]
        # Should not raise an error
        widths = _calculate_column_widths(headers, rows, 2)
        assert len(widths) == 2


class TestTableOverflowProtection:
    """Tests to verify tables don't overflow page width."""

    def test_arn_column_truncated(self) -> None:
        """Test that AWS ARNs are truncated to prevent overflow."""
        long_arn = (
            "arn:aws:iam::123456789012:role/very-long-role-name-that-would-overflow-the-page-margin"
        )
        table = TableData(
            headers=["User", "ARN"],
            rows=[["admin", long_arn]],
        )
        latex = format_table(table, max_cell_width=45)
        # ARN should be truncated
        assert "..." in latex
        # The full ARN should not appear
        assert "very-long-role-name-that-would-overflow-the-page-margin" not in latex

    def test_multiple_long_columns(self) -> None:
        """Test table with multiple potentially long columns."""
        table = TableData(
            headers=["Resource Type", "Resource ID", "ARN"],
            rows=[
                [
                    "AWS::S3::Bucket",
                    "my-very-long-bucket-name-that-exceeds-normal-limits",
                    "arn:aws:s3:::my-very-long-bucket-name-that-exceeds-normal-limits",
                ]
            ],
        )
        latex = format_table(table, max_cell_width=35)
        # Both long values should be truncated
        assert latex.count("...") >= 2

    def test_empty_string_values_handled(self) -> None:
        """Test that empty string values in cells are handled gracefully."""
        table = TableData(
            headers=["A", "B", "C"],
            rows=[["", "value", ""]],
        )
        latex = format_table(table)
        # Should not raise an error and should produce valid LaTeX
        assert r"\begin{longtable}" in latex

    def test_total_table_width_constrained(self) -> None:
        """Test that calculated p{} widths are within reasonable bounds."""
        headers = ["A" * 50, "B" * 50, "C" * 50]  # Long headers
        rows = [["x" * 60, "y" * 60, "z" * 60]]  # Long content
        widths = _calculate_column_widths(headers, rows, 3)

        # Check that all p{} columns have widths <= 0.4\textwidth
        for w in widths:
            if w.startswith("p{"):
                # Extract the fraction value
                fraction = float(w.split("{")[1].split(r"\textwidth")[0])
                assert fraction <= 0.4, f"Column width {fraction} exceeds 0.4"


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


class TestTimelineInReports:
    """Tests for timeline data in investigation reports."""

    def test_investigation_report_with_timeline_data(self) -> None:
        """Test that timeline fields are included in report data."""
        data = InvestigationReportData(
            title="Timeline Test",
            timeline_events=[
                {
                    "id": "evt-1",
                    "timestamp": "2026-01-15T10:00:00",
                    "title": "Login attempt",
                    "tag": "suspicious",
                    "entity_type": "Principal",
                    "entity_id": "user-1",
                    "operation": "ConsoleLogin",
                },
                {
                    "id": "evt-2",
                    "timestamp": "2026-01-15T10:05:00",
                    "title": "S3 access",
                    "tag": "data_exfiltration",
                    "entity_type": "Resource",
                    "entity_id": "bucket-1",
                    "operation": "GetObject",
                },
            ],
            timeline_tag_counts={"suspicious": 1, "data_exfiltration": 1},
            timeline_ai_summary="AI detected attack chain.",
            timeline_analyst_summary="Confirmed credential compromise.",
        )
        assert len(data.timeline_events) == 2
        assert data.timeline_tag_counts["suspicious"] == 1
        assert data.timeline_ai_summary == "AI detected attack chain."

    def test_render_investigation_with_timeline(self) -> None:
        """Test LaTeX rendering includes timeline section."""
        data = InvestigationReportData(
            title="Timeline Report",
            investigation_id="INV-TL-001",
            total_nodes=5,
            total_edges=10,
            timeline_events=[
                {
                    "id": "evt-1",
                    "timestamp": "2026-01-15T10:00:00",
                    "title": "Suspicious login from external IP",
                    "tag": "initial_access",
                    "entity_type": "Principal",
                    "entity_id": "admin-user",
                    "operation": "ConsoleLogin",
                },
            ],
            timeline_tag_counts={"initial_access": 1},
            timeline_analyst_summary="Confirmed attack vector.",
        )
        renderer = LaTeXRenderer()
        latex = renderer.render_investigation_report(data)

        assert "Investigation Timeline" in latex
        assert "Chronological Events" in latex
        assert "Suspicious login" in latex
        assert "Initial Access" in latex
        assert "Confirmed attack vector" in latex

    def test_render_investigation_without_timeline(self) -> None:
        """Test that timeline section shows placeholder when empty."""
        data = InvestigationReportData(
            title="No Timeline Report",
            total_nodes=5,
            total_edges=10,
        )
        renderer = LaTeXRenderer()
        latex = renderer.render_investigation_report(data)

        assert "No timeline data" in latex

    def test_render_timeline_tag_summary(self) -> None:
        """Test tag summary table renders correctly."""
        data = InvestigationReportData(
            title="Tag Summary Test",
            total_nodes=5,
            total_edges=10,
            timeline_events=[
                {
                    "id": f"evt-{i}",
                    "timestamp": f"2026-01-15T{10+i}:00:00",
                    "title": f"Event {i}",
                    "tag": tag,
                    "entity_type": "Principal",
                    "entity_id": "user-1",
                    "operation": "Op",
                }
                for i, tag in enumerate(["suspicious", "suspicious", "benign", "initial_access"])
            ],
            timeline_tag_counts={
                "suspicious": 2,
                "benign": 1,
                "initial_access": 1,
            },
        )
        renderer = LaTeXRenderer()
        latex = renderer.render_investigation_report(data)

        assert "Tag Summary" in latex
        assert "Suspicious" in latex
        assert "Benign" in latex

    def test_render_timeline_ai_summary(self) -> None:
        """Test AI summary section renders when present."""
        data = InvestigationReportData(
            title="AI Summary Test",
            total_nodes=1,
            total_edges=0,
            timeline_events=[
                {
                    "id": "evt-1",
                    "timestamp": "2026-01-15T10:00:00",
                    "title": "Event",
                    "tag": "unreviewed",
                    "entity_type": "Principal",
                    "entity_id": "user-1",
                    "operation": "",
                }
            ],
            timeline_ai_summary="The timeline shows a clear pattern.",
        )
        renderer = LaTeXRenderer()
        latex = renderer.render_investigation_report(data)

        assert "AI Timeline Summary" in latex
        assert "clear pattern" in latex
