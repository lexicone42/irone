"""LaTeX rendering utilities using Jinja2."""

import re
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .models import (
    CodeBlock,
    DetectionReportData,
    Figure,
    InvestigationReportData,
    Report,
    ReportType,
    TableData,
)

# LaTeX special characters that need escaping
LATEX_SPECIAL_CHARS = {
    "&": r"\&",
    "%": r"\%",
    "$": r"\$",
    "#": r"\#",
    "_": r"\_",
    "{": r"\{",
    "}": r"\}",
    "~": r"\textasciitilde{}",
    "^": r"\textasciicircum{}",
    "\\": r"\textbackslash{}",
    "<": r"\textless{}",
    ">": r"\textgreater{}",
    "|": r"\textbar{}",
}

# Regex pattern for all special characters
LATEX_ESCAPE_PATTERN = re.compile("|".join(re.escape(char) for char in LATEX_SPECIAL_CHARS))


def escape_latex(text: str | None) -> str:
    """Escape special LaTeX characters in text.

    Args:
        text: Text to escape

    Returns:
        LaTeX-safe escaped text
    """
    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)
    return LATEX_ESCAPE_PATTERN.sub(lambda match: LATEX_SPECIAL_CHARS[match.group()], text)


def escape_latex_url(url: str) -> str:
    """Escape URL for use in LaTeX href commands.

    URLs need different escaping - only escape characters that break LaTeX
    but preserve URL structure.
    """
    # Only escape characters that would break LaTeX parsing
    return url.replace("%", r"\%").replace("#", r"\#").replace("&", r"\&")


def truncate_text(text: str, max_length: int = 50, suffix: str = "...") -> str:
    """Truncate text to a maximum length with ellipsis.

    Args:
        text: Text to truncate
        max_length: Maximum length before truncation
        suffix: Suffix to append when truncated

    Returns:
        Truncated text
    """
    if text is None:
        return ""
    text = str(text)
    if len(text) <= max_length:
        return text
    return text[: max_length - len(suffix)] + suffix


# Maximum character widths for common column types (for table overflow prevention)
COLUMN_MAX_WIDTHS = {
    "arn": 40,  # AWS ARNs can be very long
    "resource_id": 35,
    "user_name": 30,
    "ip_address": 15,
    "default": 45,
}


def format_table(
    table: TableData,
    max_cell_width: int = 45,
    use_small_font: bool = False,
) -> str:
    """Format a TableData object as a LaTeX longtable with overflow protection.

    Args:
        table: TableData object with headers and rows
        max_cell_width: Maximum characters per cell before truncation
        use_small_font: Use smaller font for table content

    Returns:
        LaTeX longtable string with proper column widths
    """
    if not table.headers or not table.rows:
        return ""

    num_cols = len(table.headers)

    # Calculate column widths based on content analysis
    # Use p{width} columns for text wrapping instead of l columns
    if table.column_alignments:
        alignments = table.column_alignments
    else:
        # Calculate proportional widths based on header names and content
        col_widths = _calculate_column_widths(table.headers, table.rows, num_cols)
        alignments = "|" + "|".join(col_widths) + "|"

    lines = []

    # Optional smaller font
    if use_small_font:
        lines.append(r"{\small")

    lines.extend(
        [
            r"\begin{longtable}{" + alignments + "}",
            r"\hline",
        ]
    )

    # Header row
    escaped_headers = [escape_latex(h) for h in table.headers]
    lines.append(" & ".join(escaped_headers) + r" \\ \hline")
    lines.append(r"\endfirsthead")

    # Continuation header
    lines.append(r"\hline")
    lines.append(" & ".join(escaped_headers) + r" \\ \hline")
    lines.append(r"\endhead")

    # Footer
    lines.append(r"\hline")
    lines.append(r"\endfoot")

    # Data rows - truncate long values to prevent overflow
    for row in table.rows:
        escaped_row = []
        for cell in row:
            cell_str = str(cell) if cell is not None else ""
            # Truncate very long cells
            if len(cell_str) > max_cell_width:
                cell_str = truncate_text(cell_str, max_cell_width)
            escaped_row.append(escape_latex(cell_str))
        lines.append(" & ".join(escaped_row) + r" \\")

    lines.append(r"\hline")

    # Caption and label
    if table.caption:
        lines.append(r"\caption{" + escape_latex(table.caption) + "}")
    if table.label:
        lines.append(r"\label{" + table.label + "}")

    lines.append(r"\end{longtable}")

    if use_small_font:
        lines.append(r"}")

    return "\n".join(lines)


def _calculate_column_widths(headers: list[str], rows: list[list[str]], num_cols: int) -> list[str]:
    """Calculate proportional column widths based on content.

    Uses p{} columns which allow text wrapping.
    Total width is constrained to \\textwidth.

    Args:
        headers: Column headers
        rows: Data rows
        num_cols: Number of columns

    Returns:
        List of LaTeX column specifications
    """
    # Analyze max content length per column
    max_lengths = [len(h) for h in headers]

    for row in rows[:20]:  # Sample first 20 rows for performance
        for i, cell in enumerate(row):
            if i < len(max_lengths):
                cell_len = len(str(cell)) if cell else 0
                max_lengths[i] = max(max_lengths[i], min(cell_len, 60))

    # Identify columns that should be fixed-width vs flexible
    col_specs = []
    total_weight = sum(max_lengths)

    for _i, (header, max_len) in enumerate(zip(headers, max_lengths, strict=False)):
        header_lower = header.lower()

        # Fixed-width columns for specific types
        if any(kw in header_lower for kw in ["count", "matches", "total", "success", "failed"]):
            col_specs.append("r")  # Right-align numbers, auto-width
        elif max_len <= 15:
            col_specs.append("l")  # Short columns, auto-width
        else:
            # Proportional width for longer text columns
            # Calculate fraction of total width (0.1 to 0.4 range)
            fraction = max(0.1, min(0.4, max_len / total_weight * num_cols * 0.8))
            col_specs.append(f"p{{{fraction:.2f}\\textwidth}}")

    return col_specs


def format_code_block(code_block: CodeBlock) -> str:
    """Format a CodeBlock as a LaTeX listing.

    Args:
        code_block: CodeBlock object with code and language

    Returns:
        LaTeX lstlisting string
    """
    lines = [
        r"\begin{lstlisting}[language=" + code_block.language,
    ]

    if code_block.caption:
        lines[0] += ", caption={" + escape_latex(code_block.caption) + "}"
    if code_block.label:
        lines[0] += ", label=" + code_block.label

    lines[0] += "]"
    lines.append(code_block.code)  # Code is NOT escaped in lstlisting
    lines.append(r"\end{lstlisting}")

    return "\n".join(lines)


def format_figure(figure: Figure) -> str:
    """Format a Figure as a LaTeX figure environment.

    Args:
        figure: Figure object with path and caption

    Returns:
        LaTeX figure string
    """
    path = str(figure.path).replace("\\", "/")  # Normalize path separators

    lines = [
        r"\begin{figure}[htbp]",
        r"\centering",
        r"\includegraphics[width=" + figure.width + "]{" + path + "}",
    ]

    if figure.caption:
        lines.append(r"\caption{" + escape_latex(figure.caption) + "}")
    if figure.label:
        lines.append(r"\label{" + figure.label + "}")

    lines.append(r"\end{figure}")

    return "\n".join(lines)


class LaTeXRenderer:
    """Renders reports to LaTeX using Jinja2 templates."""

    def __init__(self, template_dir: Path | None = None) -> None:
        """Initialize the renderer with template directory.

        Args:
            template_dir: Directory containing templates. Defaults to
                         the templates directory in this package.
        """
        if template_dir is None:
            template_dir = Path(__file__).parent / "templates"

        self.template_dir = template_dir
        self.env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(disabled_extensions=["tex", "tex.j2"]),
            block_start_string=r"\BLOCK{",
            block_end_string="}",
            variable_start_string=r"\VAR{",
            variable_end_string="}",
            comment_start_string=r"\#{",
            comment_end_string="}",
            trim_blocks=True,
            lstrip_blocks=True,
        )

        # Register custom filters
        self.env.filters["escape_latex"] = escape_latex
        self.env.filters["escape_url"] = escape_latex_url
        self.env.filters["format_table"] = format_table
        self.env.filters["format_code"] = format_code_block
        self.env.filters["format_figure"] = format_figure
        self.env.filters["truncate"] = truncate_text
        self.env.filters["truncate_arn"] = lambda x: truncate_text(x, 40)
        self.env.filters["truncate_id"] = lambda x: truncate_text(x, 35)

    def render_report(self, report: Report) -> str:
        """Render a report to LaTeX.

        Args:
            report: Report object to render

        Returns:
            LaTeX document string
        """
        template_name = self._get_template_name(report.report_type)
        template = self.env.get_template(template_name)

        context = self._build_context(report)
        return template.render(**context)

    def render_investigation_report(self, data: InvestigationReportData) -> str:
        """Render an investigation report from data.

        Args:
            data: Investigation report data

        Returns:
            LaTeX document string
        """
        template = self.env.get_template("investigation_report.tex.j2")
        return template.render(report=data, escape_latex=escape_latex)

    def render_detection_report(self, data: DetectionReportData) -> str:
        """Render a detection engineering report from data.

        Args:
            data: Detection report data

        Returns:
            LaTeX document string
        """
        template = self.env.get_template("detection_report.tex.j2")
        return template.render(report=data, escape_latex=escape_latex)

    def render_to_file(self, report: Report, output_path: Path) -> Path:
        """Render a report and save to file.

        Args:
            report: Report to render
            output_path: Path for output .tex file

        Returns:
            Path to the created file
        """
        latex_content = self.render_report(report)
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(latex_content)
        return output_path

    def _get_template_name(self, report_type: ReportType) -> str:
        """Get the template filename for a report type."""
        template_map = {
            ReportType.INVESTIGATION: "investigation_report.tex.j2",
            ReportType.DETECTION: "detection_report.tex.j2",
            ReportType.EXECUTIVE_SUMMARY: "executive_summary.tex.j2",
        }
        return template_map.get(report_type, "base.tex.j2")

    def _build_context(self, report: Report) -> dict[str, Any]:
        """Build the template context from a report."""
        context: dict[str, Any] = {
            "title": report.title,
            "subtitle": report.subtitle,
            "author": report.author,
            "generated_at": report.generated_at,
            "sections": report.sections,
            "tables": report.tables,
            "figures": report.figures,
            "code_blocks": report.code_blocks,
            "escape_latex": escape_latex,
        }

        if report.data:
            context["report"] = report.data

        return context
