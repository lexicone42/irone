"""LaTeX report generation for security analytics.

This module provides tools for exporting security investigation
and detection engineering data to professional LaTeX reports.

Example usage:
    from secdashboards.reports import (
        InvestigationReportData,
        DetectionReportData,
        LaTeXRenderer,
    )

    # Create investigation report data
    data = InvestigationReportData(
        title="Incident Investigation",
        executive_summary="Summary of findings...",
        total_nodes=42,
        total_edges=128,
    )

    # Render to LaTeX
    renderer = LaTeXRenderer()
    latex_content = renderer.render_investigation_report(data)

    # Or save to file
    from pathlib import Path
    renderer.render_to_file(report, Path("output/report.tex"))
"""

from .exporters import (
    compile_latex_to_pdf,
    detection_results_to_report_data,
    export_detection_report,
    export_detection_to_s3,
    export_investigation_report,
    export_investigation_to_s3,
    export_report_to_s3,
    generate_presigned_url,
    graph_to_report_data,
    save_graph_image,
    upload_to_s3,
)
from .latex_renderer import (
    LaTeXRenderer,
    escape_latex,
    escape_latex_url,
    format_code_block,
    format_figure,
    format_table,
)
from .models import (
    CodeBlock,
    DetectionReportData,
    DetectionResultSummary,
    EntitySummary,
    Figure,
    InvestigationReportData,
    Report,
    ReportSection,
    ReportType,
    TableData,
)

__all__ = [
    # Models
    "CodeBlock",
    "DetectionReportData",
    "DetectionResultSummary",
    "EntitySummary",
    "Figure",
    "InvestigationReportData",
    "Report",
    "ReportSection",
    "ReportType",
    "TableData",
    # Renderer
    "LaTeXRenderer",
    # Exporters
    "compile_latex_to_pdf",
    "detection_results_to_report_data",
    "export_detection_report",
    "export_detection_to_s3",
    "export_investigation_report",
    "export_investigation_to_s3",
    "export_report_to_s3",
    "generate_presigned_url",
    "graph_to_report_data",
    "save_graph_image",
    "upload_to_s3",
    # Utilities
    "escape_latex",
    "escape_latex_url",
    "format_code_block",
    "format_figure",
    "format_table",
]
