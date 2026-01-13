"""High-level export functions for security reports."""

import shutil
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import boto3
from botocore.exceptions import ClientError

from secdashboards.graph import SecurityGraph
from secdashboards.graph.models import NodeType

from .latex_renderer import LaTeXRenderer
from .models import (
    DetectionReportData,
    DetectionResultSummary,
    EntitySummary,
    InvestigationReportData,
)


def graph_to_report_data(
    graph: SecurityGraph,
    investigation_id: str = "",
    executive_summary: str = "",
    ai_analysis: str = "",
    time_range_start: datetime | None = None,
    time_range_end: datetime | None = None,
    graph_image_path: Path | str | None = None,
) -> InvestigationReportData:
    """Convert a SecurityGraph to InvestigationReportData.

    Args:
        graph: The security investigation graph
        investigation_id: Optional investigation identifier
        executive_summary: Optional executive summary text
        ai_analysis: Optional AI analysis output
        time_range_start: Start of analysis time window
        time_range_end: End of analysis time window
        graph_image_path: Path to saved graph visualization image

    Returns:
        InvestigationReportData populated from the graph
    """
    summary = graph.summary()

    # Build entity summaries
    entity_summaries = []
    for node_type, count in summary.get("nodes_by_type", {}).items():
        # Get examples of this type
        examples = [
            n.label
            for n in graph.nodes.values()
            if n.node_type.value == node_type
        ][:5]
        entity_summaries.append(
            EntitySummary(
                entity_type=node_type,
                count=count,
                examples=examples,
            )
        )

    # Extract entities by type
    principals = []
    ip_addresses = []
    resources = []
    api_operations = []
    findings = []

    for node in graph.nodes.values():
        props = node.properties.copy()
        props["label"] = node.label

        if node.node_type == NodeType.PRINCIPAL:
            principals.append(props)
        elif node.node_type == NodeType.IP_ADDRESS:
            ip_addresses.append(props)
        elif node.node_type == NodeType.RESOURCE:
            resources.append(props)
        elif node.node_type == NodeType.API_OPERATION:
            api_operations.append(props)
        elif node.node_type == NodeType.SECURITY_FINDING:
            findings.append(props)

    # Get data sources from graph
    data_sources = list({
        node.properties.get("data_source", "Unknown")
        for node in graph.nodes.values()
        if node.properties.get("data_source")
    })

    return InvestigationReportData(
        title="Security Investigation Report",
        investigation_id=investigation_id,
        executive_summary=executive_summary,
        entity_summaries=entity_summaries,
        total_nodes=summary.get("total_nodes", 0),
        total_edges=summary.get("total_edges", 0),
        principals=principals,
        ip_addresses=ip_addresses,
        resources=resources,
        api_operations=api_operations,
        findings=findings,
        ai_analysis=ai_analysis,
        graph_image_path=graph_image_path,
        time_range_start=time_range_start,
        time_range_end=time_range_end,
        data_sources=data_sources,
    )


def export_investigation_report(
    graph: SecurityGraph,
    output_path: Path | str,
    investigation_id: str = "",
    executive_summary: str = "",
    ai_analysis: str = "",
    time_range_start: datetime | None = None,
    time_range_end: datetime | None = None,
    graph_image_path: Path | str | None = None,
) -> Path:
    """Export an investigation report to LaTeX.

    Args:
        graph: The security investigation graph
        output_path: Path for the output .tex file
        investigation_id: Optional investigation identifier
        executive_summary: Optional executive summary text
        ai_analysis: Optional AI analysis output
        time_range_start: Start of analysis time window
        time_range_end: End of analysis time window
        graph_image_path: Path to saved graph visualization image

    Returns:
        Path to the created LaTeX file
    """
    output_path = Path(output_path)

    # Convert graph to report data
    report_data = graph_to_report_data(
        graph=graph,
        investigation_id=investigation_id,
        executive_summary=executive_summary,
        ai_analysis=ai_analysis,
        time_range_start=time_range_start,
        time_range_end=time_range_end,
        graph_image_path=graph_image_path,
    )

    # Render LaTeX
    renderer = LaTeXRenderer()
    latex_content = renderer.render_investigation_report(report_data)

    # Write to file
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(latex_content)

    return output_path


def detection_results_to_report_data(
    results: list[dict[str, Any]],
    mitre_techniques: list[str] | None = None,
    ai_suggestions: list[dict[str, Any]] | None = None,
    test_summary: str = "",
) -> DetectionReportData:
    """Convert detection results to DetectionReportData.

    Args:
        results: List of detection result dictionaries
        mitre_techniques: List of MITRE ATT&CK technique IDs covered
        ai_suggestions: List of AI-suggested detection rules
        test_summary: Optional summary text

    Returns:
        DetectionReportData populated from results
    """
    detection_results = []
    rules_by_severity: dict[str, int] = {}

    for result in results:
        severity = result.get("severity", "medium")
        if isinstance(severity, str):
            severity_str = severity.lower()
        else:
            severity_str = str(severity.value).lower() if hasattr(severity, "value") else "medium"

        rules_by_severity[severity_str] = rules_by_severity.get(severity_str, 0) + 1

        detection_results.append(
            DetectionResultSummary(
                rule_id=result.get("rule_id", "unknown"),
                rule_name=result.get("rule_name", "Unknown Rule"),
                severity=severity_str,
                triggered=result.get("triggered", False),
                match_count=result.get("match_count", 0),
                sample_matches=result.get("matches", [])[:5],
                query=result.get("query", ""),
            )
        )

    triggered_count = sum(1 for r in detection_results if r.triggered)

    return DetectionReportData(
        total_rules=len(detection_results),
        rules_triggered=triggered_count,
        rules_by_severity=rules_by_severity,
        detection_results=detection_results,
        mitre_coverage=mitre_techniques or [],
        ai_suggested_rules=ai_suggestions or [],
        test_summary=test_summary,
    )


def export_detection_report(
    results: list[dict[str, Any]],
    output_path: Path | str,
    mitre_techniques: list[str] | None = None,
    ai_suggestions: list[dict[str, Any]] | None = None,
    test_summary: str = "",
) -> Path:
    """Export a detection engineering report to LaTeX.

    Args:
        results: List of detection result dictionaries
        output_path: Path for the output .tex file
        mitre_techniques: List of MITRE ATT&CK technique IDs covered
        ai_suggestions: List of AI-suggested detection rules
        test_summary: Optional summary text

    Returns:
        Path to the created LaTeX file
    """
    output_path = Path(output_path)

    # Convert results to report data
    report_data = detection_results_to_report_data(
        results=results,
        mitre_techniques=mitre_techniques,
        ai_suggestions=ai_suggestions,
        test_summary=test_summary,
    )

    # Render LaTeX
    renderer = LaTeXRenderer()
    latex_content = renderer.render_detection_report(report_data)

    # Write to file
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(latex_content)

    return output_path


def save_graph_image(
    graph: SecurityGraph,
    output_path: Path | str,
    width: int = 1200,
    height: int = 800,
) -> Path | None:
    """Save a graph visualization as an image.

    Attempts to save the pyvis graph as a static image using
    playwright/selenium if available, otherwise returns None.

    Args:
        graph: The security graph to visualize
        output_path: Path for the output image file
        width: Image width in pixels
        height: Image height in pixels

    Returns:
        Path to the created image file, or None if screenshot failed
    """
    from secdashboards.graph import GraphVisualizer

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Create HTML visualization
    visualizer = GraphVisualizer(height=f"{height}px", width=f"{width}px")
    html_content = visualizer.to_html(graph)

    # Save HTML temporarily
    html_path = output_path.with_suffix(".html")
    html_path.write_text(html_content)

    # Try to capture screenshot using playwright
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page(viewport={"width": width, "height": height})
            page.goto(f"file://{html_path.absolute()}")
            # Wait for vis.js to render
            page.wait_for_timeout(2000)
            page.screenshot(path=str(output_path))
            browser.close()

        # Clean up HTML file
        html_path.unlink()
        return output_path

    except ImportError:
        # Playwright not available, keep HTML file as fallback
        return None
    except Exception:
        # Screenshot failed, keep HTML file
        return None


def compile_latex_to_pdf(
    latex_content: str,
    output_path: Path | str,
    cleanup: bool = True,
) -> Path | None:
    """Compile LaTeX content to PDF.

    Requires pdflatex or xelatex to be installed on the system.

    Args:
        latex_content: LaTeX document string
        output_path: Path for output PDF file
        cleanup: Whether to remove temporary files after compilation

    Returns:
        Path to the created PDF file, or None if compilation failed
    """
    output_path = Path(output_path)

    # Check if pdflatex is available
    pdflatex_path = shutil.which("pdflatex")
    xelatex_path = shutil.which("xelatex")

    if not pdflatex_path and not xelatex_path:
        return None

    latex_cmd = pdflatex_path or xelatex_path

    # Create temporary directory for compilation
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        tex_file = tmpdir_path / "report.tex"
        tex_file.write_text(latex_content)

        try:
            # Run LaTeX twice for proper cross-references
            for _ in range(2):
                result = subprocess.run(
                    [
                        latex_cmd,
                        "-interaction=nonstopmode",
                        "-halt-on-error",
                        "-output-directory",
                        str(tmpdir_path),
                        str(tex_file),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=120,
                )

                if result.returncode != 0:
                    # Compilation failed
                    return None

            # Copy PDF to output location
            pdf_file = tmpdir_path / "report.pdf"
            if pdf_file.exists():
                output_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(pdf_file, output_path)
                return output_path

        except subprocess.TimeoutExpired:
            return None
        except Exception:
            return None

    return None


def upload_to_s3(
    file_path: Path | str,
    bucket: str,
    key: str,
    region: str = "us-west-2",
    content_type: str | None = None,
) -> bool:
    """Upload a file to S3.

    Args:
        file_path: Local file path to upload
        bucket: S3 bucket name
        key: S3 object key
        region: AWS region
        content_type: MIME type for the file

    Returns:
        True if upload succeeded, False otherwise
    """
    file_path = Path(file_path)
    if not file_path.exists():
        return False

    s3_client = boto3.client("s3", region_name=region)

    extra_args = {}
    if content_type:
        extra_args["ContentType"] = content_type

    try:
        s3_client.upload_file(
            str(file_path),
            bucket,
            key,
            ExtraArgs=extra_args if extra_args else None,
        )
        return True
    except ClientError:
        return False


def generate_presigned_url(
    bucket: str,
    key: str,
    region: str = "us-west-2",
    expiration: int = 3600,
) -> str | None:
    """Generate a presigned URL for an S3 object.

    Args:
        bucket: S3 bucket name
        key: S3 object key
        region: AWS region
        expiration: URL expiration time in seconds (default 1 hour)

    Returns:
        Presigned URL string, or None if generation failed
    """
    s3_client = boto3.client("s3", region_name=region)

    try:
        url = s3_client.generate_presigned_url(
            "get_object",
            Params={"Bucket": bucket, "Key": key},
            ExpiresIn=expiration,
        )
        return url
    except ClientError:
        return None


def export_report_to_s3(
    latex_content: str,
    bucket: str,
    key_prefix: str,
    report_name: str = "report",
    region: str = "us-west-2",
    url_expiration: int = 86400,  # 24 hours
) -> dict[str, Any]:
    """Export a report to S3 as both LaTeX and PDF (if possible).

    This function:
    1. Uploads the LaTeX source to S3
    2. Attempts to compile to PDF and upload
    3. Generates presigned URLs for both files

    Args:
        latex_content: LaTeX document string
        bucket: S3 bucket name
        key_prefix: S3 key prefix (e.g., "reports/2024-01")
        report_name: Base name for the report files
        region: AWS region
        url_expiration: Presigned URL expiration in seconds

    Returns:
        Dictionary with:
        - latex_key: S3 key for LaTeX file
        - latex_url: Presigned URL for LaTeX file
        - pdf_key: S3 key for PDF file (if compiled)
        - pdf_url: Presigned URL for PDF file (if compiled)
        - success: Whether the export succeeded
        - error: Error message if failed
    """
    result: dict[str, Any] = {
        "latex_key": None,
        "latex_url": None,
        "pdf_key": None,
        "pdf_url": None,
        "success": False,
        "error": None,
    }

    timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    latex_key = f"{key_prefix}/{report_name}-{timestamp}.tex"
    pdf_key = f"{key_prefix}/{report_name}-{timestamp}.pdf"

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)

        # Save LaTeX file
        latex_file = tmpdir_path / f"{report_name}.tex"
        latex_file.write_text(latex_content)

        # Upload LaTeX
        if upload_to_s3(latex_file, bucket, latex_key, region, "text/x-tex"):
            result["latex_key"] = latex_key
            result["latex_url"] = generate_presigned_url(
                bucket, latex_key, region, url_expiration
            )
        else:
            result["error"] = "Failed to upload LaTeX file to S3"
            return result

        # Try to compile PDF
        pdf_file = tmpdir_path / f"{report_name}.pdf"
        if compile_latex_to_pdf(latex_content, pdf_file):
            if upload_to_s3(pdf_file, bucket, pdf_key, region, "application/pdf"):
                result["pdf_key"] = pdf_key
                result["pdf_url"] = generate_presigned_url(
                    bucket, pdf_key, region, url_expiration
                )

        result["success"] = True

    return result


def export_investigation_to_s3(
    graph: SecurityGraph,
    bucket: str,
    key_prefix: str = "reports/investigations",
    investigation_id: str = "",
    executive_summary: str = "",
    ai_analysis: str = "",
    region: str = "us-west-2",
    url_expiration: int = 86400,
) -> dict[str, Any]:
    """Export an investigation report to S3.

    Args:
        graph: The security investigation graph
        bucket: S3 bucket name
        key_prefix: S3 key prefix
        investigation_id: Optional investigation identifier
        executive_summary: Optional executive summary text
        ai_analysis: Optional AI analysis output
        region: AWS region
        url_expiration: Presigned URL expiration in seconds

    Returns:
        Export result dictionary with S3 keys and presigned URLs
    """
    report_data = graph_to_report_data(
        graph=graph,
        investigation_id=investigation_id,
        executive_summary=executive_summary,
        ai_analysis=ai_analysis,
    )

    renderer = LaTeXRenderer()
    latex_content = renderer.render_investigation_report(report_data)

    report_name = f"investigation-{investigation_id}" if investigation_id else "investigation"

    return export_report_to_s3(
        latex_content=latex_content,
        bucket=bucket,
        key_prefix=key_prefix,
        report_name=report_name,
        region=region,
        url_expiration=url_expiration,
    )


def export_detection_to_s3(
    results: list[dict[str, Any]],
    bucket: str,
    key_prefix: str = "reports/detections",
    mitre_techniques: list[str] | None = None,
    test_summary: str = "",
    region: str = "us-west-2",
    url_expiration: int = 86400,
) -> dict[str, Any]:
    """Export a detection report to S3.

    Args:
        results: List of detection result dictionaries
        bucket: S3 bucket name
        key_prefix: S3 key prefix
        mitre_techniques: List of MITRE ATT&CK technique IDs
        test_summary: Optional test summary text
        region: AWS region
        url_expiration: Presigned URL expiration in seconds

    Returns:
        Export result dictionary with S3 keys and presigned URLs
    """
    report_data = detection_results_to_report_data(
        results=results,
        mitre_techniques=mitre_techniques,
        test_summary=test_summary,
    )

    renderer = LaTeXRenderer()
    latex_content = renderer.render_detection_report(report_data)

    return export_report_to_s3(
        latex_content=latex_content,
        bucket=bucket,
        key_prefix=key_prefix,
        report_name="detection-report",
        region=region,
        url_expiration=url_expiration,
    )
