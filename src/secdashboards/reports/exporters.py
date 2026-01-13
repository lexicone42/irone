"""High-level export functions for security reports."""

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

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
