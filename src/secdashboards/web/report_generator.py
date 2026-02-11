"""HTML report generator — self-contained HTML reports from Report models."""

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from secdashboards.reports.models import Report

_TEMPLATE_DIR = Path(__file__).parent / "templates" / "reports"


def _get_jinja_env() -> Environment:
    """Create Jinja2 environment for report templates."""
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=True,
    )


def render_report(report: Report) -> str:
    """Render a Report model to self-contained HTML.

    The output is a standalone HTML page with embedded CSS — no external
    dependencies. Suitable for saving to S3, emailing, or embedding in an iframe.

    Args:
        report: A Report model (detection or investigation).

    Returns:
        Complete HTML string.
    """
    env = _get_jinja_env()
    template = env.get_template("report.html")
    return template.render(report=report)


def render_health_report(health_data: list[dict[str, object]]) -> str:
    """Render a health check report to self-contained HTML.

    Args:
        health_data: List of health check result dicts (source_name, healthy, etc.).

    Returns:
        Complete HTML string.
    """
    env = _get_jinja_env()
    template = env.get_template("health_report.html")
    return template.render(results=health_data)


def save_report(html: str, path: Path) -> Path:
    """Save an HTML report to disk.

    Args:
        html: Rendered HTML string.
        path: Output file path.

    Returns:
        The path written to.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")
    return path
