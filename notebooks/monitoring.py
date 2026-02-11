"""Monitoring Notebook

Health monitoring for data sources and security infrastructure.

Run with: marimo edit notebooks/monitoring.py
"""

import marimo

__generated_with = "0.19.2"
app = marimo.App(width="full")


@app.cell
def _():
    import marimo as mo

    mo.md(
        """
        # Security Monitoring

        Monitor data source health, connectivity, and freshness.

        **Capabilities:**
        - Data source health checks
        - Security Lake connectivity verification
        - URL/endpoint health analysis
        - Data freshness monitoring
        """
    )
    return (mo,)


@app.cell
def _():
    from datetime import UTC, datetime

    import polars as pl

    from secdashboards.catalog.models import DataSource, DataSourceType
    from secdashboards.catalog.registry import DataCatalog
    from secdashboards.health.monitor import HealthMonitor
    from secdashboards.health.url_analyzer import URLAnalyzer

    return (
        DataCatalog,
        DataSource,
        DataSourceType,
        HealthMonitor,
        URLAnalyzer,
        UTC,
        datetime,
        pl,
    )


# =============================================================================
# Configuration
# =============================================================================


@app.cell
def _(mo):
    mo.md("## Configuration")
    return


@app.cell
def _(mo):
    region_input = mo.ui.dropdown(
        options=[
            "us-west-2",
            "us-west-1",
            "us-east-1",
            "us-east-2",
            "eu-west-1",
            "eu-central-1",
        ],
        value="us-west-2",
        label="AWS Region",
    )
    region_input
    return (region_input,)


@app.cell
def _(DataCatalog, DataSource, DataSourceType, region_input):
    catalog = DataCatalog()
    region = region_input.value
    region_underscore = region.replace("-", "_")

    # Add all Security Lake sources
    catalog.add_source(
        DataSource(
            name="cloudtrail",
            type=DataSourceType.SECURITY_LAKE,
            database=f"amazon_security_lake_glue_db_{region_underscore}",
            table=f"amazon_security_lake_table_{region_underscore}_cloud_trail_mgmt_2_0",
            region=region,
            description="CloudTrail management events",
            expected_freshness_minutes=60,
        )
    )

    catalog.add_source(
        DataSource(
            name="vpc-flow",
            type=DataSourceType.SECURITY_LAKE,
            database=f"amazon_security_lake_glue_db_{region_underscore}",
            table=f"amazon_security_lake_table_{region_underscore}_vpc_flow_2_0",
            region=region,
            description="VPC Flow Logs",
            expected_freshness_minutes=60,
        )
    )

    catalog.add_source(
        DataSource(
            name="route53",
            type=DataSourceType.SECURITY_LAKE,
            database=f"amazon_security_lake_glue_db_{region_underscore}",
            table=f"amazon_security_lake_table_{region_underscore}_route53_2_0",
            region=region,
            description="Route53 DNS logs",
            expected_freshness_minutes=60,
        )
    )

    catalog.add_source(
        DataSource(
            name="security-hub",
            type=DataSourceType.SECURITY_LAKE,
            database=f"amazon_security_lake_glue_db_{region_underscore}",
            table=f"amazon_security_lake_table_{region_underscore}_sh_findings_2_0",
            region=region,
            description="Security Hub findings",
            expected_freshness_minutes=120,
        )
    )

    catalog
    return catalog, region, region_underscore


# =============================================================================
# Data Catalog
# =============================================================================


@app.cell
def _(mo):
    mo.md(
        """
        ## Data Catalog

        Configured data sources for security monitoring.
        """
    )
    return


@app.cell
def _(catalog, mo, pl):
    sources_data = [
        {
            "Name": s.name,
            "Type": s.type.value,
            "Database": s.database or "-",
            "Table": s.table or "-",
            "Expected Freshness": f"{s.expected_freshness_minutes} min",
        }
        for s in catalog.list_sources()
    ]

    if sources_data:
        sources_df = pl.DataFrame(sources_data)
        mo.ui.table(sources_df.to_pandas())
    else:
        mo.md("_No data sources configured_")
    return sources_data, sources_df


# =============================================================================
# Health Monitoring
# =============================================================================


@app.cell
def _(mo):
    mo.md(
        """
        ## Health Monitoring

        Check connectivity and data freshness for all configured sources.
        """
    )
    return


@app.cell
def _(mo):
    run_health_btn = mo.ui.run_button(label="Run Health Checks")
    run_health_btn
    return (run_health_btn,)


@app.cell
def _(HealthMonitor, catalog, mo, run_health_btn):
    health_output = mo.md("_Click 'Run Health Checks' to verify data sources_")

    if run_health_btn.value:
        try:
            monitor = HealthMonitor(catalog)
            report = monitor.check_all()

            # Build status table
            status_items = []
            for source_name, result in report.source_results.items():
                status_icon = "✅" if result.healthy else "❌"
                freshness = (
                    f"{result.data_age_minutes:.0f} min" if result.data_age_minutes else "N/A"
                )
                status_items.append(
                    {
                        "Source": source_name,
                        "Status": status_icon,
                        "Healthy": result.healthy,
                        "Freshness": freshness,
                        "Latency": f"{result.details.get('latency_ms', 0):.0f}ms",
                        "Error": result.error or "-",
                    }
                )

            import polars as pl

            status_df = pl.DataFrame(status_items)

            overall_status = "✅ Healthy" if report.overall_healthy else "⚠️ Issues Detected"

            result_items = [
                mo.md(f"**Overall Status:** {overall_status}"),
                mo.md(f"**Checked at:** {report.checked_at}"),
                mo.ui.table(status_df.to_pandas()),
            ]

            if report.issues:
                result_items.append(mo.md("**Issues:**"))
                result_items.append(mo.md("\n".join(f"- {issue}" for issue in report.issues)))

            health_output = mo.vstack(result_items)

        except Exception as e:
            health_output = mo.md(f"**Error:** {e}")

    health_output
    return (health_output,)


# =============================================================================
# URL Data Analysis
# =============================================================================


@app.cell
def _(mo):
    mo.md(
        """
        ## URL/Endpoint Health Analysis

        Check external data endpoints for availability and freshness.
        Useful for monitoring threat intelligence feeds or external APIs.
        """
    )
    return


@app.cell
def _(mo):
    url_input = mo.ui.text(
        value="",
        label="URL to Analyze",
        full_width=True,
        placeholder="https://api.example.com/v1/data",
    )
    url_input
    return (url_input,)


@app.cell
def _(mo):
    analyze_url_btn = mo.ui.run_button(label="Analyze URL")
    analyze_url_btn
    return (analyze_url_btn,)


@app.cell
def _(URLAnalyzer, analyze_url_btn, mo, url_input):
    url_output = mo.md("_Enter a URL and click 'Analyze URL'_")

    if analyze_url_btn.value and url_input.value:
        try:
            analyzer = URLAnalyzer()

            # Check endpoint health
            endpoint_health = analyzer.check_endpoint_health(url_input.value)

            health_icon = "✅" if endpoint_health["healthy"] else "❌"
            result_items = [
                mo.md(f"**URL:** {url_input.value}"),
                mo.md(
                    f"**Status:** {health_icon} {'Healthy' if endpoint_health['healthy'] else 'Unhealthy'}"
                ),
                mo.md(f"**Response Time:** {endpoint_health.get('response_time_ms', 0):.0f}ms"),
                mo.md(f"**Status Code:** {endpoint_health.get('status_code', 'N/A')}"),
            ]

            if endpoint_health.get("issues"):
                result_items.append(mo.md("**Issues:**"))
                result_items.append(
                    mo.md("\n".join(f"- {issue}" for issue in endpoint_health["issues"]))
                )

            # Try to analyze data freshness if JSON
            try:
                freshness = analyzer.analyze_data_freshness(url_input.value)
                if freshness and freshness.get("is_json"):
                    result_items.append(mo.md("---"))
                    result_items.append(mo.md("**Data Freshness:**"))
                    result_items.append(mo.md(f"- Records: {freshness.get('record_count', 'N/A')}"))
                    if freshness.get("latest_time"):
                        result_items.append(mo.md(f"- Latest: {freshness.get('latest_time')}"))
            except Exception:
                pass  # Freshness analysis is optional

            url_output = mo.vstack(result_items)

        except Exception as e:
            url_output = mo.md(f"**Error:** {e}")

    url_output
    return (url_output,)


# =============================================================================
# AWS Console Links
# =============================================================================


@app.cell
def _(mo):
    mo.md(
        """
        ## AWS Console Links

        Quick links to relevant AWS console pages.
        """
    )
    return


@app.cell
def _(mo, region):
    console_links = [
        (
            "Security Lake Dashboard",
            f"https://{region}.console.aws.amazon.com/securitylake/home?region={region}",
        ),
        (
            "Athena Query Editor",
            f"https://{region}.console.aws.amazon.com/athena/home?region={region}#/query-editor",
        ),
        (
            "CloudWatch Logs",
            f"https://{region}.console.aws.amazon.com/cloudwatch/home?region={region}#logsV2:log-groups",
        ),
        (
            "Security Hub",
            f"https://{region}.console.aws.amazon.com/securityhub/home?region={region}",
        ),
        (
            "GuardDuty",
            f"https://{region}.console.aws.amazon.com/guardduty/home?region={region}",
        ),
    ]

    links_md = "\n".join(f"- [{name}]({url})" for name, url in console_links)
    mo.md(links_md)
    return console_links, links_md


if __name__ == "__main__":
    app.run()
