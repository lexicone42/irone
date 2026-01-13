"""Investigation Notebook

Security investigation graph visualization and analysis.
Build investigation graphs from detection results or manual entity input.

Run with: marimo edit notebooks/investigation.py
"""

import marimo

__generated_with = "0.19.2"
app = marimo.App(width="full")


@app.cell
def _():
    import marimo as mo

    mo.md(
        """
        # Security Investigation

        Build and visualize investigation graphs from security events.

        **Capabilities:**
        - Build graphs from triggered detections
        - Manual investigation by user/IP
        - Interactive graph visualization
        - AI-assisted graph analysis
        """
    )
    return (mo,)


@app.cell
def _():
    from datetime import datetime, timedelta, UTC

    import polars as pl

    from secdashboards.catalog.models import DataSource, DataSourceType
    from secdashboards.catalog.registry import DataCatalog
    from secdashboards.graph import (
        GraphBuilder,
        GraphVisualizer,
        SecurityGraph,
    )

    return (
        DataCatalog,
        DataSource,
        DataSourceType,
        GraphBuilder,
        GraphVisualizer,
        SecurityGraph,
        UTC,
        datetime,
        pl,
        timedelta,
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

    catalog.add_source(
        DataSource(
            name="cloudtrail",
            type=DataSourceType.SECURITY_LAKE,
            database=f"amazon_security_lake_glue_db_{region_underscore}",
            table=f"amazon_security_lake_table_{region_underscore}_cloud_trail_mgmt_2_0",
            region=region,
            description="CloudTrail management events",
        )
    )
    return catalog, region, region_underscore


# =============================================================================
# Investigation Graph
# =============================================================================


@app.cell
def _(mo):
    mo.md(
        """
        ## Investigation Graph

        Build an investigation graph from security events. The graph shows
        relationships between principals (users), IP addresses, resources,
        and API operations.

        ### Node Types
        | Type | Color | Description |
        |------|-------|-------------|
        | Principal | Red | Users, roles, AWS identities |
        | IP Address | Teal | Source/destination IPs |
        | Resource | Blue | AWS resources (S3, EC2, etc.) |
        | API Operation | Green | AWS API calls |
        | Security Finding | Bright Red | Triggered detections |
        """
    )
    return


@app.cell
def _(mo):
    enrichment_window = mo.ui.slider(
        start=15,
        stop=1440,
        value=60,
        label="Enrichment Window (minutes)",
    )
    max_events = mo.ui.slider(
        start=50,
        stop=1000,
        value=200,
        label="Max Related Events",
    )

    mo.hstack([enrichment_window, max_events])
    return enrichment_window, max_events


# =============================================================================
# Manual Investigation
# =============================================================================


@app.cell
def _(mo):
    mo.md(
        """
        ## Manual Investigation

        Build a graph by specifying users and/or IP addresses to investigate.
        """
    )
    return


@app.cell
def _(mo):
    investigate_users = mo.ui.text(
        value="",
        label="Users (comma-separated)",
        full_width=True,
        placeholder="e.g., admin, bryan, suspicious-user",
    )
    investigate_ips = mo.ui.text(
        value="",
        label="IP Addresses (comma-separated)",
        full_width=True,
        placeholder="e.g., 10.0.0.1, 203.0.113.50",
    )

    mo.vstack([investigate_users, investigate_ips])
    return investigate_ips, investigate_users


@app.cell
def _(mo):
    build_graph_btn = mo.ui.run_button(label="Build Investigation Graph")
    build_graph_btn
    return (build_graph_btn,)


@app.cell
def _(
    GraphBuilder,
    GraphVisualizer,
    build_graph_btn,
    catalog,
    enrichment_window,
    investigate_ips,
    investigate_users,
    max_events,
    mo,
):
    graph_output = mo.md("_Enter users/IPs and click 'Build Investigation Graph'_")

    if build_graph_btn.value:
        users = [u.strip() for u in investigate_users.value.split(",") if u.strip()]
        ips = [ip.strip() for ip in investigate_ips.value.split(",") if ip.strip()]

        if not users and not ips:
            graph_output = mo.md("_Please enter at least one user or IP address_")
        else:
            try:
                connector = catalog.get_connector("cloudtrail")
                builder = GraphBuilder(connector)

                graph = builder.build_from_identifiers(
                    user_names=users,
                    ip_addresses=ips,
                    enrichment_window_minutes=enrichment_window.value,
                    max_related_events=max_events.value,
                )

                if graph.node_count() > 0:
                    visualizer = GraphVisualizer(height="700px")
                    html = visualizer.to_html(graph)
                    summary = graph.summary()

                    graph_output = mo.vstack(
                        [
                            mo.md(
                                f"**Graph Summary:** {summary['total_nodes']} nodes, "
                                f"{summary['total_edges']} edges"
                            ),
                            mo.md(
                                f"**Node Types:** "
                                + ", ".join(
                                    f"{k}: {v}" for k, v in summary["nodes_by_type"].items()
                                )
                            ),
                            mo.Html(html),
                            visualizer.generate_legend_html(),
                        ]
                    )
                else:
                    graph_output = mo.md(
                        "_No related events found. Try expanding the time window._"
                    )

            except Exception as e:
                graph_output = mo.md(f"**Error building graph:** {e}")

    graph_output
    return graph, graph_output


# =============================================================================
# AI-Assisted Graph Analysis
# =============================================================================


@app.cell
def _(mo):
    mo.md(
        """
        ## AI-Assisted Analysis

        Use Amazon Bedrock to analyze the investigation graph and identify
        potential attack patterns or suspicious behavior.
        """
    )
    return


@app.cell
def _(mo):
    from secdashboards.ai import BedrockModel

    analysis_model = mo.ui.dropdown(
        options=[
            ("Claude 3.5 Sonnet", BedrockModel.CLAUDE_3_5_SONNET.value),
            ("Claude 3 Opus (Deep Analysis)", BedrockModel.CLAUDE_3_OPUS.value),
        ],
        value=BedrockModel.CLAUDE_3_5_SONNET.value,
        label="Analysis Model",
    )
    analysis_focus = mo.ui.text(
        value="",
        label="Focus Area (optional)",
        placeholder="e.g., lateral movement, data exfiltration",
        full_width=True,
    )

    mo.vstack([analysis_model, analysis_focus])
    return BedrockModel, analysis_focus, analysis_model


@app.cell
def _(mo):
    analyze_btn = mo.ui.run_button(label="Analyze Graph with AI")
    analyze_btn
    return (analyze_btn,)


@app.cell
def _(analysis_focus, analysis_model, analyze_btn, graph, mo, region):
    analysis_output = mo.md("_Build a graph first, then click 'Analyze Graph with AI'_")

    if analyze_btn.value:
        try:
            # Check if graph exists and has nodes
            if "graph" not in dir() or graph.node_count() == 0:
                analysis_output = mo.md("_Please build an investigation graph first_")
            else:
                from secdashboards.ai import BedrockAssistant, BedrockModel, TaskConfig

                assistant = BedrockAssistant(region=region)
                config = TaskConfig(model=BedrockModel(analysis_model.value))

                response = assistant.analyze_graph(
                    graph,
                    focus_area=analysis_focus.value if analysis_focus.value else None,
                    config=config,
                )

                analysis_output = mo.vstack(
                    [
                        mo.md(f"**Cost:** ${response.cost_usd:.4f}"),
                        mo.md(
                            f"**Tokens:** {response.input_tokens} in / {response.output_tokens} out"
                        ),
                        mo.md("---"),
                        mo.md("**Analysis:**"),
                        mo.md(response.content),
                    ]
                )
        except NameError:
            analysis_output = mo.md("_Please build an investigation graph first_")
        except Exception as e:
            analysis_output = mo.md(f"**Error:** {e}")

    analysis_output
    return (analysis_output,)


# =============================================================================
# Export Options
# =============================================================================


@app.cell
def _(mo):
    mo.md(
        """
        ## Export

        Export the investigation graph for reports or further analysis.

        **Export Formats:**
        - **JSON** - Raw graph data for programmatic use
        - **LaTeX** - Professional report for documentation
        """
    )
    return


@app.cell
def _(mo):
    export_format = mo.ui.dropdown(
        options=["JSON", "LaTeX Report"],
        value="JSON",
        label="Export Format",
    )
    report_title = mo.ui.text(
        value="Security Investigation Report",
        label="Report Title (LaTeX only)",
        full_width=True,
    )
    investigation_id_input = mo.ui.text(
        value="",
        label="Investigation ID (optional)",
        placeholder="e.g., INC-2024-001",
        full_width=True,
    )

    mo.vstack([export_format, report_title, investigation_id_input])
    return export_format, investigation_id_input, report_title


@app.cell
def _(mo):
    export_btn = mo.ui.run_button(label="Generate Export")
    export_btn
    return (export_btn,)


@app.cell
def _(
    analysis_output,
    export_btn,
    export_format,
    graph,
    investigation_id_input,
    mo,
    report_title,
):
    export_output = mo.md("_Build a graph first, then click 'Generate Export'_")

    if export_btn.value:
        try:
            if "graph" not in dir() or graph.node_count() == 0:
                export_output = mo.md("_Please build an investigation graph first_")
            elif export_format.value == "JSON":
                # JSON export
                import json

                export_data = {
                    "nodes": [
                        {
                            "id": n.id,
                            "type": n.node_type.value,
                            "label": n.label,
                            "properties": n.properties,
                        }
                        for n in graph.nodes.values()
                    ],
                    "edges": [
                        {
                            "source": e.source_id,
                            "target": e.target_id,
                            "type": e.edge_type.value,
                        }
                        for e in graph.edges
                    ],
                }

                json_str = json.dumps(export_data, indent=2, default=str)

                export_output = mo.vstack(
                    [
                        mo.md("**Graph JSON (copy for export):**"),
                        mo.ui.code_editor(
                            value=json_str, language="json", min_height=200
                        ),
                    ]
                )
            else:
                # LaTeX export
                from secdashboards.reports import (
                    LaTeXRenderer,
                    graph_to_report_data,
                )

                # Get AI analysis if available
                ai_text = ""
                try:
                    if "analysis_output" in dir() and analysis_output:
                        # Extract text content from analysis output
                        ai_text = str(analysis_output)
                except Exception:
                    pass

                report_data = graph_to_report_data(
                    graph=graph,
                    investigation_id=investigation_id_input.value,
                    ai_analysis=ai_text,
                )
                report_data.title = report_title.value

                renderer = LaTeXRenderer()
                latex_content = renderer.render_investigation_report(report_data)

                export_output = mo.vstack(
                    [
                        mo.md("**LaTeX Report (copy and compile with pdflatex):**"),
                        mo.ui.code_editor(
                            value=latex_content, language="latex", min_height=400
                        ),
                        mo.md(
                            "_Tip: Save as .tex file and compile with "
                            "`pdflatex report.tex`_"
                        ),
                    ]
                )

        except NameError:
            export_output = mo.md("_Build a graph to enable export_")
        except Exception as e:
            export_output = mo.md(f"**Export Error:** {e}")

    export_output
    return (export_output,)


if __name__ == "__main__":
    app.run()
