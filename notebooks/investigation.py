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
        NeptuneConnector,
        SecurityGraph,
    )
    return (
        DataCatalog,
        DataSource,
        DataSourceType,
        GraphBuilder,
        GraphVisualizer,
        NeptuneConnector,
    )


@app.cell
def _(mo):
    mo.md("""
    ## Configuration
    """)
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
    return catalog, region


@app.cell
def _(mo):
    mo.md("""
    ### Neptune Graph Database (Optional)

    Configure Neptune to persist investigation graphs for later retrieval.
    Leave endpoint empty to skip Neptune integration.
    """)
    return


@app.cell
def _(mo):
    neptune_endpoint = mo.ui.text(
        value="",
        label="Neptune Endpoint",
        placeholder="my-cluster.xxx.us-west-2.neptune.amazonaws.com",
        full_width=True,
    )
    neptune_port = mo.ui.number(
        value=8182,
        start=1,
        stop=65535,
        label="Neptune Port",
    )
    neptune_iam_auth = mo.ui.checkbox(
        value=True,
        label="Use IAM Authentication",
    )

    mo.hstack([neptune_endpoint, neptune_port, neptune_iam_auth])
    return neptune_endpoint, neptune_iam_auth, neptune_port


@app.cell
def _(NeptuneConnector, mo, neptune_endpoint, neptune_iam_auth, neptune_port, region):
    neptune_status = mo.md("_Neptune not configured_")
    neptune_connector = None

    if neptune_endpoint.value:
        try:
            neptune_connector = NeptuneConnector(
                endpoint=neptune_endpoint.value,
                port=int(neptune_port.value),
                region=region,
                use_iam_auth=neptune_iam_auth.value,
            )
            health = neptune_connector.check_health()
            if health["status"] == "healthy":
                neptune_status = mo.md(
                    f"**Neptune:** Connected to `{neptune_endpoint.value}`"
                )
            else:
                neptune_status = mo.md(
                    f"**Neptune:** Connection failed - {health.get('error', 'Unknown error')}"
                )
        except Exception as e:
            neptune_status = mo.md(f"**Neptune:** Error - {e}")

    neptune_status
    return (neptune_connector,)


@app.cell
def _(mo):
    mo.md("""
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
    """)
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


@app.cell
def _(mo):
    mo.md("""
    ## Manual Investigation

    Build a graph by specifying users and/or IP addresses to investigate.
    """)
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
    return (graph,)


@app.cell
def _(mo):
    mo.md("""
    ## AI-Assisted Analysis

    Use Amazon Bedrock to analyze the investigation graph and identify
    potential attack patterns or suspicious behavior.
    """)
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
    return analysis_focus, analysis_model


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


@app.cell
def _(mo):
    mo.md("""
    ## Export

    Export the investigation graph for reports or further analysis.

    **Export Formats:**
    - **JSON** - Raw graph data for programmatic use
    - **LaTeX** - Professional report for documentation
    """)
    return


@app.cell
def _(mo):
    export_format = mo.ui.dropdown(
        options=["JSON", "LaTeX (Local)", "PDF to S3"],
        value="JSON",
        label="Export Format",
    )
    s3_bucket_inv = mo.ui.text(
        value="",
        label="S3 Bucket (for S3 export)",
        placeholder="my-reports-bucket",
        full_width=True,
    )
    report_title = mo.ui.text(
        value="Security Investigation Report",
        label="Report Title",
        full_width=True,
    )
    investigation_id_input = mo.ui.text(
        value="",
        label="Investigation ID (optional)",
        placeholder="e.g., INC-2024-001",
        full_width=True,
    )

    mo.vstack([export_format, s3_bucket_inv, report_title, investigation_id_input])
    return export_format, investigation_id_input, report_title, s3_bucket_inv


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
    region,
    report_title,
    s3_bucket_inv,
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
            elif export_format.value == "LaTeX (Local)":
                # Local LaTeX export
                from secdashboards.reports import (
                    LaTeXRenderer,
                    graph_to_report_data,
                )

                # Get AI analysis if available
                ai_text = ""
                try:
                    if "analysis_output" in dir() and analysis_output:
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
            else:
                # S3 export with presigned URL
                if not s3_bucket_inv.value:
                    export_output = mo.md("**Error:** Please enter an S3 bucket name")
                else:
                    from secdashboards.reports import export_investigation_to_s3

                    # Get AI analysis if available
                    ai_text = ""
                    try:
                        if "analysis_output" in dir() and analysis_output:
                            ai_text = str(analysis_output)
                    except Exception:
                        pass

                    result = export_investigation_to_s3(
                        graph=graph,
                        bucket=s3_bucket_inv.value,
                        key_prefix="reports/investigations",
                        investigation_id=investigation_id_input.value,
                        ai_analysis=ai_text,
                        region=region,
                        url_expiration=10800,  # 3 hours
                    )

                    if result["success"]:
                        output_items = [
                            mo.md("**Report uploaded to S3!**"),
                            mo.md("---"),
                        ]

                        if result["pdf_url"]:
                            output_items.append(
                                mo.md("**PDF Report (expires in 3 hours):**")
                            )
                            output_items.append(
                                mo.md(f"[Download PDF]({result['pdf_url']})")
                            )
                            output_items.append(mo.md(""))

                        output_items.append(
                            mo.md("**LaTeX Source (expires in 3 hours):**")
                        )
                        output_items.append(
                            mo.md(f"[Download LaTeX]({result['latex_url']})")
                        )

                        if not result["pdf_url"]:
                            output_items.append(mo.md(""))
                            output_items.append(
                                mo.md(
                                    "_Note: PDF compilation not available. "
                                    "Install pdflatex to enable PDF generation._"
                                )
                            )

                        output_items.append(mo.md("---"))
                        output_items.append(
                            mo.md(f"**S3 Location:** `s3://{s3_bucket_inv.value}/{result['latex_key']}`")
                        )

                        export_output = mo.vstack(output_items)
                    else:
                        export_output = mo.md(f"**Export Error:** {result['error']}")

        except NameError:
            export_output = mo.md("_Build a graph to enable export_")
        except Exception as e:
            export_output = mo.md(f"**Export Error:** {e}")

    export_output
    return


@app.cell
def _(mo):
    mo.md("""
    ## Neptune Graph Persistence

    Save investigation graphs to Neptune for future retrieval, or load
    previously saved graphs.

    **Benefits:**
    - Persist graphs across sessions
    - Share investigations with team members
    - Build comprehensive security knowledge graphs
    - Query historical investigation data
    """)
    return


@app.cell
def _(mo):
    save_graph_btn = mo.ui.run_button(label="Save Graph to Neptune")
    save_graph_btn
    return (save_graph_btn,)


@app.cell
def _(graph, mo, neptune_connector, save_graph_btn):
    save_output = mo.md("_Build a graph and configure Neptune to enable saving_")

    if save_graph_btn.value:
        try:
            if neptune_connector is None:
                save_output = mo.md(
                    "**Error:** Neptune not configured. Enter endpoint above."
                )
            elif "graph" not in dir() or graph.node_count() == 0:
                save_output = mo.md("**Error:** No graph to save. Build a graph first.")
            else:
                count = neptune_connector.save_graph(graph)
                summary = graph.summary()
                save_output = mo.vstack(
                    [
                        mo.md("**Graph saved to Neptune!**"),
                        mo.md(f"- Entities saved: {count}"),
                        mo.md(f"- Nodes: {summary['total_nodes']}"),
                        mo.md(f"- Edges: {summary['total_edges']}"),
                        mo.md("---"),
                        mo.md(
                            "_Tip: Use the node IDs below to load this graph later:_"
                        ),
                        mo.md(
                            f"```\n{', '.join(list(graph.nodes.keys())[:5])}"
                            + ("..." if len(graph.nodes) > 5 else "")
                            + "\n```"
                        ),
                    ]
                )
        except NameError:
            save_output = mo.md("_Build a graph first_")
        except Exception as e:
            save_output = mo.md(f"**Save Error:** {e}")

    save_output
    return


@app.cell
def _(mo):
    mo.md("""
    ### Load Graph from Neptune

    Load an existing investigation graph by specifying a center node ID.
    The graph will be loaded with all connected entities up to the specified depth.
    """)
    return


@app.cell
def _(mo):
    load_node_id = mo.ui.text(
        value="",
        label="Center Node ID",
        placeholder="e.g., Principal:admin or IPAddress:10.0.0.1",
        full_width=True,
    )
    load_depth = mo.ui.slider(
        start=1,
        stop=5,
        value=2,
        label="Traversal Depth",
    )

    mo.hstack([load_node_id, load_depth])
    return load_depth, load_node_id


@app.cell
def _(mo):
    load_graph_btn = mo.ui.run_button(label="Load Graph from Neptune")
    load_graph_btn
    return (load_graph_btn,)


@app.cell
def _(
    GraphVisualizer,
    load_depth,
    load_graph_btn,
    load_node_id,
    mo,
    neptune_connector,
):
    load_output = mo.md("_Configure Neptune and enter a node ID to load a graph_")
    loaded_graph = None

    if load_graph_btn.value:
        try:
            if neptune_connector is None:
                load_output = mo.md(
                    "**Error:** Neptune not configured. Enter endpoint above."
                )
            elif not load_node_id.value:
                load_output = mo.md("**Error:** Enter a node ID to load")
            else:
                loaded_graph = neptune_connector.load_graph(
                    center_node_id=load_node_id.value,
                    depth=load_depth.value,
                )

                if loaded_graph.node_count() > 0:
                    visualizer = GraphVisualizer(height="700px")
                    html = visualizer.to_html(loaded_graph)
                    summary = loaded_graph.summary()

                    load_output = mo.vstack(
                        [
                            mo.md("**Graph loaded from Neptune!**"),
                            mo.md(
                                f"**Summary:** {summary['total_nodes']} nodes, "
                                f"{summary['total_edges']} edges"
                            ),
                            mo.md(
                                f"**Node Types:** "
                                + ", ".join(
                                    f"{k}: {v}"
                                    for k, v in summary["nodes_by_type"].items()
                                )
                            ),
                            mo.Html(html),
                            visualizer.generate_legend_html(),
                        ]
                    )
                else:
                    load_output = mo.md(
                        f"_No graph found for node ID: {load_node_id.value}_"
                    )

        except Exception as e:
            load_output = mo.md(f"**Load Error:** {e}")

    load_output
    return (loaded_graph,)


@app.cell
def _(mo):
    mo.md("""
    ### Search Neptune Graph

    Find entities in Neptune by type or properties.
    """)
    return


@app.cell
def _(mo):
    from secdashboards.graph import NodeType

    search_node_type = mo.ui.dropdown(
        options=[
            ("All Types", ""),
            ("Principal (Users)", NodeType.PRINCIPAL.value),
            ("IP Address", NodeType.IP_ADDRESS.value),
            ("API Operation", NodeType.API_OPERATION.value),
            ("Resource", NodeType.RESOURCE.value),
            ("Security Finding", NodeType.SECURITY_FINDING.value),
        ],
        value="",
        label="Node Type",
    )
    search_limit = mo.ui.slider(
        start=10,
        stop=100,
        value=25,
        label="Max Results",
    )

    mo.hstack([search_node_type, search_limit])
    return NodeType, search_limit, search_node_type


@app.cell
def _(mo):
    search_btn = mo.ui.run_button(label="Search Neptune")
    search_btn
    return (search_btn,)


@app.cell
def _(NodeType, mo, neptune_connector, search_btn, search_limit, search_node_type):
    search_output = mo.md("_Configure Neptune to enable search_")

    if search_btn.value:
        try:
            if neptune_connector is None:
                search_output = mo.md(
                    "**Error:** Neptune not configured. Enter endpoint above."
                )
            else:
                node_type = None
                if search_node_type.value:
                    node_type = NodeType(search_node_type.value)

                nodes = neptune_connector.find_nodes(
                    node_type=node_type,
                    limit=search_limit.value,
                )

                if nodes:
                    # Build a table of results
                    rows = []
                    for node in nodes:
                        rows.append(
                            f"| `{node.id}` | {node.node_type.value} | {node.label} | {node.event_count} |"
                        )

                    table = (
                        "| Node ID | Type | Label | Events |\n"
                        "|---------|------|-------|--------|\n"
                        + "\n".join(rows)
                    )

                    search_output = mo.vstack(
                        [
                            mo.md(f"**Found {len(nodes)} nodes:**"),
                            mo.md(table),
                            mo.md(
                                "_Click on a Node ID and use 'Load Graph from Neptune' to explore_"
                            ),
                        ]
                    )
                else:
                    search_output = mo.md("_No nodes found matching criteria_")

        except Exception as e:
            search_output = mo.md(f"**Search Error:** {e}")

    search_output
    return


if __name__ == "__main__":
    app.run()
