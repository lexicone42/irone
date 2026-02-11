"""Detection Engineering Notebook

Create, test, and manage security detection rules.
Includes AI-assisted rule generation with Amazon Bedrock.

Run with: marimo edit notebooks/detection_engineering.py
"""

import marimo

__generated_with = "0.19.9"
app = marimo.App(width="full")


@app.cell
def _():
    import marimo as mo

    mo.md(
        """
        # Detection Engineering

        Create, test, and manage SQL-based security detection rules for AWS Security Lake.

        **Capabilities:**
        - Create detection rules with YAML syntax
        - Test rules against live Security Lake data
        - AI-assisted rule generation (Bedrock)
        - Query explorer for rule development
        """
    )
    return (mo,)


@app.cell
def _():
    from datetime import UTC, datetime

    import polars as pl

    from secdashboards.catalog.models import DataSource, DataSourceType
    from secdashboards.catalog.registry import DataCatalog
    from secdashboards.detections.rule import DetectionMetadata, Severity, SQLDetectionRule
    from secdashboards.detections.runner import DetectionRunner
    from secdashboards.graph import (
        EdgeType,
        GraphEdge,
        GraphVisualizer,
        IPAddressNode,
        NeptuneConnector,
        NodeType,
        PrincipalNode,
        SecurityFindingNode,
        SecurityGraph,
    )

    return (
        DataCatalog,
        DataSource,
        DataSourceType,
        DetectionMetadata,
        DetectionRunner,
        EdgeType,
        GraphEdge,
        GraphVisualizer,
        IPAddressNode,
        NeptuneConnector,
        NodeType,
        PrincipalNode,
        SQLDetectionRule,
        SecurityFindingNode,
        SecurityGraph,
        Severity,
        UTC,
        datetime,
        pl,
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
    return catalog, region, region_underscore


@app.cell
def _(mo):
    mo.md("""
    ### Neptune Graph Database (Optional)

    Configure Neptune to persist detection findings as security knowledge graph.
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
def _(
    NeptuneConnector,
    mo,
    neptune_endpoint,
    neptune_iam_auth,
    neptune_port,
    region,
):
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
                neptune_status = mo.md(f"**Neptune:** Connected to `{neptune_endpoint.value}`")
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
    ## Query Explorer

    Test SQL queries against Security Lake to develop detection logic.
    """)
    return


@app.cell
def _(catalog, mo, region_underscore):
    query_source = mo.ui.dropdown(
        options=[s.name for s in catalog.list_sources()],
        value="cloudtrail",
        label="Data Source",
    )

    default_query = f"""SELECT
    time_dt,
    actor.user.name as user_name,
    actor.user.type as user_type,
    src_endpoint.ip as source_ip,
    api.operation,
    api.service.name as service,
    status
    FROM "amazon_security_lake_glue_db_{region_underscore}"."amazon_security_lake_table_{region_underscore}_cloud_trail_mgmt_2_0"
    WHERE time_dt >= current_timestamp - interval '1' hour
    LIMIT 100"""

    query_input = mo.ui.code_editor(
        value=default_query,
        language="sql",
        min_height=200,
    )

    mo.vstack([query_source, query_input])
    return query_input, query_source


@app.cell
def _(mo):
    run_query_btn = mo.ui.run_button(label="Run Query")
    run_query_btn
    return (run_query_btn,)


@app.cell
def _(catalog, mo, pl, query_input, query_source, run_query_btn):
    query_result = mo.md("_Click 'Run Query' to execute_")

    if run_query_btn.value:
        try:
            connector = catalog.get_connector(query_source.value)
            result_df = connector.query(query_input.value)

            if isinstance(result_df, pl.DataFrame) and len(result_df) > 0:
                query_result = mo.vstack(
                    [
                        mo.md(f"**Results:** {len(result_df)} rows"),
                        mo.ui.table(result_df.to_pandas()),
                    ]
                )
            else:
                query_result = mo.md("_No results returned_")
        except Exception as e:
            query_result = mo.md(f"**Query Error:** {e}")

    query_result
    return


@app.cell
def _(mo):
    mo.md("""
    ## Create Detection Rule

    Define a new SQL-based detection rule.
    """)
    return


@app.cell
def _(mo):
    rule_name = mo.ui.text(
        value="detect-root-login",
        label="Rule ID",
        full_width=True,
    )
    rule_display_name = mo.ui.text(
        value="Root Account Login Detected",
        label="Display Name",
        full_width=True,
    )
    rule_description = mo.ui.text_area(
        value="Detects when the root AWS account is used for authentication",
        label="Description",
        full_width=True,
    )

    mo.vstack([rule_name, rule_display_name, rule_description])
    return rule_description, rule_display_name, rule_name


@app.cell
def _(Severity, mo):
    rule_severity = mo.ui.dropdown(
        options=[s.value for s in Severity],
        value="high",
        label="Severity",
    )
    rule_threshold = mo.ui.slider(
        start=1,
        stop=100,
        value=1,
        label="Alert Threshold",
    )

    mo.hstack([rule_severity, rule_threshold])
    return rule_severity, rule_threshold


@app.cell
def _(mo):
    mo.md("""
    **Detection Query** (use `{start_time}` and `{end_time}` placeholders):
    """)
    return


@app.cell
def _(mo, region_underscore):
    rule_query = mo.ui.code_editor(
        value=f"""SELECT
    time_dt,
    actor.user.name,
    src_endpoint.ip,
    api.operation
    FROM "amazon_security_lake_glue_db_{region_underscore}"."amazon_security_lake_table_{region_underscore}_cloud_trail_mgmt_2_0"
    WHERE time_dt >= TIMESTAMP '{{start_time}}'
      AND time_dt < TIMESTAMP '{{end_time}}'
      AND actor.user.type = 'Root'
      AND class_uid = 3002""",
        language="sql",
        min_height=200,
    )
    rule_query
    return (rule_query,)


@app.cell
def _(mo):
    create_rule_btn = mo.ui.run_button(label="Create Rule")
    create_rule_btn
    return (create_rule_btn,)


@app.cell
def _(
    DetectionMetadata,
    SQLDetectionRule,
    Severity,
    create_rule_btn,
    mo,
    rule_description,
    rule_display_name,
    rule_name,
    rule_query,
    rule_severity,
    rule_threshold,
):
    detection_rules: list[SQLDetectionRule] = []
    rule_creation_result = mo.md("")

    if create_rule_btn.value and rule_name.value:
        new_rule = SQLDetectionRule(
            metadata=DetectionMetadata(
                id=rule_name.value,
                name=rule_display_name.value,
                description=rule_description.value,
                severity=Severity(rule_severity.value),
            ),
            query_template=rule_query.value,
            threshold=rule_threshold.value,
        )
        detection_rules.append(new_rule)
        rule_creation_result = mo.md(f"**Created rule:** {rule_name.value}")

    rule_creation_result
    return (detection_rules,)


@app.cell
def _(detection_rules: "list[SQLDetectionRule]", mo, pl):
    if detection_rules:
        rules_df = pl.DataFrame(
            [
                {
                    "ID": r.metadata.id,
                    "Name": r.metadata.name,
                    "Severity": r.metadata.severity.value,
                    "Threshold": r.threshold,
                }
                for r in detection_rules
            ]
        )
        mo.ui.table(rules_df.to_pandas())
    else:
        mo.md("_No detection rules created yet_")
    return


@app.cell
def _(mo):
    mo.md("""
    ## Test Detections

    Run detection rules against recent Security Lake data.
    """)
    return


@app.cell
def _(detection_rules: "list[SQLDetectionRule]", mo):
    rule_options = (
        [r.metadata.id for r in detection_rules] if detection_rules else ["(create a rule first)"]
    )
    test_rule_select = mo.ui.dropdown(
        options=rule_options,
        value=rule_options[0] if rule_options else None,
        label="Rule to Test",
    )
    test_lookback = mo.ui.slider(
        start=15,
        stop=1440,
        value=60,
        label="Lookback (minutes)",
    )

    mo.hstack([test_rule_select, test_lookback])
    return test_lookback, test_rule_select


@app.cell
def _(mo):
    run_test_btn = mo.ui.run_button(label="Run Detection Test")
    run_test_btn
    return (run_test_btn,)


@app.cell
def _(
    DetectionRunner,
    catalog,
    detection_rules: "list[SQLDetectionRule]",
    mo,
    run_test_btn,
    test_lookback,
    test_rule_select,
):
    test_result_output = mo.md("_Click 'Run Detection Test' to execute_")

    if run_test_btn.value and detection_rules:
        try:
            connector = catalog.get_connector("cloudtrail")
            runner = DetectionRunner(catalog=catalog)

            rule = next(
                (r for r in detection_rules if r.metadata.id == test_rule_select.value),
                None,
            )

            if rule:
                runner.register_rule(rule)
                test_result = runner.run_rule(
                    rule.metadata.id, connector, lookback_minutes=test_lookback.value
                )

                status_color = "red" if test_result.triggered else "green"
                result_items = [
                    mo.md(f"**Rule:** {test_result.rule_name}"),
                    mo.md(
                        f"**Triggered:** <span style='color:{status_color}'>{test_result.triggered}</span>"
                    ),
                    mo.md(f"**Severity:** {test_result.severity}"),
                    mo.md(f"**Match Count:** {test_result.match_count}"),
                    mo.md(f"**Execution Time:** {test_result.execution_time_ms:.0f}ms"),
                ]

                if test_result.error:
                    result_items.append(mo.md(f"**Error:** {test_result.error}"))

                if test_result.triggered and test_result.matches:
                    result_items.append(mo.md("**Sample Matches:**"))
                    result_items.append(
                        mo.ui.table(pl.DataFrame(test_result.matches[:10]).to_pandas())
                    )

                test_result_output = mo.vstack(result_items)
            else:
                test_result_output = mo.md("_Rule not found_")

        except Exception as e:
            test_result_output = mo.md(f"**Test Error:** {e}")

    test_result_output
    return


@app.cell
def _(mo):
    mo.md("""
    ## AI-Assisted Rule Generation

    Use Amazon Bedrock (Claude) to generate detection rules from natural language.

    **Note:** Requires Bedrock access in your AWS account.
    """)
    return


@app.cell
def _(mo):
    ai_description = mo.ui.text_area(
        value="Detect when an IAM user creates access keys for another user, which could indicate privilege escalation",
        label="Describe what you want to detect",
        full_width=True,
        rows=3,
    )
    ai_description
    return (ai_description,)


@app.cell
def _(mo):
    from secdashboards.ai import BedrockModel

    ai_model = mo.ui.dropdown(
        options=[
            ("Claude 3.5 Sonnet (Recommended)", BedrockModel.CLAUDE_3_5_SONNET.value),
            ("Claude 3.5 Haiku (Fast/Cheap)", BedrockModel.CLAUDE_3_5_HAIKU.value),
            ("Claude 3 Opus (Most Capable)", BedrockModel.CLAUDE_3_OPUS.value),
        ],
        value=BedrockModel.CLAUDE_3_5_SONNET.value,
        label="Model",
    )
    ai_model
    return BedrockModel, ai_model


@app.cell
def _(BedrockModel, ai_model, mo):
    from secdashboards.ai import get_pricing

    selected_model = BedrockModel(ai_model.value)
    pricing = get_pricing(selected_model)

    # Estimate for typical rule generation
    est_input = 3000  # System prompt + user message
    est_output = 1500  # YAML rule output
    est_cost = pricing.estimate_cost(est_input, est_output)

    mo.md(
        f"""
        **Estimated Cost:** ~${est_cost:.4f}
        ({pricing.input_price_per_1k:.4f}/1k input, {pricing.output_price_per_1k:.4f}/1k output)
        """
    )
    return


@app.cell
def _(mo):
    generate_btn = mo.ui.run_button(label="Generate Detection Rule")
    generate_btn
    return (generate_btn,)


@app.cell
def _(ai_description, ai_model, generate_btn, mo, region):
    ai_result = mo.md("_Click 'Generate Detection Rule' to use AI_")

    if generate_btn.value and ai_description.value:
        try:
            from secdashboards.ai import BedrockAssistant, BedrockModel, TaskConfig

            assistant = BedrockAssistant(region=region)
            config = TaskConfig(model=BedrockModel(ai_model.value))

            response = assistant.generate_detection_rule(
                ai_description.value,
                context=f"Target region: {region}",
                config=config,
            )

            ai_result = mo.vstack(
                [
                    mo.md(f"**Cost:** ${response.cost_usd:.4f}"),
                    mo.md(f"**Tokens:** {response.input_tokens} in / {response.output_tokens} out"),
                    mo.md(f"**Latency:** {response.latency_ms:.0f}ms"),
                    mo.md("---"),
                    mo.md("**Generated Rule:**"),
                    mo.ui.code_editor(value=response.content, language="yaml", min_height=300),
                ]
            )
        except Exception as e:
            ai_result = mo.md(f"**Error:** {e}")

    ai_result
    return (BedrockModel,)


@app.cell
def _(mo):
    mo.md("""
    ## Export Report

    Export detection results as a formatted LaTeX report.

    **Export Options:**
    - **Local** - Download LaTeX source for local compilation
    - **S3** - Upload to S3 and get a shareable presigned URL (valid 3 hours)
    """)
    return


@app.cell
def _(mo):
    export_format = mo.ui.dropdown(
        options=["LaTeX (Local)", "PDF to S3"],
        value="LaTeX (Local)",
        label="Export Format",
    )
    s3_bucket = mo.ui.text(
        value="",
        label="S3 Bucket (for S3 export)",
        placeholder="my-reports-bucket",
        full_width=True,
    )
    report_title = mo.ui.text(
        value="Detection Engineering Report",
        label="Report Title",
        full_width=True,
    )

    mo.vstack([export_format, s3_bucket, report_title])
    return export_format, report_title, s3_bucket


@app.cell
def _(mo):
    export_btn = mo.ui.run_button(label="Generate Report")
    export_btn
    return (export_btn,)


@app.cell
def _(
    detection_rules: "list[SQLDetectionRule]",
    export_btn,
    export_format,
    mo,
    region,
    report_title,
    s3_bucket,
):
    export_output = mo.md("_Create and test detection rules, then click 'Generate Report'_")

    if export_btn.value:
        try:
            if not detection_rules:
                export_output = mo.md("_Please create at least one detection rule first_")
            else:
                # Build results from detection rules
                results = [
                    {
                        "rule_id": r.metadata.id,
                        "rule_name": r.metadata.name,
                        "severity": r.metadata.severity.value,
                        "triggered": False,  # Will be updated if tests were run
                        "match_count": 0,
                        "query": r.query_template,
                    }
                    for r in detection_rules
                ]

                # Get MITRE techniques from rules
                mitre_techniques = []
                for r in detection_rules:
                    mitre_techniques.extend(r.metadata.mitre_attack)
                mitre_techniques = list(set(mitre_techniques))

                if export_format.value == "LaTeX (Local)":
                    # Local LaTeX export
                    from secdashboards.reports import (
                        LaTeXRenderer,
                        detection_results_to_report_data,
                    )

                    report_data = detection_results_to_report_data(
                        results=results,
                        mitre_techniques=mitre_techniques,
                        test_summary=f"Report generated with {len(detection_rules)} detection rules",
                    )
                    report_data.title = report_title.value

                    renderer = LaTeXRenderer()
                    latex_content = renderer.render_detection_report(report_data)

                    export_output = mo.vstack(
                        [
                            mo.md("**LaTeX Report (copy and compile with pdflatex):**"),
                            mo.ui.code_editor(
                                value=latex_content, language="latex", min_height=400
                            ),
                            mo.md(
                                "_Tip: Save as .tex file and compile with `pdflatex report.tex`_"
                            ),
                        ]
                    )
                else:
                    # S3 export with presigned URL
                    if not s3_bucket.value:
                        export_output = mo.md("**Error:** Please enter an S3 bucket name")
                    else:
                        from secdashboards.reports import export_detection_to_s3

                        result = export_detection_to_s3(
                            results=results,
                            bucket=s3_bucket.value,
                            key_prefix="reports/detections",
                            mitre_techniques=mitre_techniques,
                            test_summary=f"Report generated with {len(detection_rules)} detection rules",
                            region=region,
                            url_expiration=10800,  # 3 hours
                        )

                        if result["success"]:
                            output_items = [
                                mo.md("**Report uploaded to S3!**"),
                                mo.md("---"),
                            ]

                            if result["pdf_url"]:
                                output_items.append(mo.md("**PDF Report (expires in 3 hours):**"))
                                output_items.append(mo.md(f"[Download PDF]({result['pdf_url']})"))
                                output_items.append(mo.md(""))

                            output_items.append(mo.md("**LaTeX Source (expires in 3 hours):**"))
                            output_items.append(mo.md(f"[Download LaTeX]({result['latex_url']})"))

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
                                mo.md(
                                    f"**S3 Location:** `s3://{s3_bucket.value}/{result['latex_key']}`"
                                )
                            )

                            export_output = mo.vstack(output_items)
                        else:
                            export_output = mo.md(f"**Export Error:** {result['error']}")

        except Exception as e:
            export_output = mo.md(f"**Export Error:** {e}")

    export_output
    return


@app.cell
def _(mo):
    mo.md("""
    ## Neptune Graph Persistence

    Save detection findings to Neptune and build investigation graphs
    from triggered detections.

    **Benefits:**
    - Track detection history over time
    - Build security knowledge graphs from alerts
    - Link findings to entities (users, IPs, APIs)
    - Query historical detection data
    """)
    return


@app.cell
def _(mo):
    mo.md("""
    ### Save Detection Finding

    Save a triggered detection as a SecurityFinding node in Neptune.
    This creates a graph linking the finding to related entities.
    """)
    return


@app.cell
def _(detection_rules: "list[SQLDetectionRule]", mo):
    save_rule_options = (
        [r.metadata.id for r in detection_rules] if detection_rules else ["(create a rule first)"]
    )
    save_rule_select = mo.ui.dropdown(
        options=save_rule_options,
        value=save_rule_options[0] if save_rule_options else None,
        label="Detection Rule",
    )
    save_lookback = mo.ui.slider(
        start=15,
        stop=1440,
        value=60,
        label="Lookback (minutes)",
    )

    mo.hstack([save_rule_select, save_lookback])
    return save_lookback, save_rule_select


@app.cell
def _(mo):
    save_finding_btn = mo.ui.run_button(label="Run Detection & Save to Neptune")
    save_finding_btn
    return (save_finding_btn,)


@app.cell
def _(
    DetectionRunner,
    EdgeType,
    GraphEdge,
    GraphVisualizer,
    IPAddressNode,
    PrincipalNode,
    SecurityFindingNode,
    SecurityGraph,
    UTC,
    catalog,
    datetime,
    detection_rules: "list[SQLDetectionRule]",
    mo,
    neptune_connector,
    save_finding_btn,
    save_lookback,
    save_rule_select,
):
    save_finding_output = mo.md(
        "_Configure Neptune and select a rule, then click 'Run Detection & Save to Neptune'_"
    )
    detection_graph = None

    if save_finding_btn.value:
        try:
            if neptune_connector is None:
                save_finding_output = mo.md(
                    "**Error:** Neptune not configured. Enter endpoint above."
                )
            elif not detection_rules:
                save_finding_output = mo.md("**Error:** Create a detection rule first.")
            else:
                rule = next(
                    (r for r in detection_rules if r.metadata.id == save_rule_select.value),
                    None,
                )

                if rule:
                    # Run the detection
                    connector = catalog.get_connector("cloudtrail")
                    runner = DetectionRunner(catalog=catalog)
                    runner.register_rule(rule)
                    result = runner.run_rule(
                        rule.metadata.id, connector, lookback_minutes=save_lookback.value
                    )

                    # Create a graph with the finding
                    detection_graph = SecurityGraph()

                    # Create finding node
                    finding_node = SecurityFindingNode(
                        id=SecurityFindingNode.create_id(rule.metadata.id, datetime.now(UTC)),
                        label=f"{rule.metadata.name}",
                        rule_id=rule.metadata.id,
                        rule_name=rule.metadata.name,
                        severity=rule.metadata.severity.value,
                        triggered=result.triggered,
                        match_count=result.match_count,
                        event_count=result.match_count,
                    )
                    detection_graph.add_node(finding_node)

                    # If triggered and we have matched events, extract entities
                    if result.triggered and result.matches:
                        # Extract unique users and IPs from matched events
                        users = set()
                        ips = set()

                        for row in result.matches:
                            # Try various column names for user
                            user = row.get("user_name") or row.get("name")
                            if user:
                                users.add(str(user))

                            # Try various column names for IP
                            ip = row.get("source_ip") or row.get("ip") or row.get("src_ip")
                            if ip:
                                ips.add(str(ip))

                        # Add principal nodes and edges
                        for user in list(users)[:10]:
                            principal = PrincipalNode(
                                id=PrincipalNode.create_id(user),
                                label=user,
                                user_name=user,
                                event_count=1,
                            )
                            detection_graph.add_node(principal)
                            # Link finding to principal
                            edge = GraphEdge(
                                id=GraphEdge.create_id(
                                    EdgeType.RELATED_TO, finding_node.id, principal.id
                                ),
                                edge_type=EdgeType.RELATED_TO,
                                source_id=finding_node.id,
                                target_id=principal.id,
                            )
                            detection_graph.add_edge(edge)

                        # Add IP nodes and edges
                        for ip in list(ips)[:10]:
                            ip_node = IPAddressNode(
                                id=IPAddressNode.create_id(ip),
                                label=ip,
                                ip_address=ip,
                                is_internal=ip.startswith(("10.", "172.", "192.168.")),
                                event_count=1,
                            )
                            detection_graph.add_node(ip_node)
                            # Link finding to IP
                            edge = GraphEdge(
                                id=GraphEdge.create_id(
                                    EdgeType.RELATED_TO, finding_node.id, ip_node.id
                                ),
                                edge_type=EdgeType.RELATED_TO,
                                source_id=finding_node.id,
                                target_id=ip_node.id,
                            )
                            detection_graph.add_edge(edge)

                    # Save to Neptune
                    count = neptune_connector.save_graph(detection_graph)

                    # Build output
                    status_color = "red" if result.triggered else "green"
                    output_items = [
                        mo.md("**Detection executed and saved to Neptune!**"),
                        mo.md("---"),
                        mo.md(f"**Rule:** {result.rule_name}"),
                        mo.md(
                            f"**Triggered:** <span style='color:{status_color}'>"
                            f"{result.triggered}</span>"
                        ),
                        mo.md(f"**Match Count:** {result.match_count}"),
                        mo.md(f"**Entities Saved:** {count}"),
                        mo.md(f"**Finding ID:** `{finding_node.id}`"),
                    ]

                    if detection_graph.node_count() > 1:
                        visualizer = GraphVisualizer(height="500px")
                        html = visualizer.to_html(detection_graph)
                        output_items.append(mo.md("---"))
                        output_items.append(mo.md("**Detection Graph:**"))
                        output_items.append(mo.Html(html))

                    save_finding_output = mo.vstack(output_items)
                else:
                    save_finding_output = mo.md("_Rule not found_")

        except Exception as e:
            save_finding_output = mo.md(f"**Error:** {e}")

    save_finding_output
    return


@app.cell
def _(mo):
    mo.md("""
    ### Search Detection Findings

    Search for historical detection findings stored in Neptune.
    """)
    return


@app.cell
def _(mo):
    search_severity_filter = mo.ui.dropdown(
        options=[
            ("All Severities", ""),
            ("Critical", "critical"),
            ("High", "high"),
            ("Medium", "medium"),
            ("Low", "low"),
        ],
        value="",
        label="Severity Filter",
    )
    search_findings_limit = mo.ui.slider(
        start=10,
        stop=100,
        value=25,
        label="Max Results",
    )

    mo.hstack([search_severity_filter, search_findings_limit])
    return search_findings_limit, search_severity_filter


@app.cell
def _(mo):
    search_findings_btn = mo.ui.run_button(label="Search Findings in Neptune")
    search_findings_btn
    return (search_findings_btn,)


@app.cell
def _(
    NodeType,
    mo,
    neptune_connector,
    search_findings_btn,
    search_findings_limit,
    search_severity_filter,
):
    search_findings_output = mo.md("_Configure Neptune to enable search_")

    if search_findings_btn.value:
        try:
            if neptune_connector is None:
                search_findings_output = mo.md(
                    "**Error:** Neptune not configured. Enter endpoint above."
                )
            else:
                # Search for SecurityFinding nodes
                properties = {}
                if search_severity_filter.value:
                    properties["severity"] = search_severity_filter.value

                findings = neptune_connector.find_nodes(
                    node_type=NodeType.SECURITY_FINDING,
                    properties=properties if properties else None,
                    limit=search_findings_limit.value,
                )

                if findings:
                    # Build a table of results
                    rows = []
                    for node in findings:
                        triggered = node.properties.get("triggered", False)
                        status = "TRIGGERED" if triggered else "OK"
                        status_style = "color:red" if triggered else "color:green"
                        rows.append(
                            f"| `{node.id}` | {node.properties.get('rule_name', node.label)} | "
                            f"{node.properties.get('severity', 'unknown')} | "
                            f"<span style='{status_style}'>{status}</span> | "
                            f"{node.properties.get('match_count', 0)} |"
                        )

                    table = (
                        "| Finding ID | Rule | Severity | Status | Matches |\n"
                        "|------------|------|----------|--------|--------|\n" + "\n".join(rows)
                    )

                    search_findings_output = mo.vstack(
                        [
                            mo.md(f"**Found {len(findings)} detection findings:**"),
                            mo.md(table),
                        ]
                    )
                else:
                    search_findings_output = mo.md("_No findings found in Neptune_")

        except Exception as e:
            search_findings_output = mo.md(f"**Search Error:** {e}")

    search_findings_output
    return


@app.cell
def _(mo):
    mo.md("""
    ### Load Finding Graph

    Load an investigation graph centered on a detection finding.
    """)
    return


@app.cell
def _(mo):
    load_finding_id = mo.ui.text(
        value="",
        label="Finding ID",
        placeholder="e.g., Finding:detect-root-login:2024-01-13T...",
        full_width=True,
    )
    load_finding_depth = mo.ui.slider(
        start=1,
        stop=5,
        value=2,
        label="Traversal Depth",
    )

    mo.hstack([load_finding_id, load_finding_depth])
    return load_finding_depth, load_finding_id


@app.cell
def _(mo):
    load_finding_btn = mo.ui.run_button(label="Load Finding Graph")
    load_finding_btn
    return (load_finding_btn,)


@app.cell
def _(
    GraphVisualizer,
    load_finding_btn,
    load_finding_depth,
    load_finding_id,
    mo,
    neptune_connector,
):
    load_finding_output = mo.md("_Enter a finding ID and click 'Load Finding Graph'_")

    if load_finding_btn.value:
        try:
            if neptune_connector is None:
                load_finding_output = mo.md(
                    "**Error:** Neptune not configured. Enter endpoint above."
                )
            elif not load_finding_id.value:
                load_finding_output = mo.md("**Error:** Enter a finding ID to load")
            else:
                loaded_graph = neptune_connector.load_graph(
                    center_node_id=load_finding_id.value,
                    depth=load_finding_depth.value,
                )

                if loaded_graph.node_count() > 0:
                    visualizer = GraphVisualizer(height="600px")
                    html = visualizer.to_html(loaded_graph)
                    summary = loaded_graph.summary()

                    load_finding_output = mo.vstack(
                        [
                            mo.md("**Finding graph loaded from Neptune!**"),
                            mo.md(
                                f"**Summary:** {summary['total_nodes']} nodes, "
                                f"{summary['total_edges']} edges"
                            ),
                            mo.md(
                                "**Node Types:** "
                                + ", ".join(
                                    f"{k}: {v}" for k, v in summary["nodes_by_type"].items()
                                )
                            ),
                            mo.Html(html),
                            visualizer.generate_legend_html(),
                        ]
                    )
                else:
                    load_finding_output = mo.md(
                        f"_No graph found for finding ID: {load_finding_id.value}_"
                    )

        except Exception as e:
            load_finding_output = mo.md(f"**Load Error:** {e}")

    load_finding_output
    return


if __name__ == "__main__":
    app.run()
