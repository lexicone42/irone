#!/usr/bin/env python3
"""Example Incident Investigation Script

Demonstrates the complete investigation workflow:
1. Build investigation graph from suspicious activity
2. Enrich with related events from Security Lake
3. Visualize the graph
4. Generate AI analysis
5. Export to PDF report

This can be run standalone or used as a reference for the notebook.

Usage:
    # With real AWS credentials and Security Lake:
    python scripts/example_investigation.py

    # Demo mode with mock data (no AWS required):
    python scripts/example_investigation.py --demo
"""

import argparse
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path


def create_demo_graph():
    """Create a demo investigation graph without AWS connectivity."""
    from secdashboards.graph import SecurityGraph
    from secdashboards.graph.models import EdgeType, GraphNode, GraphEdge, NodeType

    graph = SecurityGraph()

    # Scenario: Suspicious activity from user "compromised-admin"
    # - Authenticated from unusual IP
    # - Made high-privilege API calls
    # - Accessed sensitive S3 bucket
    # - Created new IAM user

    # Principal nodes
    graph.add_node(
        GraphNode(
            id="Principal:compromised-admin",
            node_type=NodeType.PRINCIPAL,
            label="compromised-admin",
            properties={
                "user_name": "compromised-admin",
                "user_type": "IAMUser",
                "account_id": "123456789012",
                "arn": "arn:aws:iam::123456789012:user/compromised-admin",
            },
            event_count=47,
            first_seen=datetime.now(UTC) - timedelta(hours=2),
            last_seen=datetime.now(UTC),
        )
    )

    graph.add_node(
        GraphNode(
            id="Principal:backdoor-user",
            node_type=NodeType.PRINCIPAL,
            label="backdoor-user",
            properties={
                "user_name": "backdoor-user",
                "user_type": "IAMUser",
                "account_id": "123456789012",
                "arn": "arn:aws:iam::123456789012:user/backdoor-user",
            },
            event_count=1,
            first_seen=datetime.now(UTC) - timedelta(minutes=30),
            last_seen=datetime.now(UTC) - timedelta(minutes=30),
        )
    )

    # IP Address nodes
    graph.add_node(
        GraphNode(
            id="IPAddress:203.0.113.50",
            node_type=NodeType.IP_ADDRESS,
            label="203.0.113.50",
            properties={
                "ip_address": "203.0.113.50",
                "is_internal": False,
                "geo_location": "Unknown (TEST-NET-3)",
            },
            event_count=47,
        )
    )

    graph.add_node(
        GraphNode(
            id="IPAddress:10.0.1.100",
            node_type=NodeType.IP_ADDRESS,
            label="10.0.1.100",
            properties={
                "ip_address": "10.0.1.100",
                "is_internal": True,
                "geo_location": "Internal",
            },
            event_count=5,
        )
    )

    # API Operation nodes
    api_operations = [
        ("iam", "CreateUser", 1, 0),
        ("iam", "CreateAccessKey", 2, 0),
        ("iam", "AttachUserPolicy", 1, 0),
        ("s3", "ListBuckets", 1, 0),
        ("s3", "GetObject", 15, 2),
        ("sts", "GetCallerIdentity", 3, 0),
        ("ec2", "DescribeInstances", 5, 0),
        ("secretsmanager", "GetSecretValue", 8, 1),
    ]

    for service, operation, success, failed in api_operations:
        graph.add_node(
            GraphNode(
                id=f"APIOperation:{service}:{operation}",
                node_type=NodeType.API_OPERATION,
                label=f"{service}:{operation}",
                properties={
                    "service": service,
                    "operation": operation,
                    "success_count": success,
                    "failure_count": failed,
                },
                event_count=success + failed,
            )
        )

    # Resource nodes
    graph.add_node(
        GraphNode(
            id="Resource:s3:sensitive-data-bucket",
            node_type=NodeType.RESOURCE,
            label="s3:sensitive-data-bucket",
            properties={
                "resource_type": "AWS::S3::Bucket",
                "resource_id": "sensitive-data-bucket",
                "arn": "arn:aws:s3:::sensitive-data-bucket",
                "region": "us-west-2",
            },
            event_count=15,
        )
    )

    graph.add_node(
        GraphNode(
            id="Resource:secretsmanager:prod/database/credentials",
            node_type=NodeType.RESOURCE,
            label="secretsmanager:prod/database/credentials",
            properties={
                "resource_type": "AWS::SecretsManager::Secret",
                "resource_id": "prod/database/credentials",
                "arn": "arn:aws:secretsmanager:us-west-2:123456789012:secret:prod/database/credentials",
                "region": "us-west-2",
            },
            event_count=8,
        )
    )

    # Security Finding node
    graph.add_node(
        GraphNode(
            id="Finding:iam-user-creation:2024-01-15T10:30:00",
            node_type=NodeType.SECURITY_FINDING,
            label="IAM User Creation Alert",
            properties={
                "rule_id": "iam-user-creation",
                "severity": "high",
                "triggered_at": "2024-01-15T10:30:00Z",
                "match_count": 1,
                "description": "New IAM user created outside of normal process",
            },
            event_count=1,
        )
    )

    # Add edges
    # Principal authenticated from IP
    graph.add_edge(
        GraphEdge(
            id=GraphEdge.create_id(
                EdgeType.AUTHENTICATED_FROM,
                "Principal:compromised-admin",
                "IPAddress:203.0.113.50",
            ),
            source_id="Principal:compromised-admin",
            target_id="IPAddress:203.0.113.50",
            edge_type=EdgeType.AUTHENTICATED_FROM,
            properties={"count": 47},
        )
    )

    # Principal called APIs
    for service, operation, _, _ in api_operations:
        graph.add_edge(
            GraphEdge(
                id=GraphEdge.create_id(
                    EdgeType.CALLED_API,
                    "Principal:compromised-admin",
                    f"APIOperation:{service}:{operation}",
                ),
                source_id="Principal:compromised-admin",
                target_id=f"APIOperation:{service}:{operation}",
                edge_type=EdgeType.CALLED_API,
            )
        )

    # APIs accessed resources
    graph.add_edge(
        GraphEdge(
            id=GraphEdge.create_id(
                EdgeType.ACCESSED_RESOURCE,
                "APIOperation:s3:GetObject",
                "Resource:s3:sensitive-data-bucket",
            ),
            source_id="APIOperation:s3:GetObject",
            target_id="Resource:s3:sensitive-data-bucket",
            edge_type=EdgeType.ACCESSED_RESOURCE,
        )
    )

    graph.add_edge(
        GraphEdge(
            id=GraphEdge.create_id(
                EdgeType.ACCESSED_RESOURCE,
                "APIOperation:secretsmanager:GetSecretValue",
                "Resource:secretsmanager:prod/database/credentials",
            ),
            source_id="APIOperation:secretsmanager:GetSecretValue",
            target_id="Resource:secretsmanager:prod/database/credentials",
            edge_type=EdgeType.ACCESSED_RESOURCE,
        )
    )

    # IAM CreateUser targeted backdoor-user
    graph.add_edge(
        GraphEdge(
            id=GraphEdge.create_id(
                EdgeType.TARGETED,
                "APIOperation:iam:CreateUser",
                "Principal:backdoor-user",
            ),
            source_id="APIOperation:iam:CreateUser",
            target_id="Principal:backdoor-user",
            edge_type=EdgeType.TARGETED,
        )
    )

    # Security finding triggered by suspicious activity
    graph.add_edge(
        GraphEdge(
            id=GraphEdge.create_id(
                EdgeType.TRIGGERED_BY,
                "Finding:iam-user-creation:2024-01-15T10:30:00",
                "APIOperation:iam:CreateUser",
            ),
            source_id="Finding:iam-user-creation:2024-01-15T10:30:00",
            target_id="APIOperation:iam:CreateUser",
            edge_type=EdgeType.TRIGGERED_BY,
        )
    )

    return graph


def run_demo_investigation(output_dir: Path):
    """Run a demo investigation without AWS connectivity."""
    print("=" * 60)
    print("DEMO MODE: Security Incident Investigation")
    print("=" * 60)
    print()
    print("Scenario: Investigating suspicious activity from 'compromised-admin'")
    print("- Unusual authentication from external IP")
    print("- High-privilege IAM operations")
    print("- Access to sensitive data")
    print()

    # Create demo graph
    print("[1/4] Building investigation graph...")
    graph = create_demo_graph()
    summary = graph.summary()
    print(f"      Graph: {summary['total_nodes']} nodes, {summary['total_edges']} edges")
    print(f"      Node types: {summary['nodes_by_type']}")
    print()

    # Generate visualization
    print("[2/4] Generating visualization...")
    from secdashboards.graph import GraphVisualizer

    visualizer = GraphVisualizer(height="800px")
    html_path = output_dir / "investigation_graph.html"
    html = visualizer.to_html(graph)
    html_path.write_text(html)
    print(f"      Saved: {html_path}")
    print()

    # Generate report data
    print("[3/4] Generating report...")
    from secdashboards.reports import graph_to_report_data, LaTeXRenderer

    report_data = graph_to_report_data(
        graph=graph,
        investigation_id="INC-2024-0115-001",
        executive_summary="""
This investigation identified a potential account compromise affecting the
'compromised-admin' IAM user. The user authenticated from an unusual external
IP address (203.0.113.50) and performed high-privilege operations including
creating a new IAM user ('backdoor-user'), accessing sensitive S3 data, and
retrieving production database credentials from Secrets Manager.

**Key Findings:**
1. External IP authentication from TEST-NET-3 range (suspicious)
2. IAM user creation outside normal provisioning process
3. Access to sensitive-data-bucket (15 GetObject calls)
4. Secrets Manager access to production credentials (8 attempts, 1 failed)

**Recommended Actions:**
1. Disable compromised-admin credentials immediately
2. Delete backdoor-user account
3. Rotate secrets accessed during incident window
4. Review CloudTrail for additional compromised activity
5. Investigate source of credential compromise
""",
        ai_analysis="[AI analysis would appear here when running with Bedrock]",
    )
    report_data.title = "Security Incident Investigation: Account Compromise"

    # Render LaTeX
    renderer = LaTeXRenderer()
    latex_content = renderer.render_investigation_report(report_data)
    latex_path = output_dir / "investigation_report.tex"
    latex_path.write_text(latex_content)
    print(f"      Saved: {latex_path}")

    # Try to compile PDF
    pdf_path = None
    try:
        from secdashboards.reports.exporters import compile_latex_to_pdf

        pdf_output = output_dir / "investigation_report.pdf"
        result = compile_latex_to_pdf(latex_content, pdf_output)
        if result and result.exists():
            pdf_path = result
            print(f"      PDF:   {pdf_path}")
    except Exception as e:
        print(f"      PDF:   Skipped ({e})")
    print()

    # Export JSON
    print("[4/4] Exporting graph data...")
    json_data = {
        "investigation_id": "INC-2024-0115-001",
        "generated_at": datetime.now(UTC).isoformat(),
        "summary": summary,
        "nodes": [
            {
                "id": n.id,
                "type": n.node_type.value,
                "label": n.label,
                "properties": n.properties,
                "event_count": n.event_count,
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
    json_path = output_dir / "investigation_data.json"
    json_path.write_text(json.dumps(json_data, indent=2, default=str))
    print(f"      Saved: {json_path}")
    print()

    print("=" * 60)
    print("Investigation Complete!")
    print("=" * 60)
    print()
    print("Output files:")
    print(f"  - Graph:  {html_path}")
    print(f"  - Report: {latex_path}")
    if pdf_path:
        print(f"  - PDF:    {pdf_path}")
    print(f"  - Data:   {json_path}")
    print()
    print("To view the interactive graph, open the HTML file in a browser:")
    print(f"  open {html_path}")
    print()

    return graph


def run_live_investigation(
    users: list[str],
    ips: list[str],
    region: str,
    output_dir: Path,
    enrichment_minutes: int = 60,
    max_events: int = 200,
):
    """Run a live investigation using AWS Security Lake."""
    from secdashboards.catalog.models import DataSource, DataSourceType
    from secdashboards.catalog.registry import DataCatalog
    from secdashboards.graph import GraphBuilder, GraphVisualizer
    from secdashboards.reports import graph_to_report_data, LaTeXRenderer

    print("=" * 60)
    print("LIVE MODE: Security Incident Investigation")
    print("=" * 60)
    print()
    print(f"Investigating: users={users}, ips={ips}")
    print(f"Region: {region}")
    print(f"Enrichment window: {enrichment_minutes} minutes")
    print()

    # Setup catalog
    print("[1/5] Configuring data sources...")
    catalog = DataCatalog()
    region_underscore = region.replace("-", "_")
    catalog.add_source(
        DataSource(
            name="cloudtrail",
            type=DataSourceType.SECURITY_LAKE,
            database=f"amazon_security_lake_glue_db_{region_underscore}",
            table=f"amazon_security_lake_table_{region_underscore}_cloud_trail_mgmt_2_0",
            region=region,
        )
    )
    print("      CloudTrail source configured")
    print()

    # Build graph
    print("[2/5] Building investigation graph from Security Lake...")
    connector = catalog.get_connector("cloudtrail")
    builder = GraphBuilder(connector)
    graph = builder.build_from_identifiers(
        user_names=users,
        ip_addresses=ips,
        enrichment_window_minutes=enrichment_minutes,
        max_related_events=max_events,
    )

    summary = graph.summary()
    print(f"      Graph: {summary['total_nodes']} nodes, {summary['total_edges']} edges")
    print(f"      Node types: {summary['nodes_by_type']}")
    print()

    if graph.node_count() == 0:
        print("WARNING: No data found. Try:")
        print("  - Expanding the enrichment window")
        print("  - Checking the user/IP values")
        print("  - Verifying Security Lake access")
        return None

    # Generate visualization
    print("[3/5] Generating visualization...")
    visualizer = GraphVisualizer(height="800px")
    html_path = output_dir / "investigation_graph.html"
    html = visualizer.to_html(graph)
    html_path.write_text(html)
    print(f"      Saved: {html_path}")
    print()

    # Generate report
    print("[4/5] Generating report...")
    investigation_id = f"INV-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}"
    report_data = graph_to_report_data(
        graph=graph,
        investigation_id=investigation_id,
    )
    report_data.title = f"Security Investigation: {', '.join(users + ips)}"

    renderer = LaTeXRenderer()
    latex_content = renderer.render_investigation_report(report_data)
    latex_path = output_dir / "investigation_report.tex"
    latex_path.write_text(latex_content)
    print(f"      Saved: {latex_path}")
    print()

    # Export JSON
    print("[5/5] Exporting graph data...")
    json_data = {
        "investigation_id": investigation_id,
        "generated_at": datetime.now(UTC).isoformat(),
        "summary": summary,
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
    json_path = output_dir / "investigation_data.json"
    json_path.write_text(json.dumps(json_data, indent=2, default=str))
    print(f"      Saved: {json_path}")
    print()

    print("=" * 60)
    print("Investigation Complete!")
    print("=" * 60)
    print()
    print(f"Investigation ID: {investigation_id}")
    print()
    print("To compile the PDF report:")
    print(f"  pdflatex -output-directory={output_dir} {latex_path}")
    print()

    return graph


def main():
    parser = argparse.ArgumentParser(
        description="Run an example security incident investigation"
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run in demo mode with mock data (no AWS required)",
    )
    parser.add_argument(
        "--users",
        type=str,
        default="",
        help="Comma-separated list of users to investigate",
    )
    parser.add_argument(
        "--ips",
        type=str,
        default="",
        help="Comma-separated list of IPs to investigate",
    )
    parser.add_argument(
        "--region",
        type=str,
        default="us-west-2",
        help="AWS region (default: us-west-2)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="output/investigations",
        help="Output directory (default: output/investigations)",
    )
    parser.add_argument(
        "--window",
        type=int,
        default=60,
        help="Enrichment window in minutes (default: 60)",
    )

    args = parser.parse_args()

    # Create output directory
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.demo:
        run_demo_investigation(output_dir)
    else:
        users = [u.strip() for u in args.users.split(",") if u.strip()]
        ips = [ip.strip() for ip in args.ips.split(",") if ip.strip()]

        if not users and not ips:
            print("Error: Specify --users and/or --ips, or use --demo mode")
            print()
            print("Examples:")
            print("  # Demo mode (no AWS required):")
            print("  python scripts/example_investigation.py --demo")
            print()
            print("  # Live mode with Security Lake:")
            print("  python scripts/example_investigation.py --users admin,bryan --ips 10.0.0.1")
            sys.exit(1)

        run_live_investigation(
            users=users,
            ips=ips,
            region=args.region,
            output_dir=output_dir,
            enrichment_minutes=args.window,
        )


if __name__ == "__main__":
    main()
