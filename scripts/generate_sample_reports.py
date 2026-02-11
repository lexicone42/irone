#!/usr/bin/env python3
"""Generate sample PDF reports for visual inspection.

This script creates sample investigation and detection reports
to verify the LaTeX output before production deployment.

Usage:
    uv run python scripts/generate_sample_reports.py

Output:
    output/reports/
    ├── investigation_report.tex
    ├── investigation_report.pdf  (if pdflatex available)
    ├── detection_report.tex
    └── detection_report.pdf      (if pdflatex available)
"""

from datetime import UTC, datetime
from pathlib import Path

from secdashboards.graph import (
    APIOperationNode,
    EdgeType,
    GraphEdge,
    IPAddressNode,
    PrincipalNode,
    ResourceNode,
    SecurityFindingNode,
    SecurityGraph,
)
from secdashboards.reports import (
    LaTeXRenderer,
    compile_latex_to_pdf,
    detection_results_to_report_data,
    graph_to_report_data,
)


def create_sample_investigation_graph() -> SecurityGraph:
    """Create a realistic sample investigation graph."""
    graph = SecurityGraph()

    # Create principals
    principals = [
        PrincipalNode(
            id=PrincipalNode.create_id("suspicious-admin"),
            label="suspicious-admin",
            user_name="suspicious-admin",
            user_type="IAMUser",
            properties={"arn": "arn:aws:iam::123456789012:user/suspicious-admin"},
            event_count=247,
        ),
        PrincipalNode(
            id=PrincipalNode.create_id("compromised-role"),
            label="compromised-role",
            user_name="compromised-role",
            user_type="AssumedRole",
            properties={"arn": "arn:aws:sts::123456789012:assumed-role/AdminRole/session"},
            event_count=156,
        ),
        PrincipalNode(
            id=PrincipalNode.create_id("root"),
            label="root",
            user_name="root",
            user_type="Root",
            event_count=3,
        ),
    ]

    # Create IPs
    ips = [
        IPAddressNode(
            id=IPAddressNode.create_id("203.0.113.50"),
            label="203.0.113.50",
            ip_address="203.0.113.50",
            is_internal=False,
            properties={"geo_country": "Unknown", "threat_intel": "suspicious"},
            event_count=89,
        ),
        IPAddressNode(
            id=IPAddressNode.create_id("10.0.1.50"),
            label="10.0.1.50",
            ip_address="10.0.1.50",
            is_internal=True,
            event_count=312,
        ),
        IPAddressNode(
            id=IPAddressNode.create_id("192.168.1.100"),
            label="192.168.1.100",
            ip_address="192.168.1.100",
            is_internal=True,
            event_count=45,
        ),
    ]

    # Create API operations
    apis = [
        APIOperationNode(
            id=APIOperationNode.create_id("iam", "CreateAccessKey"),
            label="iam:CreateAccessKey",
            service="iam",
            operation="CreateAccessKey",
            success_count=2,
            failure_count=0,
            event_count=2,
        ),
        APIOperationNode(
            id=APIOperationNode.create_id("s3", "GetObject"),
            label="s3:GetObject",
            service="s3",
            operation="GetObject",
            success_count=1500,
            failure_count=23,
            event_count=1523,
        ),
        APIOperationNode(
            id=APIOperationNode.create_id("sts", "AssumeRole"),
            label="sts:AssumeRole",
            service="sts",
            operation="AssumeRole",
            success_count=5,
            failure_count=12,
            event_count=17,
        ),
        APIOperationNode(
            id=APIOperationNode.create_id("ec2", "DescribeInstances"),
            label="ec2:DescribeInstances",
            service="ec2",
            operation="DescribeInstances",
            success_count=234,
            failure_count=0,
            event_count=234,
        ),
    ]

    # Create resources
    resources = [
        ResourceNode(
            id=ResourceNode.create_id("s3", "sensitive-data-bucket"),
            label="sensitive-data-bucket",
            resource_type="s3",
            resource_id="sensitive-data-bucket",
            properties={"arn": "arn:aws:s3:::sensitive-data-bucket"},
            event_count=1523,
        ),
        ResourceNode(
            id=ResourceNode.create_id("iam", "AdminRole"),
            label="AdminRole",
            resource_type="iam",
            resource_id="AdminRole",
            properties={"arn": "arn:aws:iam::123456789012:role/AdminRole"},
            event_count=17,
        ),
    ]

    # Create security finding
    triggered_time = datetime.now(UTC)
    finding = SecurityFindingNode(
        id=SecurityFindingNode.create_id("unauthorized-access", triggered_time),
        label="Unauthorized S3 Access Detected",
        rule_id="unauthorized-access",
        rule_name="Unauthorized S3 Access Detected",
        severity="high",
        triggered_at=triggered_time,
        match_count=47,
        event_count=47,
    )

    # Add all nodes
    for node in principals + ips + apis + resources + [finding]:
        graph.add_node(node)

    # Create edges
    edges_data = [
        # Principal -> IP (AUTHENTICATED_FROM)
        (principals[0].id, ips[0].id, EdgeType.AUTHENTICATED_FROM),
        (principals[0].id, ips[1].id, EdgeType.AUTHENTICATED_FROM),
        (principals[1].id, ips[1].id, EdgeType.AUTHENTICATED_FROM),
        (principals[2].id, ips[2].id, EdgeType.AUTHENTICATED_FROM),
        # Principal -> API (CALLED_API)
        (principals[0].id, apis[0].id, EdgeType.CALLED_API),
        (principals[0].id, apis[1].id, EdgeType.CALLED_API),
        (principals[0].id, apis[2].id, EdgeType.CALLED_API),
        (principals[1].id, apis[1].id, EdgeType.CALLED_API),
        (principals[1].id, apis[3].id, EdgeType.CALLED_API),
        # API -> Resource (TARGETED)
        (apis[1].id, resources[0].id, EdgeType.TARGETED),
        (apis[2].id, resources[1].id, EdgeType.TARGETED),
        # Finding -> Principal (RELATED_TO)
        (finding.id, principals[0].id, EdgeType.RELATED_TO),
        (finding.id, principals[1].id, EdgeType.RELATED_TO),
    ]

    for source_id, target_id, edge_type in edges_data:
        edge = GraphEdge(
            id=GraphEdge.create_id(edge_type, source_id, target_id),
            edge_type=edge_type,
            source_id=source_id,
            target_id=target_id,
            event_count=1,
        )
        graph.add_edge(edge)

    return graph


def create_sample_detection_results() -> list[dict]:
    """Create sample detection results for testing."""
    return [
        {
            "rule_id": "root-account-usage",
            "rule_name": "Root Account Usage Detected",
            "severity": "critical",
            "triggered": True,
            "match_count": 3,
            "query": """SELECT time_dt, actor.user.name, src_endpoint.ip, api.operation
FROM cloudtrail
WHERE actor.user.type = 'Root'
  AND time_dt >= TIMESTAMP '{start_time}'
  AND time_dt < TIMESTAMP '{end_time}'""",
            "sample_matches": [
                {"user_name": "root", "source_ip": "192.168.1.100", "operation": "ConsoleLogin"},
            ],
        },
        {
            "rule_id": "iam-credential-creation",
            "rule_name": "IAM Credential Creation by Non-Admin",
            "severity": "high",
            "triggered": True,
            "match_count": 2,
            "query": """SELECT time_dt, actor.user.name, api.operation, api.request.data
FROM cloudtrail
WHERE api.operation IN ('CreateAccessKey', 'CreateLoginProfile')
  AND actor.user.name NOT LIKE '%admin%'""",
            "sample_matches": [
                {"user_name": "suspicious-admin", "operation": "CreateAccessKey"},
            ],
        },
        {
            "rule_id": "s3-exfiltration-pattern",
            "rule_name": "Potential S3 Data Exfiltration",
            "severity": "high",
            "triggered": True,
            "match_count": 1523,
            "query": """SELECT actor.user.name, COUNT(*) as request_count
FROM cloudtrail
WHERE api.service.name = 's3'
  AND api.operation = 'GetObject'
GROUP BY actor.user.name
HAVING COUNT(*) > 1000""",
            "sample_matches": [
                {"user_name": "suspicious-admin", "request_count": 1523},
            ],
        },
        {
            "rule_id": "failed-assume-role",
            "rule_name": "Multiple Failed AssumeRole Attempts",
            "severity": "medium",
            "triggered": True,
            "match_count": 12,
            "query": """SELECT actor.user.name, COUNT(*) as failure_count
FROM cloudtrail
WHERE api.operation = 'AssumeRole'
  AND status = 'Failure'
GROUP BY actor.user.name
HAVING COUNT(*) > 5""",
        },
        {
            "rule_id": "external-ip-access",
            "rule_name": "Access from External IP",
            "severity": "medium",
            "triggered": True,
            "match_count": 89,
            "query": """SELECT DISTINCT src_endpoint.ip, actor.user.name
FROM cloudtrail
WHERE src_endpoint.ip NOT LIKE '10.%'
  AND src_endpoint.ip NOT LIKE '192.168.%'
  AND src_endpoint.ip NOT LIKE '172.16.%'""",
        },
        {
            "rule_id": "cloudtrail-tampering",
            "rule_name": "CloudTrail Logging Modification",
            "severity": "critical",
            "triggered": False,
            "match_count": 0,
            "query": """SELECT time_dt, actor.user.name, api.operation
FROM cloudtrail
WHERE api.operation IN ('StopLogging', 'DeleteTrail', 'UpdateTrail')""",
        },
        {
            "rule_id": "security-group-open",
            "rule_name": "Security Group Opened to Internet",
            "severity": "high",
            "triggered": False,
            "match_count": 0,
            "query": """SELECT time_dt, actor.user.name, api.request.data
FROM cloudtrail
WHERE api.operation = 'AuthorizeSecurityGroupIngress'
  AND api.request.data LIKE '%0.0.0.0/0%'""",
        },
        {
            "rule_id": "unusual-region-activity",
            "rule_name": "Activity in Unusual AWS Region",
            "severity": "low",
            "triggered": False,
            "match_count": 0,
            "query": """SELECT region, COUNT(*) as event_count
FROM cloudtrail
WHERE region NOT IN ('us-west-2', 'us-east-1')
GROUP BY region""",
        },
    ]


def main():
    """Generate sample reports."""
    # Create output directory
    output_dir = Path("output/reports")
    output_dir.mkdir(parents=True, exist_ok=True)

    renderer = LaTeXRenderer()

    print("=" * 60)
    print("Generating Sample Reports for Visual Inspection")
    print("=" * 60)

    # =========================================================================
    # Investigation Report
    # =========================================================================
    print("\n[1/2] Generating Investigation Report...")

    graph = create_sample_investigation_graph()
    report_data = graph_to_report_data(
        graph=graph,
        investigation_id="INC-2024-0042",
        ai_analysis="""## Executive Summary

This investigation reveals a sophisticated attack pattern consistent with **credential compromise and data exfiltration**.

### Key Findings

1. **Initial Access**: The attacker gained access through compromised IAM credentials for user `suspicious-admin`
2. **Privilege Escalation**: Multiple `AssumeRole` attempts (12 failures, 5 successes) indicate lateral movement
3. **Data Exfiltration**: Over 1,500 S3 GetObject requests to `sensitive-data-bucket` from external IP

### Attack Timeline

| Time | Activity | Risk |
|------|----------|------|
| 02:15 UTC | Initial login from 203.0.113.50 | External IP |
| 02:17 UTC | CreateAccessKey for persistence | High |
| 02:20-04:30 UTC | Mass S3 data download | Critical |

### Recommendations

1. **Immediate**: Rotate all credentials for `suspicious-admin` and disable the account
2. **Short-term**: Review and revoke any access keys created in the past 24 hours
3. **Long-term**: Implement stricter IAM policies and enable GuardDuty

### MITRE ATT&CK Mapping

- **T1078** - Valid Accounts (Initial Access)
- **T1530** - Data from Cloud Storage Object (Collection)
- **T1537** - Transfer Data to Cloud Account (Exfiltration)
""",
    )
    report_data.title = "Security Incident Investigation Report"

    # Render LaTeX
    latex_content = renderer.render_investigation_report(report_data)
    tex_path = output_dir / "investigation_report.tex"
    tex_path.write_text(latex_content)
    print(f"   LaTeX saved: {tex_path}")

    # Try to compile PDF
    pdf_path = compile_latex_to_pdf(latex_content, output_dir / "investigation_report.pdf")
    if pdf_path:
        print(f"   PDF generated: {pdf_path}")
    else:
        print("   PDF compilation skipped (pdflatex not available)")

    # =========================================================================
    # Detection Report
    # =========================================================================
    print("\n[2/2] Generating Detection Report...")

    results = create_sample_detection_results()
    detection_data = detection_results_to_report_data(
        results=results,
        mitre_techniques=["T1078", "T1530", "T1537", "T1098", "T1110"],
        test_summary="Comprehensive detection rule test against 24 hours of CloudTrail data. "
        "5 of 8 rules triggered, indicating active security concerns requiring investigation.",
    )
    detection_data.title = "Detection Engineering Report - Weekly Security Scan"

    # Render LaTeX
    latex_content = renderer.render_detection_report(detection_data)
    tex_path = output_dir / "detection_report.tex"
    tex_path.write_text(latex_content)
    print(f"   LaTeX saved: {tex_path}")

    # Try to compile PDF
    pdf_path = compile_latex_to_pdf(latex_content, output_dir / "detection_report.pdf")
    if pdf_path:
        print(f"   PDF generated: {pdf_path}")
    else:
        print("   PDF compilation skipped (pdflatex not available)")

    # =========================================================================
    # Summary
    # =========================================================================
    print("\n" + "=" * 60)
    print("Report Generation Complete!")
    print("=" * 60)
    print(f"\nOutput directory: {output_dir.absolute()}")
    print("\nGenerated files:")
    for f in sorted(output_dir.iterdir()):
        size = f.stat().st_size
        print(f"  - {f.name} ({size:,} bytes)")

    print("\n" + "-" * 60)
    print("To compile PDFs manually (if pdflatex not available):")
    print(f"  cd {output_dir.absolute()}")
    print("  pdflatex investigation_report.tex")
    print("  pdflatex detection_report.tex")
    print("-" * 60)

    # Suggest installing LaTeX if not available
    if not pdf_path:
        print("\nTo install pdflatex on Gentoo:")
        print("  sudo emerge -av app-text/texlive")
        print("\nOr use an online LaTeX compiler like Overleaf:")
        print("  https://www.overleaf.com/")


if __name__ == "__main__":
    main()
