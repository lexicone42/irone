#!/usr/bin/env python3
"""Check Security Lake data source health - run quick queries to verify data is flowing."""

from __future__ import annotations

import sys
from datetime import UTC, datetime

import boto3

# Configuration
REGION = "us-west-2"
DATABASE = "amazon_security_lake_glue_db_us_west_2"
OUTPUT = "s3://aws-athena-query-results-651804262336-us-west-2/"

# Tables to check (correct table names from Glue catalog)
TABLES = [
    ("CloudTrail Management", "amazon_security_lake_table_us_west_2_cloud_trail_mgmt_2_0"),
    ("VPC Flow Logs", "amazon_security_lake_table_us_west_2_vpc_flow_2_0"),
    ("Route53 DNS", "amazon_security_lake_table_us_west_2_route53_2_0"),
    ("Security Hub", "amazon_security_lake_table_us_west_2_sh_findings_2_0"),
    ("Lambda Execution", "amazon_security_lake_table_us_west_2_lambda_execution_2_0"),
    ("EKS Audit Logs", "amazon_security_lake_table_us_west_2_eks_audit_2_0"),
]


def run_query(athena: object, query: str, timeout: int = 60) -> list[dict]:
    """Execute an Athena query and return results."""
    import time

    response = athena.start_query_execution(
        QueryString=query,
        QueryExecutionContext={"Database": DATABASE},
        ResultConfiguration={"OutputLocation": OUTPUT},
    )
    query_id = response["QueryExecutionId"]

    # Poll for completion
    start = time.time()
    while time.time() - start < timeout:
        result = athena.get_query_execution(QueryExecutionId=query_id)
        state = result["QueryExecution"]["Status"]["State"]

        if state == "SUCCEEDED":
            break
        elif state in ("FAILED", "CANCELLED"):
            reason = result["QueryExecution"]["Status"].get("StateChangeReason", "Unknown")
            return [{"error": f"Query {state}: {reason}"}]
        time.sleep(1)
    else:
        return [{"error": "Query timeout"}]

    # Get results
    results = []
    paginator = athena.get_paginator("get_query_results")
    for page in paginator.paginate(QueryExecutionId=query_id):
        columns = [col["Name"] for col in page["ResultSet"]["ResultSetMetadata"]["ColumnInfo"]]
        for row in page["ResultSet"]["Rows"][1:]:  # Skip header
            values = [field.get("VarCharValue", "") for field in row["Data"]]
            results.append(dict(zip(columns, values, strict=False)))

    return results


def check_table_health(athena: object, name: str, table: str) -> dict:
    """Check health of a single table."""
    query = f"""
    SELECT
        COUNT(*) as event_count,
        MAX(time_dt) as latest_event,
        MIN(time_dt) as earliest_event
    FROM "{DATABASE}"."{table}"
    WHERE time_dt >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
    """

    results = run_query(athena, query)

    if not results:
        return {"name": name, "table": table, "status": "NO_DATA", "event_count_24h": 0}

    if "error" in results[0]:
        return {"name": name, "table": table, "status": "ERROR", "error": results[0]["error"]}

    row = results[0]
    event_count = int(row.get("event_count", 0))
    latest = row.get("latest_event", "")

    # Calculate freshness
    minutes_ago = None
    if latest:
        try:
            # Handle various timestamp formats from Athena
            # e.g., "2026-01-17 19:30:00.000" or "2026-01-17T19:30:00.000Z"
            clean_ts = latest.replace("Z", "").replace("T", " ").strip()
            if "." in clean_ts:
                clean_ts = clean_ts.split(".")[0]  # Remove milliseconds
            latest_dt = datetime.strptime(clean_ts, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)
            delta = datetime.now(UTC) - latest_dt
            minutes_ago = int(delta.total_seconds() / 60)
        except (ValueError, TypeError) as e:
            print(f"      [DEBUG] Date parse error: {e}, value: {latest}")

    status = "HEALTHY" if event_count > 0 and (minutes_ago or 999) < 120 else "UNHEALTHY"

    return {
        "name": name,
        "table": table,
        "status": status,
        "event_count_24h": event_count,
        "latest_event": latest,
        "minutes_since_last": minutes_ago,
    }


def main() -> None:
    """Run health check on all Security Lake tables."""
    print("=" * 70)
    print("SECURITY LAKE DATA SOURCE HEALTH CHECK")
    print(f"Region: {REGION} | Database: {DATABASE}")
    print(f"Time: {datetime.now(UTC).isoformat()}")
    print("=" * 70)
    print()

    athena = boto3.client("athena", region_name=REGION)

    healthy = 0
    unhealthy = 0

    for name, table in TABLES:
        print(f"Checking {name}...")
        result = check_table_health(athena, name, table)

        status_icon = "[OK]" if result["status"] == "HEALTHY" else "[!!]"
        count = result.get("event_count_24h", 0)
        minutes = result.get("minutes_since_last")
        freshness = f"{minutes}m ago" if minutes else "N/A"

        print(f"  {status_icon} {name}")
        print(f"      Events (24h): {count:,}")
        print(f"      Last event: {freshness}")

        if result.get("error"):
            print(f"      Error: {result['error']}")

        if result["status"] == "HEALTHY":
            healthy += 1
        else:
            unhealthy += 1

        print()

    print("=" * 70)
    print(f"SUMMARY: {healthy} healthy, {unhealthy} unhealthy")
    print("=" * 70)

    if unhealthy > 0:
        print("\nRecommendations for unhealthy sources:")
        print("  - VPC Flow: Enable VPC Flow Logs on your VPCs")
        print("  - Route53: Enable Route53 Resolver Query Logging")
        print("  - Lambda: Enable Lambda Data Events in CloudTrail")
        print("  - Check Security Lake console for source status")

    sys.exit(1 if unhealthy > 0 else 0)


if __name__ == "__main__":
    main()
