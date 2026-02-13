"""Lambda handler for the health dashboard API.

This provides a quick and dirty health dashboard showing:
- Security Lake data source health (event counts, freshness)
- AWS cost metrics (Athena scans, CloudWatch queries)
- Detection rule execution status

Data is cached hourly to S3 for fast reads and historical tracking.

Performance Notes:
- Security Lake uses Apache Iceberg tables (hidden time partitioning)
- Predicates on time_dt enable automatic partition pruning
- All source queries run in parallel using ThreadPoolExecutor
- COUNT(*) still scans matching Parquet files, but Iceberg prunes by time
"""

from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime, timedelta
from typing import Any

import boto3
from botocore.exceptions import ClientError

# Configuration from environment (required - set by CDK during deployment)
REGION = os.environ.get("AWS_REGION", "us-west-2")
SECURITY_LAKE_DB = os.environ.get("SECURITY_LAKE_DB", "")
ATHENA_OUTPUT = os.environ.get("ATHENA_OUTPUT", "")
CACHE_BUCKET = os.environ.get("CACHE_BUCKET", "")

# Validate required config at module load
if not SECURITY_LAKE_DB:
    SECURITY_LAKE_DB = f"amazon_security_lake_glue_db_{REGION.replace('-', '_')}"
if not ATHENA_OUTPUT:
    # Empty string = omit ResultConfiguration, letting the workgroup default apply
    pass


def get_athena_client() -> Any:
    return boto3.client("athena", region_name=REGION)


def get_cloudwatch_client() -> Any:
    return boto3.client("cloudwatch", region_name=REGION)


def get_ce_client() -> Any:
    """Cost Explorer client."""
    return boto3.client("ce", region_name="us-east-1")  # CE is global


def get_s3_client() -> Any:
    """S3 client for caching."""
    return boto3.client("s3", region_name=REGION)


# =============================================================================
# Caching Functions
# =============================================================================


def get_cache_key(timestamp: datetime | None = None) -> str:
    """Generate S3 key for hourly snapshot.

    Format: snapshots/YYYY/MM/DD/HH.json
    """
    ts = timestamp or datetime.now(UTC)
    return f"snapshots/{ts.year:04d}/{ts.month:02d}/{ts.day:02d}/{ts.hour:02d}.json"


def save_snapshot(data: dict[str, Any]) -> bool:
    """Save health data snapshot to S3."""
    if not CACHE_BUCKET:
        return False

    s3 = get_s3_client()
    key = get_cache_key()

    try:
        s3.put_object(
            Bucket=CACHE_BUCKET,
            Key=key,
            Body=json.dumps(data, default=str),
            ContentType="application/json",
        )

        # Also save as "latest.json" for quick access
        s3.put_object(
            Bucket=CACHE_BUCKET,
            Key="latest.json",
            Body=json.dumps(data, default=str),
            ContentType="application/json",
        )
        return True
    except ClientError:
        return False


def get_latest_snapshot() -> dict[str, Any] | None:
    """Get the most recent cached snapshot."""
    if not CACHE_BUCKET:
        return None

    s3 = get_s3_client()
    try:
        response = s3.get_object(Bucket=CACHE_BUCKET, Key="latest.json")
        return json.loads(response["Body"].read().decode("utf-8"))
    except ClientError:
        return None


def get_historical_snapshots(hours: int = 24) -> list[dict[str, Any]]:
    """Get historical snapshots for the specified time range."""
    if not CACHE_BUCKET:
        return []

    s3 = get_s3_client()
    snapshots = []
    now = datetime.now(UTC)

    for h in range(hours):
        ts = now - timedelta(hours=h)
        key = get_cache_key(ts)
        try:
            response = s3.get_object(Bucket=CACHE_BUCKET, Key=key)
            data = json.loads(response["Body"].read().decode("utf-8"))
            snapshots.append(data)
        except ClientError:
            # Missing hour, skip
            pass

    return snapshots


def collect_and_cache() -> dict[str, Any]:
    """Collect all health data and cache to S3.

    Called by scheduled EventBridge rule hourly.
    Returns the collected data.
    """
    data = {
        "security_lake": get_security_lake_health(),
        "costs": get_cost_metrics(),
        "detections": get_detection_status(),
        "generated_at": datetime.now(UTC).isoformat(),
        "cached": True,
    }

    save_snapshot(data)
    return data


def _start_query_kwargs(query: str) -> dict[str, Any]:
    """Build kwargs for start_query_execution, omitting ResultConfiguration when empty."""
    kwargs: dict[str, Any] = {
        "QueryString": query,
        "QueryExecutionContext": {"Database": SECURITY_LAKE_DB},
    }
    if ATHENA_OUTPUT:
        kwargs["ResultConfiguration"] = {"OutputLocation": ATHENA_OUTPUT}
    return kwargs


def execute_athena_query(query: str, timeout: int = 60) -> list[dict[str, Any]]:
    """Execute an Athena query and return results.

    Uses fast polling (0.3s) to reduce latency.
    """
    import time

    athena = get_athena_client()

    response = athena.start_query_execution(**_start_query_kwargs(query))
    query_id = response["QueryExecutionId"]

    # Fast poll for completion (0.3s interval)
    start = time.time()
    while time.time() - start < timeout:
        result = athena.get_query_execution(QueryExecutionId=query_id)
        state = result["QueryExecution"]["Status"]["State"]

        if state == "SUCCEEDED":
            break
        elif state in ("FAILED", "CANCELLED"):
            error = result["QueryExecution"]["Status"].get("StateChangeReason", "Unknown error")
            return [{"error": error}]
        time.sleep(0.3)  # Fast polling
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


def start_athena_query(query: str) -> str:
    """Start an Athena query and return the execution ID (non-blocking)."""
    athena = get_athena_client()
    response = athena.start_query_execution(**_start_query_kwargs(query))
    return response["QueryExecutionId"]


def wait_for_query(query_id: str, timeout: int = 60) -> list[dict[str, Any]]:
    """Wait for an Athena query to complete and return results."""
    import time

    athena = get_athena_client()
    start = time.time()

    while time.time() - start < timeout:
        result = athena.get_query_execution(QueryExecutionId=query_id)
        state = result["QueryExecution"]["Status"]["State"]

        if state == "SUCCEEDED":
            break
        elif state in ("FAILED", "CANCELLED"):
            error = result["QueryExecution"]["Status"].get("StateChangeReason", "Unknown")
            return [{"error": error}]
        time.sleep(0.3)
    else:
        return [{"error": "Query timeout"}]

    # Get results
    results = []
    paginator = athena.get_paginator("get_query_results")
    for page in paginator.paginate(QueryExecutionId=query_id):
        columns = [col["Name"] for col in page["ResultSet"]["ResultSetMetadata"]["ColumnInfo"]]
        for row in page["ResultSet"]["Rows"][1:]:
            values = [field.get("VarCharValue", "") for field in row["Data"]]
            results.append(dict(zip(columns, values, strict=False)))

    return results


def get_security_lake_health() -> dict[str, Any]:
    """Get Security Lake data source health metrics.

    Runs all table queries in parallel for ~5x speedup.
    Uses optimized queries for Iceberg tables.
    """
    # Security Lake tables to check
    tables = [
        ("cloud_trail_mgmt_2_0", "CloudTrail"),
        ("vpc_flow_2_0", "VPC Flow"),
        ("route53_2_0", "Route53"),
        ("sh_findings_2_0", "Security Hub"),
        ("lambda_execution_2_0", "Lambda"),  # Fixed: was lambda_2_0
    ]

    def query_table(table_info: tuple[str, str]) -> dict[str, Any]:
        """Query a single table (runs in parallel)."""
        table_suffix, display_name = table_info
        table = f"amazon_security_lake_table_us_west_2_{table_suffix}"

        # Optimized query:
        # - Only select needed columns (no SELECT *)
        # - Use approx_count_distinct for class_uid (faster)
        # - time_dt filter enables Iceberg partition pruning
        query = f"""
        SELECT
            COUNT(*) as event_count,
            MAX(time_dt) as latest_event,
            approx_distinct(class_uid) as class_count
        FROM "{SECURITY_LAKE_DB}"."{table}"
        WHERE time_dt >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
        """

        try:
            results = execute_athena_query(query, timeout=90)
            if results and "error" not in results[0]:
                row = results[0]
                event_count = int(row.get("event_count", 0))
                latest = row.get("latest_event", "")

                # Calculate freshness
                minutes_ago = None
                if latest:
                    try:
                        latest_dt = datetime.fromisoformat(latest.replace("Z", "+00:00"))
                        delta = datetime.now(UTC) - latest_dt
                        minutes_ago = int(delta.total_seconds() / 60)
                    except (ValueError, TypeError):
                        pass

                return {
                    "source": display_name,
                    "table": table,
                    "event_count_24h": event_count,
                    "latest_event": latest,
                    "minutes_since_last": minutes_ago,
                    "healthy": event_count > 0 and (minutes_ago or 999) < 120,
                }
            else:
                error = (
                    results[0].get("error", "Query returned no results")
                    if results
                    else "No results"
                )
                return {
                    "source": display_name,
                    "table": table,
                    "event_count_24h": 0,
                    "healthy": False,
                    "error": error,
                }
        except Exception as e:
            return {
                "source": display_name,
                "table": table,
                "healthy": False,
                "error": str(e),
            }

    # Run all queries in parallel (max 5 workers for 5 tables)
    health_data = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(query_table, t): t for t in tables}
        for future in as_completed(futures):
            health_data.append(future.result())

    # Sort by source name for consistent ordering
    health_data.sort(key=lambda x: x["source"])

    return {
        "sources": health_data,
        "checked_at": datetime.now(UTC).isoformat(),
    }


def get_cost_metrics() -> dict[str, Any]:
    """Get AWS cost metrics for security-related services."""
    ce = get_ce_client()

    end = datetime.now(UTC).date()
    start = end - timedelta(days=30)

    try:
        response = ce.get_cost_and_usage(
            TimePeriod={"Start": start.isoformat(), "End": end.isoformat()},
            Granularity="MONTHLY",
            Metrics=["UnblendedCost"],
            GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
            Filter={
                "Dimensions": {
                    "Key": "SERVICE",
                    "Values": [
                        "Amazon Athena",
                        "Amazon CloudWatch",
                        "Amazon S3",
                        "AWS Lambda",
                        "Amazon Security Lake",
                        "AWS Glue",
                    ],
                }
            },
        )

        costs = []
        for result in response.get("ResultsByTime", []):
            for group in result.get("Groups", []):
                service = group["Keys"][0]
                amount = float(group["Metrics"]["UnblendedCost"]["Amount"])
                if amount > 0.001:  # Filter out noise
                    costs.append(
                        {
                            "service": service,
                            "amount": round(amount, 2),
                            "currency": "USD",
                        }
                    )

        total = sum(c["amount"] for c in costs)

        return {
            "period": f"{start.isoformat()} to {end.isoformat()}",
            "services": sorted(costs, key=lambda x: x["amount"], reverse=True),
            "total": round(total, 2),
            "currency": "USD",
        }
    except ClientError as e:
        return {"error": str(e), "services": [], "total": 0}


def get_detection_status() -> dict[str, Any]:
    """Get detection rule execution status from CloudWatch metrics."""
    cw = get_cloudwatch_client()

    end = datetime.now(UTC)
    start = end - timedelta(hours=24)

    # Get Lambda invocation metrics for detection functions
    try:
        response = cw.get_metric_data(
            MetricDataQueries=[
                {
                    "Id": "invocations",
                    "MetricStat": {
                        "Metric": {
                            "Namespace": "AWS/Lambda",
                            "MetricName": "Invocations",
                            "Dimensions": [{"Name": "FunctionName", "Value": "secdash-*"}],
                        },
                        "Period": 3600,
                        "Stat": "Sum",
                    },
                    "ReturnData": True,
                },
                {
                    "Id": "errors",
                    "MetricStat": {
                        "Metric": {
                            "Namespace": "AWS/Lambda",
                            "MetricName": "Errors",
                            "Dimensions": [{"Name": "FunctionName", "Value": "secdash-*"}],
                        },
                        "Period": 3600,
                        "Stat": "Sum",
                    },
                    "ReturnData": True,
                },
            ],
            StartTime=start,
            EndTime=end,
        )

        invocations = sum(
            v
            for r in response["MetricDataResults"]
            if r["Id"] == "invocations"
            for v in r["Values"]
        )
        errors = sum(
            v for r in response["MetricDataResults"] if r["Id"] == "errors" for v in r["Values"]
        )

        return {
            "period_hours": 24,
            "total_invocations": int(invocations),
            "total_errors": int(errors),
            "success_rate": round(
                ((invocations - errors) / invocations * 100) if invocations > 0 else 100, 1
            ),
        }
    except ClientError:
        # No detection functions deployed yet
        return {
            "period_hours": 24,
            "total_invocations": 0,
            "total_errors": 0,
            "message": "No detection functions deployed",
        }


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Main Lambda handler for health dashboard API.

    Handles both:
    - HTTP API requests (from API Gateway)
    - Scheduled events (from EventBridge for hourly caching)
    """
    # Debug logging
    import logging

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    logger.info(f"Event received: {json.dumps(event, default=str)}")

    # Check if this is a scheduled event (EventBridge)
    if event.get("source") == "aws.events" or event.get("detail-type") == "Scheduled Event":
        logger.info("Scheduled event - collecting and caching health data")
        data = collect_and_cache()
        return {
            "statusCode": 200,
            "body": json.dumps({"message": "Cache updated", "data": data}, default=str),
        }

    # Get path from routeKey (e.g., "GET /health" -> "/health") or rawPath
    route_key = event.get("routeKey", "")
    if route_key and " " in route_key:
        path = route_key.split(" ", 1)[1]  # Extract path from "GET /health"
    else:
        # Fallback: strip stage prefix from rawPath if present
        raw_path = event.get("rawPath", event.get("path", "/"))
        # Remove stage prefix like "/prod" or "/dev"
        stage = event.get("requestContext", {}).get("stage", "")
        if stage and raw_path.startswith(f"/{stage}"):
            path = raw_path[len(f"/{stage}") :] or "/"
        else:
            path = raw_path

    method = event.get("requestContext", {}).get("http", {}).get("method", "GET")
    logger.info(f"Path: {path}, Method: {method}, RouteKey: {route_key}")

    # Parse query parameters
    query_params = event.get("queryStringParameters") or {}

    # Get origin from request for CORS
    request_origin = event.get("headers", {}).get("origin", "")

    # Allowed origins for CORS
    allowed_origins = [
        "https://health.lexicone.com",
        "https://d1jg66bgih1rig.cloudfront.net",  # CloudFront fallback
        "http://localhost:3000",
    ]

    # Determine which origin to allow
    cors_origin = "*"
    if request_origin in allowed_origins:
        cors_origin = request_origin

    # CORS headers - must allow credentials for Cognito auth
    headers = {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": cors_origin,
        "Access-Control-Allow-Methods": "GET, OPTIONS",
        "Access-Control-Allow-Headers": "Authorization, Content-Type, X-Requested-With",
        "Access-Control-Allow-Credentials": "true",
        "Access-Control-Max-Age": "86400",
        # Security headers
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    }

    # Handle OPTIONS for CORS preflight
    if method == "OPTIONS":
        return {"statusCode": 200, "headers": headers, "body": ""}

    try:
        if path == "/health" or path == "/":
            # Try to use cached data first (fast path)
            use_cache = query_params.get("cache", "true").lower() != "false"
            if use_cache and CACHE_BUCKET:
                cached = get_latest_snapshot()
                data = cached if cached else collect_and_cache()
            else:
                # Force fresh data (bypass cache)
                data = {
                    "security_lake": get_security_lake_health(),
                    "costs": get_cost_metrics(),
                    "detections": get_detection_status(),
                    "generated_at": datetime.now(UTC).isoformat(),
                    "cached": False,
                }

        elif path == "/health/sources":
            data = get_security_lake_health()

        elif path == "/health/costs":
            data = get_cost_metrics()

        elif path == "/health/detections":
            data = get_detection_status()

        elif path == "/health/history":
            # Return historical data for trend charts
            hours = int(query_params.get("hours", "24"))
            hours = min(hours, 168)  # Cap at 7 days
            snapshots = get_historical_snapshots(hours)
            data = {
                "hours_requested": hours,
                "snapshots_found": len(snapshots),
                "history": snapshots,
            }

        elif path == "/health/refresh":
            # Force a cache refresh
            data = collect_and_cache()

        else:
            return {
                "statusCode": 404,
                "headers": headers,
                "body": json.dumps({"error": "Not found"}),
            }

        return {
            "statusCode": 200,
            "headers": headers,
            "body": json.dumps(data, default=str),
        }

    except Exception as e:
        return {
            "statusCode": 500,
            "headers": headers,
            "body": json.dumps({"error": str(e)}),
        }
