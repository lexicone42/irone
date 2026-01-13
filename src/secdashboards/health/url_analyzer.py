"""URL-based data analyzer for external data sources."""

from datetime import UTC, datetime
from typing import Any

import httpx
import polars as pl
import structlog

logger = structlog.get_logger()


class URLAnalyzer:
    """Analyze data from custom URLs for health monitoring."""

    def __init__(self, timeout: float = 30.0) -> None:
        self.timeout = timeout
        self._client: httpx.Client | None = None

    @property
    def client(self) -> httpx.Client:
        if not self._client:
            self._client = httpx.Client(timeout=self.timeout)
        return self._client

    def fetch_json(self, url: str, headers: dict[str, str] | None = None) -> dict[str, Any]:
        """Fetch JSON data from a URL."""
        response = self.client.get(url, headers=headers)
        response.raise_for_status()
        return response.json()

    def fetch_dataframe(
        self,
        url: str,
        format: str = "json",
        headers: dict[str, str] | None = None,
    ) -> pl.DataFrame:
        """Fetch data from a URL and return as a Polars DataFrame."""
        response = self.client.get(url, headers=headers)
        response.raise_for_status()

        if format == "json":
            data = response.json()
            if isinstance(data, list):
                return pl.DataFrame(data)
            elif isinstance(data, dict) and "data" in data:
                return pl.DataFrame(data["data"])
            else:
                return pl.DataFrame([data])
        elif format == "csv":
            return pl.read_csv(response.content)
        elif format == "parquet":
            return pl.read_parquet(response.content)
        else:
            raise ValueError(f"Unsupported format: {format}")

    def check_endpoint_health(
        self,
        url: str,
        expected_fields: list[str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Check if a URL endpoint is healthy and returning expected data."""
        start_time = datetime.now(UTC)
        result: dict[str, Any] = {
            "url": url,
            "checked_at": start_time.isoformat(),
            "healthy": False,
            "response_time_ms": 0,
            "issues": [],
        }

        try:
            response = self.client.get(url, headers=headers)
            result["response_time_ms"] = (datetime.now(UTC) - start_time).total_seconds() * 1000
            result["status_code"] = response.status_code

            if response.status_code != 200:
                result["issues"].append(f"Non-200 status code: {response.status_code}")
                return result

            # Try to parse as JSON
            try:
                data = response.json()
                result["content_type"] = "json"

                # Check for expected fields
                if expected_fields:
                    if isinstance(data, list) and len(data) > 0:
                        sample = data[0]
                    elif isinstance(data, dict):
                        sample = data.get("data", [{}])[0] if "data" in data else data
                    else:
                        sample = {}

                    missing = [f for f in expected_fields if f not in sample]
                    if missing:
                        result["issues"].append(f"Missing expected fields: {missing}")

                # Get record count
                if isinstance(data, list):
                    result["record_count"] = len(data)
                elif isinstance(data, dict) and "data" in data:
                    result["record_count"] = len(data["data"])

            except Exception:
                result["content_type"] = response.headers.get("content-type", "unknown")

            result["healthy"] = len(result["issues"]) == 0

        except httpx.TimeoutException:
            result["issues"].append(f"Request timed out after {self.timeout}s")
        except httpx.RequestError as e:
            result["issues"].append(f"Request failed: {e}")
        except Exception as e:
            result["issues"].append(f"Unexpected error: {e}")

        return result

    def analyze_data_freshness(
        self,
        url: str,
        time_field: str,
        headers: dict[str, str] | None = None,
        expected_freshness_minutes: int = 60,
    ) -> dict[str, Any]:
        """Analyze data freshness from a URL endpoint."""
        result: dict[str, Any] = {
            "url": url,
            "checked_at": datetime.now(UTC).isoformat(),
            "healthy": False,
            "time_field": time_field,
        }

        try:
            df = self.fetch_dataframe(url, headers=headers)

            if time_field not in df.columns:
                result["error"] = f"Time field '{time_field}' not found in data"
                return result

            # Parse time field
            time_col = df[time_field]
            if time_col.dtype == pl.Utf8:
                time_col = time_col.str.to_datetime()

            latest_time = time_col.max()
            earliest_time = time_col.min()

            result["record_count"] = len(df)
            result["latest_time"] = str(latest_time) if latest_time else None
            result["earliest_time"] = str(earliest_time) if earliest_time else None

            if latest_time:
                # Handle timezone-naive comparison
                if isinstance(latest_time, datetime):
                    latest_naive = latest_time.replace(tzinfo=None)
                    age_minutes = (datetime.now(UTC).replace(tzinfo=None) - latest_naive).total_seconds() / 60
                else:
                    # Fallback for non-datetime types
                    age_minutes = 0.0
                result["data_age_minutes"] = age_minutes
                result["expected_freshness_minutes"] = expected_freshness_minutes
                result["healthy"] = age_minutes <= expected_freshness_minutes

        except Exception as e:
            logger.exception("Failed to analyze data freshness", url=url)
            result["error"] = str(e)

        return result

    def generate_quicksight_url(
        self,
        dashboard_id: str,
        aws_account_id: str,
        region: str = "us-west-2",
    ) -> str:
        """Generate a QuickSight dashboard URL for analysis."""
        return (
            f"https://{region}.quicksight.aws.amazon.com/sn/dashboards/{dashboard_id}"
            f"?account_id={aws_account_id}"
        )

    def generate_athena_console_url(
        self,
        query: str,
        database: str,
        region: str = "us-west-2",
    ) -> str:
        """Generate an Athena console URL with a pre-filled query."""
        from urllib.parse import quote

        encoded_query = quote(query)
        return (
            f"https://{region}.console.aws.amazon.com/athena/home"
            f"?region={region}#/query-editor/history/{encoded_query}"
        )

    def generate_cloudwatch_logs_url(
        self,
        log_group: str,
        region: str = "us-west-2",
        filter_pattern: str | None = None,
    ) -> str:
        """Generate a CloudWatch Logs Insights URL."""
        from urllib.parse import quote

        base_url = (
            f"https://{region}.console.aws.amazon.com/cloudwatch/home"
            f"?region={region}#logsV2:log-groups/log-group/{quote(log_group, safe='')}"
        )

        if filter_pattern:
            base_url += f"/log-events?filterPattern={quote(filter_pattern)}"

        return base_url

    def close(self) -> None:
        """Close the HTTP client."""
        if self._client:
            self._client.close()
            self._client = None

    def __enter__(self) -> "URLAnalyzer":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()
