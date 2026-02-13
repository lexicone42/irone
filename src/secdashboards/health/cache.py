"""DynamoDB health cache — read/write pre-computed health check results.

The ``secdash_health_cache`` table uses a composite key so we can store
historical results per source while keeping "latest" lookups O(1).

Schema::

    PK: source_name  (S)
    SK: checked_at   (S, ISO-8601 timestamp)
    Attributes: healthy (BOOL), record_count (N), latency_seconds (N),
                last_data_time (S|NULL), error (S|NULL), details (S, JSON),
                ttl (N, epoch)
"""

import json
import logging
import time
from datetime import UTC, datetime
from typing import Any

import boto3
from boto3.dynamodb.conditions import Key

from secdashboards.connectors.base import HealthCheckResult

logger = logging.getLogger(__name__)

# Items expire after 7 days by default (DynamoDB TTL)
_DEFAULT_TTL_SECONDS = 7 * 24 * 3600


class HealthCacheClient:
    """Reads and writes health check results to DynamoDB.

    This client is synchronous (standard boto3) — designed for use in both
    the API Lambda and the scheduled health checker Lambda.
    """

    def __init__(
        self,
        table_name: str = "secdash_health_cache",
        region_name: str = "us-west-2",
        endpoint_url: str = "",
        ttl_seconds: int = _DEFAULT_TTL_SECONDS,
    ) -> None:
        self._table_name = table_name
        self._ttl_seconds = ttl_seconds
        kwargs: dict[str, Any] = {"region_name": region_name}
        if endpoint_url:
            kwargs["endpoint_url"] = endpoint_url
        self._resource = boto3.resource("dynamodb", **kwargs)
        self._table = self._resource.Table(table_name)

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def put(self, result: HealthCheckResult) -> None:
        """Write a single health check result to the cache."""
        item: dict[str, Any] = {
            "source_name": result.source_name,
            "checked_at": result.checked_at.isoformat(),
            "healthy": result.healthy,
            "record_count": result.record_count,
            "latency_seconds": str(result.latency_seconds),
            "ttl": int(time.time()) + self._ttl_seconds,
        }
        if result.last_data_time:
            item["last_data_time"] = result.last_data_time.isoformat()
        if result.error:
            item["error"] = result.error
        if result.details:
            item["details"] = json.dumps(result.details)

        self._table.put_item(Item=item)
        logger.debug("Cached health for %s at %s", result.source_name, item["checked_at"])

    def put_many(self, results: list[HealthCheckResult]) -> None:
        """Batch-write multiple health check results."""
        with self._table.batch_writer() as batch:
            for result in results:
                item: dict[str, Any] = {
                    "source_name": result.source_name,
                    "checked_at": result.checked_at.isoformat(),
                    "healthy": result.healthy,
                    "record_count": result.record_count,
                    "latency_seconds": str(result.latency_seconds),
                    "ttl": int(time.time()) + self._ttl_seconds,
                }
                if result.last_data_time:
                    item["last_data_time"] = result.last_data_time.isoformat()
                if result.error:
                    item["error"] = result.error
                if result.details:
                    item["details"] = json.dumps(result.details)
                batch.put_item(Item=item)

        logger.info("Batch-cached %d health results", len(results))

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get_latest(self, source_name: str) -> dict[str, Any] | None:
        """Get the most recent health check result for a source.

        Uses a descending query on the sort key (checked_at) with limit=1.
        """
        response = self._table.query(
            KeyConditionExpression=Key("source_name").eq(source_name),
            ScanIndexForward=False,
            Limit=1,
        )
        items = response.get("Items", [])
        if not items:
            return None
        return self._deserialize(items[0])

    def get_all_latest(self) -> list[dict[str, Any]]:
        """Get the latest health result for every source.

        Scans the table and keeps only the most recent item per source.
        For small source counts (<20) this is efficient enough.
        """
        response = self._table.scan()
        items = response.get("Items", [])

        # Group by source_name, keep most recent
        latest: dict[str, dict[str, Any]] = {}
        for item in items:
            name = str(item["source_name"])
            if name not in latest or item["checked_at"] > latest[name]["checked_at"]:
                latest[name] = dict(item)

        return [self._deserialize(item) for item in latest.values()]

    def get_history(self, source_name: str, limit: int = 24) -> list[dict[str, Any]]:
        """Get recent health check history for a source (newest first)."""
        response = self._table.query(
            KeyConditionExpression=Key("source_name").eq(source_name),
            ScanIndexForward=False,
            Limit=limit,
        )
        return [self._deserialize(item) for item in response.get("Items", [])]

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _deserialize(item: dict[str, Any]) -> dict[str, Any]:
        """Convert a DynamoDB item to a JSON-friendly dict."""
        result: dict[str, Any] = {
            "source_name": item["source_name"],
            "checked_at": item["checked_at"],
            "healthy": item.get("healthy", False),
            "record_count": int(item.get("record_count", 0)),
            "latency_seconds": float(item.get("latency_seconds", 0)),
            "last_data_time": item.get("last_data_time"),
            "error": item.get("error"),
            "details": json.loads(item["details"]) if item.get("details") else {},
        }
        # Compute data_age_minutes from last_data_time
        if result["last_data_time"]:
            try:
                ldt = datetime.fromisoformat(result["last_data_time"])
                age = (datetime.now(UTC) - ldt).total_seconds() / 60
                result["data_age_minutes"] = round(age, 1)
            except (ValueError, TypeError):
                result["data_age_minutes"] = None
        else:
            result["data_age_minutes"] = None

        return result
