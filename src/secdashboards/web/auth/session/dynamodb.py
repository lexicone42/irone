"""DynamoDB session backend for production deployments."""

from __future__ import annotations

import json
import time
from typing import Any

import aioboto3


class DynamoDBSessionBackend:
    """Session backend using AWS DynamoDB.

    Table schema:
        Partition key: session_id (S)
        Attributes: data (S, JSON-encoded), created_at (N), ttl (N)

    Enable TTL on the ``ttl`` attribute for automatic cleanup.
    """

    def __init__(
        self,
        table_name: str = "secdash_sessions",
        max_age: int = 30 * 24 * 3600,
        endpoint_url: str = "",
        region_name: str = "us-west-2",
    ) -> None:
        self._table_name = table_name
        self._max_age = max_age
        self._session = aioboto3.Session()
        self._endpoint_url = endpoint_url or None
        self._region_name = region_name

    async def load(self, session_id: str) -> dict[str, Any] | None:
        async with self._session.resource(
            "dynamodb",
            endpoint_url=self._endpoint_url,
            region_name=self._region_name,
        ) as dynamodb:
            table = await dynamodb.Table(self._table_name)
            response = await table.get_item(Key={"session_id": session_id})

        item = response.get("Item")
        if item is None:
            return None

        created_at = float(item.get("created_at", 0))
        if time.time() - created_at > self._max_age:
            await self.delete(session_id)
            return None

        return json.loads(item["data"])

    async def save(self, session_id: str, data: dict[str, Any]) -> None:
        now = time.time()
        async with self._session.resource(
            "dynamodb",
            endpoint_url=self._endpoint_url,
            region_name=self._region_name,
        ) as dynamodb:
            table = await dynamodb.Table(self._table_name)
            await table.put_item(
                Item={
                    "session_id": session_id,
                    "data": json.dumps(data),
                    "created_at": int(now),
                    "ttl": int(now + self._max_age),
                }
            )

    async def delete(self, session_id: str) -> None:
        async with self._session.resource(
            "dynamodb",
            endpoint_url=self._endpoint_url,
            region_name=self._region_name,
        ) as dynamodb:
            table = await dynamodb.Table(self._table_name)
            await table.delete_item(Key={"session_id": session_id})
