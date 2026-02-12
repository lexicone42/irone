"""Tests for DynamoDB session backend.

Note: aioboto3 + moto have compatibility issues with async mocking.
We test the backend's constructor and configuration, then use a patched approach
for the async operations.
"""

import json
import time
from unittest.mock import AsyncMock, patch

import pytest


def test_dynamodb_backend_constructor():
    """DynamoDBSessionBackend initializes with correct defaults."""
    from secdashboards.web.auth.session.dynamodb import DynamoDBSessionBackend

    backend = DynamoDBSessionBackend()
    assert backend._table_name == "secdash_sessions"
    assert backend._max_age == 30 * 24 * 3600
    assert backend._region_name == "us-west-2"


def test_dynamodb_backend_custom_config():
    """DynamoDBSessionBackend accepts custom configuration."""
    from secdashboards.web.auth.session.dynamodb import DynamoDBSessionBackend

    backend = DynamoDBSessionBackend(
        table_name="custom_sessions",
        max_age=7200,
        region_name="eu-west-1",
        endpoint_url="http://localhost:8000",
    )
    assert backend._table_name == "custom_sessions"
    assert backend._max_age == 7200
    assert backend._region_name == "eu-west-1"


@pytest.mark.asyncio
async def test_dynamodb_load_returns_none_for_missing():
    """Load returns None when item doesn't exist."""
    from secdashboards.web.auth.session.dynamodb import DynamoDBSessionBackend

    backend = DynamoDBSessionBackend()

    mock_table = AsyncMock()
    mock_table.get_item = AsyncMock(return_value={})  # No "Item" key

    mock_dynamodb = AsyncMock()
    mock_dynamodb.Table = AsyncMock(return_value=mock_table)

    # Patch the aioboto3 session's resource context manager
    mock_cm = AsyncMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_dynamodb)
    mock_cm.__aexit__ = AsyncMock(return_value=False)

    with patch.object(backend._session, "resource", return_value=mock_cm):
        result = await backend.load("nonexistent-id")

    assert result is None


@pytest.mark.asyncio
async def test_dynamodb_load_returns_data():
    """Load returns deserialized data when item exists."""
    from secdashboards.web.auth.session.dynamodb import DynamoDBSessionBackend

    backend = DynamoDBSessionBackend()

    mock_table = AsyncMock()
    mock_table.get_item = AsyncMock(
        return_value={
            "Item": {
                "session_id": "test-id",
                "data": json.dumps({"key": "value"}),
                "created_at": int(time.time()),
            }
        }
    )

    mock_dynamodb = AsyncMock()
    mock_dynamodb.Table = AsyncMock(return_value=mock_table)

    mock_cm = AsyncMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_dynamodb)
    mock_cm.__aexit__ = AsyncMock(return_value=False)

    with patch.object(backend._session, "resource", return_value=mock_cm):
        result = await backend.load("test-id")

    assert result == {"key": "value"}


@pytest.mark.asyncio
async def test_dynamodb_load_expired_returns_none():
    """Load returns None and deletes when session is expired."""
    from secdashboards.web.auth.session.dynamodb import DynamoDBSessionBackend

    backend = DynamoDBSessionBackend(max_age=60)

    mock_table = AsyncMock()
    mock_table.get_item = AsyncMock(
        return_value={
            "Item": {
                "session_id": "test-id",
                "data": json.dumps({"key": "value"}),
                "created_at": int(time.time() - 120),  # Expired 60s ago
            }
        }
    )
    mock_table.delete_item = AsyncMock()

    mock_dynamodb = AsyncMock()
    mock_dynamodb.Table = AsyncMock(return_value=mock_table)

    mock_cm = AsyncMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_dynamodb)
    mock_cm.__aexit__ = AsyncMock(return_value=False)

    with patch.object(backend._session, "resource", return_value=mock_cm):
        result = await backend.load("test-id")

    assert result is None


@pytest.mark.asyncio
async def test_dynamodb_save_puts_item():
    """Save puts an item with the correct structure."""
    from secdashboards.web.auth.session.dynamodb import DynamoDBSessionBackend

    backend = DynamoDBSessionBackend()

    mock_table = AsyncMock()
    mock_table.put_item = AsyncMock()

    mock_dynamodb = AsyncMock()
    mock_dynamodb.Table = AsyncMock(return_value=mock_table)

    mock_cm = AsyncMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_dynamodb)
    mock_cm.__aexit__ = AsyncMock(return_value=False)

    with patch.object(backend._session, "resource", return_value=mock_cm):
        await backend.save("test-id", {"key": "value"})

    mock_table.put_item.assert_called_once()
    item = mock_table.put_item.call_args[1]["Item"]
    assert item["session_id"] == "test-id"
    assert json.loads(item["data"]) == {"key": "value"}
    assert "created_at" in item
    assert "ttl" in item


@pytest.mark.asyncio
async def test_dynamodb_delete_removes_item():
    """Delete removes the item by session_id."""
    from secdashboards.web.auth.session.dynamodb import DynamoDBSessionBackend

    backend = DynamoDBSessionBackend()

    mock_table = AsyncMock()
    mock_table.delete_item = AsyncMock()

    mock_dynamodb = AsyncMock()
    mock_dynamodb.Table = AsyncMock(return_value=mock_table)

    mock_cm = AsyncMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_dynamodb)
    mock_cm.__aexit__ = AsyncMock(return_value=False)

    with patch.object(backend._session, "resource", return_value=mock_cm):
        await backend.delete("test-id")

    mock_table.delete_item.assert_called_once_with(Key={"session_id": "test-id"})
