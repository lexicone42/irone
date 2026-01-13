"""Tests for S3-based rule storage."""

import tempfile
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from secdashboards.detections.rule import SQLDetectionRule
from secdashboards.detections.rule_store import (
    RuleSchema,
    RuleVersion,
    S3RuleStore,
)


# Sample valid rule YAML content
VALID_RULE_YAML = """
id: test-rule-001
name: Test Detection Rule
description: A test rule for unit testing
author: test-author
severity: high
tags:
  - test
  - security
mitre_attack:
  - T1078
data_sources:
  - cloudtrail
schedule: rate(5 minutes)
enabled: true
query: |
  SELECT time_dt, actor.user.name, api.operation
  FROM cloudtrail
  WHERE api.operation = 'CreateAccessKey'
    AND time_dt >= TIMESTAMP '{start_time}'
    AND time_dt < TIMESTAMP '{end_time}'
threshold: 1
group_by:
  - actor.user.name
"""

VALID_RULE_YAML_MINIMAL = """
id: minimal-rule
name: Minimal Rule
query: SELECT * FROM events WHERE time_dt > TIMESTAMP '2024-01-01'
"""


class TestRuleSchema:
    """Tests for RuleSchema validation."""

    def test_valid_rule_schema(self) -> None:
        """Test validating a complete rule schema."""
        schema = RuleSchema(
            id="test-rule-001",
            name="Test Rule",
            description="A test rule",
            author="tester",
            severity="high",
            tags=["test"],
            mitre_attack=["T1078"],
            data_sources=["cloudtrail"],
            schedule="rate(5 minutes)",
            enabled=True,
            query="SELECT * FROM events WHERE time > 0",
            threshold=1,
            group_by=["user"],
        )
        assert schema.id == "test-rule-001"
        assert schema.severity == "high"

    def test_minimal_rule_schema(self) -> None:
        """Test validating a minimal rule with defaults."""
        schema = RuleSchema(
            id="minimal",
            name="Minimal",
            query="SELECT * FROM events WHERE 1=1",
        )
        assert schema.severity == "medium"  # default
        assert schema.enabled is True  # default
        assert schema.threshold == 1  # default
        assert schema.tags == []  # default

    def test_invalid_rule_id_empty(self) -> None:
        """Test that empty rule ID fails validation."""
        with pytest.raises(ValueError):
            RuleSchema(id="", name="Test", query="SELECT 1")

    def test_invalid_rule_id_special_chars(self) -> None:
        """Test that special characters in rule ID fail validation."""
        with pytest.raises(ValueError):
            RuleSchema(id="test rule!", name="Test", query="SELECT 1")

    def test_invalid_severity(self) -> None:
        """Test that invalid severity fails validation."""
        with pytest.raises(ValueError):
            RuleSchema(
                id="test",
                name="Test",
                query="SELECT * FROM t",
                severity="extreme",  # invalid
            )

    def test_invalid_query_too_short(self) -> None:
        """Test that query too short fails validation."""
        with pytest.raises(ValueError):
            RuleSchema(id="test", name="Test", query="SELECT")  # too short

    def test_valid_severities(self) -> None:
        """Test all valid severity levels."""
        for severity in ["critical", "high", "medium", "low", "info"]:
            schema = RuleSchema(
                id="test",
                name="Test",
                query="SELECT * FROM events WHERE 1=1",
                severity=severity,
            )
            assert schema.severity == severity


class TestS3RuleStoreValidation:
    """Tests for S3RuleStore validation methods."""

    @pytest.fixture
    def rule_store(self) -> S3RuleStore:
        """Create a rule store with mocked S3."""
        with patch("boto3.client"):
            store = S3RuleStore(
                bucket="test-bucket",
                prefix="rules/",
                region="us-west-2",
            )
            return store

    def test_validate_rule_content_valid(self, rule_store: S3RuleStore) -> None:
        """Test validating valid rule content."""
        result = rule_store._validate_rule_content(VALID_RULE_YAML)
        assert result["id"] == "test-rule-001"
        assert result["name"] == "Test Detection Rule"
        assert result["severity"] == "high"

    def test_validate_rule_content_minimal(self, rule_store: S3RuleStore) -> None:
        """Test validating minimal rule content."""
        result = rule_store._validate_rule_content(VALID_RULE_YAML_MINIMAL)
        assert result["id"] == "minimal-rule"
        assert result["severity"] == "medium"  # default

    def test_validate_rule_content_invalid_yaml(self, rule_store: S3RuleStore) -> None:
        """Test validating invalid YAML."""
        with pytest.raises(ValueError, match="Invalid YAML"):
            rule_store._validate_rule_content("not: valid: yaml: :::")

    def test_validate_rule_content_not_dict(self, rule_store: S3RuleStore) -> None:
        """Test validating YAML that's not a dictionary."""
        with pytest.raises(ValueError, match="must be a YAML dictionary"):
            rule_store._validate_rule_content("- item1\n- item2")

    def test_validate_rule_content_missing_required(
        self, rule_store: S3RuleStore
    ) -> None:
        """Test validating rule missing required fields."""
        with pytest.raises(ValueError, match="Schema validation failed"):
            rule_store._validate_rule_content("id: test\nname: Test")  # missing query

    def test_compute_hash(self, rule_store: S3RuleStore) -> None:
        """Test content hash computation."""
        hash1 = rule_store._compute_hash("test content")
        hash2 = rule_store._compute_hash("test content")
        hash3 = rule_store._compute_hash("different content")

        assert hash1 == hash2  # Same content = same hash
        assert hash1 != hash3  # Different content = different hash
        assert len(hash1) == 64  # SHA-256 = 64 hex chars

    def test_check_dangerous_patterns_safe(self, rule_store: S3RuleStore) -> None:
        """Test that safe content passes pattern check."""
        # Use content without YAML literal block indicators (| and >) which are
        # false positives for shell injection patterns
        safe_content = """
id: safe-rule
name: Safe Rule
query: SELECT * FROM events WHERE time_dt BETWEEN TIMESTAMP '2024-01-01' AND TIMESTAMP '2024-01-02'
"""
        warnings = rule_store._check_for_dangerous_patterns(safe_content)
        assert len(warnings) == 0

    def test_check_dangerous_patterns_sql_keywords(
        self, rule_store: S3RuleStore
    ) -> None:
        """Test detection of dangerous SQL keywords."""
        dangerous_content = """
id: bad-rule
name: Bad Rule
query: SELECT * FROM events; DROP TABLE users;
"""
        warnings = rule_store._check_for_dangerous_patterns(dangerous_content)
        assert any("DROP" in w for w in warnings)

    def test_check_dangerous_patterns_shell_injection(
        self, rule_store: S3RuleStore
    ) -> None:
        """Test detection of shell injection patterns."""
        dangerous_content = """
id: shell-rule
name: Shell Rule
query: SELECT * FROM events WHERE cmd = '$(whoami)'
"""
        warnings = rule_store._check_for_dangerous_patterns(dangerous_content)
        assert any("$(" in w for w in warnings)


class TestS3RuleStoreSaveLoad:
    """Tests for S3RuleStore save and load operations."""

    @pytest.fixture
    def mock_s3(self):
        """Create mock S3 client."""
        mock = MagicMock()
        return mock

    @pytest.fixture
    def rule_store(self, mock_s3) -> S3RuleStore:
        """Create a rule store with mocked S3."""
        with patch("boto3.client", return_value=mock_s3):
            store = S3RuleStore(
                bucket="test-bucket",
                prefix="rules/",
                region="us-west-2",
            )
            store._s3 = mock_s3
            return store

    def test_save_rule_success(self, rule_store: S3RuleStore, mock_s3) -> None:
        """Test saving a valid rule."""
        mock_s3.put_object.return_value = {"VersionId": "v1"}

        version = rule_store.save_rule(
            rule_id="test-rule-001",
            content=VALID_RULE_YAML,
            author="tester",
        )

        assert version.rule_id == "test-rule-001"
        assert version.version_id == "v1"
        assert version.author == "tester"
        assert len(version.content_hash) == 64

        # Verify S3 was called correctly
        mock_s3.put_object.assert_called_once()
        call_kwargs = mock_s3.put_object.call_args[1]
        assert call_kwargs["Bucket"] == "test-bucket"
        assert call_kwargs["Key"] == "rules/test-rule-001.yaml"
        assert call_kwargs["ContentType"] == "application/x-yaml"

    def test_save_rule_id_mismatch(self, rule_store: S3RuleStore) -> None:
        """Test that rule ID mismatch fails."""
        with pytest.raises(ValueError, match="Rule ID mismatch"):
            rule_store.save_rule(
                rule_id="wrong-id",
                content=VALID_RULE_YAML,  # Contains id: test-rule-001
            )

    def test_save_rule_invalid_content(self, rule_store: S3RuleStore) -> None:
        """Test that invalid content fails."""
        with pytest.raises(ValueError):
            rule_store.save_rule(
                rule_id="test",
                content="invalid: yaml: content",
            )

    def test_load_rule_success(self, rule_store: S3RuleStore, mock_s3) -> None:
        """Test loading a rule from S3."""
        mock_s3.get_object.return_value = {
            "Body": MagicMock(read=lambda: VALID_RULE_YAML.encode("utf-8")),
            "VersionId": "v1",
            "LastModified": datetime.now(UTC),
            "ContentLength": len(VALID_RULE_YAML),
            "Metadata": {"author": "tester", "content-hash": "abc123"},
        }

        rule, version = rule_store.load_rule("test-rule-001")

        assert isinstance(rule, SQLDetectionRule)
        assert rule.id == "test-rule-001"
        assert rule.name == "Test Detection Rule"
        assert rule.metadata.severity.value == "high"
        assert version.version_id == "v1"

    def test_load_rule_specific_version(
        self, rule_store: S3RuleStore, mock_s3
    ) -> None:
        """Test loading a specific version of a rule."""
        mock_s3.get_object.return_value = {
            "Body": MagicMock(read=lambda: VALID_RULE_YAML.encode("utf-8")),
            "VersionId": "v2",
            "LastModified": datetime.now(UTC),
            "ContentLength": len(VALID_RULE_YAML),
            "Metadata": {},
        }

        rule, version = rule_store.load_rule("test-rule-001", version_id="v2")

        assert version.version_id == "v2"
        mock_s3.get_object.assert_called_once()
        call_kwargs = mock_s3.get_object.call_args[1]
        assert call_kwargs["VersionId"] == "v2"

    def test_load_rule_not_found(self, rule_store: S3RuleStore, mock_s3) -> None:
        """Test loading a non-existent rule."""
        from botocore.exceptions import ClientError

        mock_s3.get_object.side_effect = ClientError(
            {"Error": {"Code": "NoSuchKey"}},
            "GetObject",
        )

        with pytest.raises(ValueError, match="Rule not found"):
            rule_store.load_rule("nonexistent-rule")


class TestS3RuleStoreList:
    """Tests for S3RuleStore list operations."""

    @pytest.fixture
    def mock_s3(self):
        """Create mock S3 client."""
        return MagicMock()

    @pytest.fixture
    def rule_store(self, mock_s3) -> S3RuleStore:
        """Create a rule store with mocked S3."""
        with patch("boto3.client", return_value=mock_s3):
            store = S3RuleStore(
                bucket="test-bucket",
                prefix="rules/",
            )
            store._s3 = mock_s3
            return store

    def test_list_rules(self, rule_store: S3RuleStore, mock_s3) -> None:
        """Test listing rules."""
        # Mock paginator
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "Contents": [
                    {"Key": "rules/rule-1.yaml"},
                    {"Key": "rules/rule-2.yaml"},
                    {"Key": "rules/rule-3.yaml"},
                ]
            }
        ]
        mock_s3.get_paginator.return_value = mock_paginator

        rules = rule_store.list_rules()

        assert rules == ["rule-1", "rule-2", "rule-3"]

    def test_list_rules_empty(self, rule_store: S3RuleStore, mock_s3) -> None:
        """Test listing rules when bucket is empty."""
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [{"Contents": []}]
        mock_s3.get_paginator.return_value = mock_paginator

        rules = rule_store.list_rules()

        assert rules == []

    def test_list_rules_filters_non_yaml(
        self, rule_store: S3RuleStore, mock_s3
    ) -> None:
        """Test that non-YAML files are filtered out."""
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "Contents": [
                    {"Key": "rules/rule-1.yaml"},
                    {"Key": "rules/readme.md"},
                    {"Key": "rules/rule-2.yaml"},
                    {"Key": "rules/backup.json"},
                ]
            }
        ]
        mock_s3.get_paginator.return_value = mock_paginator

        rules = rule_store.list_rules()

        assert rules == ["rule-1", "rule-2"]


class TestS3RuleStoreHistory:
    """Tests for S3RuleStore version history."""

    @pytest.fixture
    def mock_s3(self):
        """Create mock S3 client."""
        return MagicMock()

    @pytest.fixture
    def rule_store(self, mock_s3) -> S3RuleStore:
        """Create a rule store with mocked S3."""
        with patch("boto3.client", return_value=mock_s3):
            store = S3RuleStore(
                bucket="test-bucket",
                prefix="rules/",
            )
            store._s3 = mock_s3
            return store

    def test_get_rule_history(self, rule_store: S3RuleStore, mock_s3) -> None:
        """Test getting rule version history."""
        now = datetime.now(UTC)
        mock_s3.list_object_versions.return_value = {
            "Versions": [
                {
                    "Key": "rules/test-rule.yaml",
                    "VersionId": "v3",
                    "LastModified": now,
                    "Size": 500,
                },
                {
                    "Key": "rules/test-rule.yaml",
                    "VersionId": "v2",
                    "LastModified": now,
                    "Size": 450,
                },
                {
                    "Key": "rules/test-rule.yaml",
                    "VersionId": "v1",
                    "LastModified": now,
                    "Size": 400,
                },
            ]
        }

        history = rule_store.get_rule_history("test-rule")

        assert len(history) == 3
        assert history[0].version_id == "v3"
        assert history[1].version_id == "v2"
        assert history[2].version_id == "v1"


class TestS3RuleStoreLocalFallback:
    """Tests for S3RuleStore local fallback functionality."""

    @pytest.fixture
    def temp_rules_dir(self, tmp_path: Path) -> Path:
        """Create a temporary directory with a test rule."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()

        # Write a valid rule file
        rule_file = rules_dir / "local-rule.yaml"
        rule_file.write_text(
            """
id: local-rule
name: Local Test Rule
query: SELECT * FROM events WHERE time_dt > TIMESTAMP '2024-01-01'
severity: low
"""
        )
        return rules_dir

    @pytest.fixture
    def mock_s3(self):
        """Create mock S3 client."""
        return MagicMock()

    def test_local_fallback_when_s3_fails(
        self, mock_s3, temp_rules_dir: Path
    ) -> None:
        """Test loading from local when S3 fails."""
        from botocore.exceptions import ClientError

        with patch("boto3.client", return_value=mock_s3):
            store = S3RuleStore(
                bucket="test-bucket",
                prefix="rules/",
                enable_local_fallback=True,
                local_rules_dir=temp_rules_dir,
            )
            store._s3 = mock_s3

        mock_s3.get_object.side_effect = ClientError(
            {"Error": {"Code": "NoSuchKey"}},
            "GetObject",
        )

        rule, version = store.load_rule("local-rule")

        assert rule.id == "local-rule"
        assert rule.name == "Local Test Rule"
        assert version.version_id == "local"

    def test_local_fallback_disabled(self, mock_s3) -> None:
        """Test that local fallback is disabled by default."""
        from botocore.exceptions import ClientError

        with patch("boto3.client", return_value=mock_s3):
            store = S3RuleStore(
                bucket="test-bucket",
                prefix="rules/",
                enable_local_fallback=False,
            )
            store._s3 = mock_s3

        mock_s3.get_object.side_effect = ClientError(
            {"Error": {"Code": "NoSuchKey"}},
            "GetObject",
        )

        with pytest.raises(ValueError, match="Rule not found"):
            store.load_rule("any-rule")

    def test_list_includes_local_rules(self, mock_s3, temp_rules_dir: Path) -> None:
        """Test that list_rules includes local rules."""
        with patch("boto3.client", return_value=mock_s3):
            store = S3RuleStore(
                bucket="test-bucket",
                prefix="rules/",
                enable_local_fallback=True,
                local_rules_dir=temp_rules_dir,
            )
            store._s3 = mock_s3

        # S3 returns one rule
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {"Contents": [{"Key": "rules/s3-rule.yaml"}]}
        ]
        mock_s3.get_paginator.return_value = mock_paginator

        rules = store.list_rules()

        # Should include both S3 and local rules
        assert "s3-rule" in rules
        assert "local-rule" in rules


class TestS3RuleStoreSync:
    """Tests for S3RuleStore sync functionality."""

    @pytest.fixture
    def mock_s3(self):
        """Create mock S3 client."""
        return MagicMock()

    @pytest.fixture
    def temp_rules_dir(self, tmp_path: Path) -> Path:
        """Create a temporary directory with test rules."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()

        # Write valid rule files
        (rules_dir / "new-rule.yaml").write_text(
            """
id: new-rule
name: New Rule
query: SELECT * FROM events WHERE time_dt > TIMESTAMP '2024-01-01'
"""
        )

        (rules_dir / "existing-rule.yaml").write_text(
            """
id: existing-rule
name: Existing Rule
query: SELECT * FROM events WHERE time_dt > TIMESTAMP '2024-01-01'
"""
        )

        return rules_dir

    def test_sync_dry_run(self, mock_s3, temp_rules_dir: Path) -> None:
        """Test sync in dry run mode."""
        from botocore.exceptions import ClientError

        with patch("boto3.client", return_value=mock_s3):
            store = S3RuleStore(bucket="test-bucket", prefix="rules/")
            store._s3 = mock_s3

        # Read actual local file content to ensure hash matches
        existing_content = (temp_rules_dir / "existing-rule.yaml").read_text()

        # Simulate new-rule not existing, existing-rule exists with matching content
        def get_object_side_effect(**kwargs):
            if "new-rule" in kwargs["Key"]:
                raise ClientError({"Error": {"Code": "NoSuchKey"}}, "GetObject")
            return {
                "Body": MagicMock(read=lambda: existing_content.encode("utf-8")),
                "VersionId": "v1",
                "LastModified": datetime.now(UTC),
                "ContentLength": len(existing_content),
                "Metadata": {},
            }

        mock_s3.get_object.side_effect = get_object_side_effect

        results = store.sync_from_local(temp_rules_dir, dry_run=True)

        assert results["new-rule"] == "would_be_created"
        assert results["existing-rule"] == "skipped"  # Same content
        mock_s3.put_object.assert_not_called()  # Dry run = no writes


class TestRuleVersion:
    """Tests for RuleVersion model."""

    def test_create_rule_version(self) -> None:
        """Test creating a RuleVersion."""
        version = RuleVersion(
            rule_id="test-rule",
            version_id="v1",
            last_modified=datetime.now(UTC),
            content_hash="abc123",
            size_bytes=500,
            author="tester",
        )
        assert version.rule_id == "test-rule"
        assert version.version_id == "v1"
        assert version.author == "tester"

    def test_rule_version_defaults(self) -> None:
        """Test RuleVersion with defaults."""
        version = RuleVersion(
            rule_id="test-rule",
            version_id="v1",
            last_modified=datetime.now(UTC),
            content_hash="abc123",
            size_bytes=500,
        )
        assert version.author == ""  # default
