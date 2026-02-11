"""Secure rule storage with S3 backend.

This module provides a secure alternative to filesystem-based rule loading
by storing detection rules in S3 with:
- YAML-only rules (no arbitrary code execution)
- Schema validation
- Version tracking via S3 versioning
- Audit logging
- Optional local fallback for development
"""

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import boto3
import structlog
import yaml
from botocore.exceptions import ClientError
from pydantic import BaseModel, Field, ValidationError

from secdashboards.detections.rule import (
    DetectionMetadata,
    DetectionRule,
    Severity,
    SQLDetectionRule,
)

logger = structlog.get_logger()


class RuleSchema(BaseModel):
    """Schema for validating detection rule YAML."""

    id: str = Field(..., min_length=1, max_length=100, pattern=r"^[a-zA-Z0-9_-]+$")
    name: str = Field(..., min_length=1, max_length=200)
    description: str = ""
    author: str = ""
    severity: str = Field(default="medium", pattern=r"^(critical|high|medium|low|info)$")
    tags: list[str] = Field(default_factory=list)
    mitre_attack: list[str] = Field(default_factory=list)
    data_sources: list[str] = Field(default_factory=list)
    schedule: str = Field(default="rate(5 minutes)")
    enabled: bool = True
    query: str = Field(..., min_length=10)
    threshold: int = Field(default=1, ge=0)
    group_by: list[str] = Field(default_factory=list)


class RuleVersion(BaseModel):
    """Metadata about a rule version."""

    rule_id: str
    version_id: str
    last_modified: datetime
    content_hash: str
    size_bytes: int
    author: str = ""


class S3RuleStore:
    """Secure S3-based storage for detection rules.

    Features:
    - YAML-only (no Python code execution)
    - Schema validation before saving
    - Content hash verification
    - Version history via S3 versioning
    - Audit logging
    """

    def __init__(
        self,
        bucket: str,
        prefix: str = "detection-rules/",
        region: str | None = None,
        enable_local_fallback: bool = False,
        local_rules_dir: Path | None = None,
    ) -> None:
        """Initialize the S3 rule store.

        Args:
            bucket: S3 bucket name
            prefix: Key prefix for rules (must end with /)
            region: AWS region (uses default if not specified)
            enable_local_fallback: Allow loading from local directory
            local_rules_dir: Path to local rules directory (for dev)
        """
        self.bucket = bucket
        self.prefix = prefix if prefix.endswith("/") else f"{prefix}/"
        self.region = region
        self._s3 = boto3.client("s3", region_name=region)
        self._enable_local_fallback = enable_local_fallback
        self._local_rules_dir = local_rules_dir

        logger.info(
            "initialized_s3_rule_store",
            bucket=bucket,
            prefix=prefix,
            local_fallback=enable_local_fallback,
        )

    def _validate_rule_content(self, content: str) -> dict[str, Any]:
        """Validate rule content against schema.

        Args:
            content: YAML content to validate

        Returns:
            Parsed and validated rule dictionary

        Raises:
            ValueError: If validation fails
        """
        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML: {e}") from e

        if not isinstance(data, dict):
            raise ValueError("Rule must be a YAML dictionary")

        # Validate against schema
        try:
            validated = RuleSchema(**data)
            return validated.model_dump()
        except ValidationError as e:
            raise ValueError(f"Schema validation failed: {e}") from e

    def _compute_hash(self, content: str) -> str:
        """Compute SHA-256 hash of content."""
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def _check_for_dangerous_patterns(self, content: str) -> list[str]:
        """Check for potentially dangerous patterns in rule content.

        Returns list of warnings if any dangerous patterns found.
        """
        warnings = []

        # Check for potential code injection in query
        dangerous_keywords = [
            "DROP",
            "DELETE",
            "INSERT",
            "UPDATE",
            "TRUNCATE",
            "ALTER",
            "CREATE",
            "GRANT",
            "REVOKE",
        ]

        content_upper = content.upper()
        for keyword in dangerous_keywords:
            if keyword in content_upper and (
                f" {keyword} " in content_upper or content_upper.startswith(keyword)
            ):
                warnings.append(f"Potentially dangerous SQL keyword: {keyword}")

        # Check for shell injection patterns
        shell_patterns = ["$(", "`", "&&", "||", "|", ";", ">>", ">"]
        for pattern in shell_patterns:
            if pattern in content:
                warnings.append(f"Potential shell injection pattern: {pattern}")

        return warnings

    def save_rule(
        self,
        rule_id: str,
        content: str,
        author: str = "",
        force: bool = False,
    ) -> RuleVersion:
        """Save a detection rule to S3.

        Args:
            rule_id: Unique rule identifier
            content: YAML content of the rule
            author: Author of this version
            force: Skip safety checks (not recommended)

        Returns:
            RuleVersion with version information

        Raises:
            ValueError: If validation fails
            ClientError: If S3 operation fails
        """
        # Validate content
        validated = self._validate_rule_content(content)

        # Ensure rule_id in content matches parameter
        if validated["id"] != rule_id:
            raise ValueError(f"Rule ID mismatch: {validated['id']} != {rule_id}")

        # Check for dangerous patterns
        if not force:
            warnings = self._check_for_dangerous_patterns(content)
            if warnings:
                logger.warning(
                    "dangerous_patterns_in_rule",
                    rule_id=rule_id,
                    warnings=warnings,
                )

        # Compute hash
        content_hash = self._compute_hash(content)

        # Save to S3
        key = f"{self.prefix}{rule_id}.yaml"
        try:
            response = self._s3.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=content.encode("utf-8"),
                ContentType="application/x-yaml",
                Metadata={
                    "content-hash": content_hash,
                    "author": author,
                    "rule-id": rule_id,
                },
            )

            version_id = response.get("VersionId", "null")

            logger.info(
                "saved_detection_rule",
                rule_id=rule_id,
                version_id=version_id,
                content_hash=content_hash[:16],
                author=author,
            )

            return RuleVersion(
                rule_id=rule_id,
                version_id=version_id,
                last_modified=datetime.now(UTC),
                content_hash=content_hash,
                size_bytes=len(content),
                author=author,
            )

        except ClientError as e:
            logger.error(
                "failed_to_save_rule",
                rule_id=rule_id,
                error=str(e),
            )
            raise

    def load_rule(
        self,
        rule_id: str,
        version_id: str | None = None,
    ) -> tuple[DetectionRule, RuleVersion]:
        """Load a detection rule from S3.

        Args:
            rule_id: Rule identifier
            version_id: Specific version to load (latest if None)

        Returns:
            Tuple of (DetectionRule, RuleVersion)

        Raises:
            ValueError: If rule not found or invalid
            ClientError: If S3 operation fails
        """
        key = f"{self.prefix}{rule_id}.yaml"

        try:
            get_params: dict[str, Any] = {"Bucket": self.bucket, "Key": key}
            if version_id:
                get_params["VersionId"] = version_id

            response = self._s3.get_object(**get_params)
            content = response["Body"].read().decode("utf-8")

            # Validate content
            validated = self._validate_rule_content(content)

            # Verify hash if available
            stored_hash = response.get("Metadata", {}).get("content-hash")
            computed_hash = self._compute_hash(content)
            if stored_hash and stored_hash != computed_hash:
                logger.warning(
                    "content_hash_mismatch",
                    rule_id=rule_id,
                    stored=stored_hash[:16],
                    computed=computed_hash[:16],
                )

            # Create rule object
            metadata = DetectionMetadata(
                id=validated["id"],
                name=validated["name"],
                description=validated["description"],
                author=validated["author"],
                severity=Severity(validated["severity"]),
                tags=validated["tags"],
                mitre_attack=validated["mitre_attack"],
                data_sources=validated["data_sources"],
                schedule=validated["schedule"],
                enabled=validated["enabled"],
            )

            rule = SQLDetectionRule(
                metadata=metadata,
                query_template=validated["query"],
                threshold=validated["threshold"],
                group_by_fields=validated["group_by"],
            )

            version = RuleVersion(
                rule_id=rule_id,
                version_id=response.get("VersionId", "null"),
                last_modified=response["LastModified"],
                content_hash=computed_hash,
                size_bytes=response["ContentLength"],
                author=response.get("Metadata", {}).get("author", ""),
            )

            logger.debug(
                "loaded_detection_rule",
                rule_id=rule_id,
                version_id=version.version_id,
            )

            return rule, version

        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchKey":
                # Try local fallback if enabled
                if self._enable_local_fallback and self._local_rules_dir:
                    return self._load_from_local(rule_id)
                raise ValueError(f"Rule not found: {rule_id}") from e
            raise

    def _load_from_local(self, rule_id: str) -> tuple[DetectionRule, RuleVersion]:
        """Load rule from local directory (development fallback)."""
        if not self._local_rules_dir:
            raise ValueError("Local rules directory not configured")

        local_path = self._local_rules_dir / f"{rule_id}.yaml"
        if not local_path.exists():
            raise ValueError(f"Rule not found locally: {rule_id}")

        content = local_path.read_text()
        validated = self._validate_rule_content(content)

        metadata = DetectionMetadata(
            id=validated["id"],
            name=validated["name"],
            description=validated["description"],
            author=validated["author"],
            severity=Severity(validated["severity"]),
            tags=validated["tags"],
            mitre_attack=validated["mitre_attack"],
            data_sources=validated["data_sources"],
            schedule=validated["schedule"],
            enabled=validated["enabled"],
        )

        rule = SQLDetectionRule(
            metadata=metadata,
            query_template=validated["query"],
            threshold=validated["threshold"],
            group_by_fields=validated["group_by"],
        )

        stat = local_path.stat()
        version = RuleVersion(
            rule_id=rule_id,
            version_id="local",
            last_modified=datetime.fromtimestamp(stat.st_mtime, tz=UTC),
            content_hash=self._compute_hash(content),
            size_bytes=stat.st_size,
            author="local",
        )

        logger.info("loaded_rule_from_local_fallback", rule_id=rule_id)
        return rule, version

    def list_rules(self) -> list[str]:
        """List all rule IDs in the store.

        Returns:
            List of rule IDs
        """
        rule_ids = []

        try:
            paginator = self._s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=self.bucket, Prefix=self.prefix):
                for obj in page.get("Contents", []):
                    key = obj["Key"]
                    if key.endswith(".yaml"):
                        # Extract rule ID from key
                        rule_id = key[len(self.prefix) :].replace(".yaml", "")
                        rule_ids.append(rule_id)
        except ClientError as e:
            logger.error("failed_to_list_rules", error=str(e))
            raise

        # Add local rules if fallback enabled
        if self._enable_local_fallback and self._local_rules_dir:
            for yaml_file in self._local_rules_dir.glob("*.yaml"):
                rule_id = yaml_file.stem
                if rule_id not in rule_ids:
                    rule_ids.append(rule_id)

        return sorted(rule_ids)

    def load_all_rules(self) -> list[tuple[DetectionRule, RuleVersion]]:
        """Load all rules from the store.

        Returns:
            List of (DetectionRule, RuleVersion) tuples
        """
        results = []

        for rule_id in self.list_rules():
            try:
                rule, version = self.load_rule(rule_id)
                results.append((rule, version))
            except Exception as e:
                logger.warning(
                    "failed_to_load_rule",
                    rule_id=rule_id,
                    error=str(e),
                )

        return results

    def delete_rule(self, rule_id: str) -> None:
        """Delete a rule from the store.

        Note: With S3 versioning enabled, this creates a delete marker
        but previous versions remain accessible.

        Args:
            rule_id: Rule to delete
        """
        key = f"{self.prefix}{rule_id}.yaml"

        try:
            self._s3.delete_object(Bucket=self.bucket, Key=key)
            logger.info("deleted_detection_rule", rule_id=rule_id)
        except ClientError as e:
            logger.error("failed_to_delete_rule", rule_id=rule_id, error=str(e))
            raise

    def get_rule_history(self, rule_id: str, max_versions: int = 10) -> list[RuleVersion]:
        """Get version history for a rule.

        Args:
            rule_id: Rule identifier
            max_versions: Maximum versions to return

        Returns:
            List of RuleVersion objects (newest first)
        """
        key = f"{self.prefix}{rule_id}.yaml"
        versions = []

        try:
            response = self._s3.list_object_versions(
                Bucket=self.bucket,
                Prefix=key,
                MaxKeys=max_versions,
            )

            for v in response.get("Versions", []):
                if v["Key"] == key:  # Exact match only
                    versions.append(
                        RuleVersion(
                            rule_id=rule_id,
                            version_id=v["VersionId"],
                            last_modified=v["LastModified"],
                            content_hash="",  # Would need to fetch to get hash
                            size_bytes=v["Size"],
                        )
                    )

        except ClientError as e:
            logger.error("failed_to_get_rule_history", rule_id=rule_id, error=str(e))
            raise

        return versions

    def sync_from_local(
        self,
        local_dir: Path,
        author: str = "sync",
        dry_run: bool = False,
    ) -> dict[str, str]:
        """Sync rules from local directory to S3.

        Args:
            local_dir: Directory containing YAML rule files
            author: Author to record for synced rules
            dry_run: If True, only report what would be synced

        Returns:
            Dictionary of rule_id -> action (created/updated/skipped)
        """
        results: dict[str, str] = {}

        for yaml_file in local_dir.glob("*.yaml"):
            rule_id = yaml_file.stem
            content = yaml_file.read_text()

            try:
                # Validate locally first
                self._validate_rule_content(content)

                # Check if rule exists and has same content
                try:
                    existing_rule, existing_version = self.load_rule(rule_id)
                    existing_hash = existing_version.content_hash
                    new_hash = self._compute_hash(content)

                    if existing_hash == new_hash:
                        results[rule_id] = "skipped"
                        continue
                    else:
                        action = "updated"
                except ValueError:
                    action = "created"

                if dry_run:
                    results[rule_id] = f"would_be_{action}"
                else:
                    self.save_rule(rule_id, content, author=author)
                    results[rule_id] = action

            except Exception as e:
                results[rule_id] = f"error: {e}"
                logger.warning(
                    "sync_rule_failed",
                    rule_id=rule_id,
                    error=str(e),
                )

        return results
