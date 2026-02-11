"""SQL sanitization utilities for safe query construction.

This module provides defense-in-depth against SQL injection for Athena queries.
Athena uses Presto/Trino SQL which does not support parameterized queries via boto3,
so we must sanitize inputs carefully.
"""

import re
from typing import Any

# Pattern for valid SQL identifiers (table names, database names, column names)
# Must start with letter or underscore, contain only alphanumeric and underscore
_IDENTIFIER_PATTERN = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")

# Pattern for valid IPv4 addresses
_IPV4_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)

# Pattern for valid AWS ARNs
_ARN_PATTERN = re.compile(r"^arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:\d*:[a-zA-Z0-9\-_/:.]+$")


class SQLSanitizationError(ValueError):
    """Raised when input fails sanitization validation."""

    pass


def sanitize_string(value: str) -> str:
    """Sanitize a string value for use in SQL queries.

    This provides defense-in-depth against SQL injection by:
    1. Escaping single quotes (standard SQL escaping)
    2. Escaping backslashes
    3. Removing null bytes
    4. Removing SQL comment sequences

    Args:
        value: The string to sanitize

    Returns:
        Sanitized string safe for SQL interpolation in single quotes

    Example:
        >>> sanitize_string("O'Brien")
        "O''Brien"
        >>> sanitize_string("admin'; DROP TABLE users--")
        "admin''; DROP TABLE users"
    """
    if not isinstance(value, str):
        value = str(value)

    # Remove null bytes
    value = value.replace("\x00", "")

    # Escape backslashes first (before other escapes)
    value = value.replace("\\", "\\\\")

    # Escape single quotes (SQL standard)
    value = value.replace("'", "''")

    # Remove SQL comment sequences
    value = value.replace("--", "")
    value = value.replace("/*", "")
    value = value.replace("*/", "")

    return value


def sanitize_like_pattern(value: str) -> str:
    """Sanitize a string for use in SQL LIKE patterns.

    In addition to standard sanitization, escapes LIKE wildcards
    unless they appear to be intentional.

    Args:
        value: The string to sanitize for LIKE

    Returns:
        Sanitized string safe for LIKE patterns
    """
    # First apply standard sanitization
    value = sanitize_string(value)

    # Escape LIKE wildcards that aren't at start/end (likely intentional wildcards)
    # This preserves patterns like "%.example.com" or "admin%"
    if not value.startswith("%") and not value.endswith("%"):
        value = value.replace("%", "\\%")
    value = value.replace("_", "\\_")

    return value


def validate_identifier(name: str) -> str:
    """Validate and return a SQL identifier (table/database/column name).

    Args:
        name: The identifier to validate

    Returns:
        The validated identifier

    Raises:
        SQLSanitizationError: If the identifier is invalid
    """
    if not name:
        raise SQLSanitizationError("Identifier cannot be empty")

    if not _IDENTIFIER_PATTERN.match(name):
        raise SQLSanitizationError(
            f"Invalid SQL identifier: {name!r}. "
            "Must start with letter/underscore and contain only alphanumeric/underscore."
        )

    return name


def quote_identifier(name: str) -> str:
    """Quote a SQL identifier for safe use in queries.

    Uses double quotes for identifier quoting (ANSI SQL standard).

    Args:
        name: The identifier to quote

    Returns:
        Quoted identifier safe for use in SQL

    Raises:
        SQLSanitizationError: If the identifier is invalid
    """
    # Validate the identifier first
    validate_identifier(name)

    # Double-quote and escape any embedded double quotes
    escaped = name.replace('"', '""')
    return f'"{escaped}"'


def quote_table(database: str, table: str) -> str:
    """Create a fully qualified, quoted table reference.

    Args:
        database: The database name
        table: The table name

    Returns:
        Quoted table reference like "database"."table"

    Raises:
        SQLSanitizationError: If either identifier is invalid
    """
    return f"{quote_identifier(database)}.{quote_identifier(table)}"


def validate_ipv4(ip: str) -> str:
    """Validate an IPv4 address.

    Args:
        ip: The IP address to validate

    Returns:
        The validated IP address

    Raises:
        SQLSanitizationError: If the IP address is invalid
    """
    if not ip:
        raise SQLSanitizationError("IP address cannot be empty")

    if not _IPV4_PATTERN.match(ip):
        raise SQLSanitizationError(f"Invalid IPv4 address: {ip!r}")

    return ip


def validate_arn(arn: str) -> str:
    """Validate an AWS ARN format.

    Args:
        arn: The ARN to validate

    Returns:
        The validated ARN

    Raises:
        SQLSanitizationError: If the ARN is invalid
    """
    if not arn:
        raise SQLSanitizationError("ARN cannot be empty")

    if not arn.startswith("arn:"):
        raise SQLSanitizationError(f"Invalid ARN format: {arn!r}. Must start with 'arn:'")

    # Basic structure validation
    if not _ARN_PATTERN.match(arn):
        raise SQLSanitizationError(f"Invalid ARN format: {arn!r}")

    return arn


def sanitize_int(value: Any) -> int:
    """Safely convert a value to integer.

    Args:
        value: The value to convert

    Returns:
        Integer value

    Raises:
        SQLSanitizationError: If the value cannot be safely converted
    """
    try:
        # Convert to int, then back to string to verify
        int_val = int(value)
        if str(int_val) != str(value).strip():
            # Value had extra characters
            raise SQLSanitizationError(f"Value {value!r} is not a pure integer")
        return int_val
    except (ValueError, TypeError) as e:
        raise SQLSanitizationError(f"Cannot convert {value!r} to integer: {e}") from e


def build_in_clause(values: list[str]) -> str:
    """Build a safe IN clause from a list of string values.

    Args:
        values: List of values for the IN clause

    Returns:
        SQL IN clause content like "'val1', 'val2'"

    Raises:
        SQLSanitizationError: If any value fails sanitization
    """
    if not values:
        raise SQLSanitizationError("IN clause cannot be empty")

    sanitized = [sanitize_string(v) for v in values]
    return ", ".join(f"'{v}'" for v in sanitized)
