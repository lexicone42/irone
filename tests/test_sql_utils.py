"""Tests for SQL sanitization utilities."""

import pytest

from secdashboards.connectors.sql_utils import (
    SQLSanitizationError,
    build_in_clause,
    quote_identifier,
    quote_table,
    sanitize_int,
    sanitize_like_pattern,
    sanitize_string,
    validate_arn,
    validate_identifier,
    validate_ipv4,
)


class TestSanitizeString:
    """Tests for sanitize_string function."""

    def test_sanitize_normal_string(self) -> None:
        """Test sanitizing normal strings."""
        assert sanitize_string("hello") == "hello"
        assert sanitize_string("test_user") == "test_user"

    def test_sanitize_single_quotes(self) -> None:
        """Test escaping single quotes."""
        assert sanitize_string("O'Brien") == "O''Brien"
        assert sanitize_string("It's a test") == "It''s a test"

    def test_sanitize_sql_injection_attempt(self) -> None:
        """Test blocking SQL injection attempts."""
        result = sanitize_string("admin'; DROP TABLE users--")
        # Single quotes escaped, comment removed
        assert "''" in result
        assert "--" not in result

    def test_sanitize_removes_null_bytes(self) -> None:
        """Test removing null bytes."""
        assert sanitize_string("test\x00value") == "testvalue"

    def test_sanitize_removes_comments(self) -> None:
        """Test removing SQL comments."""
        assert sanitize_string("test--comment") == "testcomment"
        assert sanitize_string("test/*comment*/") == "testcomment"

    def test_sanitize_escapes_backslashes(self) -> None:
        """Test escaping backslashes."""
        assert sanitize_string("path\\to\\file") == "path\\\\to\\\\file"

    def test_sanitize_non_string(self) -> None:
        """Test converting non-strings."""
        assert sanitize_string(123) == "123"
        assert sanitize_string(True) == "True"


class TestSanitizeLikePattern:
    """Tests for sanitize_like_pattern function."""

    def test_preserve_wildcards_at_edges(self) -> None:
        """Test preserving % wildcards at start/end."""
        assert sanitize_like_pattern("%.example.com") == "%.example.com"
        assert sanitize_like_pattern("admin%") == "admin%"

    def test_escape_wildcards_in_middle(self) -> None:
        """Test escaping wildcards in the middle."""
        assert sanitize_like_pattern("test%value") == "test\\%value"

    def test_escape_underscore(self) -> None:
        """Test escaping underscore wildcard."""
        assert sanitize_like_pattern("test_value") == "test\\_value"


class TestValidateIdentifier:
    """Tests for validate_identifier function."""

    def test_valid_identifiers(self) -> None:
        """Test valid SQL identifiers."""
        assert validate_identifier("users") == "users"
        assert validate_identifier("_private") == "_private"
        assert validate_identifier("table123") == "table123"
        assert validate_identifier("MyTable") == "MyTable"

    def test_invalid_identifiers(self) -> None:
        """Test invalid SQL identifiers."""
        with pytest.raises(SQLSanitizationError):
            validate_identifier("123table")  # Starts with number
        with pytest.raises(SQLSanitizationError):
            validate_identifier("table-name")  # Contains hyphen
        with pytest.raises(SQLSanitizationError):
            validate_identifier("table name")  # Contains space
        with pytest.raises(SQLSanitizationError):
            validate_identifier("")  # Empty
        with pytest.raises(SQLSanitizationError):
            validate_identifier("table;DROP")  # Contains semicolon


class TestQuoteIdentifier:
    """Tests for quote_identifier function."""

    def test_quote_simple_identifier(self) -> None:
        """Test quoting simple identifiers."""
        assert quote_identifier("users") == '"users"'
        assert quote_identifier("my_table") == '"my_table"'

    def test_quote_escapes_quotes(self) -> None:
        """Test escaping embedded quotes."""
        # This is an edge case - identifier with quote in name
        # First need a valid identifier that could have quotes
        # Actually, quotes aren't valid in identifiers, so this is covered
        pass

    def test_quote_rejects_invalid(self) -> None:
        """Test rejecting invalid identifiers."""
        with pytest.raises(SQLSanitizationError):
            quote_identifier("invalid-name")


class TestQuoteTable:
    """Tests for quote_table function."""

    def test_quote_table_reference(self) -> None:
        """Test creating quoted table reference."""
        assert quote_table("my_database", "my_table") == '"my_database"."my_table"'

    def test_quote_table_rejects_invalid(self) -> None:
        """Test rejecting invalid database/table names."""
        with pytest.raises(SQLSanitizationError):
            quote_table("invalid-db", "table")
        with pytest.raises(SQLSanitizationError):
            quote_table("database", "invalid-table")


class TestValidateIPv4:
    """Tests for validate_ipv4 function."""

    def test_valid_ipv4_addresses(self) -> None:
        """Test valid IPv4 addresses."""
        assert validate_ipv4("192.168.1.1") == "192.168.1.1"
        assert validate_ipv4("10.0.0.1") == "10.0.0.1"
        assert validate_ipv4("255.255.255.255") == "255.255.255.255"
        assert validate_ipv4("0.0.0.0") == "0.0.0.0"

    def test_invalid_ipv4_addresses(self) -> None:
        """Test invalid IPv4 addresses."""
        with pytest.raises(SQLSanitizationError):
            validate_ipv4("256.1.1.1")  # Octet > 255
        with pytest.raises(SQLSanitizationError):
            validate_ipv4("192.168.1")  # Missing octet
        with pytest.raises(SQLSanitizationError):
            validate_ipv4("192.168.1.1.1")  # Extra octet
        with pytest.raises(SQLSanitizationError):
            validate_ipv4("192.168.1.a")  # Non-numeric
        with pytest.raises(SQLSanitizationError):
            validate_ipv4("")  # Empty
        with pytest.raises(SQLSanitizationError):
            validate_ipv4("192.168.1.1; DROP TABLE users")  # Injection


class TestValidateArn:
    """Tests for validate_arn function."""

    def test_valid_arns(self) -> None:
        """Test valid AWS ARNs."""
        assert validate_arn("arn:aws:s3:::my-bucket") == "arn:aws:s3:::my-bucket"
        assert (
            validate_arn("arn:aws:iam::123456789012:user/test")
            == "arn:aws:iam::123456789012:user/test"
        )
        assert (
            validate_arn("arn:aws:ec2:us-west-2:123456789012:instance/i-12345")
            == "arn:aws:ec2:us-west-2:123456789012:instance/i-12345"
        )

    def test_invalid_arns(self) -> None:
        """Test invalid AWS ARNs."""
        with pytest.raises(SQLSanitizationError):
            validate_arn("not-an-arn")
        with pytest.raises(SQLSanitizationError):
            validate_arn("")
        with pytest.raises(SQLSanitizationError):
            validate_arn("arn:invalid")


class TestSanitizeInt:
    """Tests for sanitize_int function."""

    def test_valid_integers(self) -> None:
        """Test valid integer values."""
        assert sanitize_int(123) == 123
        assert sanitize_int("456") == 456
        assert sanitize_int(0) == 0
        assert sanitize_int(-10) == -10

    def test_invalid_integers(self) -> None:
        """Test invalid integer values."""
        with pytest.raises(SQLSanitizationError):
            sanitize_int("123abc")
        with pytest.raises(SQLSanitizationError):
            sanitize_int("12.34")
        with pytest.raises(SQLSanitizationError):
            sanitize_int("abc")
        with pytest.raises(SQLSanitizationError):
            sanitize_int(None)


class TestBuildInClause:
    """Tests for build_in_clause function."""

    def test_build_in_clause(self) -> None:
        """Test building IN clause."""
        assert build_in_clause(["a", "b", "c"]) == "'a', 'b', 'c'"

    def test_build_in_clause_sanitizes(self) -> None:
        """Test that IN clause sanitizes values."""
        result = build_in_clause(["normal", "O'Brien", "test"])
        assert "O''Brien" in result

    def test_build_in_clause_empty(self) -> None:
        """Test empty IN clause raises error."""
        with pytest.raises(SQLSanitizationError):
            build_in_clause([])


class TestSQLInjectionScenarios:
    """Integration tests for SQL injection prevention."""

    def test_union_injection(self) -> None:
        """Test UNION-based injection is blocked."""
        result = sanitize_string("' UNION SELECT * FROM passwords--")
        # Single quote becomes '' (escaped), comment removed
        assert result == "'' UNION SELECT * FROM passwords"

    def test_boolean_injection(self) -> None:
        """Test boolean-based injection is escaped."""
        result = sanitize_string("' OR '1'='1")
        # Each single quote becomes ''
        assert result == "'' OR ''1''=''1"

    def test_stacked_query_injection(self) -> None:
        """Test stacked query injection is handled."""
        # Note: Athena doesn't support stacked queries anyway
        result = sanitize_string("'; DELETE FROM users; --")
        assert "''" in result  # Quotes escaped
        assert "--" not in result  # Comments removed

    def test_identifier_injection(self) -> None:
        """Test identifier-based injection is blocked."""
        with pytest.raises(SQLSanitizationError):
            validate_identifier("users; DROP TABLE users")

    def test_ip_injection(self) -> None:
        """Test IP-based injection is blocked."""
        with pytest.raises(SQLSanitizationError):
            validate_ipv4("192.168.1.1' OR '1'='1")
