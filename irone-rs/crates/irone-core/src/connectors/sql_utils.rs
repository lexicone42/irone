use std::sync::LazyLock;

use regex::Regex;

static IDENTIFIER_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z_][a-zA-Z0-9_]*$").unwrap());

static IPV4_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
    )
    .unwrap()
});

static ARN_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^arn:aws:[a-z0-9\-]+:[a-z0-9\-]*:\d*:[a-zA-Z0-9\-_/:.]+$").unwrap()
});

/// Error returned when input fails SQL sanitization validation.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct SqlSanitizationError(String);

impl SqlSanitizationError {
    fn new(msg: impl Into<String>) -> Self {
        Self(msg.into())
    }
}

/// Sanitize a string value for use in SQL queries.
///
/// Defense-in-depth against SQL injection:
/// 1. Escapes single quotes (standard SQL escaping)
/// 2. Escapes backslashes
/// 3. Removes null bytes
/// 4. Removes SQL comment sequences
#[must_use]
pub fn sanitize_string(value: &str) -> String {
    let mut s = value.replace('\0', "");
    s = s.replace('\\', "\\\\");
    s = s.replace('\'', "''");
    s = s.replace("--", "");
    s = s.replace("/*", "");
    s = s.replace("*/", "");
    s
}

/// Sanitize a string for use in SQL LIKE patterns.
///
/// In addition to standard sanitization, escapes LIKE wildcards
/// unless they appear at the start/end (likely intentional).
#[must_use]
pub fn sanitize_like_pattern(value: &str) -> String {
    let mut s = sanitize_string(value);
    if !s.starts_with('%') && !s.ends_with('%') {
        s = s.replace('%', "\\%");
    }
    s = s.replace('_', "\\_");
    s
}

/// Validate a SQL identifier (table/database/column name).
///
/// # Errors
/// Returns `Err` if the identifier is empty or contains invalid characters.
pub fn validate_identifier(name: &str) -> Result<&str, SqlSanitizationError> {
    if name.is_empty() {
        return Err(SqlSanitizationError::new("Identifier cannot be empty"));
    }
    if !IDENTIFIER_PATTERN.is_match(name) {
        return Err(SqlSanitizationError::new(format!(
            "Invalid SQL identifier: {name:?}. \
             Must start with letter/underscore and contain only alphanumeric/underscore."
        )));
    }
    Ok(name)
}

/// Quote a SQL identifier for safe use in queries (ANSI double-quoting).
///
/// # Errors
/// Returns `Err` if the identifier fails validation.
pub fn quote_identifier(name: &str) -> Result<String, SqlSanitizationError> {
    validate_identifier(name)?;
    let escaped = name.replace('"', "\"\"");
    Ok(format!("\"{escaped}\""))
}

/// Create a fully qualified, quoted table reference: `"database"."table"`.
///
/// # Errors
/// Returns `Err` if either identifier fails validation.
pub fn quote_table(database: &str, table: &str) -> Result<String, SqlSanitizationError> {
    Ok(format!(
        "{}.{}",
        quote_identifier(database)?,
        quote_identifier(table)?
    ))
}

/// Validate an IPv4 address.
///
/// # Errors
/// Returns `Err` if the IP address is empty or invalid.
pub fn validate_ipv4(ip: &str) -> Result<&str, SqlSanitizationError> {
    if ip.is_empty() {
        return Err(SqlSanitizationError::new("IP address cannot be empty"));
    }
    if !IPV4_PATTERN.is_match(ip) {
        return Err(SqlSanitizationError::new(format!(
            "Invalid IPv4 address: {ip:?}"
        )));
    }
    Ok(ip)
}

/// Validate an AWS ARN format.
///
/// # Errors
/// Returns `Err` if the ARN is empty or malformed.
pub fn validate_arn(arn: &str) -> Result<&str, SqlSanitizationError> {
    if arn.is_empty() {
        return Err(SqlSanitizationError::new("ARN cannot be empty"));
    }
    if !arn.starts_with("arn:") {
        return Err(SqlSanitizationError::new(format!(
            "Invalid ARN format: {arn:?}. Must start with 'arn:'"
        )));
    }
    if !ARN_PATTERN.is_match(arn) {
        return Err(SqlSanitizationError::new(format!(
            "Invalid ARN format: {arn:?}"
        )));
    }
    Ok(arn)
}

/// Safely convert a value to an integer.
///
/// # Errors
/// Returns `Err` if the value is not a pure integer string.
pub fn sanitize_int(value: &str) -> Result<i64, SqlSanitizationError> {
    let trimmed = value.trim();
    let parsed: i64 = trimmed.parse().map_err(|e| {
        SqlSanitizationError::new(format!("Cannot convert {value:?} to integer: {e}"))
    })?;
    // Verify round-trip: parsed back to string must equal trimmed input
    if parsed.to_string() != trimmed {
        return Err(SqlSanitizationError::new(format!(
            "Value {value:?} is not a pure integer"
        )));
    }
    Ok(parsed)
}

/// Build a safe IN clause from a list of string values.
///
/// Returns content like `'val1', 'val2'`.
///
/// # Errors
/// Returns `Err` if the list is empty.
pub fn build_in_clause(values: &[&str]) -> Result<String, SqlSanitizationError> {
    if values.is_empty() {
        return Err(SqlSanitizationError::new("IN clause cannot be empty"));
    }
    let parts: Vec<String> = values
        .iter()
        .map(|v| format!("'{}'", sanitize_string(v)))
        .collect();
    Ok(parts.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- sanitize_string ---

    #[test]
    fn sanitize_escapes_quotes() {
        assert_eq!(sanitize_string("O'Brien"), "O''Brien");
    }

    #[test]
    fn sanitize_escapes_backslashes() {
        assert_eq!(sanitize_string("path\\file"), "path\\\\file");
    }

    #[test]
    fn sanitize_removes_null_bytes() {
        assert_eq!(sanitize_string("hello\0world"), "helloworld");
    }

    #[test]
    fn sanitize_removes_comments() {
        assert_eq!(
            sanitize_string("admin'; DROP TABLE users--"),
            "admin''; DROP TABLE users"
        );
        assert_eq!(sanitize_string("val /* comment */"), "val  comment ");
    }

    #[test]
    fn sanitize_clean_string_unchanged() {
        assert_eq!(sanitize_string("hello world"), "hello world");
    }

    // --- sanitize_like_pattern ---

    #[test]
    fn like_pattern_preserves_boundary_wildcards() {
        // % at start or end is treated as intentional
        assert_eq!(sanitize_like_pattern("%.example.com"), "%.example.com");
        assert_eq!(sanitize_like_pattern("admin%"), "admin%");
    }

    #[test]
    fn like_pattern_escapes_interior_percent() {
        assert_eq!(sanitize_like_pattern("50%off"), "50\\%off");
    }

    #[test]
    fn like_pattern_escapes_underscores() {
        assert_eq!(sanitize_like_pattern("user_name"), "user\\_name");
    }

    // --- validate_identifier ---

    #[test]
    fn valid_identifiers() {
        assert!(validate_identifier("my_table").is_ok());
        assert!(validate_identifier("_private").is_ok());
        assert!(validate_identifier("Table123").is_ok());
    }

    #[test]
    fn invalid_identifiers() {
        assert!(validate_identifier("").is_err());
        assert!(validate_identifier("123abc").is_err());
        assert!(validate_identifier("table-name").is_err());
        assert!(validate_identifier("table.name").is_err());
        assert!(validate_identifier("table; DROP").is_err());
    }

    // --- quote_identifier ---

    #[test]
    fn quote_identifier_wraps_in_double_quotes() {
        assert_eq!(quote_identifier("my_table").unwrap(), "\"my_table\"");
    }

    // --- quote_table ---

    #[test]
    fn quote_table_formats_correctly() {
        assert_eq!(
            quote_table("mydb", "mytable").unwrap(),
            "\"mydb\".\"mytable\""
        );
    }

    // --- validate_ipv4 ---

    #[test]
    fn valid_ipv4() {
        assert!(validate_ipv4("192.168.1.1").is_ok());
        assert!(validate_ipv4("10.0.0.1").is_ok());
        assert!(validate_ipv4("255.255.255.255").is_ok());
        assert!(validate_ipv4("0.0.0.0").is_ok());
    }

    #[test]
    fn invalid_ipv4() {
        assert!(validate_ipv4("").is_err());
        assert!(validate_ipv4("256.1.1.1").is_err());
        assert!(validate_ipv4("1.2.3").is_err());
        assert!(validate_ipv4("not-an-ip").is_err());
        assert!(validate_ipv4("1.2.3.4.5").is_err());
    }

    // --- validate_arn ---

    #[test]
    fn valid_arn() {
        assert!(validate_arn("arn:aws:s3:::my-bucket").is_ok());
        assert!(validate_arn("arn:aws:iam::123456789012:role/my-role").is_ok());
        assert!(validate_arn("arn:aws:lambda:us-west-2:123456789012:function:my-func").is_ok());
    }

    #[test]
    fn invalid_arn() {
        assert!(validate_arn("").is_err());
        assert!(validate_arn("not-an-arn").is_err());
        assert!(validate_arn("arn:invalid").is_err());
    }

    // --- sanitize_int ---

    #[test]
    fn valid_int() {
        assert_eq!(sanitize_int("42").unwrap(), 42);
        assert_eq!(sanitize_int("-1").unwrap(), -1);
        assert_eq!(sanitize_int("0").unwrap(), 0);
        assert_eq!(sanitize_int(" 100 ").unwrap(), 100);
    }

    #[test]
    fn invalid_int() {
        assert!(sanitize_int("abc").is_err());
        assert!(sanitize_int("12.5").is_err());
        assert!(sanitize_int("").is_err());
    }

    // --- build_in_clause ---

    #[test]
    fn in_clause_builds_correctly() {
        assert_eq!(build_in_clause(&["a", "b", "c"]).unwrap(), "'a', 'b', 'c'");
    }

    #[test]
    fn in_clause_sanitizes_values() {
        assert_eq!(
            build_in_clause(&["O'Brien", "normal"]).unwrap(),
            "'O''Brien', 'normal'"
        );
    }

    #[test]
    fn in_clause_empty_is_error() {
        assert!(build_in_clause(&[]).is_err());
    }

    // --- SQL injection scenarios ---

    #[test]
    fn injection_union_attack() {
        let input = "' UNION SELECT * FROM users--";
        let sanitized = sanitize_string(input);
        assert!(!sanitized.contains("--"));
        assert!(sanitized.starts_with("''"));
    }

    #[test]
    fn injection_boolean_based() {
        let input = "' OR '1'='1";
        let sanitized = sanitize_string(input);
        assert_eq!(sanitized, "'' OR ''1''=''1");
    }

    #[test]
    fn injection_stacked_queries() {
        let input = "'; DROP TABLE users; --";
        let sanitized = sanitize_string(input);
        assert!(!sanitized.contains("--"));
        assert!(sanitized.starts_with("'';"));
    }
}
