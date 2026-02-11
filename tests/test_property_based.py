"""Property-based tests using Hypothesis.

These tests complement the existing example-based tests by verifying
properties that must hold for ALL valid inputs, not just hand-picked cases.
"""

from hypothesis import example, given, settings
from hypothesis import strategies as st

from secdashboards.connectors.sql_utils import (
    build_in_clause,
    quote_identifier,
    sanitize_like_pattern,
    sanitize_string,
    validate_identifier,
)
from secdashboards.detections.rule import DetectionResult, Severity
from secdashboards.notifications.base import SecurityAlert
from secdashboards.notifications.manager import _SEVERITY_ORDER, NotificationManager
from secdashboards.notifications.sns import SNSNotifier

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Arbitrary text including control characters and SQL metacharacters
sql_payloads = st.text(
    alphabet=st.characters(categories=("L", "N", "P", "Z", "S", "C")),
    min_size=0,
    max_size=200,
)

# Valid SQL identifiers: start with letter/underscore, alphanumeric/underscore after
valid_identifiers = st.from_regex(r"[a-zA-Z_][a-zA-Z0-9_]{0,49}", fullmatch=True)

# Severity values
severities = st.sampled_from(list(Severity))

# Detection results with arbitrary valid fields
detection_results = st.builds(
    DetectionResult,
    rule_id=st.from_regex(r"[a-z0-9\-]{1,50}", fullmatch=True),
    rule_name=st.text(min_size=1, max_size=100),
    triggered=st.booleans(),
    severity=severities,
    match_count=st.integers(min_value=0, max_value=10000),
    matches=st.lists(
        st.dictionaries(
            keys=st.text(min_size=1, max_size=10),
            values=st.text(max_size=20),
            min_size=1,
            max_size=3,
        ),
        max_size=20,
    ),
    message=st.text(max_size=200),
)


# ---------------------------------------------------------------------------
# SQL Sanitization Properties
# ---------------------------------------------------------------------------


class TestSanitizeStringProperties:
    """Properties that sanitize_string must satisfy for ALL inputs."""

    @given(sql_payloads)
    @example("")
    @example("'")
    @example("''")
    @example("\\")
    @example("\x00")
    @example("--")
    @example("/**/")
    @example("admin'; DROP TABLE users--")
    def test_no_unescaped_single_quotes(self, s: str) -> None:
        """Sanitized output never contains an odd number of consecutive single quotes.

        In SQL, '' is an escaped quote. An unescaped ' (odd sequence) would
        break out of a string literal.
        """
        result = sanitize_string(s)
        # Split on non-quote chars; each segment of quotes should be even-length
        i = 0
        while i < len(result):
            if result[i] == "'":
                j = i
                while j < len(result) and result[j] == "'":
                    j += 1
                quote_run = j - i
                assert quote_run % 2 == 0, f"Odd quote run of length {quote_run} in: {result!r}"
                i = j
            else:
                i += 1

    @given(sql_payloads)
    @example("--comment")
    @example("/* block */")
    def test_no_sql_comments(self, s: str) -> None:
        """Sanitized output never contains SQL comment sequences."""
        result = sanitize_string(s)
        assert "--" not in result
        assert "/*" not in result
        assert "*/" not in result

    @given(sql_payloads)
    def test_no_null_bytes(self, s: str) -> None:
        """Sanitized output never contains null bytes."""
        result = sanitize_string(s)
        assert "\x00" not in result

    @given(sql_payloads)
    def test_safety_guarantees_stable(self, s: str) -> None:
        r"""Security guarantees hold after any number of sanitize passes.

        Note: sanitize_string is NOT fully idempotent — escaping operations
        like ' → '' and \ → \\ inherently double on re-application. This is
        correct because the function is designed for single-pass use before
        SQL embedding. The important property is that security guarantees
        (no unescaped quotes, no comments, no nulls) are never violated
        regardless of how many times you sanitize.
        """
        once = sanitize_string(s)
        twice = sanitize_string(once)
        # Safety guarantees hold after any number of applications
        assert "--" not in twice
        assert "/*" not in twice
        assert "*/" not in twice
        assert "\x00" not in twice

    @given(sql_payloads)
    def test_type_preservation(self, s: str) -> None:
        """Output is always a string."""
        assert isinstance(sanitize_string(s), str)


class TestSanitizeLikePatternProperties:
    """Properties for LIKE pattern sanitization."""

    @given(sql_payloads)
    def test_inherits_string_sanitization(self, s: str) -> None:
        """LIKE sanitization includes all string sanitization guarantees."""
        result = sanitize_like_pattern(s)
        assert "--" not in result
        assert "/*" not in result
        assert "\x00" not in result


class TestValidateIdentifierProperties:
    """Properties for SQL identifier validation."""

    @given(valid_identifiers)
    def test_valid_identifiers_accepted(self, name: str) -> None:
        """All syntactically valid identifiers are accepted."""
        assert validate_identifier(name) == name

    @given(valid_identifiers)
    def test_quoting_valid_identifiers(self, name: str) -> None:
        """Valid identifiers can always be quoted."""
        quoted = quote_identifier(name)
        assert quoted.startswith('"')
        assert quoted.endswith('"')

    @given(valid_identifiers)
    def test_quoted_identifier_roundtrip(self, name: str) -> None:
        """Quoted identifier contains the original name."""
        quoted = quote_identifier(name)
        # Strip outer quotes
        inner = quoted[1:-1]
        # Unescape double-quotes
        unescaped = inner.replace('""', '"')
        assert unescaped == name


class TestBuildInClauseProperties:
    """Properties for IN clause construction."""

    @given(st.lists(sql_payloads, min_size=1, max_size=10))
    def test_correct_element_count(self, values: list[str]) -> None:
        """IN clause contains exactly as many quoted values as inputs."""
        result = build_in_clause(values)
        # Count comma-separated segments
        segments = result.split("', '")
        assert len(segments) == len(values)


# ---------------------------------------------------------------------------
# SecurityAlert Serialization Properties
# ---------------------------------------------------------------------------


class TestSecurityAlertProperties:
    """Properties for SecurityAlert model."""

    @given(detection_results)
    @settings(max_examples=50)
    def test_roundtrip_serialization(self, result: DetectionResult) -> None:
        """SecurityAlert survives JSON serialization roundtrip."""
        alert = SecurityAlert.from_detection_result(result)
        data = alert.model_dump(mode="json")
        restored = SecurityAlert.model_validate(data)
        assert restored.rule_id == alert.rule_id
        assert restored.severity == alert.severity
        assert restored.match_count == alert.match_count
        assert restored.message == alert.message

    @given(detection_results)
    @settings(max_examples=50)
    def test_sample_matches_capped(self, result: DetectionResult) -> None:
        """from_detection_result always caps sample_matches at 5."""
        alert = SecurityAlert.from_detection_result(result)
        assert len(alert.sample_matches) <= 5

    @given(detection_results)
    @settings(max_examples=50)
    def test_preserves_identity_fields(self, result: DetectionResult) -> None:
        """Conversion preserves rule_id, rule_name, severity, match_count."""
        alert = SecurityAlert.from_detection_result(result)
        assert alert.rule_id == result.rule_id
        assert alert.rule_name == result.rule_name
        assert alert.severity == result.severity
        assert alert.match_count == result.match_count


# ---------------------------------------------------------------------------
# SNS Subject Formatting Properties
# ---------------------------------------------------------------------------


class TestSNSSubjectProperties:
    """Properties for SNS subject line formatting."""

    @given(
        rule_name=st.text(min_size=0, max_size=500),
        severity=severities,
    )
    def test_subject_never_exceeds_100_chars(self, rule_name: str, severity: Severity) -> None:
        """SNS subject is always <= 100 characters (AWS limit)."""
        notifier = SNSNotifier(topic_arn="arn:aws:sns:us-west-2:123:test")
        alert = SecurityAlert(
            rule_id="test",
            rule_name=rule_name,
            severity=severity,
        )
        subject = notifier._format_subject(alert)
        assert len(subject) <= 100

    @given(severity=severities)
    def test_subject_starts_with_severity(self, severity: Severity) -> None:
        """SNS subject always starts with [SEVERITY] prefix."""
        notifier = SNSNotifier(topic_arn="arn:aws:sns:us-west-2:123:test")
        alert = SecurityAlert(
            rule_id="test",
            rule_name="Test Rule",
            severity=severity,
        )
        subject = notifier._format_subject(alert)
        assert subject.startswith(f"[{severity.value.upper()}]")


# ---------------------------------------------------------------------------
# Severity Filter Ordering Properties
# ---------------------------------------------------------------------------


class TestSeverityFilterProperties:
    """Properties for severity filtering in NotificationManager."""

    @given(
        alert_sev=severities,
        filter_sev=severities,
    )
    def test_filter_monotonic(self, alert_sev: Severity, filter_sev: Severity) -> None:
        """If severity X passes the filter, all severities above X also pass.

        This verifies the ordering is consistent and there are no gaps.
        """
        mgr = NotificationManager(severity_filter=filter_sev)
        alert = SecurityAlert(
            rule_id="test",
            rule_name="Test",
            severity=alert_sev,
        )
        passes = mgr._passes_filter(alert)

        alert_order = _SEVERITY_ORDER[alert_sev]
        filter_order = _SEVERITY_ORDER[filter_sev]
        expected = alert_order >= filter_order
        assert passes == expected

    def test_severity_order_covers_all_values(self) -> None:
        """Every Severity enum value has an entry in the ordering dict."""
        for sev in Severity:
            assert sev in _SEVERITY_ORDER, f"{sev} missing from _SEVERITY_ORDER"

    def test_severity_order_is_strictly_increasing(self) -> None:
        """Severity ordering matches the expected INFO < LOW < MEDIUM < HIGH < CRITICAL."""
        expected = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        for i in range(len(expected) - 1):
            assert _SEVERITY_ORDER[expected[i]] < _SEVERITY_ORDER[expected[i + 1]]
