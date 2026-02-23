use std::fmt;

/// Error type for AWS connector operations.
#[derive(Debug)]
pub enum AwsError {
    /// Athena query execution failed.
    QueryFailed(String),
    /// Athena query timed out.
    QueryTimeout {
        query_id: String,
        max_wait_seconds: u64,
    },
    /// Athena query was cancelled.
    QueryCancelled(String),
    /// Failed to read query results from S3.
    ResultReadFailed(String),
    /// Invalid S3 location format.
    InvalidS3Location(String),
    /// CSV parsing error.
    CsvParse(String),
    /// `DynamoDB` operation failed.
    DynamoDb(String),
    /// SNS publish failed.
    Sns(String),
    /// Configuration error.
    Config(String),
    /// AWS SDK error (generic).
    Sdk(Box<dyn std::error::Error + Send + Sync>),
}

impl fmt::Display for AwsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::QueryFailed(msg) => write!(f, "query failed: {msg}"),
            Self::QueryTimeout {
                query_id,
                max_wait_seconds,
            } => {
                write!(f, "query {query_id} timed out after {max_wait_seconds}s")
            }
            Self::QueryCancelled(msg) => write!(f, "query cancelled: {msg}"),
            Self::ResultReadFailed(msg) => write!(f, "failed to read results: {msg}"),
            Self::InvalidS3Location(loc) => write!(f, "invalid S3 location: {loc}"),
            Self::CsvParse(msg) => write!(f, "CSV parse error: {msg}"),
            Self::DynamoDb(msg) => write!(f, "DynamoDB error: {msg}"),
            Self::Sns(msg) => write!(f, "SNS error: {msg}"),
            Self::Config(msg) => write!(f, "configuration error: {msg}"),
            Self::Sdk(e) => write!(f, "AWS SDK error: {e}"),
        }
    }
}

impl std::error::Error for AwsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sdk(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}

impl AwsError {
    /// Convert into a boxed error for trait compatibility.
    pub fn boxed(self) -> Box<dyn std::error::Error + Send + Sync> {
        Box::new(self)
    }
}

impl From<AwsError> for irone_core::connectors::base::ConnectorError {
    fn from(e: AwsError) -> Self {
        match &e {
            AwsError::QueryTimeout { .. } => Self::Transient {
                message: e.to_string(),
                source: Some(Box::new(e)),
            },
            _ => Self::Permanent {
                message: e.to_string(),
                source: Some(Box::new(e)),
            },
        }
    }
}

/// Parse an S3 location URI into (bucket, key).
///
/// # Errors
/// Returns `AwsError::InvalidS3Location` if the URI format is invalid.
pub fn parse_s3_location(location: &str) -> Result<(&str, &str), AwsError> {
    let path = location
        .strip_prefix("s3://")
        .ok_or_else(|| AwsError::InvalidS3Location(location.to_string()))?;
    let (bucket, key) = path
        .split_once('/')
        .ok_or_else(|| AwsError::InvalidS3Location(location.to_string()))?;
    if bucket.is_empty() || key.is_empty() {
        return Err(AwsError::InvalidS3Location(location.to_string()));
    }
    Ok((bucket, key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_s3_location_valid() {
        let (bucket, key) = parse_s3_location("s3://my-bucket/path/to/results.csv").unwrap();
        assert_eq!(bucket, "my-bucket");
        assert_eq!(key, "path/to/results.csv");
    }

    #[test]
    fn parse_s3_location_invalid_prefix() {
        assert!(parse_s3_location("https://example.com/file").is_err());
    }

    #[test]
    fn parse_s3_location_no_key() {
        assert!(parse_s3_location("s3://bucket-only").is_err());
    }

    #[test]
    fn error_display() {
        let e = AwsError::QueryTimeout {
            query_id: "abc-123".into(),
            max_wait_seconds: 300,
        };
        assert_eq!(e.to_string(), "query abc-123 timed out after 300s");
    }
}
