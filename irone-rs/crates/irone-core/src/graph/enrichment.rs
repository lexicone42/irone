use chrono::{DateTime, Utc};
use tracing::{debug, warn};

use crate::connectors::ocsf::{ColumnFilter, OCSFEventClass, SecurityLakeQueries};
use crate::connectors::result::QueryResult;
use crate::connectors::sql_utils::validate_ipv4;

/// Enriches investigation graphs with related Security Lake events.
///
/// Queries multiple OCSF event classes for a given identifier (user, IP, service)
/// and returns combined results for graph building.
pub struct SecurityLakeEnricher<'a, S: SecurityLakeQueries> {
    connector: &'a S,
}

impl<'a, S: SecurityLakeQueries> SecurityLakeEnricher<'a, S> {
    pub fn new(connector: &'a S) -> Self {
        Self { connector }
    }

    /// Get all events for a user within a time window.
    ///
    /// Queries authentication, API activity, and account change event classes.
    pub async fn enrich_by_user(
        &self,
        user_name: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        event_classes: Option<&[OCSFEventClass]>,
        limit: usize,
    ) -> QueryResult {
        let default_classes = [
            OCSFEventClass::ApiActivity,
            OCSFEventClass::Authentication,
            OCSFEventClass::AccountChange,
        ];
        let classes = event_classes.unwrap_or(&default_classes);

        let filter = ColumnFilter::StringEquals {
            path: "actor.user.name".into(),
            value: user_name.to_string(),
        };
        let filters = [filter];

        let mut all_results = Vec::new();

        for &event_class in classes {
            match self
                .connector
                .query_by_event_class(event_class, start, end, limit, Some(&filters))
                .await
            {
                Ok(qr) if !qr.is_empty() => {
                    debug!(
                        user = user_name,
                        event_class = %event_class,
                        count = qr.len(),
                        "enrichment found events by user"
                    );
                    all_results.push(qr);
                }
                Ok(_) => {}
                Err(e) => {
                    warn!(
                        user = user_name,
                        event_class = %event_class,
                        error = %e,
                        "enrichment query by user failed"
                    );
                }
            }
        }

        if all_results.is_empty() {
            QueryResult::empty()
        } else {
            QueryResult::concat(all_results)
        }
    }

    /// Get all events involving an IP address.
    ///
    /// Queries network activity, API activity, and authentication event classes.
    pub async fn enrich_by_ip(
        &self,
        ip_address: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        direction: &str,
        limit: usize,
    ) -> QueryResult {
        if validate_ipv4(ip_address).is_err() {
            warn!(
                ip = ip_address,
                "invalid IP address format, skipping enrichment"
            );
            return QueryResult::empty();
        }

        let mut direction_filters = Vec::new();
        if direction == "source" || direction == "both" {
            direction_filters.push(ColumnFilter::StringEquals {
                path: "src_endpoint.ip".into(),
                value: ip_address.to_string(),
            });
        }
        if direction == "dest" || direction == "both" {
            direction_filters.push(ColumnFilter::StringEquals {
                path: "dst_endpoint.ip".into(),
                value: ip_address.to_string(),
            });
        }
        if direction_filters.is_empty() {
            return QueryResult::empty();
        }

        let ip_filter = if direction_filters.len() == 1 {
            direction_filters.remove(0)
        } else {
            ColumnFilter::Or(direction_filters)
        };
        let net_filters = [ip_filter];

        let mut all_results = Vec::new();

        // Network activity
        match self
            .connector
            .query_by_event_class(
                OCSFEventClass::NetworkActivity,
                start,
                end,
                limit,
                Some(&net_filters),
            )
            .await
        {
            Ok(qr) if !qr.is_empty() => all_results.push(qr),
            Ok(_) => {}
            Err(e) => warn!(ip = ip_address, error = %e, "network enrichment failed"),
        }

        // API activity (source IP only)
        if direction == "source" || direction == "both" {
            let src_filter = [ColumnFilter::StringEquals {
                path: "src_endpoint.ip".into(),
                value: ip_address.to_string(),
            }];
            match self
                .connector
                .query_by_event_class(
                    OCSFEventClass::ApiActivity,
                    start,
                    end,
                    limit,
                    Some(&src_filter),
                )
                .await
            {
                Ok(qr) if !qr.is_empty() => all_results.push(qr),
                Ok(_) => {}
                Err(e) => warn!(ip = ip_address, error = %e, "API enrichment by IP failed"),
            }
        }

        // Authentication events
        let auth_filter = [ColumnFilter::StringEquals {
            path: "src_endpoint.ip".into(),
            value: ip_address.to_string(),
        }];
        match self
            .connector
            .query_by_event_class(
                OCSFEventClass::Authentication,
                start,
                end,
                limit,
                Some(&auth_filter),
            )
            .await
        {
            Ok(qr) if !qr.is_empty() => all_results.push(qr),
            Ok(_) => {}
            Err(e) => warn!(ip = ip_address, error = %e, "auth enrichment by IP failed"),
        }

        if all_results.is_empty() {
            QueryResult::empty()
        } else {
            QueryResult::concat(all_results)
        }
    }

    /// Get API activity for a specific AWS service.
    pub async fn enrich_by_service(
        &self,
        service_name: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        operations: Option<&[&str]>,
        limit: usize,
    ) -> QueryResult {
        let mut filter_list = vec![ColumnFilter::StringEquals {
            path: "api.service.name".into(),
            value: service_name.to_string(),
        }];

        if let Some(ops) = operations {
            filter_list.push(ColumnFilter::StringIn {
                path: "api.operation".into(),
                values: ops.iter().map(|s| (*s).to_string()).collect(),
            });
        }

        match self
            .connector
            .query_by_event_class(
                OCSFEventClass::ApiActivity,
                start,
                end,
                limit,
                Some(&filter_list),
            )
            .await
        {
            Ok(qr) => qr,
            Err(e) => {
                warn!(service = service_name, error = %e, "enrichment by service failed");
                QueryResult::empty()
            }
        }
    }

    /// Get events for a specific API operation.
    pub async fn enrich_by_operation(
        &self,
        operation: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        service: Option<&str>,
        limit: usize,
    ) -> QueryResult {
        let mut filter_list = vec![ColumnFilter::StringEquals {
            path: "api.operation".into(),
            value: operation.to_string(),
        }];

        if let Some(svc) = service {
            filter_list.push(ColumnFilter::StringEquals {
                path: "api.service.name".into(),
                value: svc.to_string(),
            });
        }

        match self
            .connector
            .query_by_event_class(
                OCSFEventClass::ApiActivity,
                start,
                end,
                limit,
                Some(&filter_list),
            )
            .await
        {
            Ok(qr) => qr,
            Err(e) => {
                warn!(operation = operation, error = %e, "enrichment by operation failed");
                QueryResult::empty()
            }
        }
    }

    /// Get authentication events to trace a user's login chain.
    pub async fn get_authentication_chain(
        &self,
        user_name: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        limit: usize,
    ) -> QueryResult {
        let filters = [ColumnFilter::StringEquals {
            path: "actor.user.name".into(),
            value: user_name.to_string(),
        }];

        match self
            .connector
            .query_by_event_class(
                OCSFEventClass::Authentication,
                start,
                end,
                limit,
                Some(&filters),
            )
            .await
        {
            Ok(qr) => qr,
            Err(e) => {
                warn!(user = user_name, error = %e, "auth chain query failed");
                QueryResult::empty()
            }
        }
    }

    /// Get all events for a batch of users within a time window.
    ///
    /// Uses SQL `IN (...)` clauses to query multiple users per event class,
    /// reducing Athena round-trips from `N_users × 3` to just 3.
    pub async fn enrich_users_batch(
        &self,
        user_names: &[String],
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        event_classes: Option<&[OCSFEventClass]>,
        limit: usize,
    ) -> QueryResult {
        if user_names.is_empty() {
            return QueryResult::empty();
        }

        let default_classes = [
            OCSFEventClass::ApiActivity,
            OCSFEventClass::Authentication,
            OCSFEventClass::AccountChange,
        ];
        let classes = event_classes.unwrap_or(&default_classes);

        let filters = [ColumnFilter::StringIn {
            path: "actor.user.name".into(),
            values: user_names.to_vec(),
        }];

        let mut all_results = Vec::new();

        for &event_class in classes {
            match self
                .connector
                .query_by_event_class(event_class, start, end, limit, Some(&filters))
                .await
            {
                Ok(qr) if !qr.is_empty() => {
                    debug!(
                        user_count = user_names.len(),
                        event_class = %event_class,
                        count = qr.len(),
                        "batch enrichment found events by users"
                    );
                    all_results.push(qr);
                }
                Ok(_) => {}
                Err(e) => {
                    warn!(
                        user_count = user_names.len(),
                        event_class = %event_class,
                        error = %e,
                        "batch enrichment query by users failed"
                    );
                }
            }
        }

        if all_results.is_empty() {
            QueryResult::empty()
        } else {
            QueryResult::concat(all_results)
        }
    }

    /// Get all events involving a batch of IP addresses.
    ///
    /// Uses SQL `IN (...)` clauses to query multiple IPs per event class,
    /// reducing Athena round-trips from `N_ips × 3` to just 3.
    pub async fn enrich_ips_batch(
        &self,
        ip_addresses: &[String],
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        limit: usize,
    ) -> QueryResult {
        // Filter to valid IPs only
        let valid_ips: Vec<&str> = ip_addresses
            .iter()
            .filter(|ip| validate_ipv4(ip).is_ok())
            .map(String::as_str)
            .collect();

        if valid_ips.is_empty() {
            return QueryResult::empty();
        }

        let ip_values: Vec<String> = valid_ips.iter().map(|s| (*s).to_string()).collect();

        let mut all_results = Vec::new();

        // NetworkActivity: match either src or dst endpoint
        let net_filters = [ColumnFilter::Or(vec![
            ColumnFilter::StringIn {
                path: "src_endpoint.ip".into(),
                values: ip_values.clone(),
            },
            ColumnFilter::StringIn {
                path: "dst_endpoint.ip".into(),
                values: ip_values.clone(),
            },
        ])];
        match self
            .connector
            .query_by_event_class(
                OCSFEventClass::NetworkActivity,
                start,
                end,
                limit,
                Some(&net_filters),
            )
            .await
        {
            Ok(qr) if !qr.is_empty() => all_results.push(qr),
            Ok(_) => {}
            Err(e) => {
                warn!(ip_count = valid_ips.len(), error = %e, "batch network enrichment failed");
            }
        }

        // ApiActivity + Authentication: source IP only
        let src_filters = [ColumnFilter::StringIn {
            path: "src_endpoint.ip".into(),
            values: ip_values,
        }];
        for event_class in [OCSFEventClass::ApiActivity, OCSFEventClass::Authentication] {
            match self
                .connector
                .query_by_event_class(event_class, start, end, limit, Some(&src_filters))
                .await
            {
                Ok(qr) if !qr.is_empty() => {
                    debug!(
                        ip_count = valid_ips.len(),
                        event_class = %event_class,
                        count = qr.len(),
                        "batch enrichment found events by IPs"
                    );
                    all_results.push(qr);
                }
                Ok(_) => {}
                Err(e) => {
                    warn!(
                        ip_count = valid_ips.len(),
                        event_class = %event_class,
                        error = %e,
                        "batch enrichment query by IPs failed"
                    );
                }
            }
        }

        if all_results.is_empty() {
            QueryResult::empty()
        } else {
            QueryResult::concat(all_results)
        }
    }

    /// Get all events involving a specific resource ARN.
    ///
    /// Queries the OCSF `resources` array to find events that reference the
    /// given ARN. Works on both Athena (`any_match`) and Iceberg (Arrow list
    /// traversal). Queries `ApiActivity` only since API calls are the primary
    /// source of resource-level audit events.
    pub async fn enrich_by_resource(
        &self,
        arn: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        limit: usize,
    ) -> QueryResult {
        if !arn.starts_with("arn:") {
            warn!(
                arn = arn,
                "invalid ARN format, skipping resource enrichment"
            );
            return QueryResult::empty();
        }

        let filters = [ColumnFilter::ListContains {
            list_path: "resources".into(),
            field: "uid".into(),
            value: arn.to_string(),
        }];

        match self
            .connector
            .query_by_event_class(
                OCSFEventClass::ApiActivity,
                start,
                end,
                limit,
                Some(&filters),
            )
            .await
        {
            Ok(qr) if !qr.is_empty() => {
                debug!(
                    arn = arn,
                    count = qr.len(),
                    "enrichment found events by resource"
                );
                qr
            }
            Ok(_) => QueryResult::empty(),
            Err(e) => {
                warn!(arn = arn, error = %e, "enrichment by resource failed");
                QueryResult::empty()
            }
        }
    }

    /// Get all events involving a batch of resource ARNs.
    ///
    /// Queries the OCSF `resources` array to find events referencing any of the
    /// given ARNs. Works on both Athena and Iceberg. Only queries `ApiActivity`.
    pub async fn enrich_resources_batch(
        &self,
        arns: &[String],
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        limit: usize,
    ) -> QueryResult {
        let valid_arns: Vec<&str> = arns
            .iter()
            .filter(|a| a.starts_with("arn:"))
            .map(String::as_str)
            .collect();

        if valid_arns.is_empty() {
            return QueryResult::empty();
        }

        let filters = [ColumnFilter::ListContainsAny {
            list_path: "resources".into(),
            field: "uid".into(),
            values: valid_arns.iter().map(|a| (*a).to_string()).collect(),
        }];

        match self
            .connector
            .query_by_event_class(
                OCSFEventClass::ApiActivity,
                start,
                end,
                limit,
                Some(&filters),
            )
            .await
        {
            Ok(qr) if !qr.is_empty() => {
                debug!(
                    arn_count = valid_arns.len(),
                    count = qr.len(),
                    "batch enrichment found events by resources"
                );
                qr
            }
            Ok(_) => QueryResult::empty(),
            Err(e) => {
                warn!(
                    arn_count = valid_arns.len(),
                    error = %e,
                    "batch enrichment by resources failed"
                );
                QueryResult::empty()
            }
        }
    }

    /// Find all principals that have accessed from a specific IP.
    pub async fn find_related_principals(
        &self,
        ip_address: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        limit: usize,
    ) -> QueryResult {
        if validate_ipv4(ip_address).is_err() {
            warn!(ip = ip_address, "invalid IP address for related principals");
            return QueryResult::empty();
        }

        let filters = [ColumnFilter::StringEquals {
            path: "src_endpoint.ip".into(),
            value: ip_address.to_string(),
        }];
        let mut results = Vec::new();

        // Authentication events
        if let Ok(qr) = self
            .connector
            .query_by_event_class(
                OCSFEventClass::Authentication,
                start,
                end,
                limit,
                Some(&filters),
            )
            .await
            && !qr.is_empty()
        {
            results.push(qr);
        }

        // API activity
        if let Ok(qr) = self
            .connector
            .query_by_event_class(
                OCSFEventClass::ApiActivity,
                start,
                end,
                limit,
                Some(&filters),
            )
            .await
            && !qr.is_empty()
        {
            results.push(qr);
        }

        if results.is_empty() {
            QueryResult::empty()
        } else {
            QueryResult::concat(results)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connectors::ocsf::SecurityLakeError;
    use crate::json_row;

    /// Mock `SecurityLakeQueries` that returns canned results.
    struct MockSecurityLake {
        /// Results returned for each event class.
        results: std::collections::HashMap<u32, QueryResult>,
    }

    impl MockSecurityLake {
        fn new() -> Self {
            Self {
                results: std::collections::HashMap::new(),
            }
        }

        fn with_result(mut self, class: OCSFEventClass, qr: QueryResult) -> Self {
            self.results.insert(class.class_uid(), qr);
            self
        }
    }

    impl SecurityLakeQueries for MockSecurityLake {
        async fn query_by_event_class(
            &self,
            event_class: OCSFEventClass,
            _start: DateTime<Utc>,
            _end: DateTime<Utc>,
            _limit: usize,
            _filters: Option<&[ColumnFilter]>,
        ) -> Result<QueryResult, SecurityLakeError> {
            Ok(self
                .results
                .get(&event_class.class_uid())
                .cloned()
                .unwrap_or_else(QueryResult::empty))
        }

        async fn query_authentication_events(
            &self,
            _start: DateTime<Utc>,
            _end: DateTime<Utc>,
            _status: Option<&str>,
            _limit: usize,
        ) -> Result<QueryResult, SecurityLakeError> {
            Ok(QueryResult::empty())
        }

        async fn query_api_activity(
            &self,
            _start: DateTime<Utc>,
            _end: DateTime<Utc>,
            _service: Option<&str>,
            _operation: Option<&str>,
            _limit: usize,
        ) -> Result<QueryResult, SecurityLakeError> {
            Ok(QueryResult::empty())
        }

        async fn query_network_activity(
            &self,
            _start: DateTime<Utc>,
            _end: DateTime<Utc>,
            _src_ip: Option<&str>,
            _dst_ip: Option<&str>,
            _dst_port: Option<u16>,
            _limit: usize,
        ) -> Result<QueryResult, SecurityLakeError> {
            Ok(QueryResult::empty())
        }

        async fn query_security_findings(
            &self,
            _start: DateTime<Utc>,
            _end: DateTime<Utc>,
            _severity: Option<&str>,
            _limit: usize,
        ) -> Result<QueryResult, SecurityLakeError> {
            Ok(QueryResult::empty())
        }

        async fn get_event_summary(
            &self,
            _start: DateTime<Utc>,
            _end: DateTime<Utc>,
        ) -> Result<QueryResult, SecurityLakeError> {
            Ok(QueryResult::empty())
        }
    }

    fn time_window() -> (DateTime<Utc>, DateTime<Utc>) {
        let end = Utc::now();
        let start = end - chrono::Duration::hours(1);
        (start, end)
    }

    #[tokio::test]
    async fn enrich_by_user_combines_event_classes() {
        let api_rows =
            vec![json_row!("actor.user.name" => "alice", "api.operation" => "GetObject")];
        let auth_rows = vec![json_row!("actor.user.name" => "alice", "status" => "Success")];

        let mock = MockSecurityLake::new()
            .with_result(
                OCSFEventClass::ApiActivity,
                QueryResult::from_maps(api_rows),
            )
            .with_result(
                OCSFEventClass::Authentication,
                QueryResult::from_maps(auth_rows),
            );

        let enricher = SecurityLakeEnricher::new(&mock);
        let (start, end) = time_window();
        let result = enricher
            .enrich_by_user("alice", start, end, None, 500)
            .await;

        assert_eq!(result.len(), 2); // 1 API + 1 auth
    }

    #[tokio::test]
    async fn enrich_by_ip_validates_input() {
        let mock = MockSecurityLake::new();
        let enricher = SecurityLakeEnricher::new(&mock);
        let (start, end) = time_window();

        let result = enricher
            .enrich_by_ip("not-an-ip", start, end, "both", 500)
            .await;
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn enrich_users_batch_combines_results() {
        let api_rows = vec![
            json_row!("actor.user.name" => "alice", "api.operation" => "GetObject"),
            json_row!("actor.user.name" => "bob", "api.operation" => "PutObject"),
        ];

        let mock = MockSecurityLake::new().with_result(
            OCSFEventClass::ApiActivity,
            QueryResult::from_maps(api_rows),
        );

        let enricher = SecurityLakeEnricher::new(&mock);
        let (start, end) = time_window();
        let users = vec!["alice".to_string(), "bob".to_string()];
        let result = enricher
            .enrich_users_batch(&users, start, end, None, 500)
            .await;

        assert_eq!(result.len(), 2);
    }

    #[tokio::test]
    async fn enrich_users_batch_empty_input() {
        let mock = MockSecurityLake::new();
        let enricher = SecurityLakeEnricher::new(&mock);
        let (start, end) = time_window();
        let result = enricher
            .enrich_users_batch(&[], start, end, None, 500)
            .await;
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn enrich_ips_batch_filters_invalid() {
        let net_rows =
            vec![json_row!("src_endpoint.ip" => "10.0.0.1", "dst_endpoint.ip" => "8.8.8.8")];

        let mock = MockSecurityLake::new().with_result(
            OCSFEventClass::NetworkActivity,
            QueryResult::from_maps(net_rows),
        );

        let enricher = SecurityLakeEnricher::new(&mock);
        let (start, end) = time_window();
        let ips = vec![
            "10.0.0.1".to_string(),
            "not-an-ip".to_string(),
            "8.8.8.8".to_string(),
        ];
        let result = enricher.enrich_ips_batch(&ips, start, end, 500).await;

        assert!(!result.is_empty());
    }

    #[tokio::test]
    async fn enrich_ips_batch_empty_input() {
        let mock = MockSecurityLake::new();
        let enricher = SecurityLakeEnricher::new(&mock);
        let (start, end) = time_window();
        let result = enricher.enrich_ips_batch(&[], start, end, 500).await;
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn enrich_ips_batch_all_invalid() {
        let mock = MockSecurityLake::new();
        let enricher = SecurityLakeEnricher::new(&mock);
        let (start, end) = time_window();
        let ips = vec!["not-an-ip".to_string(), "also-bad".to_string()];
        let result = enricher.enrich_ips_batch(&ips, start, end, 500).await;
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn enrich_by_ip_queries_multiple_classes() {
        let net_rows =
            vec![json_row!("src_endpoint.ip" => "10.0.0.1", "dst_endpoint.ip" => "8.8.8.8")];

        let mock = MockSecurityLake::new().with_result(
            OCSFEventClass::NetworkActivity,
            QueryResult::from_maps(net_rows),
        );

        let enricher = SecurityLakeEnricher::new(&mock);
        let (start, end) = time_window();
        let result = enricher
            .enrich_by_ip("10.0.0.1", start, end, "both", 500)
            .await;

        assert!(!result.is_empty());
    }

    #[tokio::test]
    async fn enrich_by_resource_returns_events() {
        let api_rows = vec![json_row!(
            "actor.user.name" => "alice",
            "api.operation" => "GetObject",
            "api.service.name" => "s3"
        )];

        let mock = MockSecurityLake::new().with_result(
            OCSFEventClass::ApiActivity,
            QueryResult::from_maps(api_rows),
        );

        let enricher = SecurityLakeEnricher::new(&mock);
        let (start, end) = time_window();
        let result = enricher
            .enrich_by_resource("arn:aws:s3:::my-bucket", start, end, 500)
            .await;

        assert_eq!(result.len(), 1);
    }

    #[tokio::test]
    async fn enrich_by_resource_rejects_invalid_arn() {
        let mock = MockSecurityLake::new();
        let enricher = SecurityLakeEnricher::new(&mock);
        let (start, end) = time_window();
        let result = enricher
            .enrich_by_resource("not-an-arn", start, end, 500)
            .await;
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn enrich_resources_batch_queries_valid_arns() {
        let api_rows = vec![json_row!(
            "actor.user.name" => "bob",
            "api.operation" => "PutObject",
            "api.service.name" => "s3"
        )];

        let mock = MockSecurityLake::new().with_result(
            OCSFEventClass::ApiActivity,
            QueryResult::from_maps(api_rows),
        );

        let enricher = SecurityLakeEnricher::new(&mock);
        let (start, end) = time_window();
        let arns = vec![
            "arn:aws:s3:::bucket-1".to_string(),
            "not-an-arn".to_string(),
            "arn:aws:s3:::bucket-2".to_string(),
        ];
        let result = enricher
            .enrich_resources_batch(&arns, start, end, 500)
            .await;

        assert_eq!(result.len(), 1);
    }

    #[tokio::test]
    async fn enrich_resources_batch_empty_input() {
        let mock = MockSecurityLake::new();
        let enricher = SecurityLakeEnricher::new(&mock);
        let (start, end) = time_window();
        let result = enricher.enrich_resources_batch(&[], start, end, 500).await;
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn enrich_resources_batch_all_invalid() {
        let mock = MockSecurityLake::new();
        let enricher = SecurityLakeEnricher::new(&mock);
        let (start, end) = time_window();
        let arns = vec!["nope".to_string(), "also-bad".to_string()];
        let result = enricher
            .enrich_resources_batch(&arns, start, end, 500)
            .await;
        assert!(result.is_empty());
    }
}
