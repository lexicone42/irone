use chrono::{DateTime, Utc};
use tracing::{debug, warn};

use crate::connectors::ocsf::{OCSFEventClass, SecurityLakeQueries};
use crate::connectors::result::QueryResult;
use crate::connectors::sql_utils::{sanitize_string, validate_ipv4};

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

        let safe_user = sanitize_string(user_name);
        let filter = format!("\"actor\".\"user\".\"name\" = '{safe_user}'");

        let mut all_results = Vec::new();

        for &event_class in classes {
            match self
                .connector
                .query_by_event_class(event_class, start, end, limit, Some(&filter))
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

        let mut filters = Vec::new();
        if direction == "source" || direction == "both" {
            filters.push(format!("\"src_endpoint\".\"ip\" = '{ip_address}'"));
        }
        if direction == "dest" || direction == "both" {
            filters.push(format!("\"dst_endpoint\".\"ip\" = '{ip_address}'"));
        }
        if filters.is_empty() {
            return QueryResult::empty();
        }

        let filter_clause = format!("({})", filters.join(" OR "));

        let mut all_results = Vec::new();

        // Network activity
        match self
            .connector
            .query_by_event_class(
                OCSFEventClass::NetworkActivity,
                start,
                end,
                limit,
                Some(&filter_clause),
            )
            .await
        {
            Ok(qr) if !qr.is_empty() => all_results.push(qr),
            Ok(_) => {}
            Err(e) => warn!(ip = ip_address, error = %e, "network enrichment failed"),
        }

        // API activity (source IP only)
        if direction == "source" || direction == "both" {
            let src_filter = format!("\"src_endpoint\".\"ip\" = '{ip_address}'");
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
        let auth_filter = format!("\"src_endpoint\".\"ip\" = '{ip_address}'");
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
        let safe_service = sanitize_string(service_name);
        let mut filters = vec![format!("\"api\".\"service\".\"name\" = '{safe_service}'")];

        if let Some(ops) = operations {
            let safe_ops: Vec<String> = ops.iter().map(|op| sanitize_string(op)).collect();
            let ops_str = safe_ops
                .iter()
                .map(|s| format!("'{s}'"))
                .collect::<Vec<_>>()
                .join(", ");
            filters.push(format!("\"api\".\"operation\" IN ({ops_str})"));
        }

        let filter_clause = filters.join(" AND ");

        match self
            .connector
            .query_by_event_class(
                OCSFEventClass::ApiActivity,
                start,
                end,
                limit,
                Some(&filter_clause),
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
        let safe_op = sanitize_string(operation);
        let mut filters = vec![format!("\"api\".\"operation\" = '{safe_op}'")];

        if let Some(svc) = service {
            let safe_svc = sanitize_string(svc);
            filters.push(format!("\"api\".\"service\".\"name\" = '{safe_svc}'"));
        }

        let filter_clause = filters.join(" AND ");

        match self
            .connector
            .query_by_event_class(
                OCSFEventClass::ApiActivity,
                start,
                end,
                limit,
                Some(&filter_clause),
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
        let safe_user = sanitize_string(user_name);
        let filter = format!("\"actor\".\"user\".\"name\" = '{safe_user}'");

        match self
            .connector
            .query_by_event_class(
                OCSFEventClass::Authentication,
                start,
                end,
                limit,
                Some(&filter),
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

        let filter = format!("\"src_endpoint\".\"ip\" = '{ip_address}'");
        let mut results = Vec::new();

        // Authentication events
        if let Ok(qr) = self
            .connector
            .query_by_event_class(
                OCSFEventClass::Authentication,
                start,
                end,
                limit,
                Some(&filter),
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
                Some(&filter),
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

    /// Mock SecurityLakeQueries that returns canned results.
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
            _additional_filters: Option<&str>,
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
}
