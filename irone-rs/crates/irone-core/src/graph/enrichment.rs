use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::connectors::ocsf::{
    ColumnFilter, OCSFEventClass, SecurityLakeQueries, get_nested_array, get_nested_str,
};
use crate::connectors::result::QueryResult;
use crate::connectors::sql_utils::validate_ipv4;

/// Anomaly score for an entity (user, IP, service) in the investigation window.
///
/// Uses Median Absolute Deviation (MAD) instead of standard deviation to resist
/// the outlier contamination typical of security event data (power-law distributions).
/// A modified z-score > 3.5 is the conventional "anomalous" threshold, though the
/// caller controls the cutoff via `z_threshold`.
///
/// # Why MAD over standard z-scores?
///
/// Security event counts follow power-law distributions — a few entities (service
/// accounts, automated scanners) generate most events. Standard z-scores use mean
/// and `std_dev`, both of which are heavily influenced by these outliers. This inflates
/// σ so much that genuinely anomalous human activity (e.g., 200 events when the
/// typical human has 2) gets a z-score near zero.
///
/// MAD uses the median and the median of absolute deviations, making it resistant
/// to extreme outliers. The 0.6745 scaling constant makes MAD-based z-scores
/// comparable to standard z-scores for normally distributed data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityAnomalyScore {
    /// Entity identifier (user name, IP address, service name, etc.).
    pub entity: String,
    /// Entity kind ("user", "ip", "service").
    pub kind: String,
    /// Number of events involving this entity in the investigation window.
    pub event_count: usize,
    /// Center of the distribution (median for MAD scoring).
    pub median: f64,
    /// Spread measure: MAD (Median Absolute Deviation), or `MeanAD` as fallback.
    pub mad: f64,
    /// Modified z-score: 0.6745 × (`event_count` − median) / MAD. Higher = more anomalous.
    pub z_score: f64,
}

/// Score entity activity volumes from enrichment results using robust statistics.
///
/// Counts events per user, IP, and service from the provided `QueryResult`s,
/// then computes MAD-based modified z-scores within each entity kind. Returns
/// only entities with modified z-score above the given threshold.
///
/// Uses Median Absolute Deviation (MAD) instead of standard deviation, which
/// resists the outlier contamination typical of security event distributions.
/// A threshold of 3.5 is the conventional cutoff for MAD-based outlier detection
/// (equivalent to ~3.5σ for normal data). Lower thresholds (e.g., 2.0) increase
/// sensitivity.
///
/// This is a pure computation over already-fetched data — no additional queries.
#[must_use]
pub fn score_entity_anomalies(
    results: &[QueryResult],
    z_threshold: f64,
) -> Vec<EntityAnomalyScore> {
    let mut user_counts: HashMap<String, usize> = HashMap::new();
    let mut ip_counts: HashMap<String, usize> = HashMap::new();
    let mut service_counts: HashMap<String, usize> = HashMap::new();

    for qr in results {
        for row in qr.rows() {
            if let Some(user) = get_nested_str(row, &["actor.user.name"]) {
                *user_counts.entry(user).or_default() += 1;
            }
            if let Some(ip) = get_nested_str(row, &["src_endpoint.ip"]) {
                *ip_counts.entry(ip).or_default() += 1;
            }
            if let Some(svc) = get_nested_str(row, &["api.service.name"]) {
                *service_counts.entry(svc).or_default() += 1;
            }
        }
    }

    let mut scores = Vec::new();
    collect_anomalies(&user_counts, "user", z_threshold, &mut scores);
    collect_anomalies(&ip_counts, "ip", z_threshold, &mut scores);
    collect_anomalies(&service_counts, "service", z_threshold, &mut scores);

    // Sort by z-score descending (most anomalous first)
    scores.sort_by(|a, b| {
        b.z_score
            .partial_cmp(&a.z_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    scores
}

/// Consistency constant for MAD → standard deviation equivalence.
///
/// For normally distributed data, `MAD × 1/0.6745 ≈ σ`. We multiply by 0.6745
/// so that a modified z-score of 3.5 corresponds to ~3.5σ under normality.
const MAD_CONSISTENCY: f64 = 0.6745;

/// Compute MAD-based modified z-scores and collect entities above threshold.
///
/// Algorithm:
/// 1. Compute median of entity counts
/// 2. Compute MAD = median(|xi − median|)
/// 3. If MAD = 0 (majority of entities share the same count), fall back to
///    `MeanAD` = mean(|xi − median|), which is nonzero unless all values are identical
/// 4. Modified z-score = 0.6745 × (xi − median) / spread
#[allow(clippy::cast_precision_loss)] // Event counts won't exceed f64 mantissa range
fn collect_anomalies(
    counts: &HashMap<String, usize>,
    kind: &str,
    threshold: f64,
    out: &mut Vec<EntityAnomalyScore>,
) {
    if counts.len() < 2 {
        return; // Need at least 2 entities to compute meaningful deviation
    }

    let mut sorted: Vec<f64> = counts.values().map(|&c| c as f64).collect();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let median = compute_median(&sorted);

    // MAD = median of absolute deviations from the median
    let mut abs_devs: Vec<f64> = sorted.iter().map(|&x| (x - median).abs()).collect();
    abs_devs.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mad = compute_median(&abs_devs);

    // When MAD = 0 (more than half the values equal the median), fall back to MeanAD.
    // MeanAD is still robust (uses median as center) but nonzero when any value differs.
    let spread = if mad < f64::EPSILON {
        let n = sorted.len() as f64;
        let mean_ad: f64 = sorted.iter().map(|&x| (x - median).abs()).sum::<f64>() / n;
        if mean_ad < f64::EPSILON {
            return; // All counts identical, no anomalies
        }
        mean_ad
    } else {
        mad
    };

    for (entity, &count) in counts {
        let modified_z = MAD_CONSISTENCY * (count as f64 - median) / spread;
        if modified_z >= threshold {
            out.push(EntityAnomalyScore {
                entity: entity.clone(),
                kind: kind.to_string(),
                event_count: count,
                median,
                mad: spread,
                z_score: modified_z,
            });
        }
    }
}

/// Compute the median of a pre-sorted slice.
fn compute_median(sorted: &[f64]) -> f64 {
    let len = sorted.len();
    if len == 0 {
        return 0.0;
    }
    if len.is_multiple_of(2) {
        f64::midpoint(sorted[len / 2 - 1], sorted[len / 2])
    } else {
        sorted[len / 2]
    }
}

/// Results from a multi-hop lateral movement trace.
///
/// Starting from a seed IP, traces the chain:
/// 1. IP → authentication events → user names
/// 2. Users → API activity → services + resource ARNs
/// 3. Resources → API activity → additional users who accessed them
///
/// Each hop's raw `QueryResult` is preserved for graph building, and the
/// extracted identifiers are available for further analysis.
#[derive(Debug)]
pub struct LateralMovementTrace {
    /// Seed IP address that initiated the trace.
    pub seed_ip: String,
    /// Users who authenticated from the seed IP (hop 1).
    pub users: Vec<String>,
    /// Services those users interacted with (hop 2).
    pub services: Vec<String>,
    /// Resource ARNs those users accessed (hop 2).
    pub resources: Vec<String>,
    /// Additional users who also accessed the same resources (hop 3).
    pub related_users: Vec<String>,
    /// Raw query results from each hop, for graph node/edge creation.
    pub hop_results: Vec<QueryResult>,
}

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

    /// Get DNS activity events for a specific domain.
    ///
    /// Queries `DnsActivity` events where `query.hostname` matches.
    pub async fn enrich_by_domain(
        &self,
        domain: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        limit: usize,
    ) -> QueryResult {
        if domain.is_empty() {
            return QueryResult::empty();
        }

        let filters = [ColumnFilter::StringEquals {
            path: "query.hostname".into(),
            value: domain.to_string(),
        }];

        match self
            .connector
            .query_by_event_class(
                OCSFEventClass::DnsActivity,
                start,
                end,
                limit,
                Some(&filters),
            )
            .await
        {
            Ok(qr) if !qr.is_empty() => {
                debug!(
                    domain = domain,
                    count = qr.len(),
                    "enrichment found DNS events"
                );
                qr
            }
            Ok(_) => QueryResult::empty(),
            Err(e) => {
                warn!(domain = domain, error = %e, "DNS enrichment failed");
                QueryResult::empty()
            }
        }
    }

    /// Get DNS activity events for a batch of domains.
    ///
    /// Uses `IN (...)` to query multiple domains in a single request.
    pub async fn enrich_domains_batch(
        &self,
        domains: &[String],
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        limit: usize,
    ) -> QueryResult {
        if domains.is_empty() {
            return QueryResult::empty();
        }

        let filters = [ColumnFilter::StringIn {
            path: "query.hostname".into(),
            values: domains.to_vec(),
        }];

        match self
            .connector
            .query_by_event_class(
                OCSFEventClass::DnsActivity,
                start,
                end,
                limit,
                Some(&filters),
            )
            .await
        {
            Ok(qr) if !qr.is_empty() => {
                debug!(
                    domain_count = domains.len(),
                    count = qr.len(),
                    "batch DNS enrichment found events"
                );
                qr
            }
            Ok(_) => QueryResult::empty(),
            Err(e) => {
                warn!(
                    domain_count = domains.len(),
                    error = %e,
                    "batch DNS enrichment failed"
                );
                QueryResult::empty()
            }
        }
    }

    /// Trace lateral movement starting from a seed IP address.
    ///
    /// Performs a multi-hop correlation:
    /// 1. **IP → Users**: Query auth + API events from this IP, extract user names
    /// 2. **Users → Services + Resources**: Query API activity, extract services and ARNs
    /// 3. **Resources → Related Users**: Query API activity for resources, find other users
    pub async fn trace_lateral_movement(
        &self,
        seed_ip: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        per_hop_limit: usize,
    ) -> LateralMovementTrace {
        let mut trace = LateralMovementTrace {
            seed_ip: seed_ip.to_string(),
            users: Vec::new(),
            services: Vec::new(),
            resources: Vec::new(),
            related_users: Vec::new(),
            hop_results: Vec::new(),
        };

        if validate_ipv4(seed_ip).is_err() {
            warn!(ip = seed_ip, "invalid IP for lateral movement trace");
            return trace;
        }

        // Hop 1: IP → Users
        self.trace_hop_ip_to_users(seed_ip, start, end, per_hop_limit, &mut trace)
            .await;
        if trace.users.is_empty() {
            debug!(ip = seed_ip, "no users found from seed IP, trace complete");
            return trace;
        }
        info!(ip = seed_ip, users = trace.users.len(), "hop 1: IP → users");

        // Hop 2: Users → Services + Resources
        self.trace_hop_users_to_resources(start, end, per_hop_limit, &mut trace)
            .await;
        info!(
            ip = seed_ip,
            services = trace.services.len(),
            resources = trace.resources.len(),
            "hop 2: users → services + resources"
        );

        // Hop 3: Resources → Related Users
        self.trace_hop_resources_to_users(start, end, per_hop_limit, &mut trace)
            .await;

        trace
    }

    /// Hop 1: Query auth + API events from an IP, extract user names.
    async fn trace_hop_ip_to_users(
        &self,
        seed_ip: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        limit: usize,
        trace: &mut LateralMovementTrace,
    ) {
        let ip_filter = [ColumnFilter::StringEquals {
            path: "src_endpoint.ip".into(),
            value: seed_ip.to_string(),
        }];
        let mut users = HashSet::new();

        for event_class in [OCSFEventClass::Authentication, OCSFEventClass::ApiActivity] {
            if let Ok(qr) = self
                .connector
                .query_by_event_class(event_class, start, end, limit, Some(&ip_filter))
                .await
            {
                for row in qr.rows() {
                    if let Some(user) = get_nested_str(row, &["actor.user.name"]) {
                        users.insert(user);
                    }
                }
                if !qr.is_empty() {
                    trace.hop_results.push(qr);
                }
            }
        }

        trace.users = users.into_iter().collect();
        trace.users.sort();
    }

    /// Hop 2: Query API activity for discovered users, extract services and resource ARNs.
    async fn trace_hop_users_to_resources(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        limit: usize,
        trace: &mut LateralMovementTrace,
    ) {
        let user_filter = [ColumnFilter::StringIn {
            path: "actor.user.name".into(),
            values: trace.users.clone(),
        }];

        let Ok(qr) = self
            .connector
            .query_by_event_class(
                OCSFEventClass::ApiActivity,
                start,
                end,
                limit,
                Some(&user_filter),
            )
            .await
        else {
            return;
        };

        let mut services = HashSet::new();
        let mut resources = HashSet::new();
        for row in qr.rows() {
            if let Some(svc) = get_nested_str(row, &["api.service.name"]) {
                services.insert(svc);
            }
            if let Some(res_list) = get_nested_array(row, "resources") {
                for res in &res_list {
                    if let Some(uid) = res.get("uid").and_then(|v| v.as_str())
                        && uid.starts_with("arn:")
                    {
                        resources.insert(uid.to_string());
                    }
                }
            }
        }
        if !qr.is_empty() {
            trace.hop_results.push(qr);
        }

        trace.services = services.into_iter().collect();
        trace.services.sort();
        trace.resources = resources.into_iter().collect();
        trace.resources.sort();
    }

    /// Hop 3: Query API activity for discovered resources, extract other users.
    async fn trace_hop_resources_to_users(
        &self,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        limit: usize,
        trace: &mut LateralMovementTrace,
    ) {
        if trace.resources.is_empty() {
            return;
        }

        let arns: Vec<String> = trace.resources.iter().take(20).cloned().collect();
        let resource_filter = [ColumnFilter::ListContainsAny {
            list_path: "resources".into(),
            field: "uid".into(),
            values: arns,
        }];

        let Ok(qr) = self
            .connector
            .query_by_event_class(
                OCSFEventClass::ApiActivity,
                start,
                end,
                limit,
                Some(&resource_filter),
            )
            .await
        else {
            return;
        };

        let seed_users: HashSet<&str> = trace.users.iter().map(String::as_str).collect();
        let mut related = HashSet::new();
        for row in qr.rows() {
            if let Some(user) = get_nested_str(row, &["actor.user.name"])
                && !seed_users.contains(user.as_str())
            {
                related.insert(user);
            }
        }
        if !qr.is_empty() {
            trace.hop_results.push(qr);
        }

        trace.related_users = related.into_iter().collect();
        trace.related_users.sort();

        if !trace.related_users.is_empty() {
            info!(
                related_users = trace.related_users.len(),
                "hop 3: resources → related users"
            );
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

    // --- Domain enrichment tests ---

    #[tokio::test]
    async fn enrich_by_domain_returns_dns_events() {
        let dns_rows = vec![json_row!(
            "query.hostname" => "evil.example.com",
            "src_endpoint.ip" => "10.0.0.5",
            "class_uid" => 4003_u64
        )];

        let mock = MockSecurityLake::new().with_result(
            OCSFEventClass::DnsActivity,
            QueryResult::from_maps(dns_rows),
        );

        let enricher = SecurityLakeEnricher::new(&mock);
        let (start, end) = time_window();
        let result = enricher
            .enrich_by_domain("evil.example.com", start, end, 500)
            .await;

        assert_eq!(result.len(), 1);
    }

    #[tokio::test]
    async fn enrich_by_domain_empty_string() {
        let mock = MockSecurityLake::new();
        let enricher = SecurityLakeEnricher::new(&mock);
        let (start, end) = time_window();
        let result = enricher.enrich_by_domain("", start, end, 500).await;
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn enrich_domains_batch_returns_events() {
        let dns_rows = vec![
            json_row!("query.hostname" => "evil.example.com", "src_endpoint.ip" => "10.0.0.5"),
            json_row!("query.hostname" => "c2.badguy.net", "src_endpoint.ip" => "10.0.0.5"),
        ];

        let mock = MockSecurityLake::new().with_result(
            OCSFEventClass::DnsActivity,
            QueryResult::from_maps(dns_rows),
        );

        let enricher = SecurityLakeEnricher::new(&mock);
        let (start, end) = time_window();
        let domains = vec!["evil.example.com".to_string(), "c2.badguy.net".to_string()];
        let result = enricher
            .enrich_domains_batch(&domains, start, end, 500)
            .await;

        assert_eq!(result.len(), 2);
    }

    #[tokio::test]
    async fn enrich_domains_batch_empty_input() {
        let mock = MockSecurityLake::new();
        let enricher = SecurityLakeEnricher::new(&mock);
        let (start, end) = time_window();
        let result = enricher.enrich_domains_batch(&[], start, end, 500).await;
        assert!(result.is_empty());
    }

    // --- Anomaly scoring tests ---

    #[test]
    fn anomaly_scores_detect_outlier_user() {
        // alice appears 10 times, bob 1 time, carol 1 time
        // With MAD: median=1, MAD=0, MeanAD fallback=4.0
        // alice's modified z-score = 0.6745 × (10-1)/4.0 = 1.52 → above 1.0
        let mut rows = Vec::new();
        for _ in 0..10 {
            rows.push(json_row!(
                "actor.user.name" => "alice",
                "src_endpoint.ip" => "10.0.0.1",
                "api.service.name" => "s3"
            ));
        }
        rows.push(json_row!(
            "actor.user.name" => "bob",
            "src_endpoint.ip" => "10.0.0.2",
            "api.service.name" => "s3"
        ));
        rows.push(json_row!(
            "actor.user.name" => "carol",
            "src_endpoint.ip" => "10.0.0.3",
            "api.service.name" => "ec2"
        ));

        let qr = QueryResult::from_maps(rows);
        let scores = score_entity_anomalies(&[qr], 1.0);

        // alice should be in the results as anomalous user
        let alice_score = scores
            .iter()
            .find(|s| s.entity == "alice" && s.kind == "user");
        assert!(
            alice_score.is_some(),
            "alice should be flagged as anomalous"
        );
        assert!(alice_score.unwrap().z_score > 1.0);

        // bob and carol should NOT be flagged (below threshold)
        assert!(
            scores
                .iter()
                .all(|s| !(s.entity == "bob" && s.kind == "user"))
        );
    }

    #[test]
    fn anomaly_scores_empty_input() {
        let scores = score_entity_anomalies(&[], 1.0);
        assert!(scores.is_empty());
    }

    #[test]
    fn anomaly_scores_single_entity_no_anomaly() {
        // Only one user → can't compute deviation, no anomalies
        let rows = vec![json_row!(
            "actor.user.name" => "alice",
            "src_endpoint.ip" => "10.0.0.1"
        )];
        let qr = QueryResult::from_maps(rows);
        let scores = score_entity_anomalies(&[qr], 1.0);
        assert!(scores.is_empty());
    }

    #[test]
    fn anomaly_scores_uniform_distribution_no_anomalies() {
        // All users have equal counts → MAD = 0, MeanAD = 0 → no anomalies
        let rows = vec![
            json_row!("actor.user.name" => "alice", "src_endpoint.ip" => "10.0.0.1"),
            json_row!("actor.user.name" => "bob", "src_endpoint.ip" => "10.0.0.2"),
            json_row!("actor.user.name" => "carol", "src_endpoint.ip" => "10.0.0.3"),
        ];
        let qr = QueryResult::from_maps(rows);
        let scores = score_entity_anomalies(&[qr], 1.0);
        // No users should be anomalous (all have count=1)
        let user_scores: Vec<_> = scores.iter().filter(|s| s.kind == "user").collect();
        assert!(user_scores.is_empty());
    }

    #[test]
    fn anomaly_scores_sorted_by_z_score() {
        let mut rows = Vec::new();
        // alice: 20 events, bob: 5 events, carol: 1 event, dave: 1 event
        for _ in 0..20 {
            rows.push(json_row!("actor.user.name" => "alice"));
        }
        for _ in 0..5 {
            rows.push(json_row!("actor.user.name" => "bob"));
        }
        rows.push(json_row!("actor.user.name" => "carol"));
        rows.push(json_row!("actor.user.name" => "dave"));

        let qr = QueryResult::from_maps(rows);
        let scores = score_entity_anomalies(&[qr], 0.0); // threshold 0 to get all above-median

        let user_scores: Vec<_> = scores.iter().filter(|s| s.kind == "user").collect();
        if user_scores.len() >= 2 {
            assert!(user_scores[0].z_score >= user_scores[1].z_score);
        }
    }

    #[test]
    fn mad_resists_extreme_outlier_contamination() {
        // Classic power-law scenario: service-bot has 5000 events, alice has 200,
        // bob/carol/dave each have 1-3. With standard z-scores, service-bot's
        // extreme volume inflates σ so much that alice (genuinely anomalous for a
        // human) gets a z-score near zero. MAD correctly flags alice.
        let mut rows = Vec::new();
        for _ in 0..5000 {
            rows.push(json_row!("actor.user.name" => "service-bot"));
        }
        for _ in 0..200 {
            rows.push(json_row!("actor.user.name" => "alice"));
        }
        for _ in 0..3 {
            rows.push(json_row!("actor.user.name" => "bob"));
        }
        for _ in 0..2 {
            rows.push(json_row!("actor.user.name" => "carol"));
        }
        rows.push(json_row!("actor.user.name" => "dave"));

        let qr = QueryResult::from_maps(rows);
        // Use threshold 2.0 (investigation-sensitive)
        let scores = score_entity_anomalies(&[qr], 2.0);
        let user_scores: Vec<_> = scores.iter().filter(|s| s.kind == "user").collect();

        // Both service-bot AND alice should be flagged — this is the key difference
        // from standard z-scores where alice gets suppressed.
        let alice = user_scores.iter().find(|s| s.entity == "alice");
        let bot = user_scores.iter().find(|s| s.entity == "service-bot");
        assert!(
            alice.is_some(),
            "MAD should detect alice as anomalous despite extreme outlier"
        );
        assert!(bot.is_some(), "MAD should also detect service-bot");

        // alice's score should be substantial (not suppressed by service-bot's volume)
        assert!(
            alice.unwrap().z_score > 10.0,
            "alice's modified z-score should be high, got: {}",
            alice.unwrap().z_score
        );
    }

    #[test]
    fn mad_uses_median_not_mean() {
        // Verify the center statistic is the median, not the mean.
        // 5 entities with counts: 1, 1, 2, 3, 100. Mean=21.4, Median=2.
        let mut rows = Vec::new();
        rows.push(json_row!("actor.user.name" => "a"));
        rows.push(json_row!("actor.user.name" => "b"));
        for _ in 0..2 {
            rows.push(json_row!("actor.user.name" => "c"));
        }
        for _ in 0..3 {
            rows.push(json_row!("actor.user.name" => "d"));
        }
        for _ in 0..100 {
            rows.push(json_row!("actor.user.name" => "e"));
        }

        let qr = QueryResult::from_maps(rows);
        let scores = score_entity_anomalies(&[qr], 0.0);
        let e_score = scores
            .iter()
            .find(|s| s.entity == "e" && s.kind == "user")
            .expect("e should be flagged");

        // The center should be 2.0 (median), not 21.4 (mean)
        assert!(
            (e_score.median - 2.0).abs() < f64::EPSILON,
            "center should be median (2.0), got {}",
            e_score.median
        );
    }

    #[test]
    fn mad_fallback_to_mean_ad_when_majority_tied() {
        // When more than half the entities have the same count, MAD = 0.
        // Should fall back to MeanAD. Entities: a=1, b=1, c=1, d=1, e=50.
        let mut rows = Vec::new();
        for name in &["a", "b", "c", "d"] {
            rows.push(json_row!("actor.user.name" => *name));
        }
        for _ in 0..50 {
            rows.push(json_row!("actor.user.name" => "e"));
        }

        let qr = QueryResult::from_maps(rows);
        let scores = score_entity_anomalies(&[qr], 1.0);
        let e_score = scores.iter().find(|s| s.entity == "e" && s.kind == "user");
        assert!(
            e_score.is_some(),
            "MeanAD fallback should still detect the outlier"
        );
    }

    // --- Lateral movement tracing tests ---

    #[tokio::test]
    async fn lateral_trace_full_chain() {
        // Hop 1: Auth from 10.0.0.1 reveals user "alice"
        let auth_rows = vec![json_row!(
            "actor.user.name" => "alice",
            "src_endpoint.ip" => "10.0.0.1",
            "status" => "Success"
        )];
        // Hop 2+3: API activity reveals service + resource + related user "bob"
        let api_rows = vec![
            json_row!(
                "actor.user.name" => "alice",
                "api.service.name" => "s3",
                "api.operation" => "GetObject",
                "resources" => serde_json::json!([{"uid": "arn:aws:s3:::my-bucket"}])
            ),
            json_row!(
                "actor.user.name" => "bob",
                "api.service.name" => "s3",
                "api.operation" => "PutObject",
                "resources" => serde_json::json!([{"uid": "arn:aws:s3:::my-bucket"}])
            ),
        ];

        let mock = MockSecurityLake::new()
            .with_result(
                OCSFEventClass::Authentication,
                QueryResult::from_maps(auth_rows),
            )
            .with_result(
                OCSFEventClass::ApiActivity,
                QueryResult::from_maps(api_rows),
            );

        let enricher = SecurityLakeEnricher::new(&mock);
        let (start, end) = time_window();
        let trace = enricher
            .trace_lateral_movement("10.0.0.1", start, end, 500)
            .await;

        assert_eq!(trace.seed_ip, "10.0.0.1");
        // Hop 1: discovered alice (and bob from API events since mock returns same for all)
        assert!(trace.users.contains(&"alice".to_string()));
        // Hop 2: discovered s3 service
        assert!(trace.services.contains(&"s3".to_string()));
        // Hop 2: discovered resource ARN
        assert!(
            trace
                .resources
                .contains(&"arn:aws:s3:::my-bucket".to_string())
        );
        // Should have hop results
        assert!(!trace.hop_results.is_empty());
    }

    #[tokio::test]
    async fn lateral_trace_invalid_ip() {
        let mock = MockSecurityLake::new();
        let enricher = SecurityLakeEnricher::new(&mock);
        let (start, end) = time_window();
        let trace = enricher
            .trace_lateral_movement("not-an-ip", start, end, 500)
            .await;

        assert!(trace.users.is_empty());
        assert!(trace.services.is_empty());
        assert!(trace.resources.is_empty());
        assert!(trace.hop_results.is_empty());
    }

    #[tokio::test]
    async fn lateral_trace_no_auth_events() {
        // No auth or API events for this IP → empty trace
        let mock = MockSecurityLake::new();
        let enricher = SecurityLakeEnricher::new(&mock);
        let (start, end) = time_window();
        let trace = enricher
            .trace_lateral_movement("192.168.1.1", start, end, 500)
            .await;

        assert!(trace.users.is_empty());
        assert!(trace.services.is_empty());
        assert!(trace.hop_results.is_empty());
    }

    #[tokio::test]
    async fn lateral_trace_no_resources() {
        // Auth events reveal a user, but their API activity has no resource ARNs
        let auth_rows = vec![json_row!(
            "actor.user.name" => "carol",
            "src_endpoint.ip" => "10.0.0.5",
            "status" => "Success"
        )];
        let api_rows = vec![json_row!(
            "actor.user.name" => "carol",
            "api.service.name" => "sts",
            "api.operation" => "GetCallerIdentity"
        )];

        let mock = MockSecurityLake::new()
            .with_result(
                OCSFEventClass::Authentication,
                QueryResult::from_maps(auth_rows),
            )
            .with_result(
                OCSFEventClass::ApiActivity,
                QueryResult::from_maps(api_rows),
            );

        let enricher = SecurityLakeEnricher::new(&mock);
        let (start, end) = time_window();
        let trace = enricher
            .trace_lateral_movement("10.0.0.5", start, end, 500)
            .await;

        assert_eq!(trace.users, vec!["carol".to_string()]);
        assert_eq!(trace.services, vec!["sts".to_string()]);
        assert!(trace.resources.is_empty());
        // Hop 3 skipped since no resources
        assert!(trace.related_users.is_empty());
    }

    // --- Property tests for MAD-based anomaly scoring ---

    use proptest::prelude::*;

    /// Generate a power-law-ish distribution: many small counts + one outlier.
    fn power_law_with_outlier() -> impl Strategy<Value = (Vec<usize>, usize)> {
        // 3-20 background entities with low counts, 1 outlier with high count
        (
            proptest::collection::vec(1_usize..=5, 3..20),
            50_usize..=10_000,
        )
    }

    proptest! {
        /// A clear outlier should always be detected regardless of background distribution.
        ///
        /// This property was not guaranteed by the old z-score approach — extreme
        /// outliers in the background (e.g., service-bot with 100K events) would
        /// inflate σ and suppress detection of moderate outliers.
        #[test]
        fn mad_always_detects_clear_outlier(
            (background, outlier_count) in power_law_with_outlier()
        ) {
            let mut counts: HashMap<String, usize> = HashMap::new();
            for (i, &c) in background.iter().enumerate() {
                counts.insert(format!("entity_{i}"), c);
            }
            counts.insert("outlier".into(), outlier_count);

            let mut out = Vec::new();
            super::collect_anomalies(&counts, "test", 2.0, &mut out);

            // The outlier (50-10000 events) should always be detected when
            // background entities have 1-5 events each
            let found = out.iter().any(|s| s.entity == "outlier");
            prop_assert!(
                found,
                "outlier with {} events not detected among {} background entities with counts {:?}",
                outlier_count, background.len(), background
            );
        }

        /// Scores should always be sorted descending after collection.
        #[test]
        fn scores_are_sorted_descending(
            counts in proptest::collection::hash_map("[a-z]{3}", 1_usize..=1000, 3..30)
        ) {
            let mut out = Vec::new();
            super::collect_anomalies(&counts, "test", 0.0, &mut out);
            // After manual sort (as score_entity_anomalies does)
            out.sort_by(|a, b| b.z_score.partial_cmp(&a.z_score).unwrap_or(std::cmp::Ordering::Equal));

            for window in out.windows(2) {
                prop_assert!(
                    window[0].z_score >= window[1].z_score,
                    "scores not sorted: {} < {}",
                    window[0].z_score,
                    window[1].z_score
                );
            }
        }

        /// The median field should always be a value that actually appears in
        /// (or is interpolated between) the entity counts.
        #[test]
        fn median_is_bounded_by_data(
            counts in proptest::collection::hash_map("[a-z]{3}", 1_usize..=500, 2..20)
        ) {
            let mut out = Vec::new();
            super::collect_anomalies(&counts, "test", f64::NEG_INFINITY, &mut out);

            if let Some(score) = out.first() {
                let min = *counts.values().min().unwrap() as f64;
                let max = *counts.values().max().unwrap() as f64;
                prop_assert!(
                    score.median >= min && score.median <= max,
                    "median {} not in [{}, {}]",
                    score.median, min, max
                );
            }
        }
    }
}
