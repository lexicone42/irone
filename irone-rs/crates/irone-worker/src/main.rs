use chrono::Duration;
use irone_core::catalog::DataCatalog;
use irone_core::graph::{GraphBuilder, extract_timeline_from_graph};
use lambda_runtime::{Error, LambdaEvent, service_fn};
use serde::{Deserialize, Serialize};

/// Input payload from Step Functions.
#[derive(Debug, Deserialize)]
struct WorkerEvent {
    action: String,
    investigation_id: String,
    rule_id: String,
    source_name: String,
    enrichment_window_minutes: i64,
    /// S3 bucket where detection results and artifacts are stored.
    bucket: String,
}

/// Output returned to Step Functions (passed to `MarkActive` state).
#[derive(Debug, Serialize)]
struct WorkerResult {
    investigation_id: String,
    node_count: usize,
    edge_count: usize,
}

#[allow(clippy::too_many_lines)]
async fn handler(event: LambdaEvent<WorkerEvent>) -> Result<WorkerResult, Error> {
    let (payload, _ctx) = event.into_parts();

    tracing::info!(
        action = %payload.action,
        investigation_id = %payload.investigation_id,
        rule_id = %payload.rule_id,
        source = %payload.source_name,
        window = payload.enrichment_window_minutes,
        "worker invoked"
    );

    let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let s3_client = aws_sdk_s3::Client::new(&sdk_config);

    // 1. Read DetectionResult from S3
    let detection_key = format!(
        "investigations/{}/detection_result.json",
        payload.investigation_id
    );
    let detection_bytes = s3_client
        .get_object()
        .bucket(&payload.bucket)
        .key(&detection_key)
        .send()
        .await?
        .body
        .collect()
        .await?
        .into_bytes();

    let detection_result: irone_core::detections::DetectionResult =
        serde_json::from_slice(&detection_bytes)?;

    tracing::info!(
        triggered = detection_result.triggered,
        match_count = detection_result.match_count,
        "loaded detection result from S3"
    );

    // 2. Build connector for the specified source
    let security_lake_db = std::env::var("SECDASH_SECURITY_LAKE_DB").unwrap_or_default();
    let region = std::env::var("SECDASH_REGION").unwrap_or_else(|_| "us-west-2".into());
    let use_direct_query = std::env::var("SECDASH_USE_DIRECT_QUERY")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(true);

    let mut catalog = DataCatalog::new();
    if !security_lake_db.is_empty() {
        catalog.register_security_lake_sources(&security_lake_db, &region);
    }

    let source = catalog
        .get_source(&payload.source_name)
        .cloned()
        .ok_or_else(|| {
            Error::from(format!(
                "source '{}' not found in catalog",
                payload.source_name
            ))
        })?;

    let connector = irone_aws::create_connector(source, &sdk_config, use_direct_query).await;

    // 3. Full enrichment: graph + timeline
    let mut builder = GraphBuilder::new();
    Box::pin(builder.build_from_detection(
        &detection_result,
        Some(&connector),
        payload.enrichment_window_minutes,
        500,
        true,
    ))
    .await;

    // 3b. Cross-source enrichment: query related sources for same entities
    if let Some(identifiers) = builder.last_identifiers().cloned() {
        let cross_sources = ["cloudtrail", "vpc-flow", "route53", "lambda-execution"];
        let mut secondary_connectors = Vec::new();
        for name in &cross_sources {
            if *name == payload.source_name {
                continue;
            }
            if let Some(source) = catalog.get_source(name).cloned() {
                let conn = irone_aws::create_connector(source, &sdk_config, use_direct_query).await;
                secondary_connectors.push((name.to_string(), conn));
            }
        }

        if !secondary_connectors.is_empty() {
            let end_time = detection_result.executed_at;
            let start_time = end_time - Duration::minutes(payload.enrichment_window_minutes);

            let connector_refs: Vec<(&str, &irone_aws::ConnectorKind)> = secondary_connectors
                .iter()
                .map(|(name, conn)| (name.as_str(), conn))
                .collect();

            tracing::info!(
                sources = ?connector_refs.iter().map(|(n, _)| *n).collect::<Vec<_>>(),
                "running cross-source enrichment"
            );

            Box::pin(builder.run_cross_source_enrichment(
                &connector_refs,
                &identifiers,
                start_time,
                end_time,
                200,
                true,
            ))
            .await;
        }
    }

    let graph = builder.into_graph();
    let timeline = extract_timeline_from_graph(&graph, true, true);

    let node_count = graph.nodes.len();
    let edge_count = graph.edges.len();

    tracing::info!(
        nodes = node_count,
        edges = edge_count,
        "enrichment complete"
    );

    // 4. Write graph + timeline to S3
    let graph_json = serde_json::to_vec(&graph)?;
    let timeline_json = serde_json::to_vec(&timeline)?;

    let graph_key = format!("investigations/{}/graph.json", payload.investigation_id);
    let timeline_key = format!("investigations/{}/timeline.json", payload.investigation_id);

    s3_client
        .put_object()
        .bucket(&payload.bucket)
        .key(&graph_key)
        .body(graph_json.into())
        .content_type("application/json")
        .send()
        .await?;

    s3_client
        .put_object()
        .bucket(&payload.bucket)
        .key(&timeline_key)
        .body(timeline_json.into())
        .content_type("application/json")
        .send()
        .await?;

    tracing::info!(
        investigation_id = %payload.investigation_id,
        "wrote graph.json and timeline.json to S3"
    );

    Ok(WorkerResult {
        investigation_id: payload.investigation_id,
        node_count,
        edge_count,
    })
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt().json().with_target(false).init();

    lambda_runtime::run(service_fn(handler)).await
}
