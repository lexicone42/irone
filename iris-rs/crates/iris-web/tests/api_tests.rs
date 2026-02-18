use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use serde_json::json;
use tokio::sync::RwLock;
use tower::ServiceExt;

use iris_core::catalog::{DataCatalog, DataSource, DataSourceType};
use iris_core::detections::{DetectionMetadata, DetectionRunner, SQLDetectionRule, Severity};
use iris_core::graph::{
    EdgeType, EventTag, GraphEdge, GraphNode, InvestigationTimeline, NodeType, SecurityGraph,
    TimelineEvent,
};
use iris_web::app::build_router;
use iris_web::config::WebConfig;
use iris_web::state::{AppState, Investigation};

fn make_source(name: &str, description: &str) -> DataSource {
    DataSource {
        name: name.into(),
        source_type: DataSourceType::SecurityLake,
        description: description.into(),
        database: None,
        table: None,
        s3_location: None,
        region: "us-west-2".into(),
        schema_fields: HashMap::new(),
        connector_class: None,
        connector_config: HashMap::new(),
        health_check_query: None,
        expected_freshness_minutes: 60,
        tags: vec!["security-lake".into()],
    }
}

/// Build a test `AppState` with empty defaults.
fn test_state() -> AppState {
    let config = WebConfig::default();
    let sdk_config = aws_config::SdkConfig::builder()
        .behavior_version(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new("us-west-2"))
        .build();
    AppState {
        config: Arc::new(config),
        catalog: Arc::new(RwLock::new(DataCatalog::new())),
        runner: Arc::new(DetectionRunner::new()),
        investigation_store: None,
        investigations: Arc::new(RwLock::new(HashMap::new())),
        sdk_config: Arc::new(sdk_config),
    }
}

/// Build a test state with a catalog containing two sources.
fn test_state_with_sources() -> AppState {
    let mut state = test_state();
    let mut catalog = DataCatalog::new();
    catalog.add_source(make_source("cloudtrail", "CloudTrail logs"));
    catalog.add_source(make_source("vpc-flow", "VPC Flow Logs"));
    state.catalog = Arc::new(RwLock::new(catalog));
    state
}

/// Build a test state with a detection rule.
fn test_state_with_rules() -> AppState {
    let mut state = test_state_with_sources();
    let mut runner = DetectionRunner::new();
    runner.register_rule(Box::new(SQLDetectionRule {
        meta: DetectionMetadata {
            id: "rule-1".into(),
            name: "Test Rule".into(),
            description: "A test rule".into(),
            author: String::new(),
            severity: Severity::High,
            tags: vec![],
            mitre_attack: vec![],
            data_sources: vec![],
            schedule: "rate(5 minutes)".into(),
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        },
        query_template: "SELECT * FROM table WHERE time_dt >= '{start_time}'".into(),
        threshold: 1,
        group_by_fields: vec![],
    }));
    state.runner = Arc::new(runner);
    state
}

/// Build a test state with an investigation.
fn test_state_with_investigation() -> AppState {
    let state = test_state();

    let mut graph = SecurityGraph::new();
    graph.add_node(GraphNode {
        id: "Principal:alice".into(),
        node_type: NodeType::Principal,
        label: "alice".into(),
        properties: HashMap::new(),
        first_seen: Some(Utc::now()),
        last_seen: Some(Utc::now()),
        event_count: 5,
    });
    graph.add_node(GraphNode {
        id: "IPAddress:1.2.3.4".into(),
        node_type: NodeType::IPAddress,
        label: "1.2.3.4".into(),
        properties: HashMap::new(),
        first_seen: Some(Utc::now()),
        last_seen: Some(Utc::now()),
        event_count: 3,
    });
    graph.add_edge(GraphEdge {
        id: "e1".into(),
        edge_type: EdgeType::AuthenticatedFrom,
        source_id: "Principal:alice".into(),
        target_id: "IPAddress:1.2.3.4".into(),
        properties: HashMap::new(),
        weight: 1.0,
        first_seen: Some(Utc::now()),
        last_seen: Some(Utc::now()),
        event_count: 1,
    });

    let mut timeline = InvestigationTimeline::new("inv-1");
    timeline.add_event(TimelineEvent {
        id: "evt-1".into(),
        timestamp: Utc::now(),
        title: "Login".into(),
        description: "User login".into(),
        entity_type: "principal".into(),
        entity_id: "alice".into(),
        operation: "ConsoleLogin".into(),
        status: "success".into(),
        tag: EventTag::Unreviewed,
        notes: String::new(),
        properties: HashMap::new(),
    });

    let mut investigations = HashMap::new();
    investigations.insert(
        "inv-1".into(),
        Investigation {
            id: "inv-1".into(),
            name: "Test Investigation".into(),
            graph,
            timeline,
            created_at: Utc::now(),
            status: "active".into(),
        },
    );

    AppState {
        investigations: Arc::new(RwLock::new(investigations)),
        ..state
    }
}

async fn get(app: axum::Router, uri: &str) -> (StatusCode, serde_json::Value) {
    let response = app
        .oneshot(Request::get(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap_or(json!(null));
    (status, json)
}

async fn post_json(
    app: axum::Router,
    uri: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let response = app
        .oneshot(
            Request::post(uri)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(json!(null));
    (status, json)
}

async fn delete(app: axum::Router, uri: &str) -> (StatusCode, serde_json::Value) {
    let response = app
        .oneshot(Request::delete(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap_or(json!(null));
    (status, json)
}

// ===== Health / Dashboard =====

#[tokio::test]
async fn health_check_returns_ok() {
    let app = build_router(test_state());
    let (status, body) = get(app, "/api/health").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn dashboard_summary_empty() {
    let app = build_router(test_state());
    let (status, body) = get(app, "/api/dashboard").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["sources_count"], 0);
    assert_eq!(body["rules_count"], 0);
    assert_eq!(body["investigations_count"], 0);
}

#[tokio::test]
async fn dashboard_summary_with_data() {
    let state = test_state_with_investigation();
    // Add sources
    state
        .catalog
        .write()
        .await
        .register_security_lake_sources("my_db", "us-west-2");
    let app = build_router(state);
    let (status, body) = get(app, "/api/dashboard").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["sources_count"], 5);
    assert_eq!(body["investigations_count"], 1);
}

// ===== Sources =====

#[tokio::test]
async fn list_sources_empty() {
    let app = build_router(test_state());
    let (status, body) = get(app, "/api/sources").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn list_sources_with_entries() {
    let app = build_router(test_state_with_sources());
    let (status, body) = get(app, "/api/sources").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn list_sources_with_tag_filter() {
    let app = build_router(test_state_with_sources());
    let (status, body) = get(app, "/api/sources?tag=security-lake").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn list_sources_with_nonexistent_tag() {
    let app = build_router(test_state_with_sources());
    let (status, body) = get(app, "/api/sources?tag=nonexistent").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn source_health_not_found() {
    let app = build_router(test_state());
    let (status, body) = get(app, "/api/sources/nope/health").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body["error"].as_str().unwrap().contains("not found"));
}

// ===== Rules / Detections =====

#[tokio::test]
async fn list_rules_empty() {
    let app = build_router(test_state());
    let (status, body) = get(app, "/api/rules").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn list_rules_with_entries() {
    let app = build_router(test_state_with_rules());
    let (status, body) = get(app, "/api/rules").await;
    assert_eq!(status, StatusCode::OK);
    let rules = body.as_array().unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0]["id"], "rule-1");
    assert_eq!(rules[0]["severity"], "high");
}

#[tokio::test]
async fn get_rule_found() {
    let app = build_router(test_state_with_rules());
    let (status, body) = get(app, "/api/rules/rule-1").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["id"], "rule-1");
    assert_eq!(body["name"], "Test Rule");
}

#[tokio::test]
async fn get_rule_not_found() {
    let app = build_router(test_state_with_rules());
    let (status, body) = get(app, "/api/rules/nonexistent").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body["error"].as_str().unwrap().contains("not found"));
}

// ===== Investigations =====

#[tokio::test]
async fn list_investigations_empty() {
    let app = build_router(test_state());
    let (status, body) = get(app, "/api/investigations").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn list_investigations_with_entries() {
    let app = build_router(test_state_with_investigation());
    let (status, body) = get(app, "/api/investigations").await;
    assert_eq!(status, StatusCode::OK);
    let invs = body.as_array().unwrap();
    assert_eq!(invs.len(), 1);
    assert_eq!(invs[0]["id"], "inv-1");
    assert_eq!(invs[0]["name"], "Test Investigation");
    assert_eq!(invs[0]["node_count"], 2);
    assert_eq!(invs[0]["edge_count"], 1);
}

#[tokio::test]
async fn get_investigation_found() {
    let app = build_router(test_state_with_investigation());
    let (status, body) = get(app, "/api/investigations/inv-1").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["id"], "inv-1");
    assert_eq!(body["name"], "Test Investigation");
    assert!(body["graph_summary"]["total_nodes"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn get_investigation_not_found() {
    let app = build_router(test_state());
    let (status, body) = get(app, "/api/investigations/nope").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body["error"].as_str().unwrap().contains("not found"));
}

#[tokio::test]
async fn get_investigation_graph_cytoscape_format() {
    let app = build_router(test_state_with_investigation());
    let (status, body) = get(app, "/api/investigations/inv-1/graph").await;
    assert_eq!(status, StatusCode::OK);

    // Should have Cytoscape elements
    let elements = body["elements"].as_array().unwrap();
    let nodes: Vec<_> = elements.iter().filter(|e| e["group"] == "nodes").collect();
    let edges: Vec<_> = elements.iter().filter(|e| e["group"] == "edges").collect();
    assert_eq!(nodes.len(), 2);
    assert_eq!(edges.len(), 1);

    // Check node data format
    assert!(nodes[0]["data"]["id"].is_string());
    assert!(nodes[0]["data"]["type"].is_string());
    assert!(nodes[0]["data"]["label"].is_string());

    // Check edge data format
    assert!(edges[0]["data"]["source"].is_string());
    assert!(edges[0]["data"]["target"].is_string());

    // Summary present
    assert!(body["summary"]["total_nodes"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn get_investigation_report() {
    let app = build_router(test_state_with_investigation());
    let (status, body) = get(app, "/api/investigations/inv-1/report").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["investigation_id"], "inv-1");
    assert!(body["total_nodes"].as_u64().unwrap() > 0);
    assert!(body["entity_summaries"].is_array());
}

#[tokio::test]
async fn tag_timeline_event() {
    let app = build_router(test_state_with_investigation());
    let (status, body) = post_json(
        app,
        "/api/investigations/inv-1/timeline/tag",
        json!({
            "event_id": "evt-1",
            "tag": "suspicious",
            "notes": "looks bad"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["tagged"], true);
    assert_eq!(body["event_id"], "evt-1");
}

#[tokio::test]
async fn tag_timeline_event_not_found() {
    let app = build_router(test_state_with_investigation());
    let (status, body) = post_json(
        app,
        "/api/investigations/inv-1/timeline/tag",
        json!({
            "event_id": "nonexistent",
            "tag": "suspicious",
            "notes": ""
        }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body["error"].as_str().unwrap().contains("not found"));
}

#[tokio::test]
async fn delete_investigation() {
    let app = build_router(test_state_with_investigation());
    let (status, body) = delete(app, "/api/investigations/inv-1").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["deleted"], "inv-1");
}

#[tokio::test]
async fn delete_investigation_not_found() {
    let app = build_router(test_state());
    let (status, body) = delete(app, "/api/investigations/nope").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body["error"].as_str().unwrap().contains("not found"));
}

#[tokio::test]
async fn create_investigation_no_source() {
    let app = build_router(test_state());
    let (status, body) = post_json(
        app,
        "/api/investigations",
        json!({
            "name": "Manual investigation",
            "users": ["alice"],
            "ips": ["1.2.3.4"]
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body["id"].as_str().unwrap().is_empty());
    assert_eq!(body["name"], "Manual investigation");
}

// ===== From-detection pipeline (gate tests) =====

#[tokio::test]
async fn from_detection_rule_not_found() {
    let app = build_router(test_state_with_sources());
    let (status, body) = post_json(
        app,
        "/api/investigations/from-detection",
        json!({
            "rule_id": "nonexistent",
            "source_name": "cloudtrail",
            "lookback_minutes": 60
        }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body["error"].as_str().unwrap().contains("not found"));
}

#[tokio::test]
async fn from_detection_source_not_found() {
    let app = build_router(test_state_with_rules());
    let (status, body) = post_json(
        app,
        "/api/investigations/from-detection",
        json!({
            "rule_id": "rule-1",
            "source_name": "nonexistent",
            "lookback_minutes": 60
        }),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body["error"].as_str().unwrap().contains("not found"));
}
