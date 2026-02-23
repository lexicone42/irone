pub mod builder;
pub mod enrichment;
mod models;
mod timeline;

pub use builder::GraphBuilder;
pub use enrichment::{
    EntityAnomalyScore, LateralMovementTrace, SecurityLakeEnricher, score_entity_anomalies,
};
pub use models::{
    APIOperationNode, EdgeType, EventNode, GraphEdge, GraphNode, IPAddressNode, NodeType,
    PrincipalNode, ResourceNode, SecurityFindingNode, SecurityGraph,
};
pub use timeline::{
    EventTag, InvestigationTimeline, TAG_COLORS, TimelineEvent, extract_timeline_from_graph,
    generate_narrative, generate_timeline_summary_prompt,
};
