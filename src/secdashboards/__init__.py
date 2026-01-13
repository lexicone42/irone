"""Security Data Lake Analytics - Connect to AWS Security Lake and run detection rules.

This package provides:
- **catalog**: Data source catalog management
- **connectors**: Athena and Security Lake connectors
- **detections**: Detection rule framework and runner
- **graph**: Investigation graph visualization and Neptune integration
- **health**: Data source health monitoring
- **adversary**: Red team and detection testing
- **deploy**: Lambda deployment utilities

Example usage:
    >>> from secdashboards import DataCatalog, SecurityLakeConnector
    >>> catalog = DataCatalog.from_yaml("catalog.yaml")
    >>> connector = catalog.get_connector("cloudtrail")
    >>> df = connector.query_time_range("time_dt", start, end)
"""

from secdashboards.catalog.registry import DataCatalog
from secdashboards.connectors.base import DataConnector
from secdashboards.connectors.security_lake import SecurityLakeConnector
from secdashboards.detections.rule import DetectionRule, SQLDetectionRule
from secdashboards.detections.runner import DetectionRunner
from secdashboards.graph import GraphBuilder, GraphVisualizer, SecurityGraph

__version__ = "0.1.0"
__all__ = [
    # Catalog
    "DataCatalog",
    # Connectors
    "DataConnector",
    "SecurityLakeConnector",
    # Detections
    "DetectionRule",
    "SQLDetectionRule",
    "DetectionRunner",
    # Graph
    "GraphBuilder",
    "GraphVisualizer",
    "SecurityGraph",
]
