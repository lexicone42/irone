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

import importlib as _importlib

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

# Lazy imports — avoids pulling in heavy optional deps (polars, pyvis, etc.)
# at module load time. Enables fast Lambda cold starts.
_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "DataCatalog": ("secdashboards.catalog.registry", "DataCatalog"),
    "DataConnector": ("secdashboards.connectors.base", "DataConnector"),
    "SecurityLakeConnector": ("secdashboards.connectors.security_lake", "SecurityLakeConnector"),
    "DetectionRule": ("secdashboards.detections.rule", "DetectionRule"),
    "SQLDetectionRule": ("secdashboards.detections.rule", "SQLDetectionRule"),
    "DetectionRunner": ("secdashboards.detections.runner", "DetectionRunner"),
    "GraphBuilder": ("secdashboards.graph.builder", "GraphBuilder"),
    "GraphVisualizer": ("secdashboards.graph.visualization", "GraphVisualizer"),
    "SecurityGraph": ("secdashboards.graph.models", "SecurityGraph"),
}


def __getattr__(name: str) -> object:
    if name in _LAZY_IMPORTS:
        module_path, attr = _LAZY_IMPORTS[name]
        mod = _importlib.import_module(module_path)
        return getattr(mod, attr)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
