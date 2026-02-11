"""Tool definitions for Bedrock agent capabilities.

This module defines tools that can be used by Claude via the Bedrock
Converse API for agentic workflows. Currently a skeleton - tools are
not implemented but the structure is ready for future expansion.

Tool Use Documentation:
https://docs.aws.amazon.com/bedrock/latest/userguide/tool-use.html
"""

from typing import Any

# Tool specification format for Bedrock Converse API
# These are defined but not yet wired to implementations

SECURITY_LAKE_QUERY_TOOL = {
    "toolSpec": {
        "name": "query_security_lake",
        "description": (
            "Execute a SQL query against AWS Security Lake via Athena. "
            "Use this to search for security events matching specific criteria. "
            "Returns results as a list of matching events."
        ),
        "inputSchema": {
            "json": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "The SQL query to execute against Security Lake",
                    },
                    "database": {
                        "type": "string",
                        "description": "The Glue database name",
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of results to return",
                        "default": 100,
                    },
                },
                "required": ["query", "database"],
            }
        },
    }
}

BUILD_INVESTIGATION_GRAPH_TOOL = {
    "toolSpec": {
        "name": "build_investigation_graph",
        "description": (
            "Build an investigation graph from a set of security events or a detection result. "
            "The graph shows relationships between principals, IPs, resources, and API operations."
        ),
        "inputSchema": {
            "json": {
                "type": "object",
                "properties": {
                    "detection_id": {
                        "type": "string",
                        "description": "ID of a triggered detection to build graph from",
                    },
                    "user_names": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of user names to include in the graph",
                    },
                    "ip_addresses": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of IP addresses to include in the graph",
                    },
                    "time_window_minutes": {
                        "type": "integer",
                        "description": "Time window for enrichment queries",
                        "default": 60,
                    },
                },
                "required": [],
            }
        },
    }
}

RUN_DETECTION_TOOL = {
    "toolSpec": {
        "name": "run_detection",
        "description": (
            "Execute a detection rule against Security Lake data. "
            "Returns whether the detection triggered and any matched events."
        ),
        "inputSchema": {
            "json": {
                "type": "object",
                "properties": {
                    "rule_id": {
                        "type": "string",
                        "description": "ID of the detection rule to run",
                    },
                    "lookback_minutes": {
                        "type": "integer",
                        "description": "How far back to search",
                        "default": 60,
                    },
                },
                "required": ["rule_id"],
            }
        },
    }
}

GET_ENTITY_CONTEXT_TOOL = {
    "toolSpec": {
        "name": "get_entity_context",
        "description": (
            "Get historical context for a security entity (user, IP, or resource). "
            "Returns recent activity, baseline behavior, and any previous alerts."
        ),
        "inputSchema": {
            "json": {
                "type": "object",
                "properties": {
                    "entity_type": {
                        "type": "string",
                        "enum": ["user", "ip", "resource"],
                        "description": "Type of entity to look up",
                    },
                    "entity_id": {
                        "type": "string",
                        "description": "The entity identifier (username, IP, or ARN)",
                    },
                    "days_back": {
                        "type": "integer",
                        "description": "How many days of history to retrieve",
                        "default": 7,
                    },
                },
                "required": ["entity_type", "entity_id"],
            }
        },
    }
}

SEARCH_THREAT_INTEL_TOOL = {
    "toolSpec": {
        "name": "search_threat_intel",
        "description": (
            "Search threat intelligence sources for information about an indicator. "
            "Supports IP addresses, domains, and file hashes."
        ),
        "inputSchema": {
            "json": {
                "type": "object",
                "properties": {
                    "indicator_type": {
                        "type": "string",
                        "enum": ["ip", "domain", "hash"],
                        "description": "Type of indicator",
                    },
                    "indicator_value": {
                        "type": "string",
                        "description": "The indicator value to search for",
                    },
                },
                "required": ["indicator_type", "indicator_value"],
            }
        },
    }
}


# All available tools (for reference, not yet implemented)
ALL_TOOLS = [
    SECURITY_LAKE_QUERY_TOOL,
    BUILD_INVESTIGATION_GRAPH_TOOL,
    RUN_DETECTION_TOOL,
    GET_ENTITY_CONTEXT_TOOL,
    SEARCH_THREAT_INTEL_TOOL,
]


def get_tool_config(tool_names: list[str] | None = None) -> dict[str, Any]:
    """Get tool configuration for Bedrock Converse API.

    Args:
        tool_names: List of tool names to include, or None for all tools

    Returns:
        Tool configuration dict for Bedrock Converse API

    Note:
        Tool implementations are not yet connected. This returns the
        tool specifications only.
    """
    tool_map = {
        "query_security_lake": SECURITY_LAKE_QUERY_TOOL,
        "build_investigation_graph": BUILD_INVESTIGATION_GRAPH_TOOL,
        "run_detection": RUN_DETECTION_TOOL,
        "get_entity_context": GET_ENTITY_CONTEXT_TOOL,
        "search_threat_intel": SEARCH_THREAT_INTEL_TOOL,
    }

    if tool_names is None:
        tools = ALL_TOOLS
    else:
        tools = [tool_map[name] for name in tool_names if name in tool_map]

    return {"tools": tools}


class ToolExecutor:
    """Executor for agent tools.

    This is a skeleton class for future implementation of tool execution.
    When implementing, connect each tool to the appropriate secdashboards
    module (connectors, graph, detections, etc.).
    """

    def __init__(
        self,
        security_lake_connector: Any | None = None,
        graph_builder: Any | None = None,
        detection_runner: Any | None = None,
    ) -> None:
        """Initialize tool executor.

        Args:
            security_lake_connector: SecurityLakeConnector instance
            graph_builder: GraphBuilder instance
            detection_runner: DetectionRunner instance
        """
        self.connector = security_lake_connector
        self.graph_builder = graph_builder
        self.detection_runner = detection_runner

    def execute(self, tool_name: str, tool_input: dict[str, Any]) -> dict[str, Any]:
        """Execute a tool and return results.

        Args:
            tool_name: Name of the tool to execute
            tool_input: Input parameters for the tool

        Returns:
            Tool execution results

        Raises:
            NotImplementedError: Tool execution not yet implemented
        """
        # Skeleton - to be implemented when agent capabilities are enabled
        raise NotImplementedError(
            f"Tool execution for '{tool_name}' is not yet implemented. "
            "This is a skeleton for future agent capabilities."
        )

    def handle_tool_use(self, tool_use_block: dict[str, Any]) -> dict[str, Any]:
        """Handle a tool use block from Bedrock response.

        Args:
            tool_use_block: Tool use content block from Bedrock

        Returns:
            Tool result for sending back to Bedrock

        Raises:
            NotImplementedError: Tool handling not yet implemented
        """
        tool_name = tool_use_block.get("name", "")
        tool_input = tool_use_block.get("input", {})
        tool_use_id = tool_use_block.get("toolUseId")

        if not tool_name:
            raise ValueError("Tool name is required")

        try:
            result = self.execute(str(tool_name), tool_input)
            return {
                "toolResult": {
                    "toolUseId": tool_use_id,
                    "content": [{"json": result}],
                }
            }
        except Exception as e:
            return {
                "toolResult": {
                    "toolUseId": tool_use_id,
                    "content": [{"text": f"Error: {e!s}"}],
                    "status": "error",
                }
            }
