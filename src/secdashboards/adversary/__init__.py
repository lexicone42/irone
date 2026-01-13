"""Adversary emulation and red team testing module.

This module provides tools for testing security detections through:
- Synthetic OCSF-compliant event generation for local testing
- Network packet generation to trigger network-based detections
- Pre-built attack scenarios mapped to MITRE ATT&CK techniques
- Lambda deployment for network-based testing from within AWS VPC
"""

from secdashboards.adversary.deploy import (
    AdversaryLambdaBuilder,
    create_deployment_package,
)
from secdashboards.adversary.events import (
    OCSFEventGenerator,
    SyntheticCloudTrailEvent,
    SyntheticDNSEvent,
    SyntheticVPCFlowEvent,
)
from secdashboards.adversary.network import (
    NetworkEmulator,
    PacketGenerator,
)
from secdashboards.adversary.runner import (
    AdversaryTestRunner,
    TestResult,
)
from secdashboards.adversary.scenarios import (
    MITRE_SCENARIOS,
    AttackScenario,
    ScenarioRunner,
)

__all__ = [
    "OCSFEventGenerator",
    "SyntheticCloudTrailEvent",
    "SyntheticVPCFlowEvent",
    "SyntheticDNSEvent",
    "AttackScenario",
    "ScenarioRunner",
    "MITRE_SCENARIOS",
    "PacketGenerator",
    "NetworkEmulator",
    "AdversaryTestRunner",
    "TestResult",
    "AdversaryLambdaBuilder",
    "create_deployment_package",
]
