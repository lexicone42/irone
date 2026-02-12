"""Attack scenarios mapped to MITRE ATT&CK techniques.

This module provides pre-built attack scenarios that generate synthetic
events matching real-world attack patterns. Each scenario is mapped to
MITRE ATT&CK techniques for detection coverage validation.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import polars as pl

from secdashboards.adversary.events import (
    EventStatus,
    OCSFEventGenerator,
    SyntheticEvent,
)
from secdashboards.adversary.network import NetworkEmulator, PacketResult

logger = logging.getLogger(__name__)


class AttackPhase(StrEnum):
    """MITRE ATT&CK kill chain phases."""

    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource-development"
    INITIAL_ACCESS = "initial-access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    DEFENSE_EVASION = "defense-evasion"
    CREDENTIAL_ACCESS = "credential-access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral-movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command-and-control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


@dataclass
class MITRETechnique:
    """MITRE ATT&CK technique reference."""

    id: str
    name: str
    phase: AttackPhase
    description: str = ""
    url: str = ""

    def __post_init__(self) -> None:
        if not self.url:
            base_id = self.id.split(".")[0]
            self.url = f"https://attack.mitre.org/techniques/{base_id}/"


@dataclass
class ScenarioStep:
    """A single step in an attack scenario."""

    name: str
    description: str
    technique: MITRETechnique
    generate_events: Callable[[], list[SyntheticEvent]]
    generate_network: Callable[[], list[PacketResult]] | None = None
    delay_seconds: float = 0.0


@dataclass
class AttackScenario:
    """A complete attack scenario with multiple steps."""

    id: str
    name: str
    description: str
    techniques: list[MITRETechnique]
    steps: list[ScenarioStep]
    tags: list[str] = field(default_factory=list)
    expected_detections: list[str] = field(default_factory=list)

    def get_technique_ids(self) -> list[str]:
        """Get all MITRE technique IDs in this scenario."""
        return [t.id for t in self.techniques]

    def get_phases(self) -> list[AttackPhase]:
        """Get all attack phases covered by this scenario."""
        return list(set(t.phase for t in self.techniques))


class ScenarioRunner:
    """Runner for executing attack scenarios.

    This class orchestrates the execution of attack scenarios,
    generating both synthetic log events and optional network traffic.
    """

    def __init__(
        self,
        event_generator: OCSFEventGenerator | None = None,
        network_emulator: NetworkEmulator | None = None,
    ) -> None:
        self.event_generator = event_generator or OCSFEventGenerator()
        self.network_emulator = network_emulator

    def run_scenario(
        self,
        scenario: AttackScenario,
        generate_network_traffic: bool = False,
    ) -> dict[str, Any]:
        """Execute an attack scenario and collect generated events.

        Args:
            scenario: The attack scenario to execute
            generate_network_traffic: Whether to generate real network traffic

        Returns:
            Dictionary with events, network_results, and metadata
        """
        import time

        all_events: list[SyntheticEvent] = []
        all_network_results: list[PacketResult] = []
        step_results: list[dict[str, Any]] = []

        start_time = datetime.now(UTC)

        for step in scenario.steps:
            step_start = datetime.now(UTC)
            logger.info(f"Executing step: {step.name}")

            # Generate synthetic events
            events = step.generate_events()
            all_events.extend(events)

            # Generate network traffic if enabled
            network_results = []
            if generate_network_traffic and step.generate_network and self.network_emulator:
                network_results = step.generate_network()
                all_network_results.extend(network_results)

            step_results.append(
                {
                    "step_name": step.name,
                    "technique_id": step.technique.id,
                    "technique_name": step.technique.name,
                    "events_generated": len(events),
                    "network_packets": len(network_results),
                    "duration_ms": (datetime.now(UTC) - step_start).total_seconds() * 1000,
                }
            )

            if step.delay_seconds > 0:
                time.sleep(step.delay_seconds)

        end_time = datetime.now(UTC)

        return {
            "scenario_id": scenario.id,
            "scenario_name": scenario.name,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "duration_seconds": (end_time - start_time).total_seconds(),
            "techniques": scenario.get_technique_ids(),
            "phases": [p.value for p in scenario.get_phases()],
            "total_events": len(all_events),
            "total_network_packets": len(all_network_results),
            "events": all_events,
            "network_results": all_network_results,
            "step_results": step_results,
            "expected_detections": scenario.expected_detections,
        }

    def events_to_dataframe(
        self,
        events: list[SyntheticEvent],
    ) -> pl.DataFrame:
        """Convert scenario events to a DataFrame for testing."""
        return self.event_generator.events_to_dataframe(events)


# Pre-built MITRE techniques used in scenarios
TECHNIQUES = {
    "T1078.004": MITRETechnique(
        id="T1078.004",
        name="Valid Accounts: Cloud Accounts",
        phase=AttackPhase.INITIAL_ACCESS,
        description="Adversaries may obtain and abuse credentials of a cloud account.",
    ),
    "T1098": MITRETechnique(
        id="T1098",
        name="Account Manipulation",
        phase=AttackPhase.PERSISTENCE,
        description="Adversaries may manipulate accounts to maintain access.",
    ),
    "T1098.001": MITRETechnique(
        id="T1098.001",
        name="Account Manipulation: Additional Cloud Credentials",
        phase=AttackPhase.PERSISTENCE,
        description="Adversaries may add additional credentials to cloud accounts.",
    ),
    "T1110": MITRETechnique(
        id="T1110",
        name="Brute Force",
        phase=AttackPhase.CREDENTIAL_ACCESS,
        description="Adversaries may use brute force to attempt access to accounts.",
    ),
    "T1562.007": MITRETechnique(
        id="T1562.007",
        name="Impair Defenses: Disable or Modify Cloud Firewall",
        phase=AttackPhase.DEFENSE_EVASION,
        description="Adversaries may disable or modify cloud firewall rules.",
    ),
    "T1106": MITRETechnique(
        id="T1106",
        name="Native API",
        phase=AttackPhase.EXECUTION,
        description="Adversaries may interact with native APIs to execute behaviors.",
    ),
    "T1046": MITRETechnique(
        id="T1046",
        name="Network Service Discovery",
        phase=AttackPhase.DISCOVERY,
        description="Adversaries may attempt to get a listing of services running.",
    ),
    "T1071.004": MITRETechnique(
        id="T1071.004",
        name="Application Layer Protocol: DNS",
        phase=AttackPhase.COMMAND_AND_CONTROL,
        description="Adversaries may use DNS for C2 communications.",
    ),
    "T1048.003": MITRETechnique(
        id="T1048.003",
        name="Exfiltration Over Alternative Protocol: DNS",
        phase=AttackPhase.EXFILTRATION,
        description="Adversaries may exfiltrate data over DNS.",
    ),
    "T1595": MITRETechnique(
        id="T1595",
        name="Active Scanning",
        phase=AttackPhase.RECONNAISSANCE,
        description="Adversaries may scan victim infrastructure to gather information.",
    ),
}


def _create_root_login_scenario(generator: OCSFEventGenerator) -> AttackScenario:
    """Create scenario for root account compromise."""
    return AttackScenario(
        id="root-account-compromise",
        name="AWS Root Account Compromise",
        description="Simulates compromise of AWS root account with login from suspicious IP",
        techniques=[TECHNIQUES["T1078.004"]],
        tags=["aws", "root", "initial-access"],
        expected_detections=["detect-root-login"],
        steps=[
            ScenarioStep(
                name="Root Login from Suspicious IP",
                description="Root account login from a known malicious IP address",
                technique=TECHNIQUES["T1078.004"],
                generate_events=lambda: [
                    generator.generate_root_login(
                        source_ip="185.220.101.1",
                        status=EventStatus.SUCCESS,
                    )
                ],
            ),
        ],
    )


def _create_privilege_escalation_scenario(generator: OCSFEventGenerator) -> AttackScenario:
    """Create scenario for privilege escalation via IAM."""
    return AttackScenario(
        id="iam-privilege-escalation",
        name="IAM Privilege Escalation",
        description="Simulates attacker escalating privileges via IAM policy attachment",
        techniques=[TECHNIQUES["T1098"], TECHNIQUES["T1098.001"]],
        tags=["aws", "iam", "privilege-escalation", "persistence"],
        expected_detections=["detect-iam-policy-changes", "detect-access-key-creation"],
        steps=[
            ScenarioStep(
                name="Attach Admin Policy",
                description="Attacker attaches AdministratorAccess policy to compromised user",
                technique=TECHNIQUES["T1098"],
                generate_events=lambda: [
                    generator.generate_iam_policy_change(
                        operation="AttachUserPolicy",
                        user_name="compromised-user",
                        policy_arn="arn:aws:iam::aws:policy/AdministratorAccess",
                    )
                ],
                delay_seconds=1.0,
            ),
            ScenarioStep(
                name="Create Backdoor Access Key",
                description="Attacker creates access key for persistence",
                technique=TECHNIQUES["T1098.001"],
                generate_events=lambda: [
                    generator.generate_access_key_creation(
                        user_name="backdoor-user",
                        created_by="compromised-user",
                    )
                ],
            ),
        ],
    )


def _create_brute_force_scenario(generator: OCSFEventGenerator) -> AttackScenario:
    """Create scenario for credential brute force attack."""
    return AttackScenario(
        id="credential-brute-force",
        name="Credential Brute Force Attack",
        description="Simulates multiple failed authentication attempts indicating brute force",
        techniques=[TECHNIQUES["T1110"]],
        tags=["aws", "brute-force", "credential-access"],
        expected_detections=["detect-failed-logins"],
        steps=[
            ScenarioStep(
                name="Multiple Failed Logins",
                description="Series of failed login attempts from single source IP",
                technique=TECHNIQUES["T1110"],
                generate_events=lambda: generator.generate_failed_login_attempts(
                    count=15,
                    user_name="admin",
                    source_ip="198.51.100.50",
                    time_spread_minutes=5,
                ),
            ),
        ],
    )


def _create_security_group_evasion_scenario(generator: OCSFEventGenerator) -> AttackScenario:
    """Create scenario for defense evasion via security group modification."""
    return AttackScenario(
        id="security-group-evasion",
        name="Security Group Defense Evasion",
        description="Simulates attacker modifying security groups to enable access",
        techniques=[TECHNIQUES["T1562.007"]],
        tags=["aws", "ec2", "defense-evasion", "network"],
        expected_detections=["detect-security-group-changes"],
        steps=[
            ScenarioStep(
                name="Open SSH to World",
                description="Attacker opens port 22 to 0.0.0.0/0",
                technique=TECHNIQUES["T1562.007"],
                generate_events=lambda: [
                    generator.generate_security_group_change(
                        operation="AuthorizeSecurityGroupIngress",
                        from_port=22,
                        to_port=22,
                        cidr="0.0.0.0/0",
                    )
                ],
                delay_seconds=0.5,
            ),
            ScenarioStep(
                name="Open RDP to World",
                description="Attacker opens port 3389 to 0.0.0.0/0",
                technique=TECHNIQUES["T1562.007"],
                generate_events=lambda: [
                    generator.generate_security_group_change(
                        operation="AuthorizeSecurityGroupIngress",
                        from_port=3389,
                        to_port=3389,
                        cidr="0.0.0.0/0",
                    )
                ],
            ),
        ],
    )


def _create_api_reconnaissance_scenario(generator: OCSFEventGenerator) -> AttackScenario:
    """Create scenario for API-based reconnaissance."""
    return AttackScenario(
        id="api-reconnaissance",
        name="AWS API Reconnaissance",
        description="Simulates automated enumeration of AWS resources via APIs",
        techniques=[TECHNIQUES["T1106"], TECHNIQUES["T1595"]],
        tags=["aws", "reconnaissance", "enumeration"],
        expected_detections=["detect-unusual-api-calls"],
        steps=[
            ScenarioStep(
                name="High Volume API Enumeration",
                description="Large number of API calls to enumerate AWS resources",
                technique=TECHNIQUES["T1106"],
                generate_events=lambda: generator.generate_unusual_api_volume(
                    count=200,
                    user_name="recon-user",
                    time_spread_minutes=10,
                ),
            ),
        ],
    )


def _create_network_discovery_scenario(
    generator: OCSFEventGenerator,
    network_emulator: NetworkEmulator | None,
) -> AttackScenario:
    """Create scenario for network service discovery."""
    steps = [
        ScenarioStep(
            name="Port Scan Simulation",
            description="Generate VPC flow events simulating port scan",
            technique=TECHNIQUES["T1046"],
            generate_events=lambda: generator.generate_port_scan(
                src_ip="185.220.101.1",
                target_ip="10.0.0.50",
                ports=[22, 23, 80, 443, 3389, 8080],
            ),
        ),
    ]

    # Add real network traffic step if emulator available
    if network_emulator:
        steps.append(
            ScenarioStep(
                name="Live Port Scan",
                description="Actual port scan generating real VPC flow logs",
                technique=TECHNIQUES["T1046"],
                generate_events=lambda: [],
                generate_network=lambda: network_emulator.simulate_port_scan(
                    target_ip="127.0.0.1",  # Safe target for testing
                    common_ports=False,
                    custom_ports=[80, 443, 8080],
                ),
            )
        )

    return AttackScenario(
        id="network-discovery",
        name="Network Service Discovery",
        description="Simulates network scanning to discover running services",
        techniques=[TECHNIQUES["T1046"]],
        tags=["network", "discovery", "port-scan"],
        expected_detections=[],  # May need VPC Flow specific detections
        steps=steps,
    )


def _create_dns_c2_scenario(
    generator: OCSFEventGenerator,
    network_emulator: NetworkEmulator | None,
) -> AttackScenario:
    """Create scenario for DNS-based C2 and exfiltration."""
    steps = [
        ScenarioStep(
            name="DNS C2 Queries",
            description="Generate DNS queries to suspicious domain",
            technique=TECHNIQUES["T1071.004"],
            generate_events=lambda: [
                generator.generate_dns_query(
                    hostname=f"beacon{i}.c2.malware.evil.com",
                    query_type="TXT",
                )
                for i in range(10)
            ],
        ),
    ]

    if network_emulator:
        steps.append(
            ScenarioStep(
                name="Live DNS Exfiltration",
                description="Actual DNS queries simulating data exfiltration",
                technique=TECHNIQUES["T1048.003"],
                generate_events=lambda: [],
                generate_network=lambda: network_emulator.simulate_dns_exfil(
                    base_domain="exfil.example.com",
                    data_chunks=["secret", "data", "here"],
                ),
            )
        )

    return AttackScenario(
        id="dns-c2-exfil",
        name="DNS Command & Control and Exfiltration",
        description="Simulates DNS tunneling for C2 communications and data exfiltration",
        techniques=[TECHNIQUES["T1071.004"], TECHNIQUES["T1048.003"]],
        tags=["network", "dns", "c2", "exfiltration"],
        expected_detections=[],  # May need Route53 specific detections
        steps=steps,
    )


def _create_full_attack_chain_scenario(generator: OCSFEventGenerator) -> AttackScenario:
    """Create a comprehensive attack chain scenario."""
    return AttackScenario(
        id="full-attack-chain",
        name="Full AWS Attack Chain",
        description="Complete attack simulation from initial access to persistence",
        techniques=[
            TECHNIQUES["T1110"],
            TECHNIQUES["T1078.004"],
            TECHNIQUES["T1098"],
            TECHNIQUES["T1098.001"],
            TECHNIQUES["T1562.007"],
        ],
        tags=["aws", "full-chain", "comprehensive"],
        expected_detections=[
            "detect-failed-logins",
            "detect-root-login",
            "detect-iam-policy-changes",
            "detect-access-key-creation",
            "detect-security-group-changes",
        ],
        steps=[
            ScenarioStep(
                name="Initial Brute Force",
                description="Failed login attempts during initial compromise",
                technique=TECHNIQUES["T1110"],
                generate_events=lambda: generator.generate_failed_login_attempts(
                    count=8,
                    user_name="admin",
                    time_spread_minutes=3,
                ),
                delay_seconds=1.0,
            ),
            ScenarioStep(
                name="Successful Root Login",
                description="Attacker gains access to root account",
                technique=TECHNIQUES["T1078.004"],
                generate_events=lambda: [
                    generator.generate_root_login(
                        status=EventStatus.SUCCESS,
                    )
                ],
                delay_seconds=0.5,
            ),
            ScenarioStep(
                name="Privilege Escalation",
                description="Attach admin policy to user",
                technique=TECHNIQUES["T1098"],
                generate_events=lambda: [
                    generator.generate_iam_policy_change(
                        operation="AttachUserPolicy",
                        user_name="attacker-user",
                    )
                ],
                delay_seconds=0.5,
            ),
            ScenarioStep(
                name="Create Backdoor",
                description="Create access key for persistence",
                technique=TECHNIQUES["T1098.001"],
                generate_events=lambda: [
                    generator.generate_access_key_creation(
                        user_name="backdoor",
                        created_by="attacker-user",
                    )
                ],
                delay_seconds=0.5,
            ),
            ScenarioStep(
                name="Modify Security Groups",
                description="Open firewall for future access",
                technique=TECHNIQUES["T1562.007"],
                generate_events=lambda: [
                    generator.generate_security_group_change(
                        operation="AuthorizeSecurityGroupIngress",
                        from_port=22,
                        to_port=22,
                        cidr="0.0.0.0/0",
                    ),
                ],
            ),
        ],
    )


def get_mitre_scenarios(
    event_generator: OCSFEventGenerator | None = None,
    network_emulator: NetworkEmulator | None = None,
) -> dict[str, AttackScenario]:
    """Get all pre-built MITRE ATT&CK scenarios.

    Args:
        event_generator: Optional custom event generator
        network_emulator: Optional network emulator for live traffic

    Returns:
        Dictionary mapping scenario IDs to AttackScenario objects
    """
    gen = event_generator or OCSFEventGenerator()

    scenarios = {
        "root-account-compromise": _create_root_login_scenario(gen),
        "iam-privilege-escalation": _create_privilege_escalation_scenario(gen),
        "credential-brute-force": _create_brute_force_scenario(gen),
        "security-group-evasion": _create_security_group_evasion_scenario(gen),
        "api-reconnaissance": _create_api_reconnaissance_scenario(gen),
        "network-discovery": _create_network_discovery_scenario(gen, network_emulator),
        "dns-c2-exfil": _create_dns_c2_scenario(gen, network_emulator),
        "full-attack-chain": _create_full_attack_chain_scenario(gen),
    }

    return scenarios


# Convenience constant for importing
MITRE_SCENARIOS = get_mitre_scenarios()
