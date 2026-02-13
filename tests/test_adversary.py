"""Tests for the adversary emulation module."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from secdashboards.adversary.events import (
    ActorUser,
    APIInfo,
    DstEndpoint,
    EventStatus,
    OCSFEventGenerator,
    SrcEndpoint,
    SyntheticAuthenticationEvent,
    SyntheticCloudTrailEvent,
    SyntheticDNSEvent,
    SyntheticVPCFlowEvent,
)
from secdashboards.adversary.network import (
    DNSQuery,
    NetworkEmulator,
    PacketResult,
    Protocol,
    TCPSYNPacket,
)
from secdashboards.adversary.runner import (
    AdversaryTestRunner,
    LocalDetectionTester,
    TestOutcome,
    TestResult,
    TestSuite,
)
from secdashboards.adversary.scenarios import (
    TECHNIQUES,
    AttackPhase,
    AttackScenario,
    MITRETechnique,
    ScenarioRunner,
    ScenarioStep,
    get_mitre_scenarios,
)
from secdashboards.connectors.result import QueryResult
from secdashboards.connectors.security_lake import OCSFEventClass


class TestSyntheticEvents:
    """Tests for synthetic event generation."""

    def test_cloudtrail_event_creation(self) -> None:
        """Test creating a synthetic CloudTrail event."""
        event = SyntheticCloudTrailEvent(
            actor_user=ActorUser(name="test-user", type="IAMUser"),
            api=APIInfo(operation="DescribeInstances", service_name="ec2.amazonaws.com"),
        )

        assert event.class_uid == OCSFEventClass.API_ACTIVITY
        assert event.actor_user.name == "test-user"
        assert event.api.operation == "DescribeInstances"
        assert event.time > 0  # Epoch time set

    def test_cloudtrail_event_to_ocsf(self) -> None:
        """Test converting CloudTrail event to OCSF dict."""
        event = SyntheticCloudTrailEvent(
            actor_user=ActorUser(name="admin"),
            api=APIInfo(operation="CreateUser", service_name="iam.amazonaws.com"),
        )

        ocsf_dict = event.to_ocsf_dict()

        assert ocsf_dict["class_uid"] == 6003  # API_ACTIVITY
        assert ocsf_dict["actor"]["user"]["name"] == "admin"
        assert ocsf_dict["api"]["operation"] == "CreateUser"
        assert ocsf_dict["api"]["service"]["name"] == "iam.amazonaws.com"

    def test_authentication_event_creation(self) -> None:
        """Test creating a synthetic authentication event."""
        event = SyntheticAuthenticationEvent(
            status=EventStatus.FAILURE,
            actor_user=ActorUser(name="root", type="Root"),
            src_endpoint=SrcEndpoint(ip="192.168.1.100"),
        )

        assert event.class_uid == OCSFEventClass.AUTHENTICATION
        assert event.status == EventStatus.FAILURE
        assert event.actor_user.type == "Root"

    def test_vpc_flow_event_creation(self) -> None:
        """Test creating a synthetic VPC Flow event."""
        event = SyntheticVPCFlowEvent(
            src_endpoint=SrcEndpoint(ip="10.0.0.5", port=54321),
            dst_endpoint=DstEndpoint(ip="10.0.0.100", port=443),
            action="Accept",
        )

        assert event.class_uid == OCSFEventClass.NETWORK_ACTIVITY
        assert event.src_endpoint.ip == "10.0.0.5"
        assert event.dst_endpoint.port == 443
        assert event.action == "Accept"

    def test_dns_event_creation(self) -> None:
        """Test creating a synthetic DNS event."""
        event = SyntheticDNSEvent(
            query={"hostname": "malware.evil.com", "type": "A", "class": "IN"},
            rcode="NOERROR",
        )

        assert event.class_uid == OCSFEventClass.DNS_ACTIVITY
        assert event.query["hostname"] == "malware.evil.com"


class TestOCSFEventGenerator:
    """Tests for the OCSF event generator."""

    def test_generate_root_login(self) -> None:
        """Test generating root login event."""
        gen = OCSFEventGenerator(account_id="123456789012")
        event = gen.generate_root_login(source_ip="198.51.100.1")

        assert event.actor_user.type == "Root"
        assert event.actor_user.name == "root"
        assert event.src_endpoint.ip == "198.51.100.1"
        assert event.class_uid == OCSFEventClass.AUTHENTICATION

    def test_generate_iam_policy_change(self) -> None:
        """Test generating IAM policy change event."""
        gen = OCSFEventGenerator()
        event = gen.generate_iam_policy_change(
            operation="AttachUserPolicy",
            user_name="attacker",
            policy_arn="arn:aws:iam::aws:policy/AdministratorAccess",
        )

        assert event.api.operation == "AttachUserPolicy"
        assert event.api.service_name == "iam.amazonaws.com"
        assert "AdministratorAccess" in event.api.request_data

    def test_generate_security_group_change(self) -> None:
        """Test generating security group change event."""
        gen = OCSFEventGenerator()
        event = gen.generate_security_group_change(
            operation="AuthorizeSecurityGroupIngress",
            from_port=22,
            to_port=22,
            cidr="0.0.0.0/0",
        )

        assert event.api.operation == "AuthorizeSecurityGroupIngress"
        assert event.api.service_name == "ec2.amazonaws.com"
        request_data = json.loads(event.api.request_data)
        assert request_data["ipPermissions"][0]["fromPort"] == 22
        assert request_data["ipPermissions"][0]["ipRanges"][0]["cidrIp"] == "0.0.0.0/0"

    def test_generate_access_key_creation(self) -> None:
        """Test generating access key creation event."""
        gen = OCSFEventGenerator()
        event = gen.generate_access_key_creation(
            user_name="backdoor-user",
            created_by="attacker",
        )

        assert event.api.operation == "CreateAccessKey"
        assert event.actor_user.name == "attacker"

    def test_generate_failed_login_attempts(self) -> None:
        """Test generating multiple failed login attempts."""
        gen = OCSFEventGenerator()
        events = gen.generate_failed_login_attempts(
            count=10,
            user_name="admin",
            source_ip="198.51.100.50",
        )

        assert len(events) == 10
        assert all(e.status == EventStatus.FAILURE for e in events)
        assert all(e.actor_user.name == "admin" for e in events)
        assert all(e.src_endpoint.ip == "198.51.100.50" for e in events)

    def test_generate_unusual_api_volume(self) -> None:
        """Test generating high volume API calls."""
        gen = OCSFEventGenerator()
        events = gen.generate_unusual_api_volume(
            count=100,
            user_name="scanner",
        )

        assert len(events) == 100
        assert all(e.actor_user.name == "scanner" for e in events)

    def test_generate_port_scan(self) -> None:
        """Test generating port scan events."""
        gen = OCSFEventGenerator()
        events = gen.generate_port_scan(
            src_ip="185.220.101.1",
            target_ip="10.0.0.50",
            ports=[22, 80, 443],
        )

        assert len(events) == 3
        assert all(e.class_uid == OCSFEventClass.NETWORK_ACTIVITY for e in events)
        ports = [e.dst_endpoint.port for e in events]
        assert set(ports) == {22, 80, 443}

    def test_events_to_dataframe(self) -> None:
        """Test converting events to DataFrame."""
        gen = OCSFEventGenerator()
        events = [
            gen.generate_root_login(),
            gen.generate_iam_policy_change(),
        ]

        df = gen.events_to_dataframe(events)

        assert isinstance(df, QueryResult)
        assert len(df) == 2
        assert "class_uid" in df.columns
        assert "actor.user.name" in df.columns


class TestAttackScenarios:
    """Tests for attack scenarios."""

    def test_mitre_technique_creation(self) -> None:
        """Test creating MITRE technique reference."""
        technique = MITRETechnique(
            id="T1078.004",
            name="Valid Accounts: Cloud Accounts",
            phase=AttackPhase.INITIAL_ACCESS,
        )

        assert technique.id == "T1078.004"
        assert technique.phase == AttackPhase.INITIAL_ACCESS
        assert "attack.mitre.org" in technique.url

    def test_attack_scenario_creation(self) -> None:
        """Test creating an attack scenario."""
        gen = OCSFEventGenerator()

        scenario = AttackScenario(
            id="test-scenario",
            name="Test Scenario",
            description="A test scenario",
            techniques=[TECHNIQUES["T1078.004"]],
            steps=[
                ScenarioStep(
                    name="Test Step",
                    description="A test step",
                    technique=TECHNIQUES["T1078.004"],
                    generate_events=lambda: [gen.generate_root_login()],
                ),
            ],
            expected_detections=["detect-root-login"],
        )

        assert scenario.id == "test-scenario"
        assert len(scenario.steps) == 1
        assert scenario.get_technique_ids() == ["T1078.004"]

    def test_get_mitre_scenarios(self) -> None:
        """Test getting all pre-built scenarios."""
        scenarios = get_mitre_scenarios()

        assert len(scenarios) > 0
        assert "root-account-compromise" in scenarios
        assert "iam-privilege-escalation" in scenarios
        assert "credential-brute-force" in scenarios

    def test_scenario_runner(self) -> None:
        """Test running a scenario."""
        gen = OCSFEventGenerator()
        runner = ScenarioRunner(event_generator=gen)
        scenarios = get_mitre_scenarios(event_generator=gen)

        result = runner.run_scenario(scenarios["root-account-compromise"])

        assert result["total_events"] > 0
        assert "T1078.004" in result["techniques"]
        assert len(result["events"]) > 0

    def test_full_attack_chain_scenario(self) -> None:
        """Test the full attack chain scenario."""
        gen = OCSFEventGenerator()
        scenarios = get_mitre_scenarios(event_generator=gen)
        runner = ScenarioRunner(event_generator=gen)

        result = runner.run_scenario(scenarios["full-attack-chain"])

        assert result["total_events"] > 5
        assert len(result["techniques"]) >= 3
        assert "detect-root-login" in result["expected_detections"]


class TestNetworkEmulator:
    """Tests for network emulation."""

    def test_tcp_syn_packet_generation(self) -> None:
        """Test TCP SYN packet generation."""
        packet = TCPSYNPacket(src_port=12345, dst_port=80)
        data = packet.generate()

        # TCP header is at least 20 bytes; our minimal version is 18 (H+H+I+I+H+H+H)
        assert len(data) >= 14
        assert data[0:2] == b"\x30\x39"  # src_port 12345 in big-endian

    def test_dns_query_packet_generation(self) -> None:
        """Test DNS query packet generation."""
        query = DNSQuery(hostname="example.com", query_type="A")
        data = query.generate()

        assert len(data) > 12  # At least header size
        assert b"\x07example\x03com\x00" in data  # Encoded hostname

    def test_packet_result_creation(self) -> None:
        """Test packet result data class."""
        result = PacketResult(
            success=True,
            dst_ip="10.0.0.50",
            dst_port=443,
            protocol=Protocol.TCP,
            response_received=True,
            response_time_ms=15.5,
        )

        assert result.success
        assert result.dst_port == 443
        assert result.response_time_ms == 15.5

    def test_network_emulator_results_summary(self) -> None:
        """Test network emulator results summary."""
        emulator = NetworkEmulator()

        results = [
            PacketResult(success=True, dst_ip="10.0.0.1", dst_port=80, response_time_ms=10),
            PacketResult(
                success=True,
                dst_ip="10.0.0.1",
                dst_port=443,
                response_time_ms=20,
                response_received=True,
            ),
            PacketResult(success=False, dst_ip="10.0.0.1", dst_port=22, error="Connection refused"),
        ]

        summary = emulator.results_summary(results)

        assert summary["total_packets"] == 3
        assert summary["successful_sends"] == 2
        assert summary["responses_received"] == 1
        assert summary["average_response_time_ms"] == 10.0

    @patch("socket.socket")
    def test_tcp_connect_success(self, mock_socket_class: MagicMock) -> None:
        """Test TCP connect with mocked socket."""
        mock_socket = MagicMock()
        mock_socket.getsockname.return_value = ("192.168.1.100", 54321)
        mock_socket_class.return_value = mock_socket

        emulator = NetworkEmulator()
        result = emulator.tcp_connect("10.0.0.50", 443)

        assert result.success
        mock_socket.connect.assert_called_once_with(("10.0.0.50", 443))

    @patch("socket.socket")
    def test_dns_query_success(self, mock_socket_class: MagicMock) -> None:
        """Test DNS query with mocked socket."""
        mock_socket = MagicMock()
        mock_socket.getsockname.return_value = ("192.168.1.100", 54321)
        mock_socket.recvfrom.return_value = (b"\x00" * 100, ("8.8.8.8", 53))
        mock_socket_class.return_value = mock_socket

        emulator = NetworkEmulator()
        result = emulator.dns_query("example.com")

        assert result.success
        assert result.response_received


class TestAdversaryTestRunner:
    """Tests for the adversary test runner."""

    def test_test_result_creation(self) -> None:
        """Test creating a test result."""
        result = TestResult(
            rule_id="detect-root-login",
            rule_name="Root Login Detection",
            outcome=TestOutcome.PASS,
            scenario_id="root-account-compromise",
            events_generated=5,
        )

        assert result.outcome == TestOutcome.PASS
        assert result.rule_id == "detect-root-login"

    def test_test_result_to_dict(self) -> None:
        """Test converting test result to dict."""
        result = TestResult(
            rule_id="test-rule",
            rule_name="Test Rule",
            outcome=TestOutcome.FAIL,
            scenario_id="test-scenario",
        )

        result_dict = result.to_dict()

        assert result_dict["rule_id"] == "test-rule"
        assert result_dict["outcome"] == "fail"

    def test_test_suite_metrics(self) -> None:
        """Test test suite metrics calculation."""
        suite = TestSuite()

        suite.add_result(
            TestResult(
                rule_id="rule1",
                rule_name="Rule 1",
                outcome=TestOutcome.PASS,
                scenario_id="s1",
            )
        )
        suite.add_result(
            TestResult(
                rule_id="rule2",
                rule_name="Rule 2",
                outcome=TestOutcome.PASS,
                scenario_id="s1",
            )
        )
        suite.add_result(
            TestResult(
                rule_id="rule3",
                rule_name="Rule 3",
                outcome=TestOutcome.FAIL,
                scenario_id="s1",
            )
        )

        assert suite.total_tests == 3
        assert suite.passed == 2
        assert suite.failed == 1
        assert suite.pass_rate == pytest.approx(66.67, rel=0.1)

    def test_test_suite_summary(self) -> None:
        """Test test suite summary generation."""
        suite = TestSuite()
        suite.scenarios_run = ["scenario1", "scenario2"]
        suite.rules_tested = ["rule1", "rule2"]

        suite.add_result(
            TestResult(
                rule_id="rule1",
                rule_name="Rule 1",
                outcome=TestOutcome.PASS,
                scenario_id="scenario1",
            )
        )

        suite.complete()
        summary = suite.summary()

        assert summary["total_tests"] == 1
        assert summary["passed"] == 1
        assert len(summary["scenarios_run"]) == 2

    def test_adversary_runner_generate_events(self) -> None:
        """Test generating events from scenario."""
        gen = OCSFEventGenerator()
        runner = AdversaryTestRunner(event_generator=gen)
        scenarios = get_mitre_scenarios(event_generator=gen)

        events, df = runner.generate_test_events(scenarios["root-account-compromise"])

        assert len(events) > 0
        assert isinstance(df, QueryResult)
        assert len(df) > 0

    def test_local_detection_tester(self) -> None:
        """Test local detection tester quick_test."""
        from secdashboards.detections.rule import DetectionMetadata, Severity, SQLDetectionRule

        # Create a simple detection rule
        rule = SQLDetectionRule(
            metadata=DetectionMetadata(
                id="test-rule",
                name="Test Rule",
                severity=Severity.HIGH,
            ),
            query_template="SELECT * FROM test WHERE class_uid = 3002",
            threshold=1,
        )

        tester = LocalDetectionTester()

        # Test with root login event (should match class_uid 3002)
        result = tester.quick_test(rule, "root_login")

        # The rule evaluates the DataFrame
        assert result is not None
        assert hasattr(result, "triggered")


class TestLambdaHandler:
    """Tests for the adversary Lambda handler."""

    def test_lambda_handler_health_check(self) -> None:
        """Test Lambda handler health check action."""
        from secdashboards.adversary.lambda_handler import handler

        event = {"action": "health_check"}
        result = handler(event, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["status"] == "healthy"

    def test_lambda_handler_list_scenarios(self) -> None:
        """Test Lambda handler list scenarios action."""
        from secdashboards.adversary.lambda_handler import SCENARIOS, handler

        event = {"action": "list_scenarios"}
        result = handler(event, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert "scenarios" in body
        assert len(body["scenarios"]) == len(SCENARIOS)

    @patch("secdashboards.adversary.lambda_handler.tcp_connect")
    def test_lambda_handler_custom_test(self, mock_tcp: MagicMock) -> None:
        """Test Lambda handler with custom test."""
        from secdashboards.adversary.lambda_handler import handler

        mock_tcp.return_value = {
            "type": "tcp_connect",
            "success": True,
            "connected": False,
            "timestamp": "2026-01-12T00:00:00+00:00",
        }

        event = {"tests": [{"type": "tcp_connect", "target_ip": "10.0.0.50", "target_port": 22}]}
        result = handler(event, None)

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["tests_run"] == 1


class TestAdversaryDeployment:
    """Tests for adversary Lambda deployment."""

    def test_deployment_package_creation(self, tmp_path: Path) -> None:
        """Test creating deployment package."""
        from secdashboards.adversary.deploy import AdversaryLambdaBuilder

        builder = AdversaryLambdaBuilder(tmp_path)
        package_path = builder.build_package()

        assert package_path.exists()
        assert package_path.suffix == ".zip"

    def test_cloudformation_template_generation(self, tmp_path: Path) -> None:
        """Test CloudFormation template generation."""
        from secdashboards.adversary.deploy import AdversaryLambdaBuilder

        builder = AdversaryLambdaBuilder(tmp_path)
        template = builder.generate_cloudformation_template()

        assert "AWSTemplateFormatVersion" in template
        assert "AdversaryLambdaRole" in template["Resources"]
        assert "AdversaryNetworkTester" in template["Resources"]

    def test_cloudformation_with_vpc(self, tmp_path: Path) -> None:
        """Test CloudFormation template with VPC configuration."""
        from secdashboards.adversary.deploy import AdversaryLambdaBuilder

        builder = AdversaryLambdaBuilder(tmp_path)
        template = builder.generate_cloudformation_template(
            vpc_id="vpc-12345",
            subnet_ids=["subnet-1", "subnet-2"],
            security_group_ids=["sg-12345"],
        )

        assert "VpcId" in template["Parameters"]
        assert "SubnetIds" in template["Parameters"]
        lambda_config = template["Resources"]["AdversaryNetworkTester"]["Properties"]
        assert "VpcConfig" in lambda_config
