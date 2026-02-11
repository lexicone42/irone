"""Network packet generation for triggering network-based detections.

This module provides tools to generate actual network traffic that will
trigger VPC Flow logs, Route53 DNS logs, and other network-based detections.

WARNING: Only use these tools in controlled test environments with proper
authorization. Generating network traffic to systems you don't own or
have permission to test is illegal and unethical.
"""

import contextlib
import logging
import random
import socket
import struct
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import IntEnum
from typing import Any

logger = logging.getLogger(__name__)


class Protocol(IntEnum):
    """IP protocol numbers."""

    ICMP = 1
    TCP = 6
    UDP = 17


@dataclass
class PacketResult:
    """Result of a packet send operation."""

    success: bool
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: int = 0
    protocol: Protocol = Protocol.TCP
    error: str | None = None
    response_received: bool = False
    response_time_ms: float | None = None


class PacketGenerator(ABC):
    """Abstract base class for packet generators."""

    @abstractmethod
    def generate(self) -> bytes:
        """Generate the packet bytes."""
        ...


class TCPSYNPacket(PacketGenerator):
    """Generate a TCP SYN packet for connection attempts."""

    def __init__(
        self,
        src_port: int,
        dst_port: int,
        seq_num: int | None = None,
    ) -> None:
        self.src_port = src_port
        self.dst_port = dst_port
        self.seq_num = seq_num or random.randint(0, 2**32 - 1)

    def generate(self) -> bytes:
        """Generate TCP SYN packet payload."""
        # TCP header: src_port(2) + dst_port(2) + seq(4) + ack(4) +
        #             offset_flags(2) + window(2) + checksum(2) + urgent(2)
        offset_flags = (5 << 12) | 0x02  # 5 words offset, SYN flag
        window = 65535

        header = struct.pack(
            "!HHIIHHH",
            self.src_port,
            self.dst_port,
            self.seq_num,
            0,  # ack number
            offset_flags,
            window,
            0,  # checksum (computed by OS)
        )
        return header


class DNSQuery(PacketGenerator):
    """Generate a DNS query packet."""

    def __init__(
        self,
        hostname: str,
        query_type: str = "A",
        query_id: int | None = None,
    ) -> None:
        self.hostname = hostname
        self.query_type = query_type
        self.query_id = query_id or random.randint(0, 65535)

    def _encode_hostname(self) -> bytes:
        """Encode hostname in DNS format."""
        parts = self.hostname.split(".")
        encoded = b""
        for part in parts:
            encoded += bytes([len(part)]) + part.encode()
        encoded += b"\x00"
        return encoded

    def _get_query_type_value(self) -> int:
        """Get numeric value for query type."""
        types = {"A": 1, "AAAA": 28, "MX": 15, "TXT": 16, "CNAME": 5, "NS": 2}
        return types.get(self.query_type.upper(), 1)

    def generate(self) -> bytes:
        """Generate DNS query packet."""
        # DNS header
        flags = 0x0100  # Standard query with recursion desired
        header = struct.pack(
            "!HHHHHH",
            self.query_id,
            flags,
            1,  # questions
            0,  # answers
            0,  # authority
            0,  # additional
        )

        # Question section
        qname = self._encode_hostname()
        qtype = self._get_query_type_value()
        question = qname + struct.pack("!HH", qtype, 1)  # 1 = IN class

        return header + question


class NetworkEmulator:
    """Emulator for generating network traffic to trigger detections.

    This class provides safe methods to generate network traffic that
    will be logged by AWS VPC Flow Logs, Route53 Query Logs, etc.

    Example usage:
        emulator = NetworkEmulator()

        # Generate TCP connection attempts (triggers VPC Flow)
        results = emulator.tcp_connect_scan(
            target_ip="10.0.0.50",
            ports=[22, 80, 443],
        )

        # Generate DNS queries (triggers Route53 logs)
        results = emulator.dns_queries(
            hostnames=["suspicious.example.com", "c2.evil.com"],
        )
    """

    def __init__(
        self,
        timeout: float = 1.0,
        verbose: bool = False,
    ) -> None:
        """Initialize the network emulator.

        Args:
            timeout: Socket timeout in seconds
            verbose: Enable verbose logging
        """
        self.timeout = timeout
        self.verbose = verbose

    def tcp_connect(
        self,
        target_ip: str,
        target_port: int,
        src_port: int | None = None,
    ) -> PacketResult:
        """Attempt a TCP connection to trigger VPC Flow logs.

        This uses standard socket connect, which will be logged
        by VPC Flow Logs regardless of whether it succeeds.
        """
        result = PacketResult(
            success=False,
            dst_ip=target_ip,
            dst_port=target_port,
            protocol=Protocol.TCP,
        )

        try:
            start = datetime.now(UTC)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            if src_port:
                with contextlib.suppress(OSError):
                    sock.bind(("", src_port))

            try:
                sock.connect((target_ip, target_port))
                result.success = True
                result.response_received = True
            except (TimeoutError, ConnectionRefusedError, OSError):
                # Connection failed but packet was still sent (logged by VPC Flow)
                result.success = True  # Packet generation succeeded
                result.response_received = False

            end = datetime.now(UTC)
            result.response_time_ms = (end - start).total_seconds() * 1000
            result.src_ip = sock.getsockname()[0] if sock.getsockname()[0] else "0.0.0.0"
            sock.close()

        except Exception as e:
            result.error = str(e)
            logger.error(f"TCP connect failed: {e}")

        return result

    def tcp_connect_scan(
        self,
        target_ip: str,
        ports: list[int],
        delay_ms: int = 100,
    ) -> list[PacketResult]:
        """Perform TCP connect scan across multiple ports.

        This simulates reconnaissance activity and generates
        multiple VPC Flow log entries.
        """
        import time

        results = []
        for port in ports:
            result = self.tcp_connect(target_ip, port)
            results.append(result)
            if delay_ms > 0:
                time.sleep(delay_ms / 1000)

            if self.verbose:
                status = "open" if result.response_received else "closed/filtered"
                logger.info(f"Port {port}: {status}")

        return results

    def dns_query(
        self,
        hostname: str,
        query_type: str = "A",
        dns_server: str = "8.8.8.8",
        dns_port: int = 53,
    ) -> PacketResult:
        """Send a DNS query to trigger Route53/DNS logs.

        This sends an actual DNS query which will be logged
        by Route53 Query Logs if the DNS server is a Route53 resolver.
        """
        result = PacketResult(
            success=False,
            dst_ip=dns_server,
            dst_port=dns_port,
            protocol=Protocol.UDP,
        )

        try:
            start = datetime.now(UTC)
            query = DNSQuery(hostname, query_type)
            packet = query.generate()

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)

            sock.sendto(packet, (dns_server, dns_port))
            result.success = True

            try:
                response, _ = sock.recvfrom(4096)
                result.response_received = True
            except TimeoutError:
                result.response_received = False

            end = datetime.now(UTC)
            result.response_time_ms = (end - start).total_seconds() * 1000
            result.src_ip = sock.getsockname()[0]
            sock.close()

        except Exception as e:
            result.error = str(e)
            logger.error(f"DNS query failed: {e}")

        return result

    def dns_queries(
        self,
        hostnames: list[str],
        query_types: list[str] | None = None,
        dns_server: str = "8.8.8.8",
        delay_ms: int = 50,
    ) -> list[PacketResult]:
        """Send multiple DNS queries.

        Useful for simulating DNS tunneling or C2 beacon patterns.
        """
        import time

        query_types = query_types or ["A"]
        results = []

        for hostname in hostnames:
            for qtype in query_types:
                result = self.dns_query(hostname, qtype, dns_server)
                results.append(result)
                if delay_ms > 0:
                    time.sleep(delay_ms / 1000)

        return results

    def udp_send(
        self,
        target_ip: str,
        target_port: int,
        payload: bytes = b"",
    ) -> PacketResult:
        """Send a UDP packet to trigger VPC Flow logs."""
        result = PacketResult(
            success=False,
            dst_ip=target_ip,
            dst_port=target_port,
            protocol=Protocol.UDP,
        )

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)

            sock.sendto(payload or b"\x00", (target_ip, target_port))
            result.success = True
            result.src_ip = sock.getsockname()[0]
            sock.close()

        except Exception as e:
            result.error = str(e)
            logger.error(f"UDP send failed: {e}")

        return result

    def simulate_port_scan(
        self,
        target_ip: str,
        common_ports: bool = True,
        custom_ports: list[int] | None = None,
    ) -> list[PacketResult]:
        """Simulate a port scan for detection testing.

        Args:
            target_ip: Target IP address
            common_ports: Include common service ports
            custom_ports: Additional ports to scan
        """
        ports = []
        if common_ports:
            ports.extend(
                [
                    21,
                    22,
                    23,
                    25,
                    53,
                    80,
                    110,
                    111,
                    135,
                    139,
                    143,
                    443,
                    445,
                    993,
                    995,
                    1723,
                    3306,
                    3389,
                    5432,
                    5900,
                    8080,
                    8443,
                ]
            )
        if custom_ports:
            ports.extend(custom_ports)

        ports = sorted(set(ports))
        return self.tcp_connect_scan(target_ip, ports)

    def simulate_dns_exfil(
        self,
        base_domain: str,
        data_chunks: list[str],
        dns_server: str = "8.8.8.8",
    ) -> list[PacketResult]:
        """Simulate DNS exfiltration pattern.

        Creates DNS queries with data encoded in subdomains,
        which is a common data exfiltration technique.
        """
        import base64

        hostnames = []
        for chunk in data_chunks:
            # Encode chunk as base32 (DNS-safe)
            encoded = base64.b32encode(chunk.encode()).decode().rstrip("=").lower()
            hostname = f"{encoded}.{base_domain}"
            hostnames.append(hostname)

        return self.dns_queries(hostnames, dns_server=dns_server)

    def simulate_beacon(
        self,
        target_ip: str,
        port: int = 443,
        interval_seconds: float = 5.0,
        count: int = 5,
        jitter: float = 0.1,
    ) -> list[PacketResult]:
        """Simulate C2 beacon pattern with regular callbacks.

        Creates a pattern of connections at regular intervals
        with optional jitter, simulating malware beacon behavior.
        """
        import time

        results = []
        for i in range(count):
            result = self.tcp_connect(target_ip, port)
            results.append(result)

            if i < count - 1:
                # Add jitter
                jitter_amount = random.uniform(-jitter, jitter) * interval_seconds
                sleep_time = interval_seconds + jitter_amount
                time.sleep(max(0.1, sleep_time))

        return results

    def get_local_ip(self) -> str:
        """Get the local IP address used for outbound connections."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8", 80))
            ip = sock.getsockname()[0]
            sock.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def results_summary(self, results: list[PacketResult]) -> dict[str, Any]:
        """Generate a summary of packet results."""
        successful = sum(1 for r in results if r.success)
        responses = sum(1 for r in results if r.response_received)
        avg_time = sum(r.response_time_ms or 0 for r in results) / len(results) if results else 0

        return {
            "total_packets": len(results),
            "successful_sends": successful,
            "responses_received": responses,
            "average_response_time_ms": round(avg_time, 2),
            "unique_destinations": len(set((r.dst_ip, r.dst_port) for r in results)),
            "errors": [r.error for r in results if r.error],
        }
