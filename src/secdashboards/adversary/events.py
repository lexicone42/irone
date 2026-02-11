"""OCSF-compliant synthetic event generators for testing detections."""

import json
import random
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any
from uuid import uuid4

import polars as pl
from pydantic import BaseModel, Field

from secdashboards.connectors.security_lake import OCSFEventClass


class EventStatus(StrEnum):
    """Event outcome status."""

    SUCCESS = "Success"
    FAILURE = "Failure"
    UNKNOWN = "Unknown"


class SyntheticEvent(BaseModel):
    """Base class for synthetic OCSF events."""

    class_uid: int = Field(..., description="OCSF event class ID")
    class_name: str = Field(..., description="OCSF event class name")
    time_dt: datetime = Field(default_factory=lambda: datetime.now(UTC))
    time: int = Field(default=0, description="Epoch milliseconds")
    status: EventStatus = Field(default=EventStatus.SUCCESS)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def model_post_init(self, __context: Any) -> None:
        """Set epoch time from datetime."""
        if self.time == 0:
            self.time = int(self.time_dt.timestamp() * 1000)

    def to_ocsf_dict(self) -> dict[str, Any]:
        """Convert to OCSF-compliant dictionary."""
        return {
            "class_uid": self.class_uid,
            "class_name": self.class_name,
            "time_dt": self.time_dt.strftime("%Y-%m-%d %H:%M:%S.%f"),
            "time": self.time,
            "status": self.status.value,
            "metadata": self.metadata,
        }


class ActorUser(BaseModel):
    """OCSF actor.user object."""

    name: str = "test-user"
    uid: str = Field(default_factory=lambda: str(uuid4()))
    type: str = "IAMUser"
    account_uid: str = "123456789012"


class SrcEndpoint(BaseModel):
    """OCSF src_endpoint object."""

    ip: str = "192.168.1.100"
    port: int | None = None
    hostname: str | None = None


class DstEndpoint(BaseModel):
    """OCSF dst_endpoint object."""

    ip: str = "10.0.0.1"
    port: int = 443
    hostname: str | None = None


class APIInfo(BaseModel):
    """OCSF api object for CloudTrail events."""

    operation: str = "DescribeInstances"
    service_name: str = "ec2.amazonaws.com"
    request_data: str | None = None
    response_data: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result = {
            "operation": self.operation,
            "service": {"name": self.service_name},
        }
        if self.request_data:
            result["request"] = {"data": self.request_data}
        if self.response_data:
            result["response"] = {"data": self.response_data}
        return result


class CloudInfo(BaseModel):
    """OCSF cloud object."""

    provider: str = "AWS"
    region: str = "us-west-2"
    account_uid: str = "123456789012"


class SyntheticCloudTrailEvent(SyntheticEvent):
    """Synthetic CloudTrail event in OCSF format."""

    class_uid: int = OCSFEventClass.API_ACTIVITY
    class_name: str = "API Activity"

    actor_user: ActorUser = Field(default_factory=ActorUser)
    src_endpoint: SrcEndpoint = Field(default_factory=SrcEndpoint)
    api: APIInfo = Field(default_factory=APIInfo)
    cloud: CloudInfo = Field(default_factory=CloudInfo)

    def to_ocsf_dict(self) -> dict[str, Any]:
        base = super().to_ocsf_dict()
        base.update(
            {
                "actor": {"user": self.actor_user.model_dump()},
                "src_endpoint": self.src_endpoint.model_dump(exclude_none=True),
                "api": self.api.to_dict(),
                "cloud": self.cloud.model_dump(),
            }
        )
        return base


class SyntheticAuthenticationEvent(SyntheticEvent):
    """Synthetic authentication event (class_uid 3002)."""

    class_uid: int = OCSFEventClass.AUTHENTICATION
    class_name: str = "Authentication"

    actor_user: ActorUser = Field(default_factory=ActorUser)
    src_endpoint: SrcEndpoint = Field(default_factory=SrcEndpoint)
    auth_protocol: str = "IAM"

    def to_ocsf_dict(self) -> dict[str, Any]:
        base = super().to_ocsf_dict()
        base.update(
            {
                "actor": {"user": self.actor_user.model_dump()},
                "src_endpoint": self.src_endpoint.model_dump(exclude_none=True),
                "auth_protocol": self.auth_protocol,
            }
        )
        return base


class SyntheticVPCFlowEvent(SyntheticEvent):
    """Synthetic VPC Flow log event in OCSF format."""

    class_uid: int = OCSFEventClass.NETWORK_ACTIVITY
    class_name: str = "Network Activity"

    src_endpoint: SrcEndpoint = Field(default_factory=SrcEndpoint)
    dst_endpoint: DstEndpoint = Field(default_factory=DstEndpoint)
    connection_info: dict[str, Any] = Field(
        default_factory=lambda: {
            "protocol_num": 6,  # TCP
            "protocol_name": "TCP",
            "direction": "Inbound",
        }
    )
    traffic: dict[str, Any] = Field(
        default_factory=lambda: {
            "packets": 100,
            "bytes": 50000,
        }
    )
    action: str = "Accept"

    def to_ocsf_dict(self) -> dict[str, Any]:
        base = super().to_ocsf_dict()
        base.update(
            {
                "src_endpoint": self.src_endpoint.model_dump(exclude_none=True),
                "dst_endpoint": self.dst_endpoint.model_dump(exclude_none=True),
                "connection_info": self.connection_info,
                "traffic": self.traffic,
                "action": self.action,
            }
        )
        return base


class SyntheticDNSEvent(SyntheticEvent):
    """Synthetic Route53/DNS event in OCSF format."""

    class_uid: int = OCSFEventClass.DNS_ACTIVITY
    class_name: str = "DNS Activity"

    src_endpoint: SrcEndpoint = Field(default_factory=SrcEndpoint)
    query: dict[str, Any] = Field(
        default_factory=lambda: {
            "hostname": "example.com",
            "type": "A",
            "class": "IN",
        }
    )
    answers: list[dict[str, Any]] = Field(
        default_factory=lambda: [{"rdata": "93.184.216.34", "type": "A"}]
    )
    rcode: str = "NOERROR"

    def to_ocsf_dict(self) -> dict[str, Any]:
        base = super().to_ocsf_dict()
        base.update(
            {
                "src_endpoint": self.src_endpoint.model_dump(exclude_none=True),
                "query": self.query,
                "answers": self.answers,
                "rcode": self.rcode,
            }
        )
        return base


class SyntheticSecurityFinding(SyntheticEvent):
    """Synthetic Security Hub finding in OCSF format."""

    class_uid: int = OCSFEventClass.SECURITY_FINDING
    class_name: str = "Security Finding"

    finding_info: dict[str, Any] = Field(
        default_factory=lambda: {
            "uid": str(uuid4()),
            "title": "Test Finding",
            "desc": "This is a test security finding",
            "types": ["Software and Configuration Checks"],
        }
    )
    severity: str = "MEDIUM"
    confidence: int = 80

    def to_ocsf_dict(self) -> dict[str, Any]:
        base = super().to_ocsf_dict()
        base.update(
            {
                "finding_info": self.finding_info,
                "severity": self.severity,
                "confidence": self.confidence,
            }
        )
        return base


class OCSFEventGenerator:
    """Generator for OCSF-compliant synthetic events.

    This class provides methods to generate synthetic events that match
    the Security Lake OCSF schema for testing detection rules.
    """

    # Common malicious IPs for testing
    MALICIOUS_IPS = [
        "185.220.101.1",  # Known Tor exit
        "45.33.32.156",  # Test scanner
        "198.51.100.1",  # Documentation range (test)
        "203.0.113.50",  # Documentation range (test)
    ]

    # Suspicious user agents
    SUSPICIOUS_USER_AGENTS = [
        "python-requests/2.28.0",
        "curl/7.84.0",
        "Wget/1.21",
        "sqlmap/1.6",
    ]

    # Common AWS services
    AWS_SERVICES = [
        "ec2.amazonaws.com",
        "s3.amazonaws.com",
        "iam.amazonaws.com",
        "lambda.amazonaws.com",
        "sts.amazonaws.com",
        "kms.amazonaws.com",
    ]

    def __init__(
        self,
        account_id: str = "123456789012",
        region: str = "us-west-2",
    ) -> None:
        self.account_id = account_id
        self.region = region

    def generate_root_login(
        self,
        source_ip: str | None = None,
        status: EventStatus = EventStatus.SUCCESS,
        timestamp: datetime | None = None,
    ) -> SyntheticAuthenticationEvent:
        """Generate a root account login event."""
        return SyntheticAuthenticationEvent(
            time_dt=timestamp or datetime.now(UTC),
            status=status,
            actor_user=ActorUser(
                name="root",
                type="Root",
                account_uid=self.account_id,
            ),
            src_endpoint=SrcEndpoint(
                ip=source_ip or random.choice(self.MALICIOUS_IPS),
            ),
        )

    def generate_iam_policy_change(
        self,
        operation: str = "AttachUserPolicy",
        user_name: str = "attacker",
        policy_arn: str = "arn:aws:iam::aws:policy/AdministratorAccess",
        source_ip: str | None = None,
        timestamp: datetime | None = None,
    ) -> SyntheticCloudTrailEvent:
        """Generate an IAM policy modification event."""
        return SyntheticCloudTrailEvent(
            time_dt=timestamp or datetime.now(UTC),
            actor_user=ActorUser(
                name=user_name,
                account_uid=self.account_id,
            ),
            src_endpoint=SrcEndpoint(
                ip=source_ip or random.choice(self.MALICIOUS_IPS),
            ),
            api=APIInfo(
                operation=operation,
                service_name="iam.amazonaws.com",
                request_data=json.dumps(
                    {
                        "policyArn": policy_arn,
                        "userName": user_name,
                    }
                ),
            ),
            cloud=CloudInfo(
                region=self.region,
                account_uid=self.account_id,
            ),
        )

    def generate_security_group_change(
        self,
        operation: str = "AuthorizeSecurityGroupIngress",
        from_port: int = 22,
        to_port: int = 22,
        cidr: str = "0.0.0.0/0",
        user_name: str = "test-user",
        source_ip: str | None = None,
        timestamp: datetime | None = None,
    ) -> SyntheticCloudTrailEvent:
        """Generate a security group modification event."""
        return SyntheticCloudTrailEvent(
            time_dt=timestamp or datetime.now(UTC),
            actor_user=ActorUser(
                name=user_name,
                account_uid=self.account_id,
            ),
            src_endpoint=SrcEndpoint(
                ip=source_ip or "192.168.1.100",
            ),
            api=APIInfo(
                operation=operation,
                service_name="ec2.amazonaws.com",
                request_data=json.dumps(
                    {
                        "groupId": "sg-12345678",
                        "ipPermissions": [
                            {
                                "fromPort": from_port,
                                "toPort": to_port,
                                "ipProtocol": "tcp",
                                "ipRanges": [{"cidrIp": cidr}],
                            }
                        ],
                    }
                ),
            ),
            cloud=CloudInfo(
                region=self.region,
                account_uid=self.account_id,
            ),
        )

    def generate_access_key_creation(
        self,
        user_name: str = "backdoor-user",
        created_by: str = "attacker",
        source_ip: str | None = None,
        timestamp: datetime | None = None,
    ) -> SyntheticCloudTrailEvent:
        """Generate an access key creation event."""
        return SyntheticCloudTrailEvent(
            time_dt=timestamp or datetime.now(UTC),
            actor_user=ActorUser(
                name=created_by,
                account_uid=self.account_id,
            ),
            src_endpoint=SrcEndpoint(
                ip=source_ip or random.choice(self.MALICIOUS_IPS),
            ),
            api=APIInfo(
                operation="CreateAccessKey",
                service_name="iam.amazonaws.com",
                request_data=json.dumps({"userName": user_name}),
            ),
            cloud=CloudInfo(
                region=self.region,
                account_uid=self.account_id,
            ),
        )

    def generate_failed_login_attempts(
        self,
        count: int = 10,
        user_name: str = "target-user",
        source_ip: str | None = None,
        time_spread_minutes: int = 5,
    ) -> list[SyntheticAuthenticationEvent]:
        """Generate multiple failed login attempts (brute force simulation)."""
        events = []
        base_time = datetime.now(UTC)
        ip = source_ip or random.choice(self.MALICIOUS_IPS)

        for _i in range(count):
            offset = timedelta(seconds=random.randint(0, time_spread_minutes * 60))
            events.append(
                SyntheticAuthenticationEvent(
                    time_dt=base_time - offset,
                    status=EventStatus.FAILURE,
                    actor_user=ActorUser(
                        name=user_name,
                        account_uid=self.account_id,
                    ),
                    src_endpoint=SrcEndpoint(ip=ip),
                )
            )

        return sorted(events, key=lambda e: e.time_dt)

    def generate_unusual_api_volume(
        self,
        count: int = 150,
        user_name: str = "scanner-user",
        time_spread_minutes: int = 15,
    ) -> list[SyntheticCloudTrailEvent]:
        """Generate high volume API calls from a single user."""
        events = []
        base_time = datetime.now(UTC)

        operations = [
            ("DescribeInstances", "ec2.amazonaws.com"),
            ("ListBuckets", "s3.amazonaws.com"),
            ("DescribeSecurityGroups", "ec2.amazonaws.com"),
            ("GetUser", "iam.amazonaws.com"),
            ("ListUsers", "iam.amazonaws.com"),
            ("DescribeVpcs", "ec2.amazonaws.com"),
        ]

        for _i in range(count):
            offset = timedelta(seconds=random.randint(0, time_spread_minutes * 60))
            op, svc = random.choice(operations)
            events.append(
                SyntheticCloudTrailEvent(
                    time_dt=base_time - offset,
                    actor_user=ActorUser(
                        name=user_name,
                        account_uid=self.account_id,
                    ),
                    api=APIInfo(
                        operation=op,
                        service_name=svc,
                    ),
                    cloud=CloudInfo(
                        region=self.region,
                        account_uid=self.account_id,
                    ),
                )
            )

        return sorted(events, key=lambda e: e.time_dt)

    def generate_vpc_flow_suspicious(
        self,
        src_ip: str | None = None,
        dst_port: int = 22,
        action: str = "Accept",
        timestamp: datetime | None = None,
    ) -> SyntheticVPCFlowEvent:
        """Generate a suspicious VPC flow log entry."""
        return SyntheticVPCFlowEvent(
            time_dt=timestamp or datetime.now(UTC),
            src_endpoint=SrcEndpoint(
                ip=src_ip or random.choice(self.MALICIOUS_IPS),
                port=random.randint(1024, 65535),
            ),
            dst_endpoint=DstEndpoint(
                ip="10.0.0.50",
                port=dst_port,
            ),
            action=action,
        )

    def generate_dns_query(
        self,
        hostname: str = "malware-c2.evil.com",
        query_type: str = "A",
        src_ip: str | None = None,
        timestamp: datetime | None = None,
    ) -> SyntheticDNSEvent:
        """Generate a DNS query event."""
        return SyntheticDNSEvent(
            time_dt=timestamp or datetime.now(UTC),
            src_endpoint=SrcEndpoint(
                ip=src_ip or "10.0.0.100",
            ),
            query={
                "hostname": hostname,
                "type": query_type,
                "class": "IN",
            },
            answers=[{"rdata": "198.51.100.1", "type": query_type}],
        )

    def generate_port_scan(
        self,
        src_ip: str | None = None,
        target_ip: str = "10.0.0.50",
        ports: list[int] | None = None,
        timestamp: datetime | None = None,
    ) -> list[SyntheticVPCFlowEvent]:
        """Generate VPC flow events simulating a port scan."""
        ports = ports or [22, 23, 80, 443, 3389, 8080, 8443]
        base_time = timestamp or datetime.now(UTC)
        ip = src_ip or random.choice(self.MALICIOUS_IPS)

        events = []
        for i, port in enumerate(ports):
            events.append(
                SyntheticVPCFlowEvent(
                    time_dt=base_time + timedelta(milliseconds=i * 100),
                    src_endpoint=SrcEndpoint(
                        ip=ip,
                        port=random.randint(1024, 65535),
                    ),
                    dst_endpoint=DstEndpoint(
                        ip=target_ip,
                        port=port,
                    ),
                    action="Reject",
                    traffic={"packets": 1, "bytes": 64},
                )
            )

        return events

    def events_to_dataframe(
        self,
        events: list[SyntheticEvent],
    ) -> pl.DataFrame:
        """Convert a list of synthetic events to a Polars DataFrame.

        This creates a DataFrame structure compatible with detection rules.
        """
        records = [e.to_ocsf_dict() for e in events]

        # Flatten nested structures for SQL compatibility
        flattened = []
        for r in records:
            flat = {
                "class_uid": r["class_uid"],
                "class_name": r["class_name"],
                "time_dt": r["time_dt"],
                "time": r["time"],
                "status": r["status"],
            }

            # Flatten actor.user
            if "actor" in r and "user" in r["actor"]:
                flat["actor.user.name"] = r["actor"]["user"].get("name")
                flat["actor.user.type"] = r["actor"]["user"].get("type")
                flat["actor.user.uid"] = r["actor"]["user"].get("uid")

            # Flatten src_endpoint
            if "src_endpoint" in r:
                flat["src_endpoint.ip"] = r["src_endpoint"].get("ip")
                flat["src_endpoint.port"] = r["src_endpoint"].get("port")

            # Flatten dst_endpoint
            if "dst_endpoint" in r:
                flat["dst_endpoint.ip"] = r["dst_endpoint"].get("ip")
                flat["dst_endpoint.port"] = r["dst_endpoint"].get("port")

            # Flatten api
            if "api" in r:
                flat["api.operation"] = r["api"].get("operation")
                if "service" in r["api"]:
                    flat["api.service.name"] = r["api"]["service"].get("name")
                if "request" in r["api"]:
                    flat["api.request.data"] = r["api"]["request"].get("data")

            # Flatten cloud
            if "cloud" in r:
                flat["cloud.region"] = r["cloud"].get("region")
                flat["cloud.account_uid"] = r["cloud"].get("account_uid")

            # DNS specific
            if "query" in r:
                flat["query.hostname"] = r["query"].get("hostname")
                flat["query.type"] = r["query"].get("type")

            if "rcode" in r:
                flat["rcode"] = r["rcode"]

            # VPC Flow specific
            if "action" in r:
                flat["action"] = r["action"]

            if "traffic" in r:
                flat["traffic.packets"] = r["traffic"].get("packets")
                flat["traffic.bytes"] = r["traffic"].get("bytes")

            flattened.append(flat)

        return pl.DataFrame(flattened)
