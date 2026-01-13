"""Security Lake enrichment for graph building.

This module provides specialized query methods for enriching security
investigation graphs with related events from Security Lake.
"""

from datetime import datetime, timedelta
from typing import Any

import polars as pl
import structlog

from secdashboards.connectors.security_lake import OCSFEventClass, SecurityLakeConnector

logger = structlog.get_logger()


class SecurityLakeEnricher:
    """Enrich graphs with Security Lake event data.

    This class provides methods to query Security Lake for events related
    to specific identifiers (users, IPs, resources) to build comprehensive
    investigation graphs.
    """

    # Pattern for validating IP addresses (IPv4)
    _IP_PATTERN = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"

    @staticmethod
    def _sanitize_sql_string(value: str) -> str:
        """Sanitize a string value for use in SQL queries.

        This provides defense-in-depth against SQL injection by:
        1. Escaping single quotes (standard SQL escaping)
        2. Escaping backslashes
        3. Removing null bytes
        4. Removing SQL comment sequences

        Args:
            value: The string to sanitize

        Returns:
            Sanitized string safe for SQL interpolation
        """
        if not isinstance(value, str):
            value = str(value)
        # Remove null bytes
        value = value.replace("\x00", "")
        # Escape backslashes first (before other escapes)
        value = value.replace("\\", "\\\\")
        # Escape single quotes
        value = value.replace("'", "''")
        # Remove SQL comment sequences
        value = value.replace("--", "")
        value = value.replace("/*", "")
        value = value.replace("*/", "")
        return value

    @staticmethod
    def _validate_ip_address(ip: str) -> bool:
        """Validate that a string is a valid IPv4 address.

        Args:
            ip: The IP address string to validate

        Returns:
            True if valid IPv4 address, False otherwise
        """
        import re
        return bool(re.match(SecurityLakeEnricher._IP_PATTERN, ip))

    # OCSF field mappings for extraction
    OCSF_USER_FIELDS = [
        "actor.user.name",
        "actor.user.uid",
        "actor.user.type",
        "actor.session.uid",
    ]

    OCSF_IP_FIELDS = [
        "src_endpoint.ip",
        "dst_endpoint.ip",
        "src_endpoint.port",
        "dst_endpoint.port",
    ]

    OCSF_RESOURCE_FIELDS = [
        "resources",
        "cloud.account.uid",
        "cloud.region",
        "cloud.provider",
    ]

    OCSF_API_FIELDS = [
        "api.operation",
        "api.service.name",
        "api.request.uid",
        "api.response.code",
    ]

    def __init__(self, connector: SecurityLakeConnector) -> None:
        """Initialize the enricher with a Security Lake connector.

        Args:
            connector: A configured SecurityLakeConnector instance
        """
        self.connector = connector

    def enrich_by_user(
        self,
        user_name: str,
        start: datetime,
        end: datetime,
        event_classes: list[OCSFEventClass] | None = None,
        limit: int = 500,
    ) -> pl.DataFrame:
        """Get all events for a user within a time window.

        Args:
            user_name: The user/principal name to search for
            start: Start of the time window
            end: End of the time window
            event_classes: Optional list of event classes to query
            limit: Maximum events per event class

        Returns:
            DataFrame of events involving the user
        """
        classes = event_classes or [
            OCSFEventClass.API_ACTIVITY,
            OCSFEventClass.AUTHENTICATION,
            OCSFEventClass.ACCOUNT_CHANGE,
        ]

        all_events: list[pl.DataFrame] = []

        for event_class in classes:
            try:
                # Sanitize user name for SQL
                safe_user = self._sanitize_sql_string(user_name)
                df = self.connector.query_by_event_class(
                    event_class,
                    start=start,
                    end=end,
                    limit=limit,
                    additional_filters=f""""actor"."user"."name" = '{safe_user}'""",
                )
                if len(df) > 0:
                    all_events.append(df)
                    logger.debug(
                        "enrichment_by_user_found_events",
                        user=user_name,
                        event_class=event_class.name,
                        count=len(df),
                    )
            except Exception as e:
                logger.warning(
                    "enrichment_by_user_query_failed",
                    user=user_name,
                    event_class=event_class.name,
                    error=str(e),
                )

        if not all_events:
            return pl.DataFrame()

        return pl.concat(all_events, how="diagonal")

    def enrich_by_ip(
        self,
        ip_address: str,
        start: datetime,
        end: datetime,
        direction: str = "both",
        limit: int = 500,
    ) -> pl.DataFrame:
        """Get all events involving an IP address.

        Args:
            ip_address: The IP address to search for
            start: Start of the time window
            end: End of the time window
            direction: "source", "dest", or "both"
            limit: Maximum events to return

        Returns:
            DataFrame of events involving the IP
        """
        # Validate IP address format to prevent injection
        if not self._validate_ip_address(ip_address):
            logger.warning("invalid_ip_address_format", ip=ip_address)
            return pl.DataFrame()

        filters: list[str] = []

        if direction in ("source", "both"):
            filters.append(f""""src_endpoint"."ip" = '{ip_address}'""")
        if direction in ("dest", "both"):
            filters.append(f""""dst_endpoint"."ip" = '{ip_address}'""")

        if not filters:
            return pl.DataFrame()

        filter_clause = " OR ".join(filters)

        all_events: list[pl.DataFrame] = []

        # Query network activity for IP-based events
        try:
            df = self.connector.query_by_event_class(
                OCSFEventClass.NETWORK_ACTIVITY,
                start=start,
                end=end,
                limit=limit,
                additional_filters=f"({filter_clause})",
            )
            if len(df) > 0:
                all_events.append(df)
        except Exception as e:
            logger.warning(
                "enrichment_by_ip_network_query_failed",
                ip=ip_address,
                error=str(e),
            )

        # Also query API activity where the source IP matches
        if direction in ("source", "both"):
            try:
                df = self.connector.query_by_event_class(
                    OCSFEventClass.API_ACTIVITY,
                    start=start,
                    end=end,
                    limit=limit,
                    additional_filters=f""""src_endpoint"."ip" = '{ip_address}'""",
                )
                if len(df) > 0:
                    all_events.append(df)
            except Exception as e:
                logger.warning(
                    "enrichment_by_ip_api_query_failed",
                    ip=ip_address,
                    error=str(e),
                )

        # Query authentication events from this IP
        try:
            df = self.connector.query_by_event_class(
                OCSFEventClass.AUTHENTICATION,
                start=start,
                end=end,
                limit=limit,
                additional_filters=f""""src_endpoint"."ip" = '{ip_address}'""",
            )
            if len(df) > 0:
                all_events.append(df)
        except Exception as e:
            logger.warning(
                "enrichment_by_ip_auth_query_failed",
                ip=ip_address,
                error=str(e),
            )

        if not all_events:
            return pl.DataFrame()

        return pl.concat(all_events, how="diagonal")

    def enrich_by_service(
        self,
        service_name: str,
        start: datetime,
        end: datetime,
        operations: list[str] | None = None,
        limit: int = 500,
    ) -> pl.DataFrame:
        """Get API activity for a specific AWS service.

        Args:
            service_name: The AWS service name (e.g., "iam.amazonaws.com")
            start: Start of the time window
            end: End of the time window
            operations: Optional list of specific operations to filter
            limit: Maximum events to return

        Returns:
            DataFrame of API activity for the service
        """
        safe_service = self._sanitize_sql_string(service_name)
        filters = [f""""api"."service"."name" = '{safe_service}'"""]

        if operations:
            # Sanitize each operation name
            safe_ops = [self._sanitize_sql_string(op) for op in operations]
            ops_str = "', '".join(safe_ops)
            filters.append(f""""api"."operation" IN ('{ops_str}')""")

        filter_clause = " AND ".join(filters)

        try:
            return self.connector.query_by_event_class(
                OCSFEventClass.API_ACTIVITY,
                start=start,
                end=end,
                limit=limit,
                additional_filters=filter_clause,
            )
        except Exception as e:
            logger.warning(
                "enrichment_by_service_query_failed",
                service=service_name,
                error=str(e),
            )
            return pl.DataFrame()

    def enrich_by_operation(
        self,
        operation: str,
        start: datetime,
        end: datetime,
        service: str | None = None,
        limit: int = 500,
    ) -> pl.DataFrame:
        """Get events for a specific API operation.

        Args:
            operation: The API operation name (e.g., "CreateUser")
            start: Start of the time window
            end: End of the time window
            service: Optional service name filter
            limit: Maximum events to return

        Returns:
            DataFrame of API activity for the operation
        """
        safe_op = self._sanitize_sql_string(operation)
        filters = [f""""api"."operation" = '{safe_op}'"""]

        if service:
            safe_service = self._sanitize_sql_string(service)
            filters.append(f""""api"."service"."name" = '{safe_service}'""")

        filter_clause = " AND ".join(filters)

        try:
            return self.connector.query_by_event_class(
                OCSFEventClass.API_ACTIVITY,
                start=start,
                end=end,
                limit=limit,
                additional_filters=filter_clause,
            )
        except Exception as e:
            logger.warning(
                "enrichment_by_operation_query_failed",
                operation=operation,
                error=str(e),
            )
            return pl.DataFrame()

    def get_authentication_chain(
        self,
        user_name: str,
        start: datetime,
        end: datetime,
        limit: int = 1000,
    ) -> pl.DataFrame:
        """Get authentication events to trace a user's login chain.

        This is useful for understanding how a user authenticated
        and from which IP addresses.

        Args:
            user_name: The user to trace
            start: Start of the time window
            end: End of the time window
            limit: Maximum events to return

        Returns:
            DataFrame of authentication events
        """
        safe_user = self._sanitize_sql_string(user_name)

        try:
            return self.connector.query_by_event_class(
                OCSFEventClass.AUTHENTICATION,
                start=start,
                end=end,
                limit=limit,
                additional_filters=f""""actor"."user"."name" = '{safe_user}'""",
            )
        except Exception as e:
            logger.warning(
                "enrichment_auth_chain_query_failed",
                user=user_name,
                error=str(e),
            )
            return pl.DataFrame()

    def find_related_principals(
        self,
        ip_address: str,
        start: datetime,
        end: datetime,
        limit: int = 500,
    ) -> pl.DataFrame:
        """Find all principals that have accessed from a specific IP.

        This is useful for understanding which users have used
        a particular IP address, potentially indicating shared
        infrastructure or lateral movement.

        Args:
            ip_address: The IP address to search
            start: Start of the time window
            end: End of the time window
            limit: Maximum events to return

        Returns:
            DataFrame with principal information
        """
        # Validate IP address format
        if not self._validate_ip_address(ip_address):
            logger.warning("invalid_ip_address_format", ip=ip_address)
            return pl.DataFrame()

        try:
            df = self.connector.query_by_event_class(
                OCSFEventClass.AUTHENTICATION,
                start=start,
                end=end,
                limit=limit,
                additional_filters=f""""src_endpoint"."ip" = '{ip_address}'""",
            )

            # Also check API activity for this IP
            api_df = self.connector.query_by_event_class(
                OCSFEventClass.API_ACTIVITY,
                start=start,
                end=end,
                limit=limit,
                additional_filters=f""""src_endpoint"."ip" = '{ip_address}'""",
            )

            if len(df) > 0 and len(api_df) > 0:
                return pl.concat([df, api_df], how="diagonal")
            elif len(df) > 0:
                return df
            elif len(api_df) > 0:
                return api_df
            else:
                return pl.DataFrame()

        except Exception as e:
            logger.warning(
                "enrichment_related_principals_query_failed",
                ip=ip_address,
                error=str(e),
            )
            return pl.DataFrame()

    def find_lateral_movement(
        self,
        source_ip: str,
        start: datetime,
        end: datetime,
        limit: int = 500,
    ) -> dict[str, Any]:
        """Find potential lateral movement from an IP.

        This method:
        1. Finds authentications from the source IP
        2. Gets the users who authenticated
        3. Finds subsequent API calls from those sessions
        4. Returns a structured analysis

        Args:
            source_ip: The origin IP address
            start: Start of the time window
            end: End of the time window
            limit: Maximum events per query

        Returns:
            Dictionary with lateral movement analysis
        """
        # Validate IP address format
        if not self._validate_ip_address(source_ip):
            logger.warning("invalid_ip_address_format", ip=source_ip)
            return {"error": "Invalid IP address format", "source_ip": source_ip}

        result: dict[str, Any] = {
            "source_ip": source_ip,
            "time_window": {"start": start.isoformat(), "end": end.isoformat()},
            "authentications": [],
            "users_found": [],
            "subsequent_activity": [],
        }

        # Step 1: Find authentications from this IP
        try:
            auth_df = self.connector.query_by_event_class(
                OCSFEventClass.AUTHENTICATION,
                start=start,
                end=end,
                limit=limit,
                additional_filters=f""""src_endpoint"."ip" = '{source_ip}'""",
            )

            if len(auth_df) == 0:
                return result

            result["authentications"] = auth_df.to_dicts()

            # Step 2: Extract unique users
            user_col = None
            for col in auth_df.columns:
                if "user" in col.lower() and "name" in col.lower():
                    user_col = col
                    break

            if user_col:
                users = auth_df[user_col].drop_nulls().unique().to_list()
                result["users_found"] = users

                # Step 3: Find subsequent activity for each user
                for user in users[:5]:  # Limit to top 5 users
                    user_activity = self.enrich_by_user(
                        user,
                        start=start,
                        end=end,
                        limit=100,
                    )
                    if len(user_activity) > 0:
                        result["subsequent_activity"].append({
                            "user": user,
                            "event_count": len(user_activity),
                            "events": user_activity.to_dicts()[:10],  # Sample
                        })

        except Exception as e:
            logger.warning(
                "enrichment_lateral_movement_failed",
                ip=source_ip,
                error=str(e),
            )
            result["error"] = str(e)

        return result

    def get_resource_access_history(
        self,
        resource_arn: str,
        start: datetime,
        end: datetime,
        limit: int = 500,
    ) -> pl.DataFrame:
        """Get access history for a specific AWS resource.

        Args:
            resource_arn: The ARN of the resource
            start: Start of the time window
            end: End of the time window
            limit: Maximum events to return

        Returns:
            DataFrame of access events for the resource
        """
        # Validate ARN format
        if not resource_arn.startswith("arn:"):
            logger.warning("invalid_arn_format", arn=resource_arn)
            return pl.DataFrame()

        # Sanitize the ARN for SQL (also escape % and _ for LIKE)
        safe_arn = self._sanitize_sql_string(resource_arn)
        safe_arn = safe_arn.replace("%", "\\%").replace("_", "\\_")

        # Resources are often in the request/response data
        # This is a best-effort query since resource access patterns vary
        try:
            # Try to find in resources array or request data
            filter_clause = f"""(
                "api"."request"."data" LIKE '%{safe_arn}%'
                OR "api"."response"."data" LIKE '%{safe_arn}%'
            )"""

            return self.connector.query_by_event_class(
                OCSFEventClass.API_ACTIVITY,
                start=start,
                end=end,
                limit=limit,
                additional_filters=filter_clause,
            )
        except Exception as e:
            logger.warning(
                "enrichment_resource_access_query_failed",
                arn=resource_arn,
                error=str(e),
            )
            return pl.DataFrame()

    def get_dns_queries(
        self,
        start: datetime,
        end: datetime,
        domain_pattern: str | None = None,
        src_ip: str | None = None,
        limit: int = 500,
    ) -> pl.DataFrame:
        """Get DNS query events.

        Args:
            start: Start of the time window
            end: End of the time window
            domain_pattern: Optional domain pattern to filter (SQL LIKE pattern, use % for wildcards)
            src_ip: Optional source IP filter
            limit: Maximum events to return

        Returns:
            DataFrame of DNS query events
        """
        filters: list[str] = []

        if domain_pattern:
            # Sanitize the domain pattern but preserve % wildcards for LIKE
            safe_pattern = self._sanitize_sql_string(domain_pattern)
            # Escape _ as it's a LIKE wildcard
            safe_pattern = safe_pattern.replace("_", "\\_")
            filters.append(f""""query"."hostname" LIKE '{safe_pattern}'""")
        if src_ip:
            if not self._validate_ip_address(src_ip):
                logger.warning("invalid_ip_address_format", ip=src_ip)
                return pl.DataFrame()
            filters.append(f""""src_endpoint"."ip" = '{src_ip}'""")

        filter_clause = " AND ".join(filters) if filters else None

        try:
            return self.connector.query_by_event_class(
                OCSFEventClass.DNS_ACTIVITY,
                start=start,
                end=end,
                limit=limit,
                additional_filters=filter_clause,
            )
        except Exception as e:
            logger.warning(
                "enrichment_dns_query_failed",
                domain_pattern=domain_pattern,
                src_ip=src_ip,
                error=str(e),
            )
            return pl.DataFrame()

    def get_failed_operations(
        self,
        start: datetime,
        end: datetime,
        user_name: str | None = None,
        service: str | None = None,
        limit: int = 500,
    ) -> pl.DataFrame:
        """Get failed API operations (access denied, errors).

        Args:
            start: Start of the time window
            end: End of the time window
            user_name: Optional user filter
            service: Optional service filter
            limit: Maximum events to return

        Returns:
            DataFrame of failed operations
        """
        filters = ["status = 'Failure'"]

        if user_name:
            safe_user = self._sanitize_sql_string(user_name)
            filters.append(f""""actor"."user"."name" = '{safe_user}'""")
        if service:
            safe_service = self._sanitize_sql_string(service)
            filters.append(f""""api"."service"."name" = '{safe_service}'""")

        filter_clause = " AND ".join(filters)

        try:
            return self.connector.query_by_event_class(
                OCSFEventClass.API_ACTIVITY,
                start=start,
                end=end,
                limit=limit,
                additional_filters=filter_clause,
            )
        except Exception as e:
            logger.warning(
                "enrichment_failed_ops_query_failed",
                user=user_name,
                service=service,
                error=str(e),
            )
            return pl.DataFrame()

    def create_time_window(
        self,
        center_time: datetime,
        window_minutes: int = 60,
    ) -> tuple[datetime, datetime]:
        """Create a time window centered on a specific time.

        Args:
            center_time: The center of the time window
            window_minutes: Total window size in minutes

        Returns:
            Tuple of (start, end) datetimes
        """
        half_window = timedelta(minutes=window_minutes / 2)
        return (center_time - half_window, center_time + half_window)
