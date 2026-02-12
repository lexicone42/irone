"""Web application configuration via environment variables."""

from pydantic_settings import BaseSettings


class WebConfig(BaseSettings):
    """Configuration for the secdashboards web application.

    All fields can be set via environment variables with the ``SECDASH_`` prefix,
    e.g. ``SECDASH_REGION=eu-west-1``.
    """

    model_config = {"env_prefix": "SECDASH_"}

    # AWS settings
    region: str = "us-west-2"
    security_lake_db: str = ""
    athena_output: str = ""

    # DuckDB settings
    duckdb_path: str = ":memory:"

    # Application paths
    rules_dir: str = ""
    catalog_path: str = ""

    # Server settings
    debug: bool = False
    host: str = "0.0.0.0"
    port: int = 8000

    # Runtime mode
    is_lambda: bool = False

    # S3 report bucket
    report_bucket: str = ""

    # --- Authentication (Cognito + Passkey) ---
    auth_enabled: bool = False
    cognito_user_pool_id: str = ""
    cognito_client_id: str = ""
    cognito_client_secret: str = ""
    cognito_domain: str = ""
    cognito_region: str = "us-west-2"
    cognito_redirect_uri: str = ""

    # --- Session ---
    session_secret_key: str = "change-me-in-production"
    session_backend: str = "memory"  # "memory" or "dynamodb"
    session_max_age: int = 30 * 24 * 3600  # 30 days

    # --- Cedar Authorization ---
    cedar_enabled: bool = True

    # --- Frontend ---
    frontend_url: str = ""
