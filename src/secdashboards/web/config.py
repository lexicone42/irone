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
