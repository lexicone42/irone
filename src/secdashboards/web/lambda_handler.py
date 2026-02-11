"""AWS Lambda handler via Mangum ASGI adapter."""

from mangum import Mangum

from secdashboards.web.app import create_app
from secdashboards.web.config import WebConfig

_config = WebConfig(is_lambda=True)
_app = create_app(_config)
handler = Mangum(_app, lifespan="off")
