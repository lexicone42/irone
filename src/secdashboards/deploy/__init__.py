"""Lambda deployment utilities for detection rules."""

from secdashboards.deploy.lambda_builder import LambdaBuilder
from secdashboards.deploy.scheduler import DetectionScheduler

__all__ = ["LambdaBuilder", "DetectionScheduler"]
