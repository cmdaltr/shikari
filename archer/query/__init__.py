"""
Query execution module for MDE and Splunk APIs.

Allows running generated queries against live data sources.
"""

from .mde import MDEClient
from .splunk import SplunkClient

__all__ = ["MDEClient", "SplunkClient"]
