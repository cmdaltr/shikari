"""
Query execution module for the Splunk API.

Allows running generated queries against live data sources. Defender XDR
execution is planned (#16) on Microsoft Graph's runHuntingQuery, as
shikari/telemetry/mde.py uses.
"""

from .splunk import SplunkClient

__all__ = ["SplunkClient"]
