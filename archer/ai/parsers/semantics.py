"""
Semantic analysis for detection queries — overlap detection and combination
strategy recommendation.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set

from .splunk import parse_splunk_query
from .mde import parse_kql_query


class QuerySemanticAnalyzer:
    """
    Analyses pairs of detection queries to recommend a combination strategy
    and estimate their semantic overlap.
    """

    # Known high-signal field names for overlap detection
    _HIGH_SIGNAL_FIELDS_SPLUNK = {
        "process_name", "process_path", "cmdline", "CommandLine", "Image",
        "ParentImage", "TargetFilename", "DestinationIp", "DestinationPort",
        "src_ip", "dest_ip", "src_port", "dest_port", "user", "Username",
        "AccountName", "RegistryKeyPath", "RegistryValueData", "sha256",
        "sha1", "md5", "file_hash", "url", "http_method",
    }

    _HIGH_SIGNAL_FIELDS_KQL = {
        "ProcessCommandLine", "FolderPath", "FileName", "InitiatingProcessCommandLine",
        "InitiatingProcessFileName", "RemoteIP", "RemotePort", "LocalIP", "LocalPort",
        "AccountName", "AccountDomain", "RegistryKey", "RegistryValueData",
        "SHA256", "SHA1", "MD5", "FileOriginUrl", "ActionType", "LogonType",
    }

    def suggest_combination_strategy(
        self,
        query_a: str,
        query_b: str,
        vendor: str,
    ) -> Dict:
        """
        Analyse two queries and suggest a combination strategy.

        Returns:
            {
                "strategy": str,          # "union" | "append" | "join" | "or_merge" | "independent"
                "overlap": {
                    "overlap_score": float,   # 0.0 (no overlap) to 1.0 (identical)
                    "shared_fields": list[str],
                    "shared_sources": list[str],
                }
            }
        """
        vendor_lower = vendor.lower()

        if vendor_lower in ("splunk", "spl"):
            return self._analyse_splunk(query_a, query_b)
        elif vendor_lower in ("mde", "kql", "sentinel", "defender"):
            return self._analyse_kql(query_a, query_b)
        else:
            return self._default_result("independent", 0.0)

    # ------------------------------------------------------------------
    # Splunk analysis
    # ------------------------------------------------------------------

    def _analyse_splunk(self, query_a: str, query_b: str) -> Dict:
        pa = parse_splunk_query(query_a)
        pb = parse_splunk_query(query_b)

        # Source overlap
        shared_indexes = set(pa.indexes) & set(pb.indexes)
        shared_sourcetypes = set(pa.sourcetypes) & set(pb.sourcetypes)
        shared_sources = list(shared_indexes | shared_sourcetypes)

        # Field overlap
        fields_a = set(f.lower() for f in pa.fields)
        fields_b = set(f.lower() for f in pb.fields)
        shared_fields = list(fields_a & fields_b)

        overlap_score = self._score(
            shared_fields=shared_fields,
            total_fields_a=len(fields_a),
            total_fields_b=len(fields_b),
            shared_sources=shared_sources,
        )

        # Strategy
        if overlap_score > 0.7:
            strategy = "or_merge"   # Very similar — merge with OR inline
        elif shared_indexes:
            strategy = "append"     # Same index, different logic — append
        else:
            strategy = "union"      # Different data sources — union both

        return {
            "strategy": strategy,
            "overlap": {
                "overlap_score": round(overlap_score, 3),
                "shared_fields": shared_fields,
                "shared_sources": shared_sources,
            },
        }

    # ------------------------------------------------------------------
    # KQL analysis
    # ------------------------------------------------------------------

    def _analyse_kql(self, query_a: str, query_b: str) -> Dict:
        pa = parse_kql_query(query_a)
        pb = parse_kql_query(query_b)

        shared_tables = list(set(pa.tables) & set(pb.tables))

        fields_a = set(f.lower() for f in pa.fields)
        fields_b = set(f.lower() for f in pb.fields)
        shared_fields = list(fields_a & fields_b)

        overlap_score = self._score(
            shared_fields=shared_fields,
            total_fields_a=len(fields_a),
            total_fields_b=len(fields_b),
            shared_sources=shared_tables,
        )

        if overlap_score > 0.7:
            strategy = "or_merge"
        elif shared_tables:
            strategy = "union"
        else:
            strategy = "join"

        return {
            "strategy": strategy,
            "overlap": {
                "overlap_score": round(overlap_score, 3),
                "shared_fields": shared_fields,
                "shared_sources": shared_tables,
            },
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _score(
        shared_fields: List[str],
        total_fields_a: int,
        total_fields_b: int,
        shared_sources: List[str],
    ) -> float:
        """Compute a 0-1 overlap score."""
        # Jaccard on fields
        total_union = total_fields_a + total_fields_b - len(shared_fields)
        field_score = len(shared_fields) / max(total_union, 1)

        # Bonus for shared data sources
        source_bonus = 0.3 if shared_sources else 0.0

        return min(field_score + source_bonus, 1.0)

    @staticmethod
    def _default_result(strategy: str, overlap_score: float) -> Dict:
        return {
            "strategy": strategy,
            "overlap": {
                "overlap_score": overlap_score,
                "shared_fields": [],
                "shared_sources": [],
            },
        }
