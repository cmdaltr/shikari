"""
Elasticsearch Query Generator
Generates Elastic Query DSL and ECS-based detection queries using templates
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple


class ElasticQueryGenerator:
    """Generates Elasticsearch queries for threat detection using templates"""

    def __init__(self):
        """
        Initialize Elastic generator with ECS schema mappings
        """
        # Load Elastic ECS schema mappings
        self.schema = self._load_schema()

    def _load_schema(self) -> Dict:
        """Load Elastic ECS schema mappings"""
<<<<<<< HEAD
        schema_path = Path(__file__).parent.parent.parent / "data" / "bespoke" / "mappings" / "schemaElastic.json"
=======
        schema_path = Path(__file__).parent.parent / "mappings" / "schemaElastic.json"
>>>>>>> 534dbed55db820eea689f7a2b6dc4330fafc6b07
        if schema_path.exists():
            with open(schema_path, 'r') as f:
                return json.load(f)
        return {}

    def generate_query(
        self,
        technique_id: str,
        technique_name: str,
        tactic: str,
        description: str,
        indicators: Optional[Dict] = None,
        osint_data: Optional[Dict] = None,
        group_name: Optional[str] = None
    ) -> Dict[str, any]:
        """
        Generate Elasticsearch query for technique using templates

        Returns:
            Dict with keys: query_name, query_dsl, description, index_pattern
        """

        # Generate query name
        query_name = f"{technique_id}_{technique_name.replace(' ', '_')}"

        # Determine index pattern
        index_pattern = self._determine_index_pattern(indicators or {})

        # Build Elasticsearch Query DSL
        query_dsl = self._build_query_dsl(
            technique_id=technique_id,
            technique_name=technique_name,
            indicators=indicators or {}
        )

        return {
            "query_name": query_name,
            "query_dsl": query_dsl,
            "description": f"Detects {technique_name} ({technique_id})",
            "index_pattern": index_pattern
        }

    def _determine_index_pattern(self, indicators: Dict) -> str:
        """Determine appropriate index pattern based on indicators"""
        if "cmd" in indicators or "sw" in indicators:
            return "logs-endpoint.events.process-*"
        elif "reg" in indicators:
            return "logs-endpoint.events.registry-*"
        elif "network" in indicators or "url" in indicators:
            return "logs-endpoint.events.network-*"
        elif "file" in indicators:
            return "logs-endpoint.events.file-*"
        else:
            return "logs-endpoint.events.*"

    def _build_query_dsl(
        self,
        technique_id: str,
        technique_name: str,
        indicators: Dict
    ) -> Dict:
        """Build Elasticsearch Query DSL using templates"""

        must_clauses = []
        should_clauses = []

        # Process command line indicators
        if "cmd" in indicators:
            cmd_should = []
            for cmd in indicators["cmd"][:5]:  # Limit to 5 indicators
                cmd_should.append({
                    "wildcard": {
                        "process.command_line": {
                            "value": f"*{cmd}*",
                            "case_insensitive": True
                        }
                    }
                })
            if cmd_should:
                should_clauses.extend(cmd_should)

        # Process software/file indicators
        if "sw" in indicators:
            sw_should = []
            for sw in indicators["sw"][:5]:
                sw_should.append({
                    "wildcard": {
                        "process.name": {
                            "value": f"*{sw}*",
                            "case_insensitive": True
                        }
                    }
                })
            if sw_should:
                should_clauses.extend(sw_should)

        # Process registry indicators
        if "reg" in indicators:
            reg_should = []
            for reg in indicators["reg"][:5]:
                reg_should.append({
                    "wildcard": {
                        "registry.path": {
                            "value": f"*{reg}*",
                            "case_insensitive": True
                        }
                    }
                })
            if reg_should:
                should_clauses.extend(reg_should)

        # Process network indicators (URLs)
        if "network" in indicators or "url" in indicators:
            net_indicators = indicators.get("network", []) + indicators.get("url", [])
            net_should = []
            for net in net_indicators[:5]:
                net_should.append({
                    "wildcard": {
                        "url.full": {
                            "value": f"*{net}*",
                            "case_insensitive": True
                        }
                    }
                })
            if net_should:
                should_clauses.extend(net_should)

        # Process port indicators
        if "port" in indicators:
            port_should = []
            for port in indicators["port"][:5]:
                port_should.append({
                    "bool": {
                        "should": [
                            {"term": {"destination.port": int(port)}},
                            {"term": {"source.port": int(port)}}
                        ],
                        "minimum_should_match": 1
                    }
                })
            if port_should:
                should_clauses.extend(port_should)

        # Process protocol indicators
        if "protocol" in indicators:
            proto_should = []
            for proto in indicators["protocol"][:5]:
                proto_should.append({
                    "bool": {
                        "should": [
                            {"term": {"network.protocol": proto.lower()}},
                            {"term": {"network.transport": proto.upper()}}
                        ],
                        "minimum_should_match": 1
                    }
                })
            if proto_should:
                should_clauses.extend(proto_should)

        # Process service indicators
        if "service" in indicators:
            svc_should = []
            for svc in indicators["service"][:5]:
                svc_should.append({
                    "bool": {
                        "should": [
                            {"wildcard": {"network.application": {"value": f"*{svc}*", "case_insensitive": True}}},
                            {"wildcard": {"destination.service.name": {"value": f"*{svc}*", "case_insensitive": True}}}
                        ],
                        "minimum_should_match": 1
                    }
                })
            if svc_should:
                should_clauses.extend(svc_should)

        # Build the complete query
        if should_clauses:
            query = {
                "query": {
                    "bool": {
                        "should": should_clauses,
                        "minimum_should_match": 1
                    }
                }
            }
        else:
            # Default query if no specific indicators
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {
                                "exists": {
                                    "field": "process.name"
                                }
                            }
                        ]
                    }
                }
            }

        # Add metadata
        query["_meta"] = {
            "technique_id": technique_id,
            "technique_name": technique_name,
            "author": "Archer Detection Engineering"
        }

        return query

    def validate_query(self, query_dsl: Dict) -> Tuple[bool, str]:
        """
        Validate Elasticsearch Query DSL syntax

        Args:
            query_dsl: The query DSL dictionary

        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            # Basic validation - check for required structure
            if not isinstance(query_dsl, dict):
                return False, "Query must be a dictionary"

            if "query" not in query_dsl:
                return False, "Missing 'query' field"

            # Check that it's valid JSON-serializable
            json.dumps(query_dsl)

            return True, ""
        except Exception as e:
            return False, str(e)

    def format_query_for_display(self, query_dsl: Dict) -> str:
        """Format query DSL as pretty-printed JSON string"""
        return json.dumps(query_dsl, indent=4)

    def generate_correlation_query(
        self,
        techniques: List[Dict],
        group_name: str,
        time_window: str = "5m"
    ) -> Dict[str, any]:
        """Generate multi-event correlation query using Elastic EQL or bool queries"""

        query_name = f"{group_name.replace(' ', '_')}_correlation"

        # Build EQL sequence query
        eql_query = self._build_eql_sequence(techniques, time_window)

        return {
            "query_name": query_name,
            "query_dsl": {
                "query": eql_query,
                "_meta": {
                    "group_name": group_name,
                    "type": "correlation",
                    "author": "Archer Detection Engineering"
                }
            },
            "description": f"Correlation query for {group_name}",
            "index_pattern": "logs-endpoint.events.*"
        }

    def _build_eql_sequence(self, techniques: List[Dict], time_window: str) -> Dict:
        """Build EQL sequence for correlation"""
        # Simplified EQL-style correlation using bool query
        must_clauses = []

        for tech in techniques[:3]:  # Limit to 3 techniques
            tech_name = tech.get('name', 'process')
            must_clauses.append({
                "exists": {
                    "field": "process.name"
                }
            })

        return {
            "bool": {
                "must": must_clauses
            }
        }
