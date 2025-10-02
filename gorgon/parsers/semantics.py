"""
Query semantics analyzer to understand the purpose and meaning of queries.
"""

import re
from typing import Dict, List, Set, Tuple, Optional
from collections import Counter
import json
import os

# Known query categories and their associated keywords or patterns
QUERY_CATEGORIES = {
    "authentication": {
        "keywords": ["login", "logon", "authenticate", "credential", "password", "account", "identity"],
        "patterns": [r"\bauth\w+\b", r"\blogin\b", r"\bsign\s?in\b"]
    },
    "network_traffic": {
        "keywords": ["connection", "packet", "traffic", "flow", "socket", "port", "ip", "dns"],
        "patterns": [r"\bconnect\w+\b", r"\bnetwork\b", r"\btraffic\b", r"\bport\s+\d+\b"]
    },
    "file_activity": {
        "keywords": ["file", "directory", "folder", "path", "create", "modify", "delete", "read", "write"],
        "patterns": [r"\bfile\w*\b", r"\bread\b", r"\bwrit\w+\b", r"\.exe\b", r"\.dll\b", r"\.sh\b"]
    },
    "process_execution": {
        "keywords": ["process", "command", "execution", "spawn", "parent", "child", "cmd", "powershell", "bash"],
        "patterns": [r"\bproc\w+\b", r"\bexec\w+\b", r"\bcmd\.exe\b", r"\bpowershell\.exe\b"]
    },
    "registry": {
        "keywords": ["registry", "hkey", "regedit"],
        "patterns": [r"HKEY_\w+", r"HKLM", r"HKCU", r"HKCR"]
    },
    "threat_hunting": {
        "keywords": ["malware", "virus", "trojan", "ransomware", "backdoor", "exploitation", "vulnerability"],
        "patterns": [r"\bmalware\b", r"\bvirus\b", r"\bexploit\b", r"\bvulnerability\b"]
    },
    "email": {
        "keywords": ["email", "mail", "smtp", "inbox", "outlook"],
        "patterns": [r"\bemail\b", r"\bmail\b", r"@", r"\.eml\b"]
    }
}


class QuerySemanticAnalyzer:
    """Analyzes queries to understand their semantic meaning and purpose."""
    
    def __init__(self, custom_categories_file: str = None):
        """
        Initialize the semantic analyzer.
        
        Args:
            custom_categories_file: Path to a JSON file with custom categories
        """
        self.categories = QUERY_CATEGORIES.copy()
        
        # Load custom categories if provided
        if custom_categories_file and os.path.exists(custom_categories_file):
            try:
                with open(custom_categories_file, 'r') as f:
                    custom_categories = json.load(f)
                    self.categories.update(custom_categories)
            except Exception as e:
                print(f"Error loading custom categories: {e}")
        
        # Compile regex patterns for efficiency
        self.compiled_patterns = {}
        for category, data in self.categories.items():
            patterns = data.get("patterns", [])
            self.compiled_patterns[category] = [re.compile(p, re.IGNORECASE) for p in patterns]
    
    def analyze_query(self, query: str) -> Dict:
        """
        Analyze a query to determine its semantic categories.
        
        Args:
            query: The query string to analyze
            
        Returns:
            Dict with analysis results
        """
        if not query or not isinstance(query, str):
            return {"categories": [], "entities": {}, "confidence": 0}
        
        # Count category matches
        matches = Counter()
        
        # Check each category's keywords and patterns
        for category, data in self.categories.items():
            # Check keywords
            for keyword in data.get("keywords", []):
                if re.search(r'\b' + re.escape(keyword) + r'\b', query, re.IGNORECASE):
                    matches[category] += 1
            
            # Check patterns
            for pattern in self.compiled_patterns.get(category, []):
                if pattern.search(query):
                    matches[category] += 1
        
        # Extract top categories
        top_categories = matches.most_common(3)
        categories = [cat for cat, count in top_categories if count > 0]
        
        # Extract entities (e.g., IP addresses, file paths, usernames)
        entities = self._extract_entities(query)
        
        # Calculate confidence based on match counts
        total_matches = sum(matches.values())
        confidence = min(0.95, total_matches / 10) if total_matches > 0 else 0
        
        return {
            "categories": categories,
            "entities": entities,
            "confidence": confidence
        }
    
    def find_semantic_overlap(self, query_a: str, query_b: str) -> Dict:
        """
        Find semantic overlap between two queries.
        
        Args:
            query_a: First query string
            query_b: Second query string
            
        Returns:
            Dict with overlap analysis
        """
        analysis_a = self.analyze_query(query_a)
        analysis_b = self.analyze_query(query_b)
        
        # Find common categories
        categories_a = set(analysis_a.get("categories", []))
        categories_b = set(analysis_b.get("categories", []))
        common_categories = categories_a.intersection(categories_b)
        
        # Find common entities
        entities_a = analysis_a.get("entities", {})
        entities_b = analysis_b.get("entities", {})
        
        common_entities = {}
        all_entity_types = set(entities_a.keys()).union(entities_b.keys())
        
        for entity_type in all_entity_types:
            set_a = set(entities_a.get(entity_type, []))
            set_b = set(entities_b.get(entity_type, []))
            common = set_a.intersection(set_b)
            if common:
                common_entities[entity_type] = list(common)
        
        # Calculate overlap score
        total_categories = len(categories_a.union(categories_b))
        category_score = len(common_categories) / total_categories if total_categories > 0 else 0
        
        total_entities = sum(len(entities_a.get(t, [])) + len(entities_b.get(t, [])) for t in all_entity_types)
        entity_score = sum(len(v) for v in common_entities.values()) / total_entities if total_entities > 0 else 0
        
        overlap_score = (category_score * 0.6) + (entity_score * 0.4)
        
        return {
            "common_categories": list(common_categories),
            "common_entities": common_entities,
            "overlap_score": overlap_score,
            "analysis_a": analysis_a,
            "analysis_b": analysis_b
        }
    
    def suggest_combination_strategy(self, query_a: str, query_b: str, platform: str) -> Dict:
        """
        Suggest a strategy for combining two queries based on their semantics.
        
        Args:
            query_a: First query string
            query_b: Second query string
            platform: Query platform/vendor
            
        Returns:
            Dict with suggested combination strategy
        """
        overlap = self.find_semantic_overlap(query_a, query_b)
        
        # Determine the best combination strategy based on overlap
        if overlap["overlap_score"] > 0.7:
            # High overlap - queries are very similar
            strategy = "merge"
            description = "Merge queries by combining their conditions with OR"
        elif overlap["overlap_score"] > 0.3:
            # Medium overlap - queries are somewhat related
            strategy = "join"
            description = "Join queries based on common entities"
        else:
            # Low overlap - queries are different
            strategy = "union"
            description = "Use union to show results from both queries separately"
        
        # Platform-specific strategy adjustments
        if platform.lower() == "splunk":
            if strategy == "merge":
                technique = "Use search terms combined with OR"
            elif strategy == "join":
                technique = "Use join or transaction commands"
            else:
                technique = "Use append or union commands"
        elif platform.lower() in ["mde", "kql"]:
            if strategy == "merge":
                technique = "Combine where clauses with or"
            elif strategy == "join":
                technique = "Use join operator on common fields"
            else:
                technique = "Use union operator"
        else:
            technique = f"Use {strategy} approach appropriate for the platform"
        
        return {
            "strategy": strategy,
            "description": description,
            "technique": technique,
            "overlap": overlap
        }
    
    def _extract_entities(self, query: str) -> Dict[str, List[str]]:
        """Extract entities like IPs, file paths, etc. from the query."""
        entities = {
            "ip_addresses": [],
            "file_paths": [],
            "hostnames": [],
            "usernames": [],
            "hashes": []
        }
        
        # IP address pattern (simple version)
        ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        entities["ip_addresses"] = re.findall(ip_pattern, query)
        
        # File paths
        file_patterns = [
            r'\b[a-zA-Z]:\\(?:[^<>:"/\\|?*\n]+\\)*[^<>:"/\\|?*\n]*',  # Windows
            r'\b/(?:[^<>:"/\\|?*\n]+/)*[^<>:"/\\|?*\n]*',  # Unix
        ]
        for pattern in file_patterns:
            paths = re.findall(pattern, query)
            entities["file_paths"].extend([p for p in paths if len(p) > 3])
        
        # Hostnames
        hostname_pattern = r'\b[a-zA-Z0-9][-a-zA-Z0-9.]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}\b'
        entities["hostnames"] = re.findall(hostname_pattern, query)
        
        # MD5, SHA1, SHA256 hashes
        hash_patterns = [
            r'\b[a-fA-F0-9]{32}\b',  # MD5
            r'\b[a-fA-F0-9]{40}\b',  # SHA1
            r'\b[a-fA-F0-9]{64}\b',  # SHA256
        ]
        for pattern in hash_patterns:
            entities["hashes"].extend(re.findall(pattern, query))
        
        # Username pattern (basic)
        username_pattern = r'\b(?:user|username|account)(?:\s*=\s*|\s+)([a-zA-Z0-9._-]+)\b'
        username_matches = re.findall(username_pattern, query, re.IGNORECASE)
        if username_matches:
            entities["usernames"] = username_matches
        
        return entities
