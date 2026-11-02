"""
Attack Flow Generator

Generates pictorial attack flow diagrams using the MITRE ATT&CK Flow format.
Supports:
1. Correlation-specific attack flows (techniques in a correlation)
2. Complete actor attack flows (all techniques with possible routes)

Uses the attack-flow library: https://github.com/center-for-threat-informed-defense/attack-flow
"""

import json
import os
from typing import List, Dict, Optional
from datetime import datetime
import uuid


# Check if attack-flow is available
try:
    # The attack-flow library may not be installed
    # We'll build JSON manually following the attack-flow schema
    HAS_ATTACK_FLOW = False
except ImportError:
    HAS_ATTACK_FLOW = False


def generate_correlation_flow(
    correlation: Dict,
    group_name: str,
    output_dir: str = "data/attack_flows"
) -> Optional[str]:
    """
    Generate an attack flow diagram for a specific correlation.

    Args:
        correlation: Correlation dictionary with technique info
        group_name: Name of the threat group
        output_dir: Directory to save the flow JSON

    Returns:
        Path to the generated flow JSON file, or None if failed
    """
    try:
        os.makedirs(output_dir, exist_ok=True)

        # Extract techniques from correlation paths
        techniques = _extract_techniques_from_correlation(correlation)

        if not techniques:
            print(f"No techniques found in correlation")
            return None

        # Build attack flow object
        flow = _build_attack_flow(
            name=f"{group_name} - Correlation Flow",
            description=f"Attack flow for correlated techniques",
            techniques=techniques,
            is_correlation=True
        )

        # Generate filename
        corr_id = correlation.get("correlation_id", str(uuid.uuid4())[:8])
        filename = f"{group_name.replace(' ', '_')}_corr_{corr_id}.json"
        filepath = os.path.join(output_dir, filename)

        # Write to file
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(flow, f, indent=2)

        print(f"Generated correlation attack flow: {filepath}")
        return filepath

    except Exception as e:
        print(f"Failed to generate correlation flow: {e}")
        return None


def generate_actor_flow(
    group_name: str,
    techniques: List[str],
    tactics_map: Dict[str, List[str]],
    output_dir: str = "data/attack_flows"
) -> Optional[str]:
    """
    Generate a complete attack flow for an actor with all techniques and possible routes.

    Args:
        group_name: Name of the threat group
        techniques: List of technique IDs (T1234, T1234.001)
        tactics_map: Dict mapping tactics to technique IDs
        output_dir: Directory to save the flow JSON

    Returns:
        Path to the generated flow JSON file, or None if failed
    """
    try:
        os.makedirs(output_dir, exist_ok=True)

        if not techniques:
            print(f"No techniques provided for actor flow")
            return None

        # Build comprehensive attack flow
        flow = _build_attack_flow(
            name=f"{group_name} - Complete Attack Flow",
            description=f"All techniques and possible attack routes for {group_name}",
            techniques=techniques,
            tactics_map=tactics_map,
            is_correlation=False
        )

        # Generate filename
        filename = f"{group_name.replace(' ', '_')}_complete_flow.json"
        filepath = os.path.join(output_dir, filename)

        # Write to file
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(flow, f, indent=2)

        print(f"Generated actor attack flow: {filepath}")
        return filepath

    except Exception as e:
        print(f"Failed to generate actor flow: {e}")
        return None


def _extract_techniques_from_correlation(correlation: Dict) -> List[str]:
    """Extract technique IDs from correlation file paths."""
    import re

    techniques = []

    # Check file paths
    path_b = correlation.get("b") or ""
    # A chain's b is a list of paths
    for path in [correlation.get("a") or ""] + (path_b if isinstance(path_b, list) else [path_b]):
        # Extract T-codes from filename
        matches = re.findall(r'T\d{4}(?:\.\d{3})?', path)
        techniques.extend(matches)

    return list(set(techniques))


def _build_attack_flow(
    name: str,
    description: str,
    techniques: List[str],
    tactics_map: Optional[Dict[str, List[str]]] = None,
    is_correlation: bool = False
) -> Dict:
    """
    Build an attack flow JSON object following the ATT&CK Flow schema.

    Schema reference:
    https://github.com/center-for-threat-informed-defense/attack-flow/blob/main/docs/specification.md
    """
    flow_id = str(uuid.uuid4())
    created_time = datetime.utcnow().isoformat() + "Z"

    # Base flow structure
    flow = {
        "type": "bundle",
        "id": f"bundle--{flow_id}",
        "spec_version": "2.1",
        "created": created_time,
        "modified": created_time,
        "objects": []
    }

    # Add flow metadata object
    flow_meta = {
        "type": "attack-flow",
        "id": f"attack-flow--{str(uuid.uuid4())}",
        "spec_version": "2.1",
        "created": created_time,
        "modified": created_time,
        "name": name,
        "description": description,
        "scope": "incident" if is_correlation else "campaign",
        "start_refs": [],
        "end_refs": []
    }

    # Add action objects for each technique
    actions = []
    for idx, technique_id in enumerate(techniques):
        action_id = f"attack-action--{str(uuid.uuid4())}"

        action = {
            "type": "attack-action",
            "id": action_id,
            "spec_version": "2.1",
            "created": created_time,
            "modified": created_time,
            "name": f"Technique {technique_id}",
            "technique_id": technique_id,
            "technique_ref": f"attack-pattern--{technique_id}",
            "description": f"Execution of {technique_id}"
        }

        # Add execution order
        if idx > 0:
            # Link to previous action
            prev_action_id = actions[-1]["id"]
            action["effect_refs"] = [prev_action_id]

        actions.append(action)
        flow["objects"].append(action)

    # Set start and end refs
    if actions:
        flow_meta["start_refs"] = [actions[0]["id"]]
        flow_meta["end_refs"] = [actions[-1]["id"]]

    # Add flow metadata to objects
    flow["objects"].insert(0, flow_meta)

    # Add assets and operators if this is a full actor flow
    if not is_correlation and tactics_map:
        _add_tactical_routes(flow, tactics_map, created_time)

    return flow


def _add_tactical_routes(flow: Dict, tactics_map: Dict[str, List[str]], created_time: str):
    """Add tactical progression routes to the flow."""
    # Define common tactical progressions
    progressions = [
        ["initial-access", "execution", "persistence"],
        ["initial-access", "execution", "privilege-escalation", "defense-evasion"],
        ["privilege-escalation", "credential-access", "lateral-movement"],
        ["lateral-movement", "collection", "exfiltration"],
        ["persistence", "defense-evasion", "command-and-control"],
    ]

    # Create route annotations
    for progression in progressions:
        # Check if this progression exists in the actor's tactics
        if all(tactic in tactics_map for tactic in progression):
            route = {
                "type": "note",
                "id": f"note--{str(uuid.uuid4())}",
                "spec_version": "2.1",
                "created": created_time,
                "modified": created_time,
                "content": f"Tactical Route: {' → '.join(progression)}",
                "object_refs": []
            }

            # Link to relevant actions
            for tactic in progression:
                for tech_id in tactics_map.get(tactic, []):
                    # Find matching action
                    for obj in flow["objects"]:
                        if obj.get("type") == "attack-action" and obj.get("technique_id") == tech_id:
                            route["object_refs"].append(obj["id"])

            if route["object_refs"]:
                flow["objects"].append(route)


def generate_all_correlation_flows(group_name: str, correlations_file: str) -> List[str]:
    """
    Generate attack flow diagrams for all correlations in a file.

    Args:
        group_name: Name of the threat group
        correlations_file: Path to correlations JSON file

    Returns:
        List of paths to generated flow files
    """
    try:
        with open(correlations_file, 'r', encoding='utf-8') as f:
            data = json.load(f)

        vendor_corrs = data.get("vendor_correlations", [])
        cross_corrs = data.get("cross_vendor_correlations", [])

        all_corrs = vendor_corrs + cross_corrs

        generated_files = []
        for corr in all_corrs:
            filepath = generate_correlation_flow(corr, group_name)
            if filepath:
                generated_files.append(filepath)

        print(f"Generated {len(generated_files)} attack flow diagrams")
        return generated_files

    except Exception as e:
        print(f"Failed to generate correlation flows: {e}")
        return []


def export_to_html(flow_json_path: str, output_html_path: Optional[str] = None) -> Optional[str]:
    """
    Convert attack flow JSON to interactive HTML visualization.

    Args:
        flow_json_path: Path to attack flow JSON file
        output_html_path: Path for output HTML (optional)

    Returns:
        Path to generated HTML file, or None if failed
    """
    try:
        if not output_html_path:
            output_html_path = flow_json_path.replace('.json', '.html')

        with open(flow_json_path, 'r', encoding='utf-8') as f:
            flow = json.load(f)

        # Generate simple HTML visualization
        html = _generate_flow_html(flow)

        with open(output_html_path, 'w', encoding='utf-8') as f:
            f.write(html)

        print(f"Generated HTML visualization: {output_html_path}")
        return output_html_path

    except Exception as e:
        print(f"Failed to export to HTML: {e}")
        return None


def _generate_flow_html(flow: Dict) -> str:
    """Generate a simple HTML visualization of the attack flow."""
    flow_meta = next((obj for obj in flow.get("objects", []) if obj.get("type") == "attack-flow"), {})
    actions = [obj for obj in flow.get("objects", []) if obj.get("type") == "attack-action"]

    html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>{flow_meta.get("name", "Attack Flow")}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .header {{
            background: #1a73e8;
            color: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }}
        .flow-container {{
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .technique {{
            background: #e8f0fe;
            border-left: 4px solid #1a73e8;
            padding: 15px;
            margin: 10px 0;
            border-radius: 4px;
            position: relative;
        }}
        .technique-id {{
            font-weight: bold;
            color: #1a73e8;
            font-size: 1.1em;
        }}
        .technique-name {{
            margin-top: 5px;
            color: #333;
        }}
        .arrow {{
            text-align: center;
            color: #666;
            font-size: 24px;
            margin: 5px 0;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{flow_meta.get("name", "Attack Flow")}</h1>
        <p>{flow_meta.get("description", "")}</p>
    </div>
    <div class="flow-container">
"""

    for idx, action in enumerate(actions):
        tech_id = action.get("technique_id", "Unknown")
        tech_name = action.get("name", "Unknown Technique")

        html += f"""
        <div class="technique">
            <div class="technique-id">{tech_id}</div>
            <div class="technique-name">{tech_name}</div>
        </div>
"""
        if idx < len(actions) - 1:
            html += '        <div class="arrow">↓</div>\n'

    html += """
    </div>
</body>
</html>
"""

    return html
