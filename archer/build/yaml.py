from archer.build import attack_mapping, run_files
from archer.build.collate import collate_data
from archer.build.severity import rate as rate_severity
from archer.config import GENERATE_DIR
from archer.tactic_scope import intel_only
from archer.validation.mde_field_validator import format_mde_query

import getpass
import hashlib
import json
import os
import textwrap
import re
import uuid

import yaml as yaml_lib

# Detections written by an older generator are rewritten on the next run that reaches
# them. Bump this whenever generated detections change (fields, query shape, naming), so
# the fix reaches files already on disk without anyone deleting them.
GENERATOR_VERSION = 3  # 3: KQL aggregates per finding, verbatim paths, bracketed and/or

# A detection file's suffix when it isn't named for its table or index: the query language
# (At_UDM.yaml), never the product. archer.build.migrate_names renames files made before this.
LANGUAGE_SUFFIX = {"GoogleSecOps": "UDM", "MicrosoftThreatProtection": "KQL", "Splunk": "SPL", "Elastic": "ESQL"}

# BeautifulSoup and requests only needed for OLD slow additional_tactics function
# This function is replaced by yaml_patch.py, so these imports are optional
try:
    from bs4 import BeautifulSoup
    import requests

    HAS_SCRAPING = True
except ImportError:
    HAS_SCRAPING = False
    # Not needed if yaml_patch is applied (which it is in orchestrator.py)


def create_id():
    return str(uuid.uuid4())


def check_id(existing_ids):
    if len(existing_ids) > 0:
        # Check both old queries directory and new generate directory
        for directory in ["data/queries", "data/groups"]:
            if os.path.exists(directory):
                for queryfile in os.listdir(directory):
                    if queryfile.endswith(".yaml"):
                        filepath = os.path.join(directory, queryfile)
                        try:
                            with open(filepath) as qf:
                                existing_ids.append(qf.readline())
                        except:
                            pass
    uid = create_id()
    if uid in str(existing_ids):
        check_id(existing_ids)

    return uid


def get_team(author):
    """
    Get team assignment for an author based on members.json.
    Looks in bespoke/members.json first (org-specific).
    Returns default team if file not found or author not in list.
    """
    members = {}

    # Try bespoke location first (org-specific)
    bespoke_path = os.path.join("bespoke", "mappings", "sources", "members.json")
    if os.path.exists(bespoke_path):
        try:
            with open(bespoke_path) as membersjson:
                members = json.load(membersjson)
        except (json.JSONDecodeError, IOError):
            pass

    # Default team if no members file or author not found
    team = "CTH"
    for key, people in members.items():
        for person in people:
            if person.get("username", "").lower() == author.lower():
                team = key
                break
        if team != "CTH":
            return team

    return team


def additional_tactics(tid, tactic):
    """
    DEPRECATED: This function is SLOW (10-30 seconds per call).
    It is automatically replaced by yaml_patch.additional_tactics_fast() in orchestrator.py.

    If you see this function being called, the patch was not applied.
    Ensure: from archer.build import yaml_patch
    """

    def extract_tactics(extract_from):
        extracted_tactics = re.findall(
            "Initial Access|Execution|Persistence|Privilege Escalation|Defense Evasion|Credential Access|Discovery|Lateral Movement|Collection|Command and Control|Exfiltration|Impact",
            extract_from,
        )

        return extracted_tactics

    # Warn if scraping dependencies not available
    if not HAS_SCRAPING:
        print("WARNING: BeautifulSoup/requests not available. Using fallback regex extraction.")
        print("         Install with: pip install beautifulsoup4 requests")
        print("         Or apply yaml_patch for fast STIX-based extraction.")
        return extract_tactics(tactic)

    tid_uri = tid.replace(".", "/")
    url = f"https://attack.mitre.org/techniques/{tid_uri}"

    # Try to fetch from MITRE with retry logic and timeout handling
    max_retries = 3
    timeout = 10

    for attempt in range(max_retries):
        try:
            response = requests.get(url, timeout=timeout)
            soup = BeautifulSoup(response.text, "html.parser")
            text = soup.text

            if "Tactics:\\n" in text:
                extracted_tactics = extract_tactics(
                    text.split("Sub-technique of")[1][0:200]
                    .split("Platforms:")[0]
                    .split("Tactics:")[1],
                )
            else:
                extracted_tactics = extract_tactics(tactic)

            return extracted_tactics

        except (requests.exceptions.Timeout, requests.exceptions.RequestException) as e:
            if attempt < max_retries - 1:
                # Retry with exponential backoff
                wait_time = 2**attempt
                print(
                    f"Warning: Failed to fetch tactics from MITRE (attempt {attempt + 1}/{max_retries}), retrying in {wait_time}s..."
                )
                import time

                time.sleep(wait_time)
            else:
                # Final fallback: use the tactic provided
                print(
                    f"Warning: Could not fetch additional tactics from {url} after {max_retries} attempts, using provided tactic: {tactic}"
                )
                extracted_tactics = extract_tactics(tactic)
                return extracted_tactics


def find_nested_entity(field, entity_mappings):
    for entity, values in entity_mappings.items():
        for v in values:
            if isinstance(v, str):
                if v == field:
                    return (field, entity)
            elif isinstance(v, dict):
                for nested, nested_fields in v.items():
                    if field == nested:
                        return (nested, entity)
                    if isinstance(nested_fields, list) and field in nested_fields:
                        return (nested, entity)
    return None


def map_entities(query):
    """
    Extract entity mappings from a KQL query.

    Returns:
        tuple: (query, entity_mappings_string) where entity_mappings_string is empty for non-MDE queries
    """
    # Check if this is a Splunk query (starts with "index=") or KQL/MDE query
    # Splunk queries don't use "| summarize by Timestamp," syntax
    if query.strip().startswith("index="):
        # This is a Splunk query - entity mapping not applicable
        # Return query unchanged with no entity mappings
        return (query, "")

    # Check if query contains the expected KQL syntax
    if "| summarize by Timestamp, " not in query:
        # Query doesn't have the expected format - return unchanged
        return (query, "")

    # Process KQL/MDE queries with entity mapping
    fields = query.split("| summarize by Timestamp, ")[1].split(", ")
    with open(os.path.join("bespoke", "mappings", "sources", "entityMappings.json")) as f:
        entity_mappings = json.load(f)

    # Find and print nested field/entity matches
    results = []
    for field in fields:
        result = find_nested_entity(field, entity_mappings)
        if result:
            # Store as tuple for later formatting
            results.append((result[1], result[0], field))

    # Build entityMappings string efficiently
    entities = ""
    if results:
        entities = "entityMappings:"
        for entity_type, identifier, column_name in results:
            entities += (
                f"\n- entityType: {entity_type}\n"
                f"  fieldMappings:\n"
                f"    - identifier: {identifier}\n"
                f"      columnName: {column_name}"
            )

    return (query, entities)


def _without_strings(query: str) -> str:
    return re.sub(r'@?"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'', '""', query)


def _empty_group(query: str) -> bool:
    """An empty "()" outside string literals that isn't a call such as count()."""
    return bool(re.search(r"(?<![A-Za-z0-9_])\(\s*\)", _without_strings(query)))


def _brackets_balanced(query: str) -> bool:
    """KQL's round brackets pair up, ignoring any inside string literals."""
    depth = 0
    for ch in _without_strings(query):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


def write_yaml(query_file, name, tid, tdesc, connector_id, tactic, tag, query, datatype=None, indicators=None, osint_data=None, osint_enhanced=False, entity_mappings=None, reference_used=False, reference_sources=None, tags=None, version=None, attack_override=None, attack_mapping_history=None, severity=None):
    """Write a detection. tags, version and a hand-made ATT&CK mapping carry over from the
    file it replaces (detection_action). severity overrides the tactic's rating
    (a CVE's own detections are High)."""
    if isinstance(tactic, (list, tuple)):
        tactic = list(tactic)
        if intel_only(tid, tactic):
            # Adversary-side Reconnaissance/Resource Development: the estate's logs don't see it
            print(f"  ⏭️  Not written: {os.path.basename(query_file)} is intel only (pre-compromise)")
            return
    with open(os.path.join("archer", "mappings", "template.yaml")) as queryTemplate:
        template = queryTemplate.read()

    uid = check_id([])
    desc = re.sub(r"</?code>", r"`", tdesc or "").strip()
    # Every line of the "description: |" block sits at exactly two spaces: the first line's
    # indent sets the block's, so procedure text that starts with a space (" [Vidar] has…")
    # or wraps mid-path ("/lib/systemd/\nsystem/…") would end the block and break the file
    desc = "\n".join(line.strip() if i == 0 else ("  " + line.strip() if line.strip() else "")
                     for i, line in enumerate(desc.split("\n")))

    # Extract datatype from first non-comment, non-let line (if not provided)
    if not datatype:
        for line in query.split("\n"):
            stripped = line.strip()
            # Skip empty lines, comments, and let statements
            if stripped and not stripped.startswith("//") and not stripped.startswith("let "):
                datatype = stripped.split(" earliest=")[0].replace("index=", "").replace("_prod", "")
                break

        # Fallback if no valid line found
        if not datatype:
            datatype = "UnknownDataType"
    severity = severity or rate_severity(tactic)
    tactic = str(list(tactic))[2:-2].replace("', '", "\n  - ")

    # Indent ALL query lines properly for YAML literal block
    # Split query into lines, indent each non-empty line with 2 spaces.
    # A JSON-bodied query (legacy) keeps its internal indentation; piped languages (KQL, SPL,
    # Elastic ES|QL) are newline-tolerant within a command, so lines are left-aligned to the pipes.
    query_lines = query.split("\n")
    indented_lines = []

    # Detect if this is a JSON query (starts with { or whitespace + {)
    is_json_query = query.strip().startswith("{")

    if is_json_query:
        # JSON query - preserve existing indentation, just add base 2-space indent
        for line in query_lines:
            if line.strip():  # Non-empty line
                # Keep the existing indentation, just add 2-space base indent
                indented_lines.append("  " + line)
            else:
                # Empty line - keep it empty
                indented_lines.append(line)
    else:
        # Non-JSON query (KQL, SPL, etc.) - apply standard formatting
        for line in query_lines:
            if line.strip():  # Non-empty line
                stripped = line.lstrip()
                # For KQL queries, ensure pipe operators are properly aligned
                # If line starts with |, it should have no extra indentation beyond the 2-space YAML indent
                if stripped.startswith("|"):
                    indented_lines.append("  " + stripped)
                else:
                    # Non-pipe lines get standard 2-space indent
                    indented_lines.append("  " + stripped)
            else:
                # Empty line - keep it empty
                indented_lines.append(line)

    query = "\n".join(indented_lines)

    author = getpass.getuser()
    team = get_team(author)

    # Format the threat group tag with (Group) suffix; a rewrite keeps every group's tag
    formatted_tag = f"{tag} (Group)" if tag else ""
    all_tags = list(tags or [])
    if formatted_tag and formatted_tag not in all_tags:
        all_tags.insert(0, formatted_tag)

    # Format entity mappings
    # Template already has newlines before and after placeholder, so no modification needed
    entity_mappings_formatted = entity_mappings if entity_mappings else ""

    yaml_content = (
        template.replace("§id§", uid)
        .replace("§name§", name)
        .replace("§tid§", tid)
        .replace("§tdesc§", desc)
        .replace("§severity§", severity)
        .replace("§connectorId§", connector_id)
        .replace("§dataTypes§", datatype)
        .replace("§tactic§", tactic)
        .replace("§group§", "\n  - ".join(all_tags) if all_tags else formatted_tag)
        .replace("§query§", query)
        .replace("§entityMappings§", entity_mappings_formatted)
        .replace("§ver§", version or "1.0")
        .replace("§source§", "Archer")
        .replace("§author§", author)
        .replace("§support§", team)
        .replace("query:  |", "query: |")
        # NOTE: Old indentation logic removed - now handled by pre-indenting query lines above
        # .replace("  | ", " | ")
        # .replace("\n | ", "\n  | ")
    )
    # Fix: Don't add extra indentation to query lines (lines starting with "  |" after blank lines)
    # Only add indentation to description text after blank lines
    # Split on double newlines, check if next line is a query pipe, and only add indent if it's not
    def fix_blank_line_indent(match):
        # Get the text after the blank line
        next_char_idx = match.end()
        if next_char_idx < len(yaml_content):
            # Check if the next line starts with "  |" (query pipe)
            remaining = yaml_content[next_char_idx:]
            if remaining.startswith("  |"):
                # This is a query line, don't add extra indent
                return "\n\n"
        # Not a query line, add indent for description formatting
        return "\n  "

    # Note: Can't use the function approach above in re.sub easily, so use a simpler fix:
    # Only apply indentation to description section, not query section
    # Split at "query: |" marker and only apply regex to the part before it
    if "query: |" in yaml_content:
        parts = yaml_content.split("query: |", 1)
        # Apply regex only to content before query
        parts[0] = re.sub(r"\n\n", r"\n  ", parts[0])
        yaml_content = "query: |".join(parts)
    else:
        # Fallback: apply to whole content if no query marker found
        yaml_content = re.sub(r"\n\n", r"\n  ", yaml_content)

    yaml_content = re.sub(r"(\(Citation: [^\)]+\))", r"", yaml_content)
    # NOTE: Old pipe reformatting removed - now handled by pre-indenting query lines above
    # yaml_content = yaml_content.replace(" | where ", "\n   | where ").replace("   | ", "  | ")

    # Add indicators section if present
    if indicators:
        import yaml as yaml_module
        indicators_section = "\n# Extracted Indicators\n"
        indicators_section += "indicators:\n"

        # Handle dict or list format
        if isinstance(indicators, dict):
            for indicator_type, values in indicators.items():
                if values:
                    indicators_section += f"  {indicator_type}:\n"
                    for value in values:
                        yaml_str = yaml_module.dump([value], default_flow_style=False, width=1000000)
                        yaml_value = yaml_str.strip().replace('- ', '', 1).strip()
                        indicators_section += f'    - {yaml_value}\n'
        elif isinstance(indicators, list) and indicators:
            for value in indicators:
                yaml_str = yaml_module.dump([value], default_flow_style=False, width=1000000)
                yaml_value = yaml_str.strip().replace('- ', '', 1).strip()
                indicators_section += f'  - {yaml_value}\n'

        yaml_content += indicators_section

    # Add OSINT metadata if data was found during comparison
    # Debug logging removed for cleaner output
    if osint_data and osint_data.get("osint_compared"):
        osint_section = "\n# OSINT Comparison Metadata\n"
        osint_section += f"osint_compared: true\n"

        # Add osint_enhanced flag if enhancement was enabled
        if osint_enhanced:
            osint_section += f"osint_enhanced: true\n"

        osint_section += f"comparison_date: {osint_data.get('comparison_date', '')}\n"

        if osint_data.get("osint_sources"):
            osint_section += "osint_sources:\n"
            for source in osint_data["osint_sources"]:
                osint_section += f"  - {source}\n"

        # Add osint_indicators (always included for reference, even if not merged)
        if osint_data.get("osint_indicators"):
            import yaml as yaml_module
            osint_section += "osint_indicators:\n"
            for indicator_type, values in osint_data["osint_indicators"].items():
                if values:
                    osint_section += f"  {indicator_type}:\n"
                    for value in values:
                        # Use YAML library to properly escape the value
                        # This handles all special characters including backslashes
                        # Use width=1000000 to prevent line wrapping
                        yaml_str = yaml_module.dump([value], default_flow_style=False, width=1000000)
                        # Extract just the value part (remove the list syntax)
                        yaml_value = yaml_str.strip().replace('- ', '', 1).strip()
                        osint_section += f'    - {yaml_value}\n'

        # Add query snippets for correlation tracking
        if osint_data.get("osint_indicators", {}).get("query_snippets"):
            import yaml as yaml_module
            osint_section += "osint_query_snippets:\n"
            for snippet_entry in osint_data["osint_indicators"]["query_snippets"]:
                # Parse snippet format: "[Source] query|||url"
                if "|||" in snippet_entry:
                    snippet_parts = snippet_entry.split("|||")
                    snippet_text = snippet_parts[0]
                    snippet_url = snippet_parts[1].strip() if len(snippet_parts) > 1 else ""

                    # Extract source from "[Source]" prefix
                    source_match = re.match(r'\[([^\]]+)\]\s*(.*)', snippet_text)
                    if source_match:
                        source = source_match.group(1)
                        # Not "query": that is the detection's query, checked before writing below
                        snippet_query = source_match.group(2).strip()

                        osint_section += f"  - source: {source}\n"
                        yaml_str = yaml_module.dump([snippet_query], default_flow_style=False, width=1000000)
                        yaml_value = yaml_str.strip().replace('- ', '', 1).strip()
                        osint_section += f"    query: {yaml_value}\n"
                        if snippet_url:
                            # Ensure URL doesn't start with pipe character (which would be a YAML syntax error)
                            clean_url = snippet_url.lstrip('|')
                            osint_section += f"    url: {clean_url}\n"

        if osint_data.get("enrichment_notes"):
            notes = osint_data["enrichment_notes"].replace("\n", "\n  ")

            # Add explanation if OSINT comparison succeeded but query was not enhanced
            if not osint_enhanced:
                # Determine the reason based on available data
                has_indicators = any(
                    osint_data.get("osint_indicators", {}).get(ind_type)
                    for ind_type in ["cmd", "sw", "path", "acct", "reg", "api", "op", "evt"]
                )

                if not has_indicators:
                    notes += "; Query not enhanced: no actionable indicators extracted from OSINT sources (only query snippets available)"
                else:
                    notes += "; Query not enhanced: extracted indicators may be duplicates or incompatible with target platform"

            osint_section += f"enrichment_notes: |\n  {notes}\n"

        yaml_content += osint_section

    # LOLBAS/LOLRMM/LOLDrivers entries behind added indicators, and the false positives the
    # Elastic and Splunk rules for this technique document (LoFP-style): written whether or
    # not the OSINT comparison found rules
    if osint_data and (osint_data.get("lol_references") or osint_data.get("known_false_positives")):
        extra = {k: osint_data[k] for k in ("lol_references", "known_false_positives") if osint_data.get(k)}
        yaml_content += "\n# Living-off-the-land references and known false positives\n" + yaml_lib.safe_dump(
            extra, default_flow_style=False, sort_keys=False, width=1000000, allow_unicode=True)

    # Add Reference Query metadata if references were used
    if reference_used:
        reference_section = "\n# Reference Query Metadata\n"
        reference_section += f"reference_used: true\n"

        if reference_sources:
            reference_section += "reference_sources:\n"
            for source in reference_sources:
                reference_section += f"  - {source}\n"

        yaml_content += reference_section

    # "()" inside a string is an indicator (has "DSEnumerateDomainTrusts()"), not an empty group
    if _empty_group(query) or "( OR )" in query or "\n  | where \n  | " in query or (
        connector_id == "MicrosoftThreatProtection" and not _brackets_balanced(query)
    ):
        print(f"  ⚠️  Not written (empty condition or unbalanced brackets): {os.path.basename(query_file)}")
    else:
        # Contract gate (archer.contract): query-level lint on every legacy write.
        # Warn-only by default; ARCHER_CONTRACT_STRICT=1 refuses to write a query with findings.
        try:
            from archer.contract import gate_query
            # Linted as written, not with the YAML block indent: an indented closing
            # "}" hid every YARA-L condition section (false YL-5 on each SecOps rule)
            allowed, _ = gate_query(textwrap.dedent(query), label=os.path.basename(query_file))
        except Exception as gate_err:  # the gate must never take the pipeline down
            print(f"  [contract] gate error for {query_file}: {gate_err}")
            allowed = True
        if not allowed:
            print(f"  [contract BLOCKED] not written: {query_file}")
            return
        with open(query_file, "w") as new_yaml:
            new_yaml.write(_stamp(yaml_content) + yaml_content)
        # Only a file actually written is the run's: one refused above keeps any older
        # version on disk out of the run (and out of its correlations)
        run_files.note(query_file, tag)
        attack_mapping.reapply(query_file, attack_override, attack_mapping_history)


# ── Rewriting detections already on disk ──────────────────────────────────────
# The first line records the generator that wrote the file and a hash of its query.
# A later run rewrites a file from an older generator, unless the query no longer
# matches its hash: someone edited it by hand, so it's kept and reported instead.
# Regenerate on the results page rewrites every file the run reaches, edits included.

_STAMP = re.compile(r"^# archer-generator: (\d+) query-sha256: ([0-9a-f]{64})\s*$")


def _query_block(content: str) -> str:
    """The text of the query: block, up to the next top-level key."""
    m = re.search(r"^query: \|\n(.*?)(?=^\S|\Z)", content, re.M | re.S)
    return m.group(1).rstrip() if m else ""


def _stamp(content: str) -> str:
    digest = hashlib.sha256(_query_block(content).encode()).hexdigest()
    return f"# archer-generator: {GENERATOR_VERSION} query-sha256: {digest}\n"


def file_state(path: str) -> dict:
    """generator (None if unstamped), edited, tags and version of a detection on disk."""
    with open(path, encoding="utf-8") as fh:
        content = fh.read()
    first, _, body = content.partition("\n")
    m = _STAMP.match(first)
    tags = re.search(r"^tags:\n((?:  - .*\n?)+)", content, re.M)
    version = re.search(r"^version: (\S+)", content, re.M)
    mapping = {}
    if re.search(rf"^({attack_mapping.OVERRIDE_KEY}|{attack_mapping.HISTORY_KEY}):", content, re.M):
        try:
            mapping = yaml_lib.safe_load(body) or {}
        except yaml_lib.YAMLError:
            pass
    return {
        "generator": int(m.group(1)) if m else None,
        "edited": bool(m) and hashlib.sha256(_query_block(body).encode()).hexdigest() != m.group(2),
        "tags": [t[4:].strip() for t in tags.group(1).splitlines() if t.strip()] if tags else [],
        "version": version.group(1) if version else "1.0",
        "attack_override": mapping.get(attack_mapping.OVERRIDE_KEY),
        "attack_mapping_history": mapping.get(attack_mapping.HISTORY_KEY),
    }


def _next_version(version: str) -> str:
    parts = version.split(".")
    if len(parts) >= 2 and parts[1].isdigit():
        parts[1] = str(int(parts[1]) + 1)
        return ".".join(parts)
    return "1.1"


def detection_action(yamlfile: str, tag):
    """
    What to do with a detection this run produced: None means leave the file (it's been
    tagged for the group); a dict means write it, passing the dict to write_yaml.

    New file: write. Already written or tagged earlier in this run: tag only, so the
    first procedure's query stands. Edited by hand: keep and report, unless this run is
    a Regenerate. Written by an older generator, or a Regenerate: rewrite, keeping its
    tags and bumping its version. Otherwise: tag only.
    """
    if not os.path.exists(yamlfile):
        return {}
    if run_files.seen(yamlfile, tag):
        update_yaml(yamlfile, tag)
        return None
    try:
        state = file_state(yamlfile)
    except OSError:
        return {}
    regenerate = run_files.regenerating(tag)
    if state["edited"] and not regenerate:
        print(f"  ✋ Kept {os.path.basename(yamlfile)}: its query was edited by hand (Regenerate replaces it)")
        update_yaml(yamlfile, tag)
        run_files.kept(yamlfile, tag)
        return None
    if regenerate or state["generator"] != GENERATOR_VERSION:
        rewrite = {"tags": state["tags"], "version": _next_version(state["version"])}
        # A hand-made ATT&CK mapping survives the rewrite (archer.build.attack_mapping)
        rewrite.update({k: state[k] for k in ("attack_override", "attack_mapping_history") if state[k]})
        return rewrite
    update_yaml(yamlfile, tag)
    return None


def update_yaml(yamlfile, tag):
    run_files.note(yamlfile, tag)

    def increment_version(match):
        major = match.group(1)
        minor = int(match.group(2)) + 1  # increment minor version
        patch = match.group(3)

        return f"{major}{minor}{patch}"

    with open(yamlfile) as yfile:
        old_content = yfile.read()

    # Format the threat group tag with (Group) suffix
    formatted_tag = f"{tag} (Group)" if tag else ""

    if formatted_tag not in old_content:
        # Insert new Threat Group
        prefix, suffix = old_content.split("tags:\n  - ")
        added_tags = f"{prefix}tags:\n  - {formatted_tag}\n  - {suffix}"

        # Update version
        newver = re.sub(r"(version: \d+\.)(\d+)((\.\d+)?)", increment_version, added_tags)
        prefix = added_tags.split("version: ")[0]
        suffix = added_tags.split("kind:")[1]

        with open(yamlfile, "w") as yfile:
            yfile.write(newver)


def construct_yaml(
    name,
    tid,
    tdesc,
    tactic,
    tag,
    identifiers,
    log_sources,
    index_name,
    procedure_platforms,
    software_platforms,
    osint_enhancement_data=None,
    osint_enhancement=False,
    excluded_vendors=None,
):
    """
    Construct a YAML file for a detection

    Args:
        name: Name of the technique
        tid: Technique ID
        tdesc: Activity description
        tactic: Tactic
        tag: Group name tag
        identifiers: Dictionary of identifiers
        log_sources: List of log sources
        index_name: Optional index name to include in the filename
        osint_enhancement: Optional OSINT enrichment metadata dict
    """
    # CRITICAL: Don't create YAML files if there are no indicators
    # This prevents "Needs Review - no indicators extracted" detections from being created
    if not identifiers or len(identifiers) == 0:
        print(f" ⚠️  construct_yaml called with empty identifiers - skipping YAML creation for {name}")
        return

    # Check if identifiers contains only empty values
    has_real_indicators = False
    for indicator_type, values in identifiers.items():
        if values:  # Check if the value is not None, not empty list, not empty string
            if isinstance(values, list) and len(values) > 0:
                has_real_indicators = True
                break
            elif isinstance(values, str) and len(values.strip()) > 0:
                has_real_indicators = True
                break
            elif isinstance(values, dict) and len(values) > 0:
                has_real_indicators = True
                break

    if not has_real_indicators:
        print(f" ⚠️  construct_yaml: All indicator values are empty - skipping YAML creation for {name}")
        return

    # Debug logging removed for cleaner output

    # Extract OSINT indicators if enhancement is enabled
    osint_indicators_to_pass = None
    if osint_enhancement and osint_enhancement_data:
        osint_indicators_to_pass = osint_enhancement_data.get("osint_indicators", {})

    # Check for reference queries from bespoke/llm_references directory
    reference_used = False
    reference_sources = []
    try:
        from archer.build.references import get_loader
        loader = get_loader()

        # Check for MDE references
        mde_refs = loader.get_queries_by_technique(tid, vendor="MDE")
        if mde_refs:
            reference_used = True
            for ref in mde_refs:
                source_name = ref.get("name", "MDE Reference")
                if source_name not in reference_sources:
                    reference_sources.append(f"MDE: {source_name}")

        # Check for Splunk references
        splunk_refs = loader.get_queries_by_technique(tid, vendor="Splunk")
        if splunk_refs:
            reference_used = True
            for ref in splunk_refs:
                source_name = ref.get("name", "Splunk Reference")
                if source_name not in reference_sources:
                    reference_sources.append(f"Splunk: {source_name}")

        if reference_used:
            print(f" 📚 Reference queries found for {tid}: {len(reference_sources)} source(s)")
    except ImportError:
        pass  # References module not available
    except Exception as e:
        print(f" ⚠️  Error checking reference queries: {e}")

    appended_mde_queries, appended_splunk_queries = collate_data(
        identifiers, log_sources, procedure_platforms, software_platforms, name, technique_id=tid, osint_indicators=osint_indicators_to_pass
    )
    appended_splunk_queries = []  # Splunk disabled -- Stage 1 soft-disable, see docs/SIEM_ONBOARDING.md

    # Apply OSINT enhancement if requested (merge OSINT patterns into queries)
    # Track which queries were actually enhanced (not just attempted)
    mde_queries_enhanced = {}  # Map query -> was_enhanced bool
    splunk_queries_enhanced = {}  # Map query -> was_enhanced bool

    if osint_enhancement and osint_enhancement_data and osint_enhancement_data.get("osint_indicators"):
        from archer.build.osint_query_enhancer import enhance_query_with_osint

        osint_indicators = osint_enhancement_data.get("osint_indicators", {})

        # Enhance MDE queries and track which ones were actually modified
        enhanced_mde_queries = []
        for query in appended_mde_queries:
            enhanced_query, was_enhanced = enhance_query_with_osint(query, osint_indicators, target_vendor="MDE")
            enhanced_mde_queries.append(enhanced_query)
            mde_queries_enhanced[enhanced_query] = was_enhanced
        appended_mde_queries = enhanced_mde_queries

        # Enhance Splunk queries
        # NOTE: OSINT enhancement is now handled directly in compile_splunk_queries() function
        # to ensure proper query structure with transformation pipelines and | search clause
        # So we skip the post-processing enhancement here for Splunk queries
        # enhanced_splunk_queries = []
        # for query in appended_splunk_queries:
        #     enhanced_query, was_enhanced = enhance_query_with_osint(query, osint_indicators, target_vendor="Splunk")
        #     enhanced_splunk_queries.append(enhanced_query)
        #     splunk_queries_enhanced[enhanced_query] = was_enhanced
        # appended_splunk_queries = enhanced_splunk_queries

        # Count how many queries were actually enhanced
        mde_enhanced_count = sum(1 for enhanced in mde_queries_enhanced.values() if enhanced)
        print(f"  🔧 OSINT Enhancement: Successfully enhanced {mde_enhanced_count}/{len(appended_mde_queries)} MDE queries with datatables")

    # Apply RAG enhancement if enabled
    # RAG uses community detection examples to improve query quality
    try:
        from .rag_enhancer import is_rag_enabled, enhance_query_with_rag

        if is_rag_enabled():
            rag_enhanced_count = 0

            # Enhance MDE queries with RAG
            rag_enhanced_mde_queries = []
            for query in appended_mde_queries:
                enhanced_query, metadata = enhance_query_with_rag(
                    original_query=query,
                    technique_id=tid,
                    platform="MicrosoftThreatProtection",
                    technique_name=name
                )
                rag_enhanced_mde_queries.append(enhanced_query)
                if metadata.get('enhanced'):
                    rag_enhanced_count += 1
            appended_mde_queries = rag_enhanced_mde_queries

            # Enhance Splunk queries with RAG
            rag_enhanced_splunk_queries = []
            for query in appended_splunk_queries:
                enhanced_query, metadata = enhance_query_with_rag(
                    original_query=query,
                    technique_id=tid,
                    platform="Splunk",
                    technique_name=name
                )
                rag_enhanced_splunk_queries.append(enhanced_query)
                if metadata.get('enhanced'):
                    rag_enhanced_count += 1
            appended_splunk_queries = rag_enhanced_splunk_queries

            if rag_enhanced_count > 0:
                print(f"  🎯 RAG Enhancement: Enhanced {rag_enhanced_count} queries with community examples")
    except ImportError:
        pass  # RAG module not available
    except Exception as e:
        print(f"  ⚠️  RAG enhancement skipped: {e}")

    # Apply bespoke exclusions if configured
    # Bespoke exclusions are organization-specific filters (processes, users, hosts, IPs)
    try:
        from .bespoke import is_bespoke_enabled, apply_exclusions

        if is_bespoke_enabled():
            bespoke_count = 0

            # Apply exclusions to MDE queries
            bespoke_mde_queries = []
            for query in appended_mde_queries:
                enhanced_query = apply_exclusions(query, "MDE")
                bespoke_mde_queries.append(enhanced_query)
                if enhanced_query != query:
                    bespoke_count += 1
            appended_mde_queries = bespoke_mde_queries

            # Apply exclusions to Splunk queries
            bespoke_splunk_queries = []
            for query in appended_splunk_queries:
                enhanced_query = apply_exclusions(query, "Splunk")
                bespoke_splunk_queries.append(enhanced_query)
                if enhanced_query != query:
                    bespoke_count += 1
            appended_splunk_queries = bespoke_splunk_queries

            if bespoke_count > 0:
                print(f"  🏢 Bespoke: Applied org-specific exclusions to {bespoke_count} queries")
    except ImportError:
        pass  # Bespoke module not available
    except Exception as e:
        print(f"  ⚠️  Bespoke exclusions skipped: {e}")

    all_tactics = additional_tactics(tid, tactic)
    # Filename-safe name for every vendor's file; YAML metadata keeps the original.
    # Set before the MDE loop: techniques with no MDE query still write Splunk/SecOps files.
    name_safe = name.replace(" ", "").replace("/", "")

    # Writing MDE YAML file
    for query in appended_mde_queries:
        # Skip if MDE is excluded
        if excluded_vendors and "mde" in excluded_vendors:
            continue
        # Extract the table name from the query, skipping comment lines and let statements
        lines = query.split("\n")
        table_name = None
        for line in lines:
            stripped = line.strip()
            # Skip empty lines, comments, and let statements
            if stripped and not stripped.startswith("//") and not stripped.startswith("let "):
                table_name = stripped
                break

        # Fallback if no table name found
        if not table_name:
            table_name = "UnknownTable"

        # Extract query and entity mappings separately
        query_only, entity_mappings_str = map_entities(query)

        # Format MDE query: strip excluded fields, remove duplicates, add line breaks
        query_only = format_mde_query(query_only)
        if not query_only.strip():
            print(f"  ⚠️  {name} ({table_name}): every condition was on an excluded field; not written")
            continue
        # Conditions that parse but can't mean anything (archer.validation.precision)
        from archer.validation.precision import prune_kql

        pruned, dropped = prune_kql(query_only)
        for f in dropped:
            print(f"  ✂️  {name} ({table_name}): {f['check']}: {f['message']}")
        if pruned is None:
            print(f"  ⚠️  {name} ({table_name}): no condition left that can fire for the right reason; not written")
            continue
        query_only = pruned

        """if len(query_with_entities) > 10:
            print(
                f"  {name} ({table_name}) breaches the MDE entityMapping limit of 10.\n   Please review before commiting to production.\n"
            )
            time.sleep(0.5)"""
        # Use the actual MDE table name from the query for the filename
        # NOT the index_name parameter which might be a Splunk index
        filename = f"{name_safe}_{table_name}.yaml"
        yamlfile = os.path.join(GENERATE_DIR, filename)
        rewrite = detection_action(yamlfile, tag)
        if rewrite is not None:
            # Check if THIS specific query was enhanced (not just if enhancement was attempted)
            query_was_enhanced = mde_queries_enhanced.get(query, False)

            write_yaml(
                yamlfile,
                name,  # Pass original name with spaces/slashes preserved
                tid,
                tdesc,
                "MicrosoftThreatProtection",
                all_tactics,
                tag,
                query_only,  # Pass query WITHOUT entity mappings
                indicators=identifiers,  # Pass indicators for YAML metadata
                osint_data=osint_enhancement_data,  # Pass OSINT data dict
                osint_enhanced=query_was_enhanced,    # Pass TRUE only if this query was actually enhanced
                entity_mappings=entity_mappings_str,  # Pass entity mappings separately
                reference_used=reference_used,  # Pass reference query flag
                reference_sources=reference_sources,  # Pass reference sources
                **rewrite,
            )

    # Writing Splunk YAML file
    for query in appended_splunk_queries:
        # Skip if Splunk is excluded
        if excluded_vendors and "splunk" in excluded_vendors:
            continue
        index = query.split("\n")[0].split(" earliest=")[0].replace("index=", "").replace(" ", "")
        query = query.replace(" earliest=-1d\n", " earliest=-1d\n  ")
        # Use filename-safe version for Splunk filenames too
        yamlfile = os.path.join(GENERATE_DIR, f"{name_safe}_{index}.yaml")
        rewrite = detection_action(yamlfile, tag)
        if rewrite is not None:
            write_yaml(
                yamlfile,
                name,
                tid,
                tdesc,
                "Splunk",
                all_tactics,
                tag,
                query,
                indicators=identifiers,  # Pass indicators for YAML metadata
                osint_data=osint_enhancement_data,  # Pass OSINT data dict
                osint_enhanced=osint_enhancement,    # Pass enhancement flag
                reference_used=reference_used,  # Pass reference query flag
                reference_sources=reference_sources,  # Pass reference sources
                **rewrite,
            )

    # Writing Google SecOps YAML file (if Google SecOps support is enabled)
    # Google SecOps: a UDM search from the indicators (archer.build.secops, archer.build.udm)
    # Skip if Google SecOps is excluded
    if not excluded_vendors or "googlesecops" not in excluded_vendors:
      try:
        from archer.build.secops import SecOpsGenerator

        googlesecops_gen = SecOpsGenerator()
        googlesecops_rule = googlesecops_gen.generate_query(
            technique_id=tid,
            technique_name=name,
            tactic=tactic,
            tactics=all_tactics,
            description=tdesc,
            indicators=identifiers,
            osint_data=osint_enhancement_data,
            group_name=tag
        )

        if googlesecops_rule and googlesecops_rule.get("query"):
            # Create Google SecOps YAML file
            yamlfile = os.path.join(GENERATE_DIR, f"{name_safe}_{LANGUAGE_SUFFIX['GoogleSecOps']}.yaml")
            rewrite = detection_action(yamlfile, tag)
            if rewrite is not None:
                # Get event type from the rule (e.g., PROCESS_LAUNCH)
                event_types = googlesecops_rule.get("event_types", ["PROCESS_LAUNCH"])
                datatype_str = event_types[0] if event_types else "PROCESS_LAUNCH"

                write_yaml(
                    yamlfile,
                    name,
                    tid,
                    tdesc,
                    "GoogleSecOps",
                    all_tactics,
                    tag,
                    googlesecops_rule["query"],
                    datatype=datatype_str,
                    indicators=identifiers,
                    osint_data=osint_enhancement_data,
                    osint_enhanced=osint_enhancement,
                    reference_used=reference_used,
                    reference_sources=reference_sources,
                    **rewrite,
                )
                print(f"  ✅ Generated Google SecOps UDM search: {googlesecops_rule['rule_name']}")
      except Exception as e:
        # Google SecOps generation is optional - don't fail if it errors
        print(f"  ⚠️  Google SecOps generation failed for {name}: {e}")

    # Writing Elastic YAML file (ES|QL detection over ECS fields) — see archer.build.elastic
    if not excluded_vendors or "elastic" not in excluded_vendors:
      try:
        from archer.build.elastic import ElasticQueryGenerator

        elastic_gen = ElasticQueryGenerator()
        elastic_query_result = elastic_gen.generate_query(
            technique_id=tid,
            technique_name=name,
            tactic=tactic,
            description=tdesc,
            indicators=identifiers,
            osint_data=osint_enhancement_data,
            group_name=tag
        )

        if elastic_query_result and elastic_query_result.get("query"):
            is_valid, error = elastic_gen.validate_query(elastic_query_result["query"])

            if is_valid:
                # Create Elastic YAML file
                yamlfile = os.path.join(GENERATE_DIR, f"{name_safe}_{LANGUAGE_SUFFIX['Elastic']}.yaml")
                rewrite = detection_action(yamlfile, tag)
                if rewrite is not None:
                    write_yaml(
                        yamlfile,
                        name,
                        tid,
                        tdesc,
                        "Elastic",
                        all_tactics,
                        tag,
                        elastic_query_result["query"],
                        datatype=elastic_query_result.get("index_pattern", "logs-endpoint.events.*"),
                        indicators=identifiers,
                        osint_data=osint_enhancement_data,
                        osint_enhanced=osint_enhancement,
                        reference_used=reference_used,
                        reference_sources=reference_sources,
                        **rewrite,
                    )
                    print(f"  ✅ Generated Elastic ES|QL detection: {elastic_query_result['query_name']}")
            else:
                print(f"  ⚠️  Elastic query validation failed for {name}: {error}")
      except Exception as e:
        # Elastic generation is optional - don't fail if it errors
        print(f"  ⚠️  Elastic generation failed for {name}: {e}")
