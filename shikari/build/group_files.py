"""
Which detection YAMLs belong to a group.

Technique detections are written once per technique and shared between groups
(At_UDM.yaml serves FIN7 and anyone else using T1053.002), so a group's
detections are found by its "<group> (Group)" tag, not by filename.
"""

import glob
import os
import re
from typing import Dict, List, Set

from shikari.security import sanitize_group_name


def group_yaml_files(group_name: str, generate_dir: str) -> List[str]:
    """
    The group's detections: tagged "<group> (Group)" (or listed under threat_groups in a
    bespoke file), plus files named for the group such as its IOC sweeps.

    Nothing else. This used to fall back to every YAML (every "T*" file for a CVE) when no
    file was tagged, so a CVE run that generated nothing showed unrelated detections.
    """
    if not os.path.isdir(generate_dir):
        return []
    safe_group = sanitize_group_name(group_name)
    # A run is saved under its sanitised name (Scattered_Spider) but its detections are tagged with
    # the group's own (Scattered Spider), so the spaced form is looked for too
    spaced = safe_group.replace("_", " ")
    tags = {f"{group_name} (Group)", f"{safe_group} (Group)", f"{spaced} (Group)"}
    bespoke = re.compile(rf"^threat_groups:\n(?:- .*\n)*?- {re.escape(group_name)}$", re.M)
    named = {os.path.basename(p) for p in glob.glob(os.path.join(generate_dir, f"{safe_group}_*.yaml"))}
    compact = re.sub(r'[^A-Za-z0-9]+', '', group_name)
    for prefix in ("IOCSweep", "Exploit"):  # ioc_sweep, exploit_detection
        named |= {os.path.basename(p) for p in glob.glob(os.path.join(generate_dir, f"{prefix}{compact}_*.yaml"))}
    files = []
    for path in sorted(glob.glob(os.path.join(generate_dir, "*.yaml"))):
        if os.path.basename(path) in named:
            files.append(path)
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
        except OSError:
            continue
        if any(t in content for t in tags) or bespoke.search(content):
            files.append(path)
    return files


def prune(group_name: str, produced: Set[str], generate_dir: str) -> Dict[str, List[str]]:
    """
    Drop the group from detections its run didn't produce, so they don't reach its results,
    downloads or correlations: a technique no longer attributed, a table a query no longer
    uses, a query refused by a check. The group's tag comes off; a file no group is left
    tagged on is removed. A file edited by hand is never touched, nor bespoke or IOC files
    that belong to the group by name or threat_groups rather than by tag.

    Returns {"untagged", "removed", "kept_edited"} (file names).
    """
    from shikari.build.yaml import file_state

    report = {"untagged": [], "removed": [], "kept_edited": []}
    tags = {f"{group_name} (Group)", f"{sanitize_group_name(group_name)} (Group)"}
    for path in sorted(glob.glob(os.path.join(generate_dir, "*.yaml"))):
        name = os.path.basename(path)
        if name in produced:
            continue
        try:
            state = file_state(path)
        except OSError:
            continue
        if not tags & set(state["tags"]):
            continue
        if state["edited"]:
            report["kept_edited"].append(name)
            continue
        if not set(state["tags"]) - tags:
            os.remove(path)
            report["removed"].append(name)
            continue
        with open(path, encoding="utf-8") as fh:
            content = fh.read()
        content = re.sub(rf"^  - (?:{'|'.join(re.escape(t) for t in tags)})\n", "", content, flags=re.M)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.replace(tmp, path)
        report["untagged"].append(name)
    return report
