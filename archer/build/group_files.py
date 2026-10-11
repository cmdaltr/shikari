"""
Which detection YAMLs belong to a group.

Technique detections are written once per technique and shared between groups
(At_GoogleSecOps.yaml serves FIN7 and anyone else using T1053.002), so a group's
detections are found by its "<group> (Group)" tag, not by filename.
"""

import glob
import os
import re
from typing import List

from archer.security import sanitize_group_name


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
    tags = {f"{group_name} (Group)", f"{safe_group} (Group)"}
    bespoke = re.compile(rf"^threat_groups:\n(?:- .*\n)*?- {re.escape(group_name)}$", re.M)
    named = {os.path.basename(p) for p in glob.glob(os.path.join(generate_dir, f"{safe_group}_*.yaml"))}
    named |= {os.path.basename(p) for p in glob.glob(os.path.join(generate_dir, f"IOCSweep{re.sub(r'[^A-Za-z0-9]+', '', group_name)}_*.yaml"))}
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
