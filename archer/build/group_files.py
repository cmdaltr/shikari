"""
Which detection YAMLs belong to a group.

Technique detections are written once per technique and shared between groups
(At_GoogleSecOps.yaml serves FIN7 and anyone else using T1053.002), so a group's
detections are found by its "<group> (Group)" tag, not by filename.
"""

import glob
import os
from typing import List

from archer.security import sanitize_group_name


def group_yaml_files(group_name: str, generate_dir: str) -> List[str]:
    if not os.path.isdir(generate_dir):
        return []
    safe_group = sanitize_group_name(group_name)
    # Files named for the group (IOC sweeps, bespoke runs)
    files = glob.glob(os.path.join(generate_dir, f"{safe_group}_*.yaml"))
    if files:
        return files
    # CVE runs write technique-named files (T1190_*.yaml)
    pattern = "T*_*.yaml" if safe_group.upper().startswith("CVE") else "*.yaml"
    candidates = glob.glob(os.path.join(generate_dir, pattern))
    tagged = []
    for path in candidates:
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
        except OSError:
            continue
        if f"{group_name} (Group)" in content or f"{safe_group} (Group)" in content:
            tagged.append(path)
    return tagged or candidates
