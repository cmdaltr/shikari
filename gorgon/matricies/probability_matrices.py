import json
import csv
import os
import math
from urllib.request import urlopen

ATTACK_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

# Canonical ATT&CK Enterprise tactic order (shortnames)
TACTIC_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

OUT_DIR = os.path.dirname(__file__)


def save_json_csv(labels, matrix, base_name: str):
    payload = {"labels": labels, "matrix": matrix}
    with open(os.path.join(OUT_DIR, f"{base_name}.json"), "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    with open(
        os.path.join(OUT_DIR, f"{base_name}.csv"), "w", newline="", encoding="utf-8"
    ) as f:
        w = csv.writer(f)
        w.writerow(["label"] + labels)
        for i, row in enumerate(matrix):
            w.writerow([labels[i]] + [f"{v:.6f}" for v in row])


def build_tactic_probability(labels):
    """
    Forward-biased Markov matrix over tactics following the canonical order.
    Heuristic: higher prob to move forward; small mass to stay; tiny mass to jump back.
    Rows sum to 1.
    """
    n = len(labels)
    mat = []
    for i in range(n):
        weights = [0.0] * n
        # Stay
        weights[i] += 0.10
        # Forward steps: geometric decay by distance
        for j in range(i, n):
            dist = j - i
            weights[j] += 1.0 / (2.0 + dist)
        # Small back jump
        if i > 0:
            weights[i - 1] += 0.05
        s = sum(weights)
        row = [w / s for w in weights]
        mat.append(row)
    return mat


def download_attack_stix() -> dict:
    with urlopen(ATTACK_STIX_URL) as resp:
        return json.load(resp)


def extract_techniques(bundle: dict):
    """
    Returns list of (technique_id, primary_tactic_shortname).
    """
    techniques = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        # technique id
        tid = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref.get(
                "external_id", ""
            ).startswith("T"):
                tid = ref["external_id"]
                break
        if not tid:
            continue
        # primary tactic (first kill_chain phase shortname)
        kc = obj.get("kill_chain_phases", []) or []
        tac = None
        for k in kc:
            if k.get("kill_chain_name") == "mitre-attack":
                tac = k.get("phase_name")
                break
        if tac:
            techniques.append((tid, tac))
    return techniques


def build_technique_probability(techniques, tactic_labels, tactic_mat):
    """
    Lift tactic transition probabilities to techniques by tactic mapping:
    P(tech_j | tech_i) = P(tactic(tech_j) | tactic(tech_i))
    """
    tech_ids = [t[0] for t in techniques]
    tech_to_tactic = {t: tac for t, tac in techniques}
    tact_idx = {t: i for i, t in enumerate(tactic_labels)}
    n = len(tech_ids)
    mat = []
    for i in range(n):
        row = [0.0] * n
        tac_i = tech_to_tactic.get(tech_ids[i])
        if tac_i not in tact_idx:
            # uniform if missing
            row = [1.0 / n] * n
        else:
            ti = tact_idx[tac_i]
            for j in range(n):
                tac_j = tech_to_tactic.get(tech_ids[j])
                if tac_j not in tact_idx:
                    row[j] = 0.0
                else:
                    tj = tact_idx[tac_j]
                    row[j] = float(tactic_mat[ti][tj])
            # normalize in case of zeros
            s = sum(row)
            row = [x / s if s > 0 else 1.0 / n for x in row]
        mat.append(row)
    return tech_ids, mat


def main():
    # Tactic matrix
    tactic_labels = TACTIC_ORDER[:]
    tactic_mat = build_tactic_probability(tactic_labels)
    save_json_csv(tactic_labels, tactic_mat, "tactic_probability")

    # Technique matrix (derived from tactic matrix)
    bundle = download_attack_stix()
    techniques = extract_techniques(bundle)
    tech_labels, tech_mat = build_technique_probability(
        techniques, tactic_labels, tactic_mat
    )
    save_json_csv(tech_labels, tech_mat, "technique_probability")

    print(f"Wrote: {os.path.join(OUT_DIR, 'tactic_probability.{json,csv}')}")
    print(f"Wrote: {os.path.join(OUT_DIR, 'technique_probability.{json,csv}')}")


if __name__ == "__main__":
    main()
