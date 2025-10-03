import json
import csv
import os
import numpy as np
import pandas as pd
from typing import List, Tuple, Sequence


def load_probability_matrix(path: str) -> Tuple[List[str], np.ndarray]:
    """
    Load a probability matrix from JSON or CSV.
    JSON shape: {"labels": [...], "matrix": [[...], ...]}
    CSV shape: header row are labels; rows are label, then probabilities.
    """
    _, ext = os.path.splitext(path.lower())
    if ext == ".json":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        labels = data["labels"]
        mat = np.array(data["matrix"], dtype=float)
    elif ext == ".csv":
        with open(path, newline="", encoding="utf-8") as f:
            rdr = csv.reader(f)
            rows = list(rdr)
        header = rows[0][1:]
        labels = header
        values = []
        for r in rows[1:]:
            values.append([float(x) for x in r[1:]])
        mat = np.array(values, dtype=float)
    else:
        raise ValueError(f"Unsupported matrix format: {ext}")

    # Verify rows sum to 1
    row_sums = mat.sum(axis=1)
    assert np.allclose(row_sums, 1.0), "Rows must sum to 1"
    return labels, mat


def sample_next(current_label: str, labels: Sequence[str], mat: np.ndarray) -> str:
    i = labels.index(current_label)
    probs = mat[i]
    j = np.random.choice(len(labels), p=probs)
    return labels[j]


def get_probability(
    labels: Sequence[str], mat: np.ndarray, from_label: str, to_label: str
) -> float:
    return float(mat[labels.index(from_label), labels.index(to_label)])


def max_follow_likelihood(
    from_labels: Sequence[str],
    to_labels: Sequence[str],
    labels: Sequence[str],
    mat: np.ndarray,
) -> float:
    """
    Max P(next in to_labels | current in from_labels)
    Returns a positive uniform fallback (1/len(to_labels)) when no label matches exist.
    Returns 0.0 only if inputs are empty.
    """
    if not from_labels or not to_labels:
        return 0.0
    label_set = set(labels)
    fl = [f for f in from_labels if f in label_set]
    tl = [t for t in to_labels if t in label_set]
    # If nothing matches the matrix, fall back to uniform over target set
    if not fl or not tl:
        return 1.0 / max(len(to_labels), 1)

    best = 0.0
    for f in fl:
        for t in tl:
            p = mat[labels.index(f), labels.index(t)]
            if p > best:
                best = float(p)

    # If matrix probabilities are zero for this transition, use the uniform fallback
    if best == 0.0:
        return 1.0 / max(len(tl), 1)
    return best


if __name__ == "__main__":
    # Example usage with a tactic-probability matrix
    # Place a file like tactic_probability.json or tactic_probability.csv alongside this script.
    matrix_path = os.environ.get(
        "MATRIX_PATH",
        os.path.join(os.path.dirname(__file__), "tactic_probability.json"),
    )
    labels, mat = load_probability_matrix(matrix_path)
    print("Next after 'initial-access':", sample_next("initial-access", labels, mat))
    print(
        "P(execution | initial-access):",
        get_probability(labels, mat, "initial-access", "execution"),
    )
