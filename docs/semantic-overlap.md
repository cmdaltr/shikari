# Semantic overlap for combined KQL queries

What it is
- A quick heuristic that estimates how similar two KQL queries are, expressed as a percentage (0–100).
- Not a count of matching fields. It reflects shared meaningful tokens after removing common KQL noise.

How it’s computed (heuristic)
1) Tokenize each query into lowercase alphanumeric tokens with length ≥ 3.
2) Remove common KQL operators and very common columns (e.g., where, summarize, project, DeviceName, Timestamp, ActionType, etc.).
3) Compute Jaccard similarity = 100 * |intersection(tokens)| / |union(tokens)|, rounded to an integer and clamped to [0, 100].

What typically counts toward overlap
- Uncommon columns and tables (e.g., DeviceFileEvents, DeviceProcessEvents when distinctive), specific function/verb names, and distinctive literals/strings (e.g., “Evilginx2”, “gcloud”, “NTDS.dit”).
- Specific filter terms in command lines or URLs.

What’s ignored or downweighted
- Common KQL keywords and operators (where, summarize, join, project, etc.).
- Very common schema/columns across detections (DeviceName, DeviceId, Timestamp, ActionType, AccountName, etc.).
- This prevents inflating overlap just because both queries project typical fields.

Displayed headers
- In heuristic mode for MDE/Sentinel/KQL, combined queries include:
  // {QueryAName} followed by {QueryBName}; {X}% semantic overlap.
- In non-heuristic mode, if a deeper semantic analyzer is available, its score is preferred; otherwise the heuristic is used. An extra line may appear:
  // Semantic: {X}% overlap via {strategy}

Scope
- Applied to KQL-family vendors: mde, microsoft, sentinel, kql.
- Splunk output is unaffected by this heuristic.

Interpreting the percentage (rough guide)
- 0–10%: Essentially unrelated
- 10–30%: Low overlap
- 30–60%: Moderate overlap
- 60%+: High overlap (likely similar concepts or shared indicators)

Why it’s not “matching fields”
- The heuristic doesn’t count identical columns. It focuses on distinctive tokens so that common columns don’t dominate the score.
- Two queries with the same projection list can still be low-overlap if their core filters and distinctive terms differ.

Limitations
- Token-based and schema-agnostic: no AST or operator semantics considered.
- Rare tokens can disproportionately affect the score.
- Use as a hint for conceptual proximity, not a measure of result-set equivalence or performance.

FAQ
- “Is it the number of fields that match?” No. It’s a Jaccard-like similarity over meaningful tokens after stripping common KQL noise.
- “Why do some pairs show high overlap?” They likely share distinctive strings (e.g., same tool names) and uncommon columns/tables.
