# Part B — Correlation & Enrichment

Part B of the master diagram. Shows how completed detection files are correlated into attack chains (via heuristic, semantic, or AI modes), scored for relevance (0-100), and optionally enriched through OSINT cross-referencing, Docker-based validation, and Atomic Red Team emulation.

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'lineColor': '#ff6600', 'edgeLabelBackground': '#ffffff', 'primaryColor': '#4a90d9', 'primaryTextColor': '#ffffff', 'primaryBorderColor': '#2c5f8a', 'secondaryColor': '#e8e8e8', 'tertiaryColor': '#f5f5f5', 'clusterBkg': '#f0f0f0', 'clusterBorder': '#999999', 'titleColor': '#000000', 'nodeTextColor': '#000000', 'background': '#ffffff'}}}%%
flowchart TD
    FROM_A((" ")) ==>|"From Part A"| YAMLS_IN["Completed detection files"]

    subgraph CORR ["CORRELATION — Link detections into attack chains"]
        direction TB
        MODE{"Choose mode"}
        MODE --> HEUR["Heuristic"]
        MODE --> SEM["Semantic"]
        MODE --> AIGEN["AI Generator"]

        subgraph SCORE ["Score each pair (0–100)"]
            direction LR
            S1["Group match 30"]
            S2["Sequence 20"]
            S3["Data avail 20"]
            S4["Severity 15"]
            S5["Specificity 15"]
        end

        HEUR & SEM & AIGEN --> SCORE
        SCORE --> GATE{"≥ 70?"}
        GATE -- "Yes" --> CHAIN["Attack chain query"]
        GATE -- "No" --> DROP["Discard"]
    end

    subgraph ENRICH ["ENRICHMENT — All optional"]
        direction LR
        OSINT["OSINT<br/>Cross-reference with<br/>public detection repos"]
        VALID["Validation<br/>Test in Docker SIEM<br/>→ Measure accuracy<br/>→ AI refines query"]
        EMUL["Emulation<br/>Atomic Red Team<br/>simulates attack"]
    end

    subgraph EXT ["EXTERNAL SYSTEMS"]
        direction LR
        LLM["LLM Providers<br/>Claude · GPT-4o · Local"]
        NVD_GH["NVD · GitHub"]
        ART["Atomic Red Team"]
        VECTR_E["VECTR"]
    end

    YAMLS_IN --> MODE
    CHAIN --> OSINT & VALID & EMUL

    LLM -.-> AIGEN
    ART -.-> EMUL
    VECTR_E -.-> ENRICH

    OSINT & VALID & EMUL ==>|"To Part C"| CONTINUE2((" "))

    style FROM_A fill:#f5a623,stroke:#c17d10,color:#fff
    style CORR fill:#fde8d4,stroke:#e8752a
    style ENRICH fill:#f0d4f8,stroke:#bd10e0
    style EXT fill:#f5f5f5,stroke:#999
    style MODE fill:#f8e71c,stroke:#b8a700,color:#333
    style GATE fill:#f8e71c,stroke:#b8a700,color:#333
    style CHAIN fill:#7ed321,stroke:#4a8c0f,color:#fff
    style LLM fill:#bd10e0,stroke:#8a0ba5,color:#fff
    style CONTINUE2 fill:#7ed321,stroke:#4a8c0f,color:#fff
    linkStyle default stroke:#ff6600,stroke-width:3px
```
