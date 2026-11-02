# 5. Data Flow — What Goes Where

Traces data movement through the system: external sources (MITRE, NVD, GitHub, public repos, recorded attacks) → Shikari processing (ingest, build, correlate, enrich) → local storage (YAMLs, JSON, caches) → outputs (results page, Excel, attack flow, JSON API).

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'lineColor': '#ff6600', 'edgeLabelBackground': '#ffffff', 'primaryColor': '#4a90d9', 'primaryTextColor': '#ffffff', 'primaryBorderColor': '#2c5f8a', 'secondaryColor': '#e8e8e8', 'tertiaryColor': '#f5f5f5', 'clusterBkg': '#f0f0f0', 'clusterBorder': '#999999', 'titleColor': '#000000', 'nodeTextColor': '#000000', 'background': '#ffffff'}}}%%
flowchart TD
    subgraph SOURCES ["External Sources"]
        STIX["MITRE ATT&CK"]
        NVD_S["NVD"]
        GH_S["GitHub PoCs"]
        OSINT_S["Public Detection Repos"]
        TEL_S["Recorded attacks<br/>+ GUIDE"]
    end

    subgraph PROCESS ["Shikari Processing"]
        INGEST["Ingest & Normalise"]
        BUILD["Build Detections"]
        CORRELATE_P["Correlate & Score"]
        ENRICH_P["Enrich & Validate"]
    end

    subgraph STORE ["Local Storage"]
        YAMLS_S["Detection YAMLs"]
        CORR_S["Correlation JSON"]
        CACHE_S["Caches"]
    end

    subgraph OUT ["Outputs"]
        BROWSER["Results Page"]
        XLSX_O["Excel Export"]
        FLOW_O["Attack Flow (STIX)"]
        JSON_O["JSON API"]
    end

    STIX -->|"At startup"| INGEST
    NVD_S -->|"On demand"| INGEST
    GH_S -->|"On demand"| INGEST

    INGEST --> BUILD
    BUILD --> YAMLS_S
    BUILD --> CORRELATE_P
    CORRELATE_P --> CORR_S
    CORRELATE_P --> ENRICH_P

    OSINT_S -->|"Cross-reference"| ENRICH_P
    TEL_S -->|"Emulate"| ENRICH_P

    ENRICH_P --> BROWSER
    ENRICH_P --> XLSX_O
    ENRICH_P --> FLOW_O
    ENRICH_P --> JSON_O

    YAMLS_S -.->|"Read back"| BROWSER
    CORR_S -.->|"Read back"| BROWSER
    CACHE_S -.->|"Speeds up repeats"| INGEST

    style STIX fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style NVD_S fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style GH_S fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style OSINT_S fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style TEL_S fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style BROWSER fill:#7ed321,stroke:#4a8c0f,color:#fff
    style XLSX_O fill:#7ed321,stroke:#4a8c0f,color:#fff
    style FLOW_O fill:#7ed321,stroke:#4a8c0f,color:#fff
    style JSON_O fill:#7ed321,stroke:#4a8c0f,color:#fff
    linkStyle default stroke:#ff6600,stroke-width:3px
```
