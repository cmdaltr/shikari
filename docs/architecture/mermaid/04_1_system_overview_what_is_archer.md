# 1. System Overview — What Is Archer?

High-level overview of Archer. Shows the three columns: what you give Archer (threat actor, CVE, blog, techniques), what Archer does (looks up behaviours, builds queries, links into chains, enriches), and what you get back (Splunk/MDE/SecOps/Elastic queries, attack chains, coverage reports).

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'lineColor': '#ff6600', 'edgeLabelBackground': '#ffffff', 'primaryColor': '#4a90d9', 'primaryTextColor': '#ffffff', 'primaryBorderColor': '#2c5f8a', 'secondaryColor': '#e8e8e8', 'tertiaryColor': '#f5f5f5', 'clusterBkg': '#f0f0f0', 'clusterBorder': '#999999', 'titleColor': '#000000', 'nodeTextColor': '#000000', 'background': '#ffffff'}}}%%
graph TB
    subgraph "What You Give Archer"
        A["Threat Actor Name<br/><i>e.g. Scattered Spider</i>"]
        B["CVE Number<br/><i>e.g. CVE-2024-1234</i>"]
        C["Threat Blog / Report"]
        D["Specific ATT&CK Techniques<br/><i>e.g. T1059.004</i>"]
    end

    subgraph "What Archer Does"
        E["Looks up real attack behaviours<br/>from MITRE ATT&CK"]
        F["Builds detection queries<br/>for each behaviour"]
        G["Links related detections<br/>into attack chains"]
        H["Optionally tests, enriches<br/>& exports results"]
    end

    subgraph "What You Get Back"
        I["Splunk Searches<br/><i>SPL</i>"]
        J["Microsoft Defender Queries<br/><i>KQL</i>"]
        K["Google SecOps Rules<br/><i>YARAL</i>"]
        L["Elastic Queries<br/><i>EQL</i>"]
        M["Correlated Attack Chains"]
        N["Coverage Reports & Exports"]
    end

    A --> E
    B --> E
    C --> E
    D --> E
    E --> F
    F --> G
    G --> H
    H --> I
    H --> J
    H --> K
    H --> L
    H --> M
    H --> N

    style A fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style B fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style C fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style D fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style E fill:#f5a623,stroke:#c17d10,color:#fff
    style F fill:#f5a623,stroke:#c17d10,color:#fff
    style G fill:#f5a623,stroke:#c17d10,color:#fff
    style H fill:#f5a623,stroke:#c17d10,color:#fff
    style I fill:#7ed321,stroke:#4a8c0f,color:#fff
    style J fill:#7ed321,stroke:#4a8c0f,color:#fff
    style K fill:#7ed321,stroke:#4a8c0f,color:#fff
    style L fill:#7ed321,stroke:#4a8c0f,color:#fff
    style M fill:#7ed321,stroke:#4a8c0f,color:#fff
    style N fill:#7ed321,stroke:#4a8c0f,color:#fff
    linkStyle default stroke:#ff6600,stroke-width:3px
```
