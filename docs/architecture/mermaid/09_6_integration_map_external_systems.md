# 6. Integration Map — External Systems

Shows the external systems Archer uses: MITRE ATT&CK (required), AI providers (opt-in: cloud or local), intelligence sources (NVD, GitHub PoCs, public detection repos, Threat Feed sources, LOLBAS and LOLDrivers), recorded attack telemetry and GUIDE, CALDERA for live chained emulation, and your SIEMs. Solid lines = required, dashed = optional, grey = coming soon or planned.

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'lineColor': '#ff6600', 'edgeLabelBackground': '#ffffff', 'primaryColor': '#4a90d9', 'primaryTextColor': '#ffffff', 'primaryBorderColor': '#2c5f8a', 'secondaryColor': '#e8e8e8', 'tertiaryColor': '#f5f5f5', 'clusterBkg': '#f0f0f0', 'clusterBorder': '#999999', 'titleColor': '#000000', 'nodeTextColor': '#000000', 'background': '#ffffff'}}}%%
graph LR
    ARCHER(("<b>Archer</b>"))

    subgraph REQ ["Required"]
        STIX["MITRE ATT&CK<br/>STIX bundle"]
    end

    subgraph AI ["AI — opt-in"]
        CLOUD["Cloud models<br/>Anthropic · OpenAI · Gemini"]
        LOCAL["Local models<br/>Ollama · LM Studio · llama.cpp"]
    end

    subgraph INTEL ["Intelligence"]
        NVD["NVD"]
        GHPOC["GitHub PoCs"]
        RULES["Public detection repos"]
        FEEDS["Threat Feed sources"]
        LOL["LOLBAS · LOLDrivers"]
    end

    subgraph TEL ["Recorded Attacks — Emulate"]
        SPL["Splunk attack_data"]
        OTRF["OTRF Security-Datasets"]
        EVTX["EVTX-to-MITRE-Attack"]
        MAC["macOS-ATTACK-DATASET"]
        GUIDE["Microsoft GUIDE<br/>via Kaggle"]
    end

    subgraph SIEM ["Your SIEMs"]
        SECOPS["Google SecOps"]
        MDE["Defender XDR"]
        DOCKER["Docker SIEMs<br/>runtime validation"]
    end

    subgraph EMU ["Live Emulation — Emulate"]
        CALDERA["CALDERA server<br/>plan · run · collect<br/>capture logs over C2"]
    end

    subgraph SOON ["Coming Soon / Planned"]
        LAB["Your lab<br/>Atomic Red Team + recorder"]
        VECTR["VECTR import/export<br/>threat library, issue 24"]
    end

    STIX --> ARCHER
    CLOUD -.-> ARCHER
    LOCAL -.-> ARCHER
    NVD -.-> ARCHER
    GHPOC -.-> ARCHER
    RULES -.-> ARCHER
    FEEDS -.-> ARCHER
    LOL -.-> ARCHER
    SPL & OTRF & EVTX & MAC -.-> ARCHER
    GUIDE -.-> ARCHER
    ARCHER -.->|"queries"| SECOPS
    ARCHER -.->|"queries"| MDE
    ARCHER -.-> DOCKER
    ARCHER -.->|"REST"| CALDERA
    LAB -.-> ARCHER
    ARCHER -.-> VECTR

    style ARCHER fill:#f5a623,stroke:#c17d10,color:#fff
    style STIX fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style CLOUD fill:#bd10e0,stroke:#8a0ba5,color:#fff
    style LOCAL fill:#bd10e0,stroke:#8a0ba5,color:#fff
    style SECOPS fill:#7ed321,stroke:#4a8c0f,color:#fff
    style MDE fill:#7ed321,stroke:#4a8c0f,color:#fff
    style CALDERA fill:#50e3c2,stroke:#2ca089,color:#333
    style SPL fill:#50e3c2,stroke:#2ca089,color:#333
    style OTRF fill:#50e3c2,stroke:#2ca089,color:#333
    style EVTX fill:#50e3c2,stroke:#2ca089,color:#333
    style MAC fill:#50e3c2,stroke:#2ca089,color:#333
    style GUIDE fill:#50e3c2,stroke:#2ca089,color:#333
    style SOON fill:#fafafa,stroke:#bbb,stroke-dasharray:4 3
    style LAB fill:#f5f5f5,stroke:#999,stroke-dasharray:4 3,color:#777
    style VECTR fill:#f5f5f5,stroke:#999,stroke-dasharray:4 3,color:#777
    linkStyle default stroke:#ff6600,stroke-width:3px
```
