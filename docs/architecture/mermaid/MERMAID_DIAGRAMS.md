# Archer — Architecture & Process Diagrams

> **Audience:** Anyone who needs to understand how Archer works — security engineers, managers, stakeholders.
> **Minimal code.** These diagrams focus on *what happens* and *why*, not implementation details.

---

## Master Diagram — The Complete Picture

The master view is split into three connected sections for readability. Read top-to-bottom: **Part A** (input to processing) flows into **Part B** (correlation and enrichment) flows into **Part C** (storage and output).

### Part A — Input, Intelligence & Build

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'lineColor': '#ff6600', 'edgeLabelBackground': '#ffffff', 'primaryColor': '#4a90d9', 'primaryTextColor': '#ffffff', 'primaryBorderColor': '#2c5f8a', 'secondaryColor': '#e8e8e8', 'tertiaryColor': '#f5f5f5', 'clusterBkg': '#f0f0f0', 'clusterBorder': '#999999', 'titleColor': '#000000', 'nodeTextColor': '#000000', 'background': '#ffffff'}}}%%
flowchart TD
    subgraph INPUTS ["INPUTS"]
        direction LR
        IN_GROUP["Threat Actor"]
        IN_CVE["CVE"]
        IN_BLOG["Blog / Report"]
        IN_TECH["Technique IDs"]
        IN_MANUAL["Manual Data"]
    end

    subgraph UI ["BROWSER — 6 Tabs"]
        direction LR
        TAB_GEN["Generate"]
        TAB_MANUAL["Manual"]
        TAB_HUNT["Hunt"]
        TAB_RESEARCH["Research"]
        TAB_EMULATE["Emulate"]
        TAB_LIBRARY["Library"]
    end

    subgraph SERVER ["WEB SERVER — 84 endpoints"]
        direction LR
        API["API Router"]
        AUTH["Auth"]
        BG["Background Workers"]
    end

    subgraph INTEL ["INTELLIGENCE"]
        direction LR
        MITRE["MITRE ATT&CK<br/>3 attribution paths"]
        CVE_R["CVE Research<br/>NVD + PoC search"]
        BLOG_A["Blog Analyser"]
        BRIEF["Threat Briefing"]
    end

    subgraph BUILD ["BUILD — For each technique"]
        direction LR
        ORCH["Orchestrator"]
        COMPILE["Extract indicators<br/>→ Check platform<br/>→ Build queries"]
        VENDORS["Splunk | MDE<br/>SecOps | Elastic"]
        YAML_OUT["Save YAML"]
        ORCH --> COMPILE --> VENDORS --> YAML_OUT
    end

    IN_GROUP & IN_CVE & IN_BLOG --> TAB_GEN
    IN_TECH --> TAB_HUNT
    IN_MANUAL --> TAB_MANUAL

    UI --> SERVER
    API --> AUTH
    API --> BG

    BG --> MITRE & CVE_R & BLOG_A & BRIEF
    MITRE & CVE_R & BLOG_A --> ORCH

    YAML_OUT ==>|"To Part B"| CONTINUE((" "))

    style INPUTS fill:#e8f4fd,stroke:#4a90d9
    style UI fill:#d4e8fc,stroke:#4a90d9
    style SERVER fill:#e8d4f8,stroke:#9013fe
    style INTEL fill:#fef3d4,stroke:#f5a623
    style BUILD fill:#fef3d4,stroke:#f5a623
    style IN_GROUP fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style IN_CVE fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style IN_BLOG fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style IN_TECH fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style IN_MANUAL fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style API fill:#9013fe,stroke:#6b0fb8,color:#fff
    style ORCH fill:#f5a623,stroke:#c17d10,color:#fff
    style COMPILE fill:#f5a623,stroke:#c17d10,color:#fff
    style CONTINUE fill:#f5a623,stroke:#c17d10,color:#fff
    linkStyle default stroke:#ff6600,stroke-width:3px
```

### Part B — Correlation & Enrichment

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

### Part C — Storage & Output

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'lineColor': '#ff6600', 'edgeLabelBackground': '#ffffff', 'primaryColor': '#4a90d9', 'primaryTextColor': '#ffffff', 'primaryBorderColor': '#2c5f8a', 'secondaryColor': '#e8e8e8', 'tertiaryColor': '#f5f5f5', 'clusterBkg': '#f0f0f0', 'clusterBorder': '#999999', 'titleColor': '#000000', 'nodeTextColor': '#000000', 'background': '#ffffff'}}}%%
flowchart TD
    FROM_B((" ")) ==>|"From Part B"| READY["Detections + correlations ready"]

    subgraph STORAGE ["DATA STORAGE"]
        direction LR
        YAMLS["Detection YAMLs<br/>data/groups/"]
        CORR_F["Correlation JSON<br/>data/correlate/"]
        CACHE["Caches<br/>data/cache/"]
        DB["Database<br/>archer.db"]
    end

    subgraph OUTPUTS ["OUTPUTS"]
        direction LR
        RESULTS["Results Page<br/>Queries, chains, metrics"]
        XLSX["Excel Export"]
        VECTR_O["VECTR Export"]
        JSON_O["JSON API"]
        LIBRARY["Detection Library"]
    end

    READY --> YAMLS & CORR_F
    READY --> CACHE
    YAMLS & CORR_F --> RESULTS
    RESULTS --> XLSX & JSON_O & LIBRARY
    RESULTS --> VECTR_O

    style FROM_B fill:#7ed321,stroke:#4a8c0f,color:#fff
    style STORAGE fill:#e8e8e8,stroke:#666
    style OUTPUTS fill:#d4f8d4,stroke:#4a8c0f
    style RESULTS fill:#7ed321,stroke:#4a8c0f,color:#fff
    style XLSX fill:#7ed321,stroke:#4a8c0f,color:#fff
    style VECTR_O fill:#7ed321,stroke:#4a8c0f,color:#fff
    style JSON_O fill:#7ed321,stroke:#4a8c0f,color:#fff
    style LIBRARY fill:#7ed321,stroke:#4a8c0f,color:#fff
    style YAMLS fill:#e8e8e8,stroke:#666
    style CORR_F fill:#e8e8e8,stroke:#666
    linkStyle default stroke:#ff6600,stroke-width:3px
```

---

## 1. System Overview — What Is Archer?

Archer takes a **threat actor name** (or CVE, or blog post) and automatically produces **detection queries** for your security tools (Splunk, Microsoft Defender, Google SecOps, Elastic). It does this by looking up what that threat actor actually does (via MITRE ATT&CK), then building tailored searches for each technique.

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

---

## 2. Core Process — End-to-End Flow

This is the full journey from "I want detections for Scattered Spider" to finished queries.

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'lineColor': '#ff6600', 'edgeLabelBackground': '#ffffff', 'primaryColor': '#4a90d9', 'primaryTextColor': '#ffffff', 'primaryBorderColor': '#2c5f8a', 'secondaryColor': '#e8e8e8', 'tertiaryColor': '#f5f5f5', 'clusterBkg': '#f0f0f0', 'clusterBorder': '#999999', 'titleColor': '#000000', 'nodeTextColor': '#000000', 'background': '#ffffff'}}}%%
flowchart TD
    START(["User submits a<br/>threat actor name"]) --> VALIDATE{"Does this actor<br/>exist in MITRE<br/>ATT&CK?"}

    VALIDATE -- "No" --> ERR["Return error:<br/>actor not found"]
    VALIDATE -- "Yes" --> RETRIEVE["Retrieve all known<br/>attack techniques<br/>for this actor"]

    RETRIEVE --> PATHS["Gather techniques<br/>from 3 sources"]

    subgraph "MITRE Attribution Paths"
        P1["Path 1: Direct<br/><i>Actor → Technique</i>"]
        P2["Path 2: Via Software<br/><i>Actor → Tool → Technique</i>"]
        P3["Path 3: Via Campaign<br/><i>Actor → Campaign → Technique</i>"]
    end

    PATHS --> P1
    PATHS --> P2
    PATHS --> P3
    P1 --> MERGE["Merge & deduplicate<br/>all techniques"]
    P2 --> MERGE
    P3 --> MERGE

    MERGE --> LOOP["For each technique..."]

    LOOP --> EXTRACT["Extract indicators:<br/>commands, files, registry keys,<br/>network addresses, hashes"]

    EXTRACT --> PLATFORM{"Which platforms<br/>does this technique<br/>target?"}

    PLATFORM --> VENDORS["Build queries for<br/>each enabled vendor"]

    subgraph "Query Builders"
        SPL["Splunk<br/><i>SPL query</i>"]
        KQL["Microsoft Defender<br/><i>KQL query</i>"]
        YARAL["Google SecOps<br/><i>YARAL rule</i>"]
        EQL["Elastic<br/><i>EQL query</i>"]
    end

    VENDORS --> SPL
    VENDORS --> KQL
    VENDORS --> YARAL
    VENDORS --> EQL

    SPL --> YAML["Save as detection file<br/><i>YAML with metadata</i>"]
    KQL --> YAML
    YARAL --> YAML
    EQL --> YAML

    YAML --> NEXT{"More techniques<br/>to process?"}
    NEXT -- "Yes" --> LOOP
    NEXT -- "No" --> CORRELATE["Build attack chain<br/>correlations"]

    CORRELATE --> ENRICH{"Optional enrichment<br/>steps enabled?"}

    ENRICH -- "OSINT" --> OSINT["Cross-reference with<br/>open-source intel"]
    ENRICH -- "Validation" --> TESTQ["Test queries in<br/>sandboxed SIEM"]
    ENRICH -- "Emulation" --> ATOMIC["Run attack simulation<br/><i>Atomic Red Team</i>"]
    ENRICH -- "Export" --> EXPORT["Send to VECTR<br/>or download XLSX"]
    ENRICH -- "No" --> RESULTS

    OSINT --> RESULTS
    TESTQ --> RESULTS
    ATOMIC --> RESULTS
    EXPORT --> RESULTS

    RESULTS(["Display results page<br/>with all detections,<br/>correlations & metrics"])

    style START fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style RESULTS fill:#7ed321,stroke:#4a8c0f,color:#fff
    style ERR fill:#d0021b,stroke:#8b0000,color:#fff
    style VALIDATE fill:#f8e71c,stroke:#b8a700,color:#333
    style PLATFORM fill:#f8e71c,stroke:#b8a700,color:#333
    style NEXT fill:#f8e71c,stroke:#b8a700,color:#333
    style ENRICH fill:#f8e71c,stroke:#b8a700,color:#333
    linkStyle default stroke:#ff6600,stroke-width:3px
```

---

## 3. Component Architecture — How the Parts Fit Together

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'lineColor': '#ff6600', 'edgeLabelBackground': '#ffffff', 'primaryColor': '#4a90d9', 'primaryTextColor': '#ffffff', 'primaryBorderColor': '#2c5f8a', 'secondaryColor': '#e8e8e8', 'tertiaryColor': '#f5f5f5', 'clusterBkg': '#f0f0f0', 'clusterBorder': '#999999', 'titleColor': '#000000', 'nodeTextColor': '#000000', 'background': '#ffffff'}}}%%
graph TD
    UI["Browser UI"]

    subgraph SERVER ["Web Server"]
        API["API Router<br/>84 endpoints"]
        AUTH["Auth"]
        BG["Background Workers"]
    end

    subgraph INTEL ["Intelligence"]
        MITRE["MITRE ATT&CK"]
        CVE_HUNT["CVE Researcher"]
        BLOG["Blog Analyser"]
        BRIEFING["Threat Briefing"]
    end

    subgraph PIPELINE ["Build Pipeline"]
        ORCH["Orchestrator"]
        COMPILE["Query Compiler"]
        YAML_W["YAML Writer"]
    end

    subgraph CORR_ENG ["Correlation Engine"]
        HEUR["Heuristic"]
        SEM["Semantic"]
        AIGEN["AI Generator"]
    end

    subgraph VALID ["Validation · Optional"]
        DOCKER["Docker SIEMs"]
        TESTER["Test & Refine"]
    end

    subgraph EXT ["External · Optional"]
        LLM_P["LLM Providers"]
        VECTR_I["VECTR"]
        ATOMIC_I["Atomic Red Team"]
        NVD["NVD / GitHub"]
    end

    subgraph STORE ["Storage"]
        YAMLS["Detection YAMLs"]
        CORR_F["Correlations"]
        DB["Database"]
    end

    UI --> API
    API --> AUTH
    API --> BG

    BG --> MITRE
    BG --> CVE_HUNT
    BG --> BLOG
    BG --> BRIEFING

    MITRE --> ORCH
    CVE_HUNT --> ORCH
    BLOG --> ORCH
    ORCH --> COMPILE --> YAML_W

    YAML_W --> HEUR
    YAML_W --> SEM
    YAML_W --> AIGEN

    YAML_W --> YAMLS
    HEUR --> CORR_F
    SEM --> CORR_F
    AUTH --> DB

    AIGEN --> LLM_P
    BRIEFING --> LLM_P
    CVE_HUNT --> NVD
    ORCH --> VECTR_I
    ORCH --> ATOMIC_I
    ORCH --> DOCKER --> TESTER

    style UI fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style API fill:#9013fe,stroke:#6b0fb8,color:#fff
    style ORCH fill:#f5a623,stroke:#c17d10,color:#fff
    style COMPILE fill:#f5a623,stroke:#c17d10,color:#fff
    style MITRE fill:#f5a623,stroke:#c17d10,color:#fff
    style YAMLS fill:#7ed321,stroke:#4a8c0f,color:#fff
    style CORR_F fill:#7ed321,stroke:#4a8c0f,color:#fff
    style DB fill:#7ed321,stroke:#4a8c0f,color:#fff
    linkStyle default stroke:#ff6600,stroke-width:3px
```

---

## 4. Decision Map — Every Choice Archer Makes

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'lineColor': '#ff6600', 'edgeLabelBackground': '#ffffff', 'primaryColor': '#4a90d9', 'primaryTextColor': '#ffffff', 'primaryBorderColor': '#2c5f8a', 'secondaryColor': '#e8e8e8', 'tertiaryColor': '#f5f5f5', 'clusterBkg': '#f0f0f0', 'clusterBorder': '#999999', 'titleColor': '#000000', 'nodeTextColor': '#000000', 'background': '#ffffff'}}}%%
flowchart TD
    subgraph "Input Decisions"
        D1{"What type of input?"}
        D1 -- "Threat Actor" --> D1A["Look up in MITRE ATT&CK"]
        D1 -- "CVE Number" --> D1B["Query NVD vulnerability DB<br/>+ search for exploit code"]
        D1 -- "Blog / Report" --> D1C["Parse text for IOCs,<br/>tools, and techniques"]
        D1 -- "Specific Techniques" --> D1D["Resolve technique details<br/>directly from ATT&CK"]
    end

    subgraph "Attribution Decisions"
        D2{"How is this technique<br/>linked to the actor?"}
        D2 -- "Direct use" --> D2A["Highest confidence<br/><i>Actor personally used it</i>"]
        D2 -- "Via a tool they use" --> D2B["Medium confidence<br/><i>Actor uses software X,<br/>which has this capability</i>"]
        D2 -- "Via a campaign" --> D2C["Lower confidence<br/><i>Actor ran campaign Y,<br/>which involved this</i>"]
    end

    subgraph "Query Building Decisions"
        D3{"Which security tools<br/>should we target?"}
        D3 -- "Not excluded" --> D3A["Build query for<br/>this vendor"]
        D3 -- "Excluded by user" --> D3B["Skip this vendor"]

        D4{"Does this technique<br/>apply to this<br/>vendor's platform?"}
        D4 -- "Yes" --> D4A["Generate the query"]
        D4 -- "No" --> D4B["Skip — technique doesn't<br/>produce relevant telemetry<br/>on this platform"]
    end

    subgraph "Correlation Decisions"
        D5{"Which correlation<br/>mode to use?"}
        D5 -- "Default" --> D5A["Heuristic<br/><i>Rule-based matching:<br/>same tactic, platform,<br/>data source overlap</i>"]
        D5 -- "Advanced" --> D5B["Semantic<br/><i>Parse query structure,<br/>find logical relationships</i>"]
        D5 -- "AI-Assisted" --> D5C["AI Generator<br/><i>Ask LLM to suggest<br/>related technique chains</i>"]
        D5 -- "On-Premise" --> D5D["Local LLM<br/><i>Same as AI but runs<br/>on your own hardware</i>"]
    end

    subgraph "Relevance Scoring<br/><i>Each correlation gets a 0–100 score</i>"
        D6["Group/platform match → 30 points"]
        D7["Position in attack chain → 20 points"]
        D8["Data availability → 20 points"]
        D9["Severity level → 15 points"]
        D10["Tactic specificity → 15 points"]
        D11{"Score ≥ 70?"}
        D11 -- "Yes" --> D11A["Include in results"]
        D11 -- "No" --> D11B["Discard — not relevant enough"]
    end

    subgraph "Enrichment Decisions<br/><i>All optional, user-selected</i>"
        D12{"OSINT enabled?"}
        D12 -- "Yes" --> D12A["Cross-check queries against<br/>public detection repos<br/><i>MITRE CAR, Elastic rules</i>"]
        D12 -- "No" --> D12B["Skip"]

        D13{"Validation enabled?"}
        D13 -- "Yes" --> D13A["Spin up test SIEM in Docker<br/>→ Generate fake events<br/>→ Run query<br/>→ Measure accuracy<br/>→ Suggest improvements"]
        D13 -- "No" --> D13B["Skip"]

        D14{"Emulation enabled?"}
        D14 -- "Yes" --> D14A["Run Atomic Red Team tests<br/>to simulate the attack<br/>and verify detection fires"]
        D14 -- "No" --> D14B["Skip"]
    end

    D1A --> D2
    D1B --> D3
    D1C --> D3
    D1D --> D3
    D2A --> D3
    D2B --> D3
    D2C --> D3
    D3A --> D4
    D4A --> D5
    D5A --> D6
    D5B --> D6
    D5C --> D6
    D5D --> D6
    D6 --> D7 --> D8 --> D9 --> D10 --> D11
    D11A --> D12
    D12A --> D13
    D12B --> D13
    D13A --> D14
    D13B --> D14

    style D1 fill:#f8e71c,stroke:#b8a700,color:#333
    style D2 fill:#f8e71c,stroke:#b8a700,color:#333
    style D3 fill:#f8e71c,stroke:#b8a700,color:#333
    style D4 fill:#f8e71c,stroke:#b8a700,color:#333
    style D5 fill:#f8e71c,stroke:#b8a700,color:#333
    style D11 fill:#f8e71c,stroke:#b8a700,color:#333
    style D12 fill:#f8e71c,stroke:#b8a700,color:#333
    style D13 fill:#f8e71c,stroke:#b8a700,color:#333
    style D14 fill:#f8e71c,stroke:#b8a700,color:#333
    linkStyle default stroke:#ff6600,stroke-width:3px
```

---

## 5. Data Flow — What Goes Where

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'lineColor': '#ff6600', 'edgeLabelBackground': '#ffffff', 'primaryColor': '#4a90d9', 'primaryTextColor': '#ffffff', 'primaryBorderColor': '#2c5f8a', 'secondaryColor': '#e8e8e8', 'tertiaryColor': '#f5f5f5', 'clusterBkg': '#f0f0f0', 'clusterBorder': '#999999', 'titleColor': '#000000', 'nodeTextColor': '#000000', 'background': '#ffffff'}}}%%
flowchart TD
    subgraph SOURCES ["External Sources"]
        STIX["MITRE ATT&CK"]
        NVD_S["NVD"]
        GH_S["GitHub PoCs"]
        OSINT_S["Public Detection Repos"]
    end

    subgraph PROCESS ["Archer Processing"]
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
        VECTR_O["VECTR"]
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

    ENRICH_P --> BROWSER
    ENRICH_P --> XLSX_O
    ENRICH_P --> VECTR_O
    ENRICH_P --> JSON_O

    YAMLS_S -.->|"Read back"| BROWSER
    CORR_S -.->|"Read back"| BROWSER
    CACHE_S -.->|"Speeds up repeats"| INGEST

    style STIX fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style NVD_S fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style GH_S fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style OSINT_S fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style BROWSER fill:#7ed321,stroke:#4a8c0f,color:#fff
    style XLSX_O fill:#7ed321,stroke:#4a8c0f,color:#fff
    style VECTR_O fill:#7ed321,stroke:#4a8c0f,color:#fff
    style JSON_O fill:#7ed321,stroke:#4a8c0f,color:#fff
    linkStyle default stroke:#ff6600,stroke-width:3px
```

---

## 6. Integration Map — External Systems

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'lineColor': '#ff6600', 'edgeLabelBackground': '#ffffff', 'primaryColor': '#4a90d9', 'primaryTextColor': '#ffffff', 'primaryBorderColor': '#2c5f8a', 'secondaryColor': '#e8e8e8', 'tertiaryColor': '#f5f5f5', 'clusterBkg': '#f0f0f0', 'clusterBorder': '#999999', 'titleColor': '#000000', 'nodeTextColor': '#000000', 'background': '#ffffff'}}}%%
graph LR
    ARCHER["ARCHER"]

    subgraph REQUIRED ["Required"]
        MITRE_I["MITRE ATT&CK"]
    end

    subgraph AI ["AI Providers · Optional"]
        CLAUDE["Claude"]
        GPT["GPT-4o"]
        LLAMA["Local LLM"]
    end

    subgraph VULN ["Vulnerability Intel · Optional"]
        NVD_I["NVD API"]
        GH_I["GitHub PoC"]
    end

    subgraph SIM ["Simulation · Optional"]
        ART["Atomic Red Team"]
        CAL["CALDERA"]
        SPL_D["Docker SIEMs"]
    end

    subgraph EXPORT ["Export · Optional"]
        VECTR_E["VECTR"]
        XLSX_E["Excel"]
    end

    ARCHER --> MITRE_I
    ARCHER -.-> CLAUDE
    ARCHER -.-> GPT
    ARCHER -.-> LLAMA
    ARCHER -.-> NVD_I
    ARCHER -.-> GH_I
    ARCHER -.-> ART
    ARCHER -.-> CAL
    ARCHER -.-> SPL_D
    ARCHER -.-> VECTR_E
    ARCHER --> XLSX_E

    style ARCHER fill:#9013fe,stroke:#6b0fb8,color:#fff
    style MITRE_I fill:#f5a623,stroke:#c17d10,color:#fff
    style CLAUDE fill:#bd10e0,stroke:#8a0ba5,color:#fff
    style GPT fill:#bd10e0,stroke:#8a0ba5,color:#fff
    style LLAMA fill:#bd10e0,stroke:#8a0ba5,color:#fff
    linkStyle default stroke:#ff6600,stroke-width:3px
```

---

## 7. User Interface — The Six Tabs

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'lineColor': '#ff6600', 'edgeLabelBackground': '#ffffff', 'primaryColor': '#4a90d9', 'primaryTextColor': '#ffffff', 'primaryBorderColor': '#2c5f8a', 'secondaryColor': '#e8e8e8', 'tertiaryColor': '#f5f5f5', 'clusterBkg': '#f0f0f0', 'clusterBorder': '#999999', 'titleColor': '#000000', 'nodeTextColor': '#000000', 'background': '#ffffff'}}}%%
graph LR
    subgraph "Archer Web Interface"
        direction TB

        T1["<b>Generate</b><br/>Enter a threat actor name.<br/>Archer builds detections<br/>for everything that<br/>actor is known to do."]

        T2["<b>Manual</b><br/>Paste your own threat data<br/>— IOCs, techniques, procedures —<br/>and Archer builds custom<br/>detections from it."]

        T3["<b>Hunt</b><br/>Pick specific ATT&CK<br/>technique IDs and get<br/>targeted detection queries<br/>for just those techniques."]

        T4["<b>Research</b><br/>Browse threat actors,<br/>view technique coverage,<br/>export intelligence data<br/>to Excel."]

        T5["<b>Emulate</b><br/>Run attack simulations<br/>using Atomic Red Team.<br/>Validate that your<br/>detections actually fire."]

        T6["<b>Library</b><br/>Save, search, tag, and<br/>manage your detection<br/>collection. Export or<br/>share with the team."]
    end

    T1 --> RESULT["<b>Results Page</b><br/>• Per-technique query blocks<br/>• Copy-to-clipboard<br/>• Attack chain view<br/>• Combined correlation query<br/>• Coverage metrics<br/>• Export options"]

    T2 --> RESULT
    T3 --> RESULT

    style T1 fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style T2 fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style T3 fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style T4 fill:#50e3c2,stroke:#2ca089,color:#333
    style T5 fill:#f5a623,stroke:#c17d10,color:#fff
    style T6 fill:#50e3c2,stroke:#2ca089,color:#333
    style RESULT fill:#7ed321,stroke:#4a8c0f,color:#fff
    linkStyle default stroke:#ff6600,stroke-width:3px
```

---

## 8. Validation Workflow — Testing Detections

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'lineColor': '#ff6600', 'edgeLabelBackground': '#ffffff', 'primaryColor': '#4a90d9', 'primaryTextColor': '#ffffff', 'primaryBorderColor': '#2c5f8a', 'secondaryColor': '#e8e8e8', 'tertiaryColor': '#f5f5f5', 'clusterBkg': '#f0f0f0', 'clusterBorder': '#999999', 'titleColor': '#000000', 'nodeTextColor': '#000000', 'background': '#ffffff'}}}%%
flowchart TD
    START_V(["User clicks<br/>'Validate Detection'"]) --> DOCKER_CHECK{"Is Docker<br/>available?"}

    DOCKER_CHECK -- "No" --> SKIP["Validation unavailable<br/><i>Docker required</i>"]
    DOCKER_CHECK -- "Yes" --> SPIN["Start a sandboxed<br/>SIEM container<br/><i>e.g. Splunk in Docker</i>"]

    SPIN --> GENERATE_EVENTS["Generate realistic<br/>fake log events<br/><i>Based on what the<br/>detection looks for</i>"]

    GENERATE_EVENTS --> RUN_QUERY["Run the detection<br/>query against the<br/>fake events"]

    RUN_QUERY --> MEASURE["Measure results:<br/>• True positives <i>(caught real attacks)</i><br/>• False positives <i>(false alarms)</i><br/>• False negatives <i>(missed attacks)</i>"]

    MEASURE --> GOOD{"Detection<br/>performing<br/>well?"}

    GOOD -- "Yes" --> ACCEPT["Accept detection<br/>as validated"]
    GOOD -- "Needs work" --> REFINE["AI suggests<br/>improvements:<br/>• Adjust field names<br/>• Tighten filters<br/>• Rewrite logic"]

    REFINE --> APPLY["Apply refined query"]
    APPLY --> RUN_QUERY

    ACCEPT --> CLEANUP["Shut down<br/>Docker containers"]

    style START_V fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style ACCEPT fill:#7ed321,stroke:#4a8c0f,color:#fff
    style SKIP fill:#d0021b,stroke:#8b0000,color:#fff
    style DOCKER_CHECK fill:#f8e71c,stroke:#b8a700,color:#333
    style GOOD fill:#f8e71c,stroke:#b8a700,color:#333
    linkStyle default stroke:#ff6600,stroke-width:3px
```

---

## 9. CVE Workflow — Vulnerability-Based Detection

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'lineColor': '#ff6600', 'edgeLabelBackground': '#ffffff', 'primaryColor': '#4a90d9', 'primaryTextColor': '#ffffff', 'primaryBorderColor': '#2c5f8a', 'secondaryColor': '#e8e8e8', 'tertiaryColor': '#f5f5f5', 'clusterBkg': '#f0f0f0', 'clusterBorder': '#999999', 'titleColor': '#000000', 'nodeTextColor': '#000000', 'background': '#ffffff'}}}%%
flowchart TD
    CVE_IN(["User enters a<br/>CVE number"]) --> FETCH["Fetch vulnerability<br/>details from NVD"]

    FETCH --> SEVERITY["Read severity score,<br/>affected products,<br/>vulnerability type"]

    SEVERITY --> POC{"Search for<br/>proof-of-concept<br/>exploit code?"}

    POC -- "Found on GitHub" --> EXTRACT_POC["Extract attack indicators<br/>from exploit code:<br/>commands, files, network calls"]
    POC -- "Found on Exploit-DB" --> EXTRACT_POC
    POC -- "Not found" --> SYNTH["Build synthetic indicators<br/>from vulnerability description"]

    EXTRACT_POC --> MAP["Map indicators to<br/>ATT&CK techniques"]
    SYNTH --> MAP

    MAP --> BUILD_Q["Build detection queries<br/><i>Same pipeline as<br/>threat actor workflow</i>"]

    BUILD_Q --> RESULTS_CVE(["Detection queries<br/>tailored to this<br/>specific vulnerability"])

    style CVE_IN fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style RESULTS_CVE fill:#7ed321,stroke:#4a8c0f,color:#fff
    style POC fill:#f8e71c,stroke:#b8a700,color:#333
    linkStyle default stroke:#ff6600,stroke-width:3px
```

---

## 10. Correlation Engine — How Attack Chains Are Built

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'lineColor': '#ff6600', 'edgeLabelBackground': '#ffffff', 'primaryColor': '#4a90d9', 'primaryTextColor': '#ffffff', 'primaryBorderColor': '#2c5f8a', 'secondaryColor': '#e8e8e8', 'tertiaryColor': '#f5f5f5', 'clusterBkg': '#f0f0f0', 'clusterBorder': '#999999', 'titleColor': '#000000', 'nodeTextColor': '#000000', 'background': '#ffffff'}}}%%
flowchart TD
    ALL_YAMLS(["All detection files<br/>generated for this actor"]) --> READ["Read each detection's<br/>metadata: technique, tactic,<br/>platform, severity, data sources"]

    READ --> GROUP["Group detections<br/>by tactic phase<br/><i>Initial Access → Execution<br/>→ Persistence → ...</i>"]

    GROUP --> SCORE["Score each pair of<br/>detections for relevance"]

    subgraph "Scoring Criteria (0–100)"
        S1["Do they target the<br/>same group/platform?<br/><b>+30 points</b>"]
        S2["Do they form a<br/>logical attack sequence?<br/><b>+20 points</b>"]
        S3["Is the data available<br/>in your environment?<br/><b>+20 points</b>"]
        S4["How severe is<br/>the threat?<br/><b>+15 points</b>"]
        S5["How specific is<br/>the tactic?<br/><b>+15 points</b>"]
    end

    SCORE --> S1
    SCORE --> S2
    SCORE --> S3
    SCORE --> S4
    SCORE --> S5

    S1 --> THRESHOLD
    S2 --> THRESHOLD
    S3 --> THRESHOLD
    S4 --> THRESHOLD
    S5 --> THRESHOLD

    THRESHOLD{"Total score<br/>≥ 70?"}
    THRESHOLD -- "Yes" --> CHAIN["Link into an<br/>attack chain"]
    THRESHOLD -- "No" --> DISCARD["Not included<br/><i>Weak connection</i>"]

    CHAIN --> COMBINED["Build combined<br/>correlation query<br/><i>Detects the full<br/>attack sequence</i>"]

    COMBINED --> OUTPUT(["Correlation result:<br/>• Individual technique queries<br/>• Combined chain query<br/>• Tactics covered<br/>• Time window<br/>• Relevance score"])

    style ALL_YAMLS fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style OUTPUT fill:#7ed321,stroke:#4a8c0f,color:#fff
    style THRESHOLD fill:#f8e71c,stroke:#b8a700,color:#333
    linkStyle default stroke:#ff6600,stroke-width:3px
```

---

## Quick Reference — Explaining Archer in One Paragraph

> **Archer** is a tool that turns threat intelligence into working detection queries. You give it the name of a threat actor (like "Scattered Spider"), and it looks up every attack technique that actor is known to use — drawing from the industry-standard MITRE ATT&CK database. For each technique, it extracts the specific indicators (commands, files, network addresses) and builds tailored search queries for your security tools (Splunk, Microsoft Defender, Google SecOps, or Elastic). It then links related detections into attack chains so you can spot multi-step intrusions, not just individual events. Optionally, it can test those detections in a sandboxed environment, cross-reference them against public intelligence, simulate the actual attacks, and export everything to your purple team platform or a spreadsheet.
