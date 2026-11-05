# Shikari — Architecture & Process Diagrams

> **Audience:** Anyone who needs to understand how Shikari works — security engineers, managers, stakeholders.
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
        IN_BLOG["Report<br/>URL or file"]
        IN_TECH["Technique IDs"]
        IN_MANUAL["Manual Data"]
    end

    subgraph UI ["BROWSER — Home, Detections, Intel, Build"]
        direction LR
        TAB_GEN["Home → Hunt"]
        TAB_MANUAL["Build → Manual"]
        TAB_HUNT["Home → Analyse"]
        TAB_RESEARCH["Home → Research"]
        TAB_EMULATE["Build → Emulate"]
        TAB_LIBRARY["Detections → Library"]
    end

    subgraph SERVER ["WEB SERVER — FastAPI"]
        direction LR
        API["API Router"]
        AUTH["Auth"]
        BG["Background Workers"]
    end

    subgraph INTEL ["INTELLIGENCE"]
        direction LR
        MITRE["MITRE ATT&CK + MITRESaw<br/>3 attribution paths"]
        CVE_R["CVE Research<br/>NVD + PoC search"]
        BLOG_A["Report Analyser"]
        BRIEF["Threat Briefing"]
    end

    subgraph BUILD ["BUILD — For each technique"]
        direction LR
        ORCH["Orchestrator"]
        COMPILE["Technology stack filter<br/>→ Extract indicators<br/>→ Build queries<br/>→ Precision checks"]
        VENDORS["SecOps | MDE | Splunk | Elastic"]
        YAML_OUT["Save YAML"]
        ORCH --> COMPILE --> VENDORS --> YAML_OUT
    end

    IN_GROUP & IN_CVE & IN_TECH --> TAB_GEN
    IN_BLOG --> TAB_HUNT
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
        OSINT["OSINT<br/>Inherited from each<br/>chain's detections"]
        VALID["Validation<br/>Test in Docker SIEM<br/>→ Measure accuracy<br/>→ AI refines query"]
        EMUL["Emulate<br/>Do the indicators appear<br/>in recorded attacks?"]
    end

    subgraph EXT ["EXTERNAL SYSTEMS"]
        direction LR
        LLM["AI, opt-in<br/>Anthropic · OpenAI · Gemini · Local"]
        NVD_GH["NVD · GitHub"]
        ART["Recorded attacks<br/>4 public sources + GUIDE"]
    end

    YAMLS_IN --> MODE
    CHAIN --> OSINT & VALID & EMUL

    LLM -.-> AIGEN
    ART -.-> EMUL

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
        DB["Database<br/>shikari.db"]
    end

    subgraph OUTPUTS ["OUTPUTS"]
        direction LR
        RESULTS["Results Page<br/>Queries, chains, metrics"]
        XLSX["Excel Export"]
        FLOW_O["Attack Flow<br/>STIX bundle"]
        JSON_O["JSON API"]
        LIBRARY["Detection Library"]
    end

    READY --> YAMLS & CORR_F
    READY --> CACHE
    YAMLS & CORR_F --> RESULTS
    RESULTS --> XLSX & JSON_O & LIBRARY
    RESULTS --> FLOW_O

    style FROM_B fill:#7ed321,stroke:#4a8c0f,color:#fff
    style STORAGE fill:#e8e8e8,stroke:#666
    style OUTPUTS fill:#d4f8d4,stroke:#4a8c0f
    style RESULTS fill:#7ed321,stroke:#4a8c0f,color:#fff
    style XLSX fill:#7ed321,stroke:#4a8c0f,color:#fff
    style FLOW_O fill:#7ed321,stroke:#4a8c0f,color:#fff
    style JSON_O fill:#7ed321,stroke:#4a8c0f,color:#fff
    style LIBRARY fill:#7ed321,stroke:#4a8c0f,color:#fff
    style YAMLS fill:#e8e8e8,stroke:#666
    style CORR_F fill:#e8e8e8,stroke:#666
    linkStyle default stroke:#ff6600,stroke-width:3px
```

---

## 1. System Overview — What Is Shikari?

Shikari takes a **threat actor name** (or CVE, report, ATT&CK techniques or company) and automatically produces **detection queries** for your SIEMs (Google SecOps, Microsoft Defender XDR, Splunk and Elastic). It does this by looking up what that threat actor actually does (via MITRE ATT&CK), then building tailored searches for each technique.

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'lineColor': '#ff6600', 'edgeLabelBackground': '#ffffff', 'primaryColor': '#4a90d9', 'primaryTextColor': '#ffffff', 'primaryBorderColor': '#2c5f8a', 'secondaryColor': '#e8e8e8', 'tertiaryColor': '#f5f5f5', 'clusterBkg': '#f0f0f0', 'clusterBorder': '#999999', 'titleColor': '#000000', 'nodeTextColor': '#000000', 'background': '#ffffff'}}}%%
graph TB
    subgraph "What You Give Shikari"
        A["Threat Actor Name<br/><i>e.g. Scattered Spider</i>"]
        B["CVE Number<br/><i>e.g. CVE-2024-1234</i>"]
        C["Threat Blog / Report"]
        D["Specific ATT&CK Techniques<br/><i>e.g. T1059.004</i>"]
    end

    subgraph "What Shikari Does"
        E["Looks up real attack behaviours<br/>from MITRE ATT&CK"]
        F["Builds detection queries<br/>for each behaviour"]
        G["Links related detections<br/>into attack chains"]
        H["Optionally tests, emulates,<br/>enriches & exports results"]
    end

    subgraph "What You Get Back"
        I["Google SecOps Rules<br/><i>YARA-L 2.0</i>"]
        J["Defender XDR Queries<br/><i>KQL</i>"]
        K["Splunk & Elastic<br/><i>SPL and ES|QL</i>"]
        L["IOC Sweeps"]
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
    subgraph "Entry Points"
        WEB(["Web UI"])
        CLI(["shikari offline"])
        ADF(["shikari console<br/><i>Interactive Shell</i>"])
    end

    WEB --> START
    CLI --> START
    ADF --> START
    START(["Submit threat<br/>actor name"]) --> VALIDATE{"Does this actor<br/>exist in MITRE<br/>ATT&CK?"}

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

    VENDORS --> BESPOKE{"Bespoke mode?"}
    BESPOKE -- "LLM (Mode 1)" --> LLM["Send prompt + evidence<br/>to LLM → parse response"]
    BESPOKE -- "Fallback (Mode 2)" --> TMPL["Map indicators to<br/>SIEM fields via templates"]
    BESPOKE -- "Standard" --> YAML
    LLM --> YAML
    TMPL --> YAML

    YAML --> NEXT{"More techniques<br/>to process?"}
    NEXT -- "Yes" --> LOOP
    NEXT -- "No" --> CORRELATE["Build attack chain<br/>correlations"]

    CORRELATE --> ENRICH{"Optional enrichment<br/>steps enabled?"}

    ENRICH -- "OSINT" --> OSINT["Cross-reference with<br/>open-source intel"]
    ENRICH -- "Validation" --> TESTQ["Test queries in<br/>sandboxed SIEM"]
    ENRICH -- "Emulate" --> ATOMIC["Check indicators against<br/>recorded attacks<br/><i>Emulate</i>"]
    ENRICH -- "Export" --> EXPORT["Download XLSX<br/>or attack flow (STIX)"]
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
    style BESPOKE fill:#f8e71c,stroke:#b8a700,color:#333
    style ADF fill:#9b59b6,stroke:#6c3483,color:#fff
    linkStyle default stroke:#ff6600,stroke-width:3px
```

---

## 3. Component Architecture — How the Parts Fit Together

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'lineColor': '#ff6600', 'edgeLabelBackground': '#ffffff', 'primaryColor': '#4a90d9', 'primaryTextColor': '#ffffff', 'primaryBorderColor': '#2c5f8a', 'secondaryColor': '#e8e8e8', 'tertiaryColor': '#f5f5f5', 'clusterBkg': '#f0f0f0', 'clusterBorder': '#999999', 'titleColor': '#000000', 'nodeTextColor': '#000000', 'background': '#ffffff'}}}%%
graph TB
    subgraph IFACE ["Interfaces"]
        direction LR
        WEB["Web UI<br/>server-rendered"]
        CON["shikari console"]
        CLI["shikari"]
        MCP["MCP server"]
    end

    subgraph SERVER ["FastAPI Server"]
        direction LR
        API["Pages + REST API<br/>/docs"]
        AUTH["Auth + roles"]
        JOBS["Background jobs<br/>runs, Feed every 6 h"]
    end

    subgraph INTEL ["Intelligence"]
        direction LR
        MITRE["ATT&CK + MITRESaw<br/>procedures, indicators"]
        CVE["CVE Research<br/>NVD + PoCs"]
        REPORT["Report Analyser<br/>URL, PDF, DOCX"]
        FEED["Threat Feed<br/>+ watchlists"]
        OSINT["OSINT rule index<br/>+ LOLBAS, LOLDrivers"]
    end

    subgraph PIPE ["Build Pipeline"]
        direction LR
        STACK["Technology stack<br/>filter"]
        ORCH["Orchestrator"]
        BUILD["Query builders<br/>SecOps · MDE"]
        PREC["Precision checks"]
        IOC["IOC sweeps<br/>known-good, expiry"]
    end

    subgraph CORR ["Correlation"]
        direction LR
        HEUR["Heuristic"]
        SEM["Semantic"]
        AIC["AI, opt-in"]
    end

    subgraph TEL ["Recorded Telemetry — Emulate"]
        direction LR
        REC["Recordings<br/>Splunk · OTRF · EVTX · macOS"]
        GUIDE["GUIDE<br/>Defender XDR alerting"]
        LAB["Your lab<br/>CALDERA operations<br/><i>Atomic recorder coming soon</i>"]
    end

    subgraph TOOLS ["Tools"]
        direction LR
        REGEX["Regex<br/>RE2 · PCRE2"]
        AGENTS["Agents, opt-in"]
        VAL["Runtime validation<br/>Docker SIEMs"]
    end

    subgraph STORE ["Storage"]
        direction LR
        DB["shikari.db<br/>Library, users, Feed"]
        YAML["Detection YAMLs<br/>data/groups/"]
        CJSON["Correlations<br/>data/correlate/"]
        BESPOKE["bespoke/ mappings<br/>gitignored"]
    end

    WEB & CON & CLI & MCP --> API
    API --> AUTH
    API --> JOBS
    JOBS --> MITRE & CVE & REPORT & FEED
    MITRE & CVE & REPORT --> STACK --> ORCH --> BUILD --> PREC
    BUILD --> IOC
    BESPOKE -.-> BUILD
    OSINT -.-> BUILD
    PREC --> YAML
    YAML --> HEUR & SEM & AIC
    HEUR & SEM & AIC --> CJSON
    OSINT -.->|"inherited"| CJSON
    YAML -.->|"indicators checked"| REC
    LAB -.-> REC
    API --> REGEX & AGENTS & VAL
    API --> DB

    style IFACE fill:#d4e8fc,stroke:#4a90d9
    style SERVER fill:#e8d4f8,stroke:#9013fe
    style INTEL fill:#fef3d4,stroke:#f5a623
    style PIPE fill:#fef3d4,stroke:#f5a623
    style CORR fill:#fde8d4,stroke:#e8752a
    style TEL fill:#d4f8ef,stroke:#2ca089
    style TOOLS fill:#f0d4f8,stroke:#bd10e0
    style STORE fill:#e8e8e8,stroke:#666
    style API fill:#9013fe,stroke:#6b0fb8,color:#fff
    style ORCH fill:#f5a623,stroke:#c17d10,color:#fff
    style BUILD fill:#f5a623,stroke:#c17d10,color:#fff
    style REC fill:#50e3c2,stroke:#2ca089,color:#333
    style GUIDE fill:#50e3c2,stroke:#2ca089,color:#333
    style LAB fill:#50e3c2,stroke:#2ca089,color:#333
    linkStyle default stroke:#ff6600,stroke-width:3px
```

---

## 4. Decision Map — Every Choice Shikari Makes

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
        D12 -- "Yes" --> D12A["Cross-check queries against<br/>public detection repos<br/><i>Elastic, Splunk, Sentinel rules</i>"]
        D12 -- "No" --> D12B["Skip"]

        D13{"Validation enabled?"}
        D13 -- "Yes" --> D13A["Spin up test SIEM in Docker<br/>→ Generate fake events<br/>→ Run query<br/>→ Measure accuracy<br/>→ Suggest improvements"]
        D13 -- "No" --> D13B["Skip"]

        D14{"Check against recordings?"}
        D14 -- "Yes" --> D14A["Emulate: which logs record<br/>the technique, and do the<br/>indicators appear in them?"]
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

---

## 6. Integration Map — External Systems

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'lineColor': '#ff6600', 'edgeLabelBackground': '#ffffff', 'primaryColor': '#4a90d9', 'primaryTextColor': '#ffffff', 'primaryBorderColor': '#2c5f8a', 'secondaryColor': '#e8e8e8', 'tertiaryColor': '#f5f5f5', 'clusterBkg': '#f0f0f0', 'clusterBorder': '#999999', 'titleColor': '#000000', 'nodeTextColor': '#000000', 'background': '#ffffff'}}}%%
graph LR
    SHIKARI(("<b>Shikari</b>"))

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

    subgraph ATTR ["Incidents & Attribution — Adversary List"]
        VCDB["VERIS Community DB<br/>incidents by org & sector"]
        KEV["CISA KEV<br/>CVEs exploited in the wild"]
        RL["ransomware.live<br/>recent victims by group"]
    end

    subgraph SOON ["Coming Soon / Planned"]
        LAB["Your lab<br/>Atomic Red Team + recorder"]
        VECTR["VECTR import/export<br/>threat library, issue 24"]
    end

    STIX --> SHIKARI
    CLOUD -.-> SHIKARI
    LOCAL -.-> SHIKARI
    NVD -.-> SHIKARI
    GHPOC -.-> SHIKARI
    RULES -.-> SHIKARI
    FEEDS -.-> SHIKARI
    LOL -.-> SHIKARI
    SPL & OTRF & EVTX & MAC -.-> SHIKARI
    GUIDE -.-> SHIKARI
    SHIKARI -.->|"queries"| SECOPS
    SHIKARI -.->|"queries"| MDE
    SHIKARI -.-> DOCKER
    SHIKARI -.->|"REST"| CALDERA
    VCDB & KEV & RL -.->|"cached feeds"| SHIKARI
    LAB -.-> SHIKARI
    SHIKARI -.-> VECTR

    style SHIKARI fill:#f5a623,stroke:#c17d10,color:#fff
    style VCDB fill:#50e3c2,stroke:#2ca089,color:#333
    style KEV fill:#50e3c2,stroke:#2ca089,color:#333
    style RL fill:#50e3c2,stroke:#2ca089,color:#333
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

---

## 7. User Interface — Menus and Pages

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'lineColor': '#ff6600', 'edgeLabelBackground': '#ffffff', 'primaryColor': '#4a90d9', 'primaryTextColor': '#ffffff', 'primaryBorderColor': '#2c5f8a', 'secondaryColor': '#e8e8e8', 'tertiaryColor': '#f5f5f5', 'clusterBkg': '#f0f0f0', 'clusterBorder': '#999999', 'titleColor': '#000000', 'nodeTextColor': '#000000', 'background': '#ffffff'}}}%%
graph LR
    subgraph HOME ["Home"]
        direction TB
        H1["<b>Hunt</b><br/>A group, a CVE or<br/>ATT&CK techniques"]
        H2["<b>Analyse</b><br/>A report: URL or<br/>uploaded file"]
        H3["<b>Profile</b><br/>The groups likely<br/>to target a company"]
        H4["<b>Research</b><br/>Find groups by keyword,<br/>compare techniques"]
    end

    RESULT["<b>Results</b><br/>Briefing · detections per SIEM<br/>· correlations · attack flow<br/>· IOC flow · exports"]

    subgraph DET ["Detections"]
        direction TB
        D1["<b>Library</b><br/>Saved detections<br/>and correlations"]
        D2["<b>Coverage</b><br/>The ATT&CK matrix"]
        D3["<b>Flows</b><br/>What you can and<br/>can't detect"]
    end

    subgraph INT ["Intel"]
        direction TB
        I1["<b>Feed</b><br/>The week's research,<br/>watchlists"]
        I2["<b>Cyber Powers</b><br/>National capability map"]
        I3["<b>MITRESaw</b><br/>Procedures, indicators"]
    end

    subgraph BLD ["Build"]
        direction TB
        B1["<b>Manual</b><br/>One technique at a time"]
        B2["<b>Regex</b><br/>Test per SIEM engine"]
        B3["<b>Agents</b><br/>Repair, triage — opt-in"]
        B4["<b>Emulate</b><br/>Which logs record each technique;<br/>your detections against recorded<br/>attacks; Lab runs CALDERA operations"]
    end

    H1 & H2 & H3 --> RESULT
    H4 --> H1
    I1 -.-> H2
    RESULT --> D1
    RESULT --> D3
    B1 --> D1
    D1 -.-> B4
    RESULT -.->|"Run Emulation"| B4

    style H1 fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style H2 fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style H3 fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style H4 fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style RESULT fill:#7ed321,stroke:#4a8c0f,color:#fff
    style D1 fill:#50e3c2,stroke:#2ca089,color:#333
    style D2 fill:#50e3c2,stroke:#2ca089,color:#333
    style D3 fill:#50e3c2,stroke:#2ca089,color:#333
    style B4 fill:#f5a623,stroke:#c17d10,color:#fff
    linkStyle default stroke:#ff6600,stroke-width:3px
```

---

## 8. Validation Workflow — Testing Detections

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'lineColor': '#ff6600', 'edgeLabelBackground': '#ffffff', 'primaryColor': '#4a90d9', 'primaryTextColor': '#ffffff', 'primaryBorderColor': '#2c5f8a', 'secondaryColor': '#e8e8e8', 'tertiaryColor': '#f5f5f5', 'clusterBkg': '#f0f0f0', 'clusterBorder': '#999999', 'titleColor': '#000000', 'nodeTextColor': '#000000', 'background': '#ffffff'}}}%%
flowchart TD
    START_V(["Validate a<br/>detection"]) --> STATIC["Static checks <i>(no AI, no Docker)</i>:<br/>• Parses, known tables and fields<br/>• Quality grade A–F<br/>• False-positive risk<br/>• Run cost"]

    STATIC --> GATE{"Meets the<br/>thresholds?"}

    GATE -- "In CI<br/><i>detections as code</i>" --> CI["CI gate passes or fails<br/>the build<br/><i>shikari.validation.ci</i>"]
    GATE -- "Interactive" --> DOCKER_CHECK{"Is Docker<br/>available?"}

    DOCKER_CHECK -- "No" --> SKIP["Runtime test unavailable<br/><i>Docker required</i>"]
    DOCKER_CHECK -- "Yes" --> SPIN["Start a sandboxed<br/>SIEM container<br/><i>e.g. Splunk in Docker</i>"]

    SPIN --> GENERATE_EVENTS["Generate realistic<br/>fake log events<br/><i>Based on what the<br/>detection looks for</i>"]

    GENERATE_EVENTS --> RUN_QUERY["Run the detection query<br/>against the fake events<br/><i>and time it</i>"]

    RUN_QUERY --> MEASURE["Measure results:<br/>• True positives <i>(caught real attacks)</i><br/>• False positives <i>(false alarms)</i><br/>• False negatives <i>(missed attacks)</i><br/>• Query time"]

    MEASURE --> GOOD{"Detection<br/>performing<br/>well?"}

    GOOD -- "Yes" --> ACCEPT["Accept detection<br/>as validated"]
    GOOD -- "Needs work" --> REFINE["AI agent suggests<br/>improvements <i>(opt-in)</i>:<br/>• Adjust field names<br/>• Tighten filters<br/>• Rewrite logic"]

    REFINE --> APPLY["Apply refined query"]
    APPLY --> RUN_QUERY

    ACCEPT --> CLEANUP["Shut down<br/>Docker containers"]

    style START_V fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style ACCEPT fill:#7ed321,stroke:#4a8c0f,color:#fff
    style CI fill:#7ed321,stroke:#4a8c0f,color:#fff
    style SKIP fill:#d0021b,stroke:#8b0000,color:#fff
    style STATIC fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style DOCKER_CHECK fill:#f8e71c,stroke:#b8a700,color:#333
    style GATE fill:#f8e71c,stroke:#b8a700,color:#333
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
    POC -- "Not found" --> NOPOC["Read indicators from the<br/>NVD description, the CWE<br/>and linked advisories"]

    EXTRACT_POC --> MAP["Map indicators to<br/>ATT&CK techniques"]
    NOPOC --> MAP

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

## 11. CALDERA Workflow — Chained Emulation and Static Checks

How a CALDERA operation validates detections and correlations. CALDERA is used for what Atomic Red Team runs can't give: fact chaining between steps and a real implant (sandcat) on the agents. Shikari plans the operation first and changes nothing on CALDERA until it's confirmed, then runs it, collects each step's command, host, times and output, optionally captures the agent host's logs over each step's window — over the agent's own C2 (any OS, nothing installed on the host) or a lab machine Lab manages — and checks saved detections and correlations against that evidence statically, with no AI.

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'lineColor': '#ff6600', 'edgeLabelBackground': '#ffffff', 'primaryColor': '#4a90d9', 'primaryTextColor': '#ffffff', 'primaryBorderColor': '#2c5f8a', 'secondaryColor': '#e8e8e8', 'tertiaryColor': '#f5f5f5', 'clusterBkg': '#f0f0f0', 'clusterBorder': '#999999', 'titleColor': '#000000', 'nodeTextColor': '#000000', 'background': '#ffffff'}}}%%
flowchart TD
    PROVISION(["Add an agent — provision &amp; enrol<br/>web · desktop app · shikari caldera"]) --> AGENTS["Managed agent in a group<br/>Tart VM · Docker · UTM · OrbStack<br/><i>machine pulls arch-correct sandcat, runs it detached;<br/>topology shows enrolled vs not, managed vs external</i>"]
    AGENTS -.->|"the agents an operation runs on"| TARGET

    TARGET(["Techniques, a threat group<br/>or a CVE + an agent group"]) --> READ["Read CALDERA's abilities<br/>and the group's agents<br/><i>reads only</i>"]

    READ --> CHOOSE["One ability per technique<br/>an agent can run:<br/>exact technique first,<br/>CALDERA's own plugins<br/>before its Atomic import"]

    CHOOSE --> PLAN["Dry-run plan:<br/>• Adversary, in order<br/>• Agents, planner, obfuscator<br/>• Command templates with<br/>#35;{facts} unfilled<br/>• Gaps"]

    PLAN --> CONFIRM{"Agents confirmed<br/>disposable?"}

    CONFIRM -- "No" --> STOP["Nothing created<br/>on CALDERA"]
    CONFIRM -- "Yes" --> RUN["Create adversary, start operation<br/><i>atomic planner: each step's facts<br/>feed the next; sandcat agent<br/>behaves like an implant</i>"]

    RUN --> COLLECT["Collect each link over the API:<br/>command as run, host, times, output<br/><i>data/telemetry/caldera/</i>"]

    COLLECT --> CAPTURE{"Capture the agent<br/>host's logs?"}

    CAPTURE -- "Yes" --> LOGS["reads each step's window back from<br/>the endpoint's logs — over the agent's<br/>own C2 (any OS, nothing installed)<br/>or a lab machine Lab manages<br/><i>imported as a Your lab run</i>"]
    CAPTURE -- "No" --> CMDS["Commands only"]

    LOGS --> CHECK["Static check <i>(no AI)</i>:<br/>detection indicators against<br/>each step's evidence"]
    CMDS --> CHECK

    CHECK --> TECH(["Per technique:<br/>matched · missed · no detections<br/>+ steps nothing matched"])
    CHECK --> CORR(["Per correlation:<br/>fired · half-fired · missed<br/><i>every part on one host,<br/>inside its window</i>"])

    style PROVISION fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style TARGET fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style TECH fill:#7ed321,stroke:#4a8c0f,color:#fff
    style CORR fill:#7ed321,stroke:#4a8c0f,color:#fff
    style STOP fill:#d0021b,stroke:#8b0000,color:#fff
    style CHECK fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style CONFIRM fill:#f8e71c,stroke:#b8a700,color:#333
    style CAPTURE fill:#f8e71c,stroke:#b8a700,color:#333
    linkStyle default stroke:#ff6600,stroke-width:3px
```

---

## 12. Adversary Ranking — Who Is Most Likely To Target You

The Ordered Adversary List (`shikari.intelligence.adversary_ranking`): the top-10 ATT&CK groups most likely to target a profiled organisation, from four offline, no-AI signals — industry, geography, exposed OSINT and public incidents. Each signal reads data Shikari already holds or caches; the ranking combines them into a likelihood and band, shown on /exposure and /review. Setting an **Organisation** on your profile auto-profiles that company and stars it in the catalogue.

```mermaid

%%{init: {'theme': 'base', 'themeVariables': {'lineColor': '#ff6600', 'edgeLabelBackground': '#ffffff', 'primaryColor': '#4a90d9', 'primaryTextColor': '#ffffff', 'primaryBorderColor': '#2c5f8a', 'secondaryColor': '#e8e8e8', 'tertiaryColor': '#f5f5f5', 'clusterBkg': '#f0f0f0', 'clusterBorder': '#999999', 'titleColor': '#000000', 'nodeTextColor': '#000000', 'background': '#ffffff'}}}%%
graph LR
    PROFILE(["Company profile<br/>industry · geography · OSINT<br/><i>your Organisation auto-profiles</i>"])

    subgraph SIG ["Four signals — offline, no AI"]
        IND["Industry<br/>org sector → target_sectors"]
        GEO["Geography<br/>country → region → target_regions"]
        EXP["Exposure<br/>OSINT → T1190/T1133/T1078/T1566<br/>+ product-keyword match"]
        INC["Incidents<br/>demonstrated activity + public incidents<br/>on the org and its sector peers"]
    end

    subgraph SRC ["Data (cached, read at render time)"]
        META["group_metadata.json<br/>target sectors/regions · campaigns"]
        CSV["MITRESaw CSV<br/>group → techniques"]
        BUNDLE["ATT&CK bundle<br/>group descriptions"]
        KEV["CISA KEV<br/>CVEs exploited in the wild"]
        VCDB["VCDB<br/>incidents by org & sector"]
        RL["ransomware.live<br/>recent victims by group"]
        BESPOKE["bespoke/mappings/<br/>incidents.json"]
    end

    RANK{{"rank_adversaries<br/>weighted sum → likelihood + band"}}
    TOP["Ordered Adversary List<br/>top 10 · /exposure & /review"]

    PROFILE --> IND & GEO & EXP & INC
    META --> IND & GEO
    CSV --> EXP
    BUNDLE --> EXP
    KEV --> EXP
    META -->|"campaigns"| INC
    VCDB & RL & BESPOKE --> INC
    IND & GEO & EXP & INC --> RANK --> TOP

    style PROFILE fill:#f5a623,stroke:#c17d10,color:#fff
    style RANK fill:#f5a623,stroke:#c17d10,color:#fff
    style TOP fill:#7ed321,stroke:#4a8c0f,color:#fff
    style IND fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style GEO fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style EXP fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style INC fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style META fill:#50e3c2,stroke:#2ca089,color:#333
    style CSV fill:#50e3c2,stroke:#2ca089,color:#333
    style BUNDLE fill:#50e3c2,stroke:#2ca089,color:#333
    style KEV fill:#50e3c2,stroke:#2ca089,color:#333
    style VCDB fill:#50e3c2,stroke:#2ca089,color:#333
    style RL fill:#50e3c2,stroke:#2ca089,color:#333
    style BESPOKE fill:#50e3c2,stroke:#2ca089,color:#333
    linkStyle default stroke:#ff6600,stroke-width:3px
```

---

## Quick Reference — Explaining Shikari in One Paragraph

> **Shikari** is a tool that turns threat intelligence into working detection queries. You give it the name of a threat actor (like "Scattered Spider"), and it looks up every attack technique that actor is known to use — drawing from the industry-standard MITRE ATT&CK database. For each technique, it extracts the specific indicators (commands, files, network addresses) and builds tailored search queries for your SIEMs (Google SecOps and Microsoft Defender XDR). It then links related detections into attack chains so you can spot multi-step intrusions, not just individual events. Optionally, it can test those detections in a sandboxed environment and cross-reference them against public detection rules. Emulate shows which logs record each technique, from attacks recorded in labs, and whether your detections' indicators appear in them. Everything exports to a spreadsheet, and attack flows to STIX. AI is opt-in throughout.
