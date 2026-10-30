# 12. Adversary Ranking — Who Is Most Likely To Target You

The Ordered Adversary List (`archer.intelligence.adversary_ranking`): the top-10 ATT&CK groups most likely to target a profiled organisation, from four offline, no-AI signals — industry, geography, exposed OSINT and public incidents. Each signal reads data Archer already holds or caches; the ranking combines them into a likelihood and band, shown on /exposure and /review. Setting an **Organisation** on your profile auto-profiles that company and stars it in the catalogue.

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
