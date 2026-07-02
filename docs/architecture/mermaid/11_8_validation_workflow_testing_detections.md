# 8. Validation Workflow — Testing Detections

The detection validation loop: check Docker availability → start sandboxed SIEM → generate realistic test events → run detection query → measure true/false positives and misses → if needs work, AI suggests improvements and re-tests → accept validated detection → clean up containers.

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
