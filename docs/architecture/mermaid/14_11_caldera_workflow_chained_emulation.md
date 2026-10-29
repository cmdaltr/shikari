# 11. CALDERA Workflow — Chained Emulation and Static Checks

How a CALDERA operation validates detections and correlations. CALDERA is used for what Atomic Red Team runs can't give: fact chaining between steps and a real implant (sandcat) on the agents. Archer plans the operation first and changes nothing on CALDERA until it's confirmed, then runs it, collects each step's command, host, times and output, optionally captures the agent host's logs over each step's window — over the agent's own C2 (any OS, nothing installed on the host) or a lab machine Lab manages — and checks saved detections and correlations against that evidence statically, with no AI.

```mermaid
%%{init: {'theme': 'base', 'themeVariables': {'lineColor': '#ff6600', 'edgeLabelBackground': '#ffffff', 'primaryColor': '#4a90d9', 'primaryTextColor': '#ffffff', 'primaryBorderColor': '#2c5f8a', 'secondaryColor': '#e8e8e8', 'tertiaryColor': '#f5f5f5', 'clusterBkg': '#f0f0f0', 'clusterBorder': '#999999', 'titleColor': '#000000', 'nodeTextColor': '#000000', 'background': '#ffffff'}}}%%
flowchart TD
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

    style TARGET fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style TECH fill:#7ed321,stroke:#4a8c0f,color:#fff
    style CORR fill:#7ed321,stroke:#4a8c0f,color:#fff
    style STOP fill:#d0021b,stroke:#8b0000,color:#fff
    style CHECK fill:#4a90d9,stroke:#2c5f8a,color:#fff
    style CONFIRM fill:#f8e71c,stroke:#b8a700,color:#333
    style CAPTURE fill:#f8e71c,stroke:#b8a700,color:#333
    linkStyle default stroke:#ff6600,stroke-width:3px
```
