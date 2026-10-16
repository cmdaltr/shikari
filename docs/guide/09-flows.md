# Flows

**Detections → Flows** lists the attack flow of every group, report and CVE in your Library. Choose one to see what you can and can't detect across its attack. The same flow appears at the foot of each [Results](06-results.md) page.

A flow appears once its results are saved with **Save to Library**. If it's listed as "not built yet", open its results once and it will be saved.

## Reading a flow

Each column is an ATT&CK tactic, in kill-chain order. Each card is a technique the group uses.

| Mark | Meaning |
|---|---|
| SIEM logos on a card | The SIEMs you have a detection for it on |
| No detection | Attributed to the group, but you have no detection for it |
| Intel only | Reconnaissance or Resource Development: activity no log source of yours sees |

The summary line counts techniques detected and gaps.

## Controls

| Control | What it does |
|---|---|
| SIEM buttons | Show coverage and correlations for one SIEM |
| Hide Undetected | Hide techniques with no detection on the selected SIEMs |
| Links | Draw the correlations between techniques |
| Select, Hide Selected, Hide Others, Show All | Pick cards (or ⌘/Ctrl-click) and focus the view on them |
| Horizontal | Lay the tactics out as columns or rows |
| Forward | Kill-chain order forwards or backwards |
| Undo, Reset | Undo a change (⌘/Ctrl-Z), or go back to the default view |

## Limits

A flow shows what ATT&CK attributes to the group, plus what the run found. A technique the group uses that ATT&CK doesn't document won't appear.
