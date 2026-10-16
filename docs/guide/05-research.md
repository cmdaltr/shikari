# Research

**Home → Research** finds threat groups by keyword, then shows which ATT&CK techniques they share. Use it to decide what to hunt when the question is "who targets finance in Europe?" rather than "detect APT29".

## Finding groups

| Control | What it does |
|---|---|
| Keyword box | Words matched against each group's ATT&CK description: a country (`Iran`), a sector (`Finance`), a technology. Add several |
| AND / OR | Groups must match all the keywords (AND) or any of them (OR) |
| Attributed / Targeted | For a country keyword: groups attributed to that country, or groups that have targeted it |
| Add Threat Groups by name | Add particular groups (`APT33`, `Lazarus Group`) to the keyword matches |

Matching groups appear as tags. Up to 20 are used. If more match, the extras are greyed out: remove some, or press **Continue with first 20**.

## The three buttons

| Button | What it does | Generates detections? |
|---|---|---|
| Consolidate Techniques | Builds a table of the techniques the groups use and which groups use each one | No |
| Hunt Threat Groups | Puts the groups' names into the Hunt tab, ready to hunt each | Not until you press Generate |
| Hunt Techniques | Puts the table's techniques into the Hunt tab, so a technique shared by several groups is hunted once | Not until you press Generate |

## The technique table

Columns: technique ID, name, tactic, the groups that use it, and how each group is linked to it (directly, through a campaign or through software). Sort by any column.

| View control | What it does |
|---|---|
| All tactics | Show one tactic only |
| Grouped / Per Actor | One row per technique, or one row per technique and group |
| Shaded rows (> 1 actor) | Techniques more than one of the groups use: the best value for a detection |
| Export: Actors, Techniques | CSV, XLSX or JSON. The XLSX is formatted for reporting |

## Data and limits

Everything here comes from ATT&CK's group descriptions and relationships, with no AI. A keyword only finds a group whose ATT&CK description uses that word. "Finance" won't find a group described only as targeting "banks".
