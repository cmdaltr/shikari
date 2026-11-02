# Cyber Powers

**Intel → Cyber Powers** shows national cyber capability on an Equal Earth world map, in three views. Hover a country for its details; hover or press a key item to fade the rest. Your own country (Profile → Country) is green in every view.

## The three views

| View | Countries are shaded by | Source |
|---|---|---|
| Nations | Cyber power tier: Tier 1, 2 or 3 | IISS, *Cyber Capabilities and National Power* (volumes 1 and 2) |
| Groups | How firmly ATT&CK attributes threat groups to the country: darker is firmer | ATT&CK group descriptions |
| Targets | How many ATT&CK groups are described as targeting the country: darker is more | ATT&CK group descriptions |

The cards under the map list the countries in each tier or confidence level, or the most targeted countries, with their flags.

## Attribution confidence

Shikari reads each group's ATT&CK description for attribution wording. No AI is used.

| Level | Wording |
|---|---|
| High | A named government body or unit ("GRU Unit 26165", "Ministry of State Security"), or an indictment |
| Moderate | A plain statement ("a North Korea-based group") |
| Low | Hedged ("suspected", "likely", "assessed to be") |

Countries the description names as targets, or as the source of an accusation, aren't counted as the group's sponsor.

## The tooltip

| View | Shows |
|---|---|
| Nations, Groups | IISS tier, attribution counts by confidence, primary motivation (the share of its groups' objectives: espionage, financial, destruction…), and a sample of its groups |
| Targets | How many groups target it, which nations they mostly come from, their motivation, and a sample of the groups |

## Limits

ATT&CK reflects what western vendors and governments publish. It under-counts some attackers (western states, for example) and over-counts some targets. The tiers are the IISS's assessment at the time of publication.
