def compile_mde_queries(indicator_mapping, indicators, indicator_type, mde_queries):
    # Mapping and building MDE queries
    for table, fields in indicator_mapping[indicator_type]["MDE"].items():
        has_all_indicators = []
        has_any_indicators = []
        for indicator in indicators:
            if " " in indicator:
                # Split into parts for has_all
                parts = [part.strip() for part in indicator.split()]
                has_all_indicators.append(parts)
            else:
                has_any_indicators.append(indicator)

        # Format indicators
        indicator_clauses = []
        for parts in has_all_indicators:
            all_str = '", "'.join(parts)
            indicator_clauses.append(f'has_all("{all_str}")')
        if has_any_indicators:
            any_str = '", "'.join(has_any_indicators)
            indicator_clauses.append(f'has_any("{any_str}")')

        condition = " or ".join(
            [f"{field} {clause}" for field in fields for clause in indicator_clauses]
        )
        mde_queries.append(f"{table}\n| where Timestamp > ago(1d)\n| where {condition}")

    return mde_queries


def compile_splunk_queries(
    indicator_mapping, indicators, indicator_type, splunk_queries
):
    # Mapping and building Splunk queries
    for index, fields in indicator_mapping[indicator_type]["Splunk"].items():
        field_clauses = []
        for field in fields:
            indicator_clauses = []
            for indicator in indicators:
                if " " in indicator:
                    # Multi-word indicator: AND each part, grouped in parentheses
                    parts = indicator.split()
                    and_clauses = []
                    for part in parts:
                        and_clauses.append(f'properties.{field}="*{part}*"')
                    indicator_clauses.append("(" + " AND ".join(and_clauses) + ")")
                else:
                    # Single-word indicator
                    indicator_clauses.append(f'properties.{field}="*{indicator}*"')
            field_clauses.append(" OR ".join(indicator_clauses))

        condition = " OR ".join(field_clauses)
        splunk_queries.append(f"index={index} earliest=-1d\n({condition})")

    return splunk_queries
