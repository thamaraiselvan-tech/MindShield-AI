def merge_tactics(llm_tactics, pattern_categories):
    """
    Merge LLM-detected tactics with pattern-matched categories.
    Avoids duplicates. Adds pattern-only categories if LLM missed them.
    """
    tactics = list(llm_tactics) if llm_tactics else []
    existing_names = {t.get("tactic", "").lower() for t in tactics}

    for category, count in (pattern_categories or {}).items():
        if category.lower() not in existing_names:
            tactics.append({
                "tactic": category,
                "description": f"Pattern-based detection found {count} indicator(s) matching this category.",
                "severity": "medium" if count >= 2 else "low",
                "evidence": "Detected via automated pattern matching",
            })

    return tactics
