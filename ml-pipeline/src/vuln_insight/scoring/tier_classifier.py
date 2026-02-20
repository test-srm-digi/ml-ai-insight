"""Tier classification utilities."""
import pandas as pd

from vuln_insight.scoring.hybrid_scorer import classify_tier


def classify_batch(risk_scores: pd.Series) -> pd.Series:
    """Classify a series of risk scores into tiers."""
    return risk_scores.apply(classify_tier)


def tier_summary(tiers: pd.Series) -> dict:
    """Generate summary statistics for tier distribution."""
    counts = tiers.value_counts()
    total = len(tiers)
    return {
        "total": total,
        "critical": int(counts.get("CRITICAL", 0)),
        "high": int(counts.get("HIGH", 0)),
        "medium": int(counts.get("MEDIUM", 0)),
        "low": int(counts.get("LOW", 0)),
        "critical_pct": counts.get("CRITICAL", 0) / max(total, 1) * 100,
        "high_pct": counts.get("HIGH", 0) / max(total, 1) * 100,
    }


TIER_THRESHOLDS = {
    "CRITICAL": 0.8,
    "HIGH": 0.6,
    "MEDIUM": 0.4,
    "LOW": 0.0,
}
