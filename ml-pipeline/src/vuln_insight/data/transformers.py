"""Data transformer — unifies JSON API and CSV/DB schemas into canonical form.

Both data sources produce DataFrames with potentially different column names
and structures. This module normalizes them into a single canonical schema
that the feature engineering pipeline expects.
"""
from datetime import datetime, timezone
from typing import Optional

import numpy as np
import pandas as pd


# Canonical columns expected by the feature pipeline
CANONICAL_COLUMNS = [
    # Identifiers
    "cve_id", "vuln_id", "title", "repo", "release",
    # Package
    "package_name", "package_version", "ecosystem", "purl",
    # Severity & scores
    "severity", "cvss_score", "cvss_vector", "epss_score", "epss_percentile",
    # Dates
    "published_date", "modified_date", "release_date", "detection_time",
    # Patch
    "has_patch", "fix_versions", "patch_recommendation",
    # CWE
    "cwes", "cwe_count", "primary_cwe",
    # Description & references
    "cve_description", "num_references", "sources", "num_sources",
    # Dependencies
    "transitive_dep_count",
    # Flags
    "is_withdrawn",
    # User action (label for training)
    "user_action", "status",
    # Licence
    "licence",
]


def to_canonical(df: pd.DataFrame) -> pd.DataFrame:
    """Transform a DataFrame from any source into canonical schema.

    Handles missing columns by filling with appropriate defaults.
    """
    result = df.copy()

    # Ensure all canonical columns exist
    for col in CANONICAL_COLUMNS:
        if col not in result.columns:
            result[col] = _default_for(col)

    # Normalize severity
    severity_map = {
        "CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM",
        "LOW": "LOW", "UNKNOWN": "UNKNOWN", "NONE": "UNKNOWN",
        "": "UNKNOWN", "NAN": "UNKNOWN",
    }
    result["severity"] = (
        result["severity"].astype(str).str.strip().str.upper()
        .map(severity_map).fillna("UNKNOWN")
    )

    # Numeric severity
    result["severity_numeric"] = result["severity"].map({
        "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0
    }).fillna(0).astype(int)

    # Parse dates if they're strings
    for col in ["published_date", "modified_date", "detection_time", "release_date"]:
        if col in result.columns:
            result[col] = pd.to_datetime(result[col], errors="coerce", utc=True)

    # Normalize scores
    result["cvss_score"] = pd.to_numeric(result["cvss_score"], errors="coerce").fillna(0.0)
    result["epss_score"] = pd.to_numeric(result["epss_score"], errors="coerce").fillna(0.0)
    result["epss_percentile"] = pd.to_numeric(
        result["epss_percentile"], errors="coerce"
    ).fillna(0.0)

    # CWE processing
    if "cwes" in result.columns:
        result["cwes"] = result["cwes"].astype(str).fillna("")
        result["cwe_count"] = result["cwes"].apply(_count_cwes)
        result["primary_cwe"] = result["cwes"].apply(_first_cwe)

    # has_patch: ensure boolean
    result["has_patch"] = result["has_patch"].apply(_to_bool)

    # is_withdrawn
    result["is_withdrawn"] = result.apply(
        lambda row: 1 if "withdrawn" in str(row.get("title", "")).lower()
        or "withdrawn" in str(row.get("status", "")).lower() else 0,
        axis=1,
    )

    # Normalize user action
    result["user_action"] = (
        result["user_action"].astype(str).str.strip().str.lower()
    )

    # Transitive deps
    result["transitive_dep_count"] = pd.to_numeric(
        result["transitive_dep_count"], errors="coerce"
    ).fillna(0).astype(int)

    # Source count
    result["num_sources"] = result["sources"].apply(
        lambda x: len([s.strip() for s in str(x).split(",") if s.strip()])
        if pd.notna(x) and str(x) != "" else 0
    )

    return result


def create_label(df: pd.DataFrame, positive_actions: Optional[list] = None) -> pd.DataFrame:
    """Create binary label from user_action column.

    Args:
        df: DataFrame with 'user_action' column.
        positive_actions: Actions considered "actionable" (label=1).
            Default: ["fixed", "remediated", "patched", "accepted"]

    Returns:
        DataFrame with 'label' column added.
    """
    if positive_actions is None:
        positive_actions = ["fixed", "remediated", "patched", "accepted"]

    negative_actions = ["false_positive", "false positive", "skipped", "ignored", "deferred"]

    result = df.copy()
    result["label"] = result["user_action"].apply(
        lambda x: 1 if str(x).strip().lower() in positive_actions
        else (0 if str(x).strip().lower() in negative_actions else np.nan)
    )
    return result


def _default_for(col: str):
    """Return a sensible default for a missing canonical column."""
    numeric_cols = {
        "cvss_score", "epss_score", "epss_percentile", "transitive_dep_count",
        "num_references", "num_sources", "cwe_count",
    }
    bool_cols = {"has_patch", "is_withdrawn"}
    if col in numeric_cols:
        return 0
    if col in bool_cols:
        return 0
    return ""


def _count_cwes(cwe_str: str) -> int:
    if not cwe_str or cwe_str == "nan":
        return 0
    return len([c.strip() for c in cwe_str.split(",") if c.strip()])


def _first_cwe(cwe_str: str) -> str:
    if not cwe_str or cwe_str == "nan":
        return ""
    parts = [c.strip() for c in cwe_str.split(",") if c.strip()]
    return parts[0] if parts else ""


def _to_bool(val) -> int:
    if isinstance(val, bool):
        return 1 if val else 0
    if isinstance(val, (int, float)):
        return 1 if val else 0
    s = str(val).strip().lower()
    return 1 if s in ("true", "yes", "1", "patched") else 0
