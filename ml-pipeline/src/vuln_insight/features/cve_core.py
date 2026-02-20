"""Block A: CVE Core Features (~32 features).

Extracts fundamental CVE metadata including severity, scores, dates,
patch status, and CVSS vector one-hot encoding.
"""
import numpy as np
import pandas as pd

from vuln_insight.utils.cvss_parser import parse_cvss_vector, get_cvss_feature_names


SEVERITY_MAP = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


def extract_cve_core_features(df: pd.DataFrame) -> pd.DataFrame:
    """Extract ~32 CVE core features.

    Returns DataFrame with only computed feature columns, index matching input.
    """
    now = pd.Timestamp.now(tz="UTC")
    features = pd.DataFrame(index=df.index)

    # Severity numeric
    features["severity_numeric"] = (
        df["severity"].astype(str).str.upper().map(SEVERITY_MAP).fillna(0).astype(int)
    )

    # Direct scores
    features["cvss_score"] = pd.to_numeric(df.get("cvss_score", 0), errors="coerce").fillna(0.0)
    features["epss_score"] = pd.to_numeric(df.get("epss_score", 0), errors="coerce").fillna(0.0)
    features["epss_percentile"] = pd.to_numeric(df.get("epss_percentile", 0), errors="coerce").fillna(0.0)

    # Days since published/modified
    for col, feat in [("published_date", "days_since_published"), ("modified_date", "days_since_modified")]:
        if col in df.columns:
            dates = pd.to_datetime(df[col], errors="coerce", utc=True)
            features[feat] = (now - dates).dt.days.fillna(0).clip(lower=0).astype(int)
        else:
            features[feat] = 0

    # Binary flags
    features["is_withdrawn"] = df.get("is_withdrawn", 0).astype(int).fillna(0)
    features["has_patch"] = df.get("has_patch", 0).astype(int).fillna(0)
    features["num_references"] = pd.to_numeric(df.get("num_references", 0), errors="coerce").fillna(0).astype(int)
    features["num_sources"] = pd.to_numeric(df.get("num_sources", 0), errors="coerce").fillna(0).astype(int)

    # CVSS vector one-hot
    cvss_feature_names = get_cvss_feature_names()
    if "cvss_vector" in df.columns:
        cvss_rows = df["cvss_vector"].apply(parse_cvss_vector)
        cvss_df = pd.DataFrame(cvss_rows.tolist(), index=df.index)
        for col_name in cvss_feature_names:
            features[col_name] = cvss_df.get(col_name, 0).fillna(0).astype(int)
    else:
        for col_name in cvss_feature_names:
            features[col_name] = 0

    return features
