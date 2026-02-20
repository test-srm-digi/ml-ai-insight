"""Block E: Time & Exposure Features (~20 features).

Temporal features, exposure windows, risk dynamics, and composite indicators.
"""
import numpy as np
import pandas as pd


def _get_col(df, col_name, default=0):
    """Safely get a column from a DataFrame, returning a Series with proper index."""
    if col_name in df.columns:
        return df[col_name]
    return pd.Series(default, index=df.index)


def extract_time_features(df: pd.DataFrame) -> pd.DataFrame:
    """Extract ~20 time and exposure features."""
    now = pd.Timestamp.now(tz="UTC")
    features = pd.DataFrame(index=df.index)

    # Parse dates
    pub = pd.to_datetime(_get_col(df, "published_date", None), errors="coerce", utc=True)
    mod = pd.to_datetime(_get_col(df, "modified_date", None), errors="coerce", utc=True)
    det = pd.to_datetime(_get_col(df, "detection_time", None), errors="coerce", utc=True)

    # Days calculations
    features["detection_delay_days"] = _safe_days(det - pub)
    features["cve_age_days"] = _safe_days(now - pub)
    features["days_since_detection"] = _safe_days(now - det)

    # Patch available delay
    has_patch = pd.to_numeric(_get_col(df, "has_patch", 0), errors="coerce").fillna(0)
    features["patch_available_delay"] = np.where(
        has_patch > 0, _safe_days(det - pub), 0
    )

    # Exposure window
    features["exposure_window_days"] = np.where(
        has_patch > 0, 0, _safe_days(now - pub)
    )

    # Binary time flags
    features["is_recent_cve"] = (features["cve_age_days"] <= 30).astype(int)
    features["is_old_cve"] = (features["cve_age_days"] > 365).astype(int)

    # Exploit known heuristic
    refs = _get_col(df, "references", "").astype(str).str.lower()
    num_refs = pd.to_numeric(_get_col(df, "num_references", 0), errors="coerce").fillna(0)
    features["is_exploit_known"] = (
        refs.str.contains("exploit", na=False) | (num_refs > 5)
    ).astype(int)

    # Patch age
    features["patch_age_days"] = np.where(
        has_patch > 0, _safe_days(now - mod), 0
    )

    # Composite ratios
    cve_age = features["cve_age_days"].clip(lower=1)
    features["time_to_patch_ratio"] = (features["detection_delay_days"] / cve_age).fillna(0).clip(0, 10)

    cvss = pd.to_numeric(_get_col(df, "cvss_score", 0), errors="coerce").fillna(0)
    epss = pd.to_numeric(_get_col(df, "epss_score", 0), errors="coerce").fillna(0)

    features["epss_cvss_ratio"] = (epss / (cvss / 10 + 0.001)).fillna(0).clip(0, 100)
    features["risk_acceleration"] = (epss * (1 / (features["cve_age_days"] + 1))).fillna(0)

    severity_num = _get_col(df, "severity_numeric", 0)
    severity_num = pd.to_numeric(severity_num, errors="coerce").fillna(0)
    features["severity_age_interaction"] = severity_num * features["cve_age_days"]

    num_sources = pd.to_numeric(_get_col(df, "num_sources", 0), errors="coerce").fillna(0)
    features["source_diversity"] = (num_sources / 4).clip(0, 1)
    features["reference_density"] = (num_refs / (features["cve_age_days"] + 1)).fillna(0)

    return features


def _safe_days(timedelta_series) -> pd.Series:
    """Convert timedelta series to integer days, handling NaT."""
    if isinstance(timedelta_series, (int, float)):
        return pd.Series(0)
    days = timedelta_series.dt.days
    return days.fillna(0).clip(lower=0).astype(int)
