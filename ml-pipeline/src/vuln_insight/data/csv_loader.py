"""CSV/Excel file loader with column normalization.

Loads vulnerability data from CSV or Excel files and normalizes column names
to the canonical schema used by the feature engineering pipeline.
"""
from pathlib import Path
from typing import Optional, Union

import pandas as pd


# Mapping from common CSV column names (case-insensitive) to canonical names
COLUMN_MAP = {
    "repo": "repo",
    "repository": "repo",
    "release": "release",
    "release_name": "release",
    "release date": "release_date",
    "release_date": "release_date",
    "releasedate": "release_date",
    "licence": "licence",
    "license": "licence",
    "severity": "severity",
    "status": "status",
    "cve id": "cve_id",
    "cve_id": "cve_id",
    "cveid": "cve_id",
    "cve": "cve_id",
    "cwe id": "primary_cwe",
    "cwe_id": "primary_cwe",
    "cweid": "primary_cwe",
    "cwe": "primary_cwe",
    "current version": "package_version",
    "current_version": "package_version",
    "currentversion": "package_version",
    "fix package versions": "fix_versions",
    "fix_package_versions": "fix_versions",
    "fixpackageversions": "fix_versions",
    "fix versions": "fix_versions",
    "detection time": "detection_time",
    "detection_time": "detection_time",
    "detectiontime": "detection_time",
    "last detected in repo": "detection_time",
    "transitive dependencies": "transitive_dep_count",
    "transitive_dependencies": "transitive_dep_count",
    "transitivedependencies": "transitive_dep_count",
    "user actions": "user_action",
    "user_actions": "user_action",
    "useractions": "user_action",
    "user action": "user_action",
    "user_action": "user_action",
    "epss score": "epss_score",
    "epss_score": "epss_score",
    "epssscore": "epss_score",
    "cvss score": "cvss_score",
    "cvss_score": "cvss_score",
    "cvssscore": "cvss_score",
    "cve description": "cve_description",
    "cve_description": "cve_description",
    "cvedescription": "cve_description",
    "description": "cve_description",
    "cve- weaknesses(cwe)": "cwes",
    "cve weaknesses": "cwes",
    "cve_weaknesses": "cwes",
    "cve-weaknesses": "cwes",
    "weaknesses": "cwes",
    "cvss vector": "cvss_vector",
    "cvss_vector": "cvss_vector",
    "cvssvector": "cvss_vector",
    "sources": "sources",
    "sources(nvd, osv...)": "sources",
    "source": "sources",
}


def load_csv(path: Union[str, Path], sheet_name: Optional[str] = None) -> pd.DataFrame:
    """Load vulnerability data from CSV or Excel file.

    Args:
        path: Path to CSV or Excel file.
        sheet_name: For Excel files, which sheet to read (default: first sheet).

    Returns:
        DataFrame with normalized column names matching canonical schema.
    """
    path = Path(path)

    if path.suffix in (".xlsx", ".xls"):
        df = pd.read_excel(path, sheet_name=sheet_name or 0)
    else:
        df = pd.read_csv(path)

    return normalize_columns(df)


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize column names to canonical schema."""
    # Lowercase and strip whitespace from column names
    df.columns = [col.strip().lower() for col in df.columns]

    # Apply column mapping
    rename_map = {}
    for col in df.columns:
        if col in COLUMN_MAP:
            rename_map[col] = COLUMN_MAP[col]

    df = df.rename(columns=rename_map)

    # Normalize severity to uppercase
    if "severity" in df.columns:
        df["severity"] = df["severity"].astype(str).str.strip().str.upper()

    # Normalize user_action to lowercase
    if "user_action" in df.columns:
        df["user_action"] = df["user_action"].astype(str).str.strip().str.lower()

    # Parse transitive_dep_count to numeric
    if "transitive_dep_count" in df.columns:
        df["transitive_dep_count"] = pd.to_numeric(
            df["transitive_dep_count"], errors="coerce"
        ).fillna(0).astype(int)

    # Parse scores to float
    for col in ["cvss_score", "epss_score"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    # Parse dates
    for col in ["release_date", "detection_time"]:
        if col in df.columns:
            df[col] = pd.to_datetime(df[col], errors="coerce", utc=True)

    return df
