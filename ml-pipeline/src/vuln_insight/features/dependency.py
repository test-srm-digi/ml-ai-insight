"""Block C: Package/Dependency Features (~40 features).

Extracts dependency depth, version gap analysis, ecosystem one-hot,
and package-level statistics from the dataset.
"""
import numpy as np
import pandas as pd


ECOSYSTEMS = ["npm", "pypi", "maven", "go", "nuget", "rubygems", "cargo", "composer"]


def _parse_version(version_str: str) -> tuple:
    """Parse semver-like string into (major, minor, patch) tuple."""
    if not version_str or str(version_str) == "nan":
        return (0, 0, 0)
    # Remove leading 'v' if present
    v = str(version_str).strip().lstrip("vV")
    # Remove pre-release suffixes
    for sep in ["-", "+", "_", " "]:
        v = v.split(sep)[0]
    parts = v.split(".")
    result = []
    for p in parts[:3]:
        try:
            result.append(int(p))
        except (ValueError, TypeError):
            result.append(0)
    while len(result) < 3:
        result.append(0)
    return tuple(result[:3])


def _first_fix_version(fix_str: str) -> str:
    """Get the first fix version from comma-separated list."""
    if not fix_str or str(fix_str) == "nan":
        return ""
    parts = [p.strip() for p in str(fix_str).split(",") if p.strip()]
    return parts[0] if parts else ""


def extract_dependency_features(df: pd.DataFrame) -> pd.DataFrame:
    """Extract ~40 package/dependency features."""
    features = pd.DataFrame(index=df.index)

    # Dependency depth
    trans_count = pd.to_numeric(df.get("transitive_dep_count", 0), errors="coerce").fillna(0).astype(int)
    features["dependency_depth"] = trans_count
    features["is_direct_dependency"] = (trans_count == 0).astype(int)
    features["is_transitive_dependency"] = (trans_count > 0).astype(int)
    features["transitive_dep_count"] = trans_count

    # Version gap analysis
    pkg_versions = df.get("package_version", pd.Series("", index=df.index)).fillna("")
    fix_versions_col = df.get("fix_versions", pd.Series("", index=df.index)).fillna("")

    version_gaps = []
    for idx in df.index:
        current = _parse_version(str(pkg_versions.loc[idx]))
        fix_str = _first_fix_version(str(fix_versions_col.loc[idx]))
        fix = _parse_version(fix_str)
        gap = (
            max(0, fix[0] - current[0]),
            max(0, fix[1] - current[1]) if fix_str else 0,
            max(0, fix[2] - current[2]) if fix_str else 0,
        )
        version_gaps.append(gap)

    gaps_df = pd.DataFrame(version_gaps, index=df.index, columns=["version_gap_major", "version_gap_minor", "version_gap_patch"])
    features["version_gap_major"] = gaps_df["version_gap_major"]
    features["version_gap_minor"] = gaps_df["version_gap_minor"]
    features["version_gap_patch"] = gaps_df["version_gap_patch"]
    features["is_major_upgrade"] = (features["version_gap_major"] > 0).astype(int)

    # Fix versions count
    features["num_fix_versions"] = fix_versions_col.apply(
        lambda x: len([p.strip() for p in str(x).split(",") if p.strip()]) if x and str(x) != "nan" else 0
    )

    # Affected ranges
    features["num_affected_ranges"] = pd.to_numeric(
        df.get("num_affected_ranges", 0), errors="coerce"
    ).fillna(0).astype(int)

    # Has fix available
    features["has_fix_available"] = fix_versions_col.apply(
        lambda x: 1 if x and str(x).strip() and str(x) != "nan" else 0
    )

    # Ecosystem one-hot
    ecosystem_col = df.get("ecosystem", pd.Series("", index=df.index)).astype(str).str.lower().str.strip()
    for eco in ECOSYSTEMS:
        features[f"package_ecosystem_{eco}"] = (ecosystem_col == eco).astype(int)

    # Package-level statistics computed from dataset
    pkg_col = df.get("package_name", pd.Series("", index=df.index)).fillna("")
    pkg_counts = pkg_col.value_counts()
    features["package_name_frequency"] = pkg_col.map(pkg_counts).fillna(0).astype(int)

    # CVE density per package
    if "cve_id" in df.columns:
        pkg_cve = df.groupby("package_name")["cve_id"].nunique()
        features["package_name_cve_density"] = pkg_col.map(pkg_cve).fillna(0).astype(int)
    else:
        features["package_name_cve_density"] = features["package_name_frequency"]

    return features
