"""Block G: User Behavior Features (~20 features).

Historical action rates per CWE, package, severity, and repo.

NOTE: This uses full dataset aggregates for simplicity.
In production, use leave-one-out aggregation to prevent target leakage.
"""
import numpy as np
import pandas as pd


def extract_user_behavior_features(df: pd.DataFrame) -> pd.DataFrame:
    """Extract ~20 user behavior features from historical action patterns."""
    features = pd.DataFrame(index=df.index)

    action_col = df.get("user_action", pd.Series("", index=df.index)).astype(str).str.lower().str.strip()

    # Define action categories
    is_fixed = action_col.isin(["fixed", "remediated", "patched"]).astype(int)
    is_skipped = (action_col == "skipped").astype(int)
    is_fp = action_col.isin(["false_positive", "false positive"]).astype(int)

    # Group columns to compute rates for
    group_specs = [
        ("same_cwe", "primary_cwe"),
        ("same_package", "package_name"),
        ("same_severity", "severity"),
        ("same_repo", "repo"),
    ]

    for suffix, group_col in group_specs:
        grp = df.get(group_col, pd.Series("", index=df.index)).fillna("")
        df_temp = pd.DataFrame({"grp": grp, "fixed": is_fixed, "skipped": is_skipped, "fp": is_fp})
        group_counts = df_temp.groupby("grp").size()

        # Fix rate
        fix_sum = df_temp.groupby("grp")["fixed"].sum()
        fix_rate = (fix_sum / group_counts.clip(lower=1)).fillna(0)
        features[f"historical_fix_rate_{suffix}"] = grp.map(fix_rate).fillna(0)

        # Skip rate
        skip_sum = df_temp.groupby("grp")["skipped"].sum()
        skip_rate = (skip_sum / group_counts.clip(lower=1)).fillna(0)
        features[f"historical_skip_rate_{suffix}"] = grp.map(skip_rate).fillna(0)

        # False positive rate
        fp_sum = df_temp.groupby("grp")["fp"].sum()
        fp_rate = (fp_sum / group_counts.clip(lower=1)).fillna(0)
        features[f"historical_fp_rate_{suffix}"] = grp.map(fp_rate).fillna(0)

    # CWE action consistency (std of fix rate per CWE group)
    cwe_col = df.get("primary_cwe", pd.Series("", index=df.index)).fillna("")
    df_cons = pd.DataFrame({"cwe": cwe_col, "fixed": is_fixed})
    cwe_std = df_cons.groupby("cwe")["fixed"].std().fillna(0)
    features["cwe_action_consistency"] = cwe_col.map(cwe_std).fillna(0)

    # Package action consistency
    pkg_col = df.get("package_name", pd.Series("", index=df.index)).fillna("")
    df_pkg_cons = pd.DataFrame({"pkg": pkg_col, "fixed": is_fixed})
    pkg_std = df_pkg_cons.groupby("pkg")["fixed"].std().fillna(0)
    features["package_action_consistency"] = pkg_col.map(pkg_std).fillna(0)

    # Repo action diversity
    repo_col = df.get("repo", pd.Series("", index=df.index)).fillna("")
    df_div = pd.DataFrame({"repo": repo_col, "action": action_col})
    unique_actions_per_repo = df_div.groupby("repo")["action"].nunique()
    total_possible = max(action_col.nunique(), 1)
    repo_diversity = (unique_actions_per_repo / total_possible).fillna(0)
    features["repo_action_diversity"] = repo_col.map(repo_diversity).fillna(0)

    # Severity action alignment
    sev_col = df.get("severity", pd.Series("UNKNOWN", index=df.index)).astype(str).str.upper()
    df_align = pd.DataFrame({"sev": sev_col, "fixed": is_fixed})
    sev_fix_rate = df_align.groupby("sev")["fixed"].mean().fillna(0)
    features["severity_action_alignment"] = sev_col.map(sev_fix_rate).fillna(0)

    return features
