"""Block D: Repo Behavioral Features (~40 features).

Computes per-repository aggregated statistics and merges them back
to each row for context-aware predictions.
"""
import numpy as np
import pandas as pd


def _get_col(df, col_name, default=0):
    """Safely get a column from a DataFrame, returning a Series with proper index."""
    if col_name in df.columns:
        return df[col_name]
    return pd.Series(default, index=df.index)


def extract_repo_features(df: pd.DataFrame) -> pd.DataFrame:
    """Extract ~40 repo behavioral features via groupby aggregates."""
    features = pd.DataFrame(index=df.index)
    repo_col = df.get("repo", pd.Series("", index=df.index)).fillna("unknown")

    if repo_col.nunique() == 0 or (repo_col == "").all():
        # No repo data — return all zeros
        for col_name in _get_feature_names():
            features[col_name] = 0
        return features

    # Total CVEs per repo
    repo_total = repo_col.value_counts()
    features["repo_total_cves"] = repo_col.map(repo_total).fillna(0).astype(int)

    # Time-windowed counts
    if "published_date" in df.columns:
        pub_dates = pd.to_datetime(df["published_date"], errors="coerce", utc=True)
        ref_date = pub_dates.max()
        if pd.notna(ref_date):
            df_temp = df.assign(_pub=pub_dates, _repo=repo_col)
            for days, feat_name in [(30, "repo_cve_count_30d"), (90, "repo_cve_count_90d")]:
                cutoff = ref_date - pd.Timedelta(days=days)
                recent = df_temp[df_temp["_pub"] >= cutoff].groupby("_repo").size()
                features[feat_name] = repo_col.map(recent).fillna(0).astype(int)
        else:
            features["repo_cve_count_30d"] = 0
            features["repo_cve_count_90d"] = 0
    else:
        features["repo_cve_count_30d"] = 0
        features["repo_cve_count_90d"] = 0

    # Severity counts per repo
    severity_col = df.get("severity", pd.Series("UNKNOWN", index=df.index)).astype(str).str.upper()
    df_sev = pd.DataFrame({"repo": repo_col, "severity": severity_col})
    for sev, feat_name in [("CRITICAL", "repo_critical_count"), ("HIGH", "repo_high_count"),
                           ("MEDIUM", "repo_medium_count"), ("LOW", "repo_low_count")]:
        sev_count = df_sev[df_sev["severity"] == sev].groupby("repo").size()
        features[feat_name] = repo_col.map(sev_count).fillna(0).astype(int)

    # Action rates
    action_col = df.get("user_action", pd.Series("", index=df.index)).astype(str).str.lower().str.strip()
    df_act = pd.DataFrame({"repo": repo_col, "action": action_col})
    total_per_repo = df_act.groupby("repo").size()

    fix_actions = {"fixed", "remediated", "patched"}
    fix_count = df_act[df_act["action"].isin(fix_actions)].groupby("repo").size()
    features["repo_fix_rate"] = (repo_col.map(fix_count).fillna(0) / repo_col.map(total_per_repo).clip(lower=1)).fillna(0)

    fp_count = df_act[df_act["action"] == "false_positive"].groupby("repo").size()
    features["repo_false_positive_rate"] = (repo_col.map(fp_count).fillna(0) / repo_col.map(total_per_repo).clip(lower=1)).fillna(0)

    skip_count = df_act[df_act["action"] == "skipped"].groupby("repo").size()
    features["repo_skip_rate"] = (repo_col.map(skip_count).fillna(0) / repo_col.map(total_per_repo).clip(lower=1)).fillna(0)

    # Score aggregates
    cvss = pd.to_numeric(_get_col(df, "cvss_score", 0), errors="coerce").fillna(0)
    epss = pd.to_numeric(_get_col(df, "epss_score", 0), errors="coerce").fillna(0)
    df_scores = pd.DataFrame({"repo": repo_col, "cvss": cvss, "epss": epss})

    repo_avg_cvss = df_scores.groupby("repo")["cvss"].mean()
    repo_max_cvss = df_scores.groupby("repo")["cvss"].max()
    repo_avg_epss = df_scores.groupby("repo")["epss"].mean()
    features["repo_avg_cvss"] = repo_col.map(repo_avg_cvss).fillna(0)
    features["repo_max_cvss"] = repo_col.map(repo_max_cvss).fillna(0)
    features["repo_avg_epss"] = repo_col.map(repo_avg_epss).fillna(0)

    # Severity ratios
    features["repo_severity_ratio_critical"] = (features["repo_critical_count"] / features["repo_total_cves"].clip(lower=1))
    features["repo_severity_ratio_high"] = (features["repo_high_count"] / features["repo_total_cves"].clip(lower=1))

    # Unique counts
    pkg_col = df.get("package_name", pd.Series("", index=df.index)).fillna("")
    cwe_col = df.get("primary_cwe", pd.Series("", index=df.index)).fillna("")
    df_uniq = pd.DataFrame({"repo": repo_col, "pkg": pkg_col, "cwe": cwe_col})
    repo_uniq_pkg = df_uniq.groupby("repo")["pkg"].nunique()
    repo_uniq_cwe = df_uniq.groupby("repo")["cwe"].nunique()
    features["repo_unique_packages"] = repo_col.map(repo_uniq_pkg).fillna(0).astype(int)
    features["repo_unique_cwes"] = repo_col.map(repo_uniq_cwe).fillna(0).astype(int)

    # Patch rate
    has_patch = pd.to_numeric(_get_col(df, "has_patch", 0), errors="coerce").fillna(0)
    df_patch = pd.DataFrame({"repo": repo_col, "has_patch": has_patch})
    repo_patch_rate = df_patch.groupby("repo")["has_patch"].mean()
    features["repo_has_patch_rate"] = repo_col.map(repo_patch_rate).fillna(0)

    # Average transitive deps
    trans = pd.to_numeric(_get_col(df, "transitive_dep_count", 0), errors="coerce").fillna(0)
    df_trans = pd.DataFrame({"repo": repo_col, "trans": trans})
    repo_avg_trans = df_trans.groupby("repo")["trans"].mean()
    features["repo_avg_transitive_deps"] = repo_col.map(repo_avg_trans).fillna(0)

    # CVE velocity
    if "published_date" in df.columns:
        pub_dates = pd.to_datetime(df["published_date"], errors="coerce", utc=True)
        df_vel = pd.DataFrame({"repo": repo_col, "pub": pub_dates})
        repo_span = df_vel.groupby("repo")["pub"].agg(lambda x: (x.max() - x.min()).days + 1 if len(x) > 1 else 1)
        repo_velocity = repo_col.map(repo_total).fillna(0) / repo_col.map(repo_span).clip(lower=1)
        features["repo_cve_velocity"] = repo_velocity.fillna(0)
    else:
        features["repo_cve_velocity"] = 0

    return features


def _get_feature_names():
    return [
        "repo_total_cves", "repo_cve_count_30d", "repo_cve_count_90d",
        "repo_critical_count", "repo_high_count", "repo_medium_count", "repo_low_count",
        "repo_fix_rate", "repo_false_positive_rate", "repo_skip_rate",
        "repo_avg_cvss", "repo_max_cvss", "repo_avg_epss",
        "repo_severity_ratio_critical", "repo_severity_ratio_high",
        "repo_unique_packages", "repo_unique_cwes",
        "repo_has_patch_rate", "repo_avg_transitive_deps", "repo_cve_velocity",
    ]
