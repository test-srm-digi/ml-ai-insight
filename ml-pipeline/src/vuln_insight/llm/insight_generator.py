"""Generate insights from ML model outputs using LLM."""
from typing import Optional

import pandas as pd

from vuln_insight.llm.bedrock_client import BedrockClient


class InsightGenerator:
    def __init__(self, bedrock_client: Optional[BedrockClient] = None):
        self.client = bedrock_client or BedrockClient()

    def explain_single(
        self, vuln_row: dict, shap_top_features: list, risk_score: float, tier: str
    ) -> str:
        """Explain a single vulnerability prediction."""
        return self.client.explain_vulnerability(
            vuln_row, shap_top_features, risk_score, tier
        )

    def generate_batch_insights(
        self,
        scored_df: pd.DataFrame,
        raw_df: pd.DataFrame,
        shap_values,
        feature_names: list,
        top_n: int = 10,
    ) -> list:
        """Generate explanations for the top N riskiest vulnerabilities."""
        top_indices = scored_df.nlargest(top_n, "risk_score").index

        insights = []
        for idx in top_indices:
            vuln_data = raw_df.loc[idx].to_dict()

            # Top 5 SHAP features for this prediction
            loc = scored_df.index.get_loc(idx)
            row_shap = shap_values[loc]
            top_features = sorted(
                zip(feature_names, row_shap),
                key=lambda x: abs(x[1]),
                reverse=True,
            )[:5]

            risk_score = scored_df.loc[idx, "risk_score"]
            tier = scored_df.loc[idx, "tier"]

            explanation = self.client.explain_vulnerability(
                vuln_data, top_features, risk_score, tier
            )

            insights.append({
                "cve_id": vuln_data.get("cve_id", ""),
                "risk_score": risk_score,
                "tier": tier,
                "explanation": explanation,
            })

        return insights

    def generate_portfolio_summary(
        self, scored_df: pd.DataFrame, raw_df: pd.DataFrame
    ) -> str:
        """Generate a portfolio-level summary from scored data."""
        summary = {
            "total_vulnerabilities": len(scored_df),
            "tier_counts": scored_df["tier"].value_counts().to_dict(),
            "avg_risk_score": float(scored_df["risk_score"].mean()),
            "top_repos": [],
            "top_cves": [],
            "cwe_patterns": [],
        }

        # Top repos by average risk
        if "repo" in raw_df.columns:
            merged = scored_df.join(raw_df[["repo"]])
            repo_risk = merged.groupby("repo")["risk_score"].agg(["mean", "count"])
            repo_risk = repo_risk.sort_values("mean", ascending=False).head(3)
            summary["top_repos"] = [
                {"repo": r, "avg_risk": round(row["mean"], 3), "cve_count": int(row["count"])}
                for r, row in repo_risk.iterrows()
            ]

        # Top CVEs
        top = scored_df.nlargest(5, "risk_score")
        for idx in top.index:
            summary["top_cves"].append({
                "cve_id": raw_df.loc[idx].get("cve_id", "") if idx in raw_df.index else "",
                "risk_score": round(float(scored_df.loc[idx, "risk_score"]), 3),
                "tier": scored_df.loc[idx, "tier"],
            })

        # CWE patterns
        if "primary_cwe" in raw_df.columns:
            cwe_counts = raw_df["primary_cwe"].value_counts().head(5).to_dict()
            summary["cwe_patterns"] = [
                {"cwe": k, "count": int(v)} for k, v in cwe_counts.items()
            ]

        return self.client.generate_portfolio_summary(summary)
