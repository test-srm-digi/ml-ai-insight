"""Hybrid risk scoring: ML prediction + business rule multipliers."""
import numpy as np
import pandas as pd
import xgboost as xgb


def classify_tier(risk_score: float) -> str:
    """Classify risk score into tier."""
    if risk_score > 0.8:
        return "CRITICAL"
    if risk_score > 0.6:
        return "HIGH"
    if risk_score > 0.4:
        return "MEDIUM"
    return "LOW"


class HybridScorer:
    def __init__(self, model, weights=None):
        """
        Args:
            model: Trained XGBoost model (Booster).
            weights: Dict with keys ml, cvss, epss, exposure, repo_criticality.
        """
        self.model = model
        self.weights = weights or {
            "ml": 0.45,
            "cvss": 0.20,
            "epss": 0.15,
            "exposure": 0.10,
            "repo_criticality": 0.10,
        }

    def score(self, features_df: pd.DataFrame, raw_data_df: pd.DataFrame) -> pd.DataFrame:
        """Score vulnerabilities with hybrid formula.

        Args:
            features_df: Feature matrix (from FeaturePipeline).
            raw_data_df: Original canonical DataFrame (for business rule fields).

        Returns:
            DataFrame with ml_score, risk_score, tier, and contributing factors.
        """
        dmatrix = xgb.DMatrix(features_df, feature_names=list(features_df.columns))
        ml_scores = self.model.predict(dmatrix)

        results = pd.DataFrame(index=raw_data_df.index)
        results["ml_score"] = ml_scores

        # Normalized components
        results["normalized_cvss"] = (
            pd.to_numeric(raw_data_df.get("cvss_score", 0), errors="coerce")
            .fillna(0).clip(0, 10) / 10
        )
        results["normalized_epss"] = (
            pd.to_numeric(raw_data_df.get("epss_percentile", 0), errors="coerce")
            .fillna(0).clip(0, 1)
        )

        # Exposure score
        results["exposure_score"] = self._calc_exposure(features_df, raw_data_df)

        # Repo criticality (default 0.5 if not specified)
        if "repo_criticality" in raw_data_df.columns:
            results["repo_criticality"] = pd.to_numeric(
                raw_data_df["repo_criticality"], errors="coerce"
            ).fillna(0.5)
        else:
            results["repo_criticality"] = 0.5

        # Weighted combination
        results["risk_score"] = (
            self.weights["ml"] * results["ml_score"]
            + self.weights["cvss"] * results["normalized_cvss"]
            + self.weights["epss"] * results["normalized_epss"]
            + self.weights["exposure"] * results["exposure_score"]
            + self.weights["repo_criticality"] * results["repo_criticality"]
        )

        # Hard overrides
        results["risk_score"] = self._apply_overrides(results, raw_data_df)
        results["risk_score"] = results["risk_score"].clip(0, 1)

        # Tier classification
        results["tier"] = results["risk_score"].apply(classify_tier)

        return results

    def _calc_exposure(self, features_df, raw_data_df):
        """Calculate exposure sub-score."""
        exposure = pd.Series(0.0, index=raw_data_df.index)

        if "attack_vector_network" in features_df.columns:
            exposure += features_df["attack_vector_network"] * 0.4

        if "privileges_required_none" in features_df.columns:
            exposure += features_df["privileges_required_none"] * 0.3

        if "is_exploit_known" in features_df.columns:
            exposure += features_df["is_exploit_known"] * 0.3

        return exposure.clip(0, 1)

    def _apply_overrides(self, results, raw_data_df):
        """Apply business rule hard overrides."""
        risk = results["risk_score"].copy()

        # Withdrawn advisory = cap at 0.1
        if "is_withdrawn" in raw_data_df.columns:
            withdrawn = raw_data_df["is_withdrawn"] == 1
            risk.loc[withdrawn] = risk.loc[withdrawn].clip(upper=0.1)

        # CVSS >= 9.0 with high exposure = minimum 0.85
        if "cvss_score" in raw_data_df.columns:
            cvss = pd.to_numeric(raw_data_df["cvss_score"], errors="coerce").fillna(0)
            critical_exploit = (cvss >= 9.0) & (results["exposure_score"] > 0.5)
            risk.loc[critical_exploit] = risk.loc[critical_exploit].clip(lower=0.85)

        return risk
