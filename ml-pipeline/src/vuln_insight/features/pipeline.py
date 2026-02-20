"""Feature pipeline orchestrator.

Applies all 7 feature blocks to produce the complete feature matrix (~275 columns).
"""
import pandas as pd

from vuln_insight.features.cve_core import extract_cve_core_features
from vuln_insight.features.cwe_intelligence import extract_cwe_features
from vuln_insight.features.dependency import extract_dependency_features
from vuln_insight.features.repo_behavior import extract_repo_features
from vuln_insight.features.time_exposure import extract_time_features
from vuln_insight.features.text_embeddings import extract_text_features
from vuln_insight.features.user_behavior import extract_user_behavior_features


class FeaturePipeline:
    def __init__(self, use_embeddings=True, feature_blocks=None):
        """
        Args:
            use_embeddings: Whether to compute text embeddings (slow). False for quick testing.
            feature_blocks: List of block names to include. None = all blocks.
                Valid: ["cve_core", "cwe", "dependency", "repo", "time", "text", "user"]
        """
        self.use_embeddings = use_embeddings
        self.feature_blocks = feature_blocks
        self.feature_names_ = None

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        """Apply all feature blocks and concatenate.

        Returns a DataFrame with only feature columns (no identifiers, no label).
        """
        blocks = []
        active = self.feature_blocks or [
            "cve_core", "cwe", "dependency", "repo", "time", "text", "user"
        ]

        if "cve_core" in active:
            blocks.append(extract_cve_core_features(df))
        if "cwe" in active:
            blocks.append(extract_cwe_features(df))
        if "dependency" in active:
            blocks.append(extract_dependency_features(df))
        if "repo" in active:
            blocks.append(extract_repo_features(df))
        if "time" in active:
            blocks.append(extract_time_features(df))
        if "text" in active:
            blocks.append(extract_text_features(df, use_embeddings=self.use_embeddings))
        if "user" in active:
            blocks.append(extract_user_behavior_features(df))

        result = pd.concat(blocks, axis=1)

        # Replace inf/-inf with NaN, then fill NaN with 0
        result = result.replace([float("inf"), float("-inf")], float("nan"))
        result = result.fillna(0)

        self.feature_names_ = list(result.columns)
        return result

    def get_feature_names(self):
        return self.feature_names_
