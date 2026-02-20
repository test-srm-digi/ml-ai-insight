"""SHAP explainability module for vulnerability risk model."""
from typing import List, Optional, Tuple

import numpy as np
import pandas as pd
import shap


def explain_model(model, X_test: pd.DataFrame) -> Tuple[pd.DataFrame, np.ndarray]:
    """Compute SHAP values and feature importance.

    Args:
        model: Trained XGBoost Booster.
        X_test: Test feature matrix.

    Returns:
        (importance_df, shap_values) tuple.
    """
    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(X_test)

    importance = pd.DataFrame({
        "feature": X_test.columns,
        "importance": np.abs(shap_values).mean(axis=0),
    }).sort_values("importance", ascending=False).reset_index(drop=True)

    return importance, shap_values


def plot_shap_summary(shap_values, X_test: pd.DataFrame, save_path: Optional[str] = None):
    """Plot SHAP summary (beeswarm) plot."""
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(12, 8))
    shap.summary_plot(shap_values, X_test, show=False, max_display=20)

    if save_path:
        plt.savefig(save_path, dpi=150, bbox_inches="tight")
    plt.close("all")


def plot_shap_bar(importance_df: pd.DataFrame, top_n: int = 20, save_path: Optional[str] = None):
    """Plot bar chart of top feature importances."""
    import matplotlib.pyplot as plt

    top = importance_df.head(top_n)
    fig, ax = plt.subplots(figsize=(10, 8))
    ax.barh(range(len(top)), top["importance"].values, color="steelblue")
    ax.set_yticks(range(len(top)))
    ax.set_yticklabels(top["feature"].values)
    ax.invert_yaxis()
    ax.set_xlabel("Mean |SHAP value|")
    ax.set_title(f"Top {top_n} Feature Importances")

    if save_path:
        fig.savefig(save_path, dpi=150, bbox_inches="tight")
    plt.close(fig)


def explain_single_prediction(
    model, X_row: pd.DataFrame, feature_names: List[str]
) -> List[Tuple[str, float]]:
    """Get top 5 contributing features for a single prediction.

    Args:
        model: Trained XGBoost Booster.
        X_row: Single-row DataFrame.
        feature_names: List of feature names.

    Returns:
        List of (feature_name, shap_value) tuples, sorted by |shap|.
    """
    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(X_row)

    if len(shap_values.shape) == 1:
        row_shap = shap_values
    else:
        row_shap = shap_values[0]

    pairs = list(zip(feature_names, row_shap))
    pairs.sort(key=lambda x: abs(x[1]), reverse=True)
    return pairs[:5]


def get_shap_explanation_text(
    model, X_row: pd.DataFrame, feature_names: List[str]
) -> str:
    """Generate human-readable explanation for a single prediction.

    Returns a string describing the top contributing features.
    """
    top_features = explain_single_prediction(model, X_row, feature_names)

    lines = ["Risk Score Explanation:"]
    for feat_name, shap_val in top_features:
        direction = "increases" if shap_val > 0 else "decreases"
        lines.append(f"  - {feat_name} {direction} risk by {abs(shap_val):.4f}")

    return "\n".join(lines)
