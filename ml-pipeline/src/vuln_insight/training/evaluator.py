"""Model evaluation metrics: AUC, precision, recall, F1, confusion matrix."""
from typing import Dict, Optional

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    auc,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)


def compute_metrics(
    y_true: np.ndarray, y_pred_proba: np.ndarray, threshold: float = 0.5
) -> Dict:
    """Compute classification metrics.

    Args:
        y_true: True binary labels.
        y_pred_proba: Predicted probabilities.
        threshold: Classification threshold.

    Returns:
        Dict with auc, precision, recall, f1, accuracy, confusion_matrix.
    """
    y_pred = (y_pred_proba >= threshold).astype(int)

    return {
        "auc": roc_auc_score(y_true, y_pred_proba),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "accuracy": accuracy_score(y_true, y_pred),
        "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
        "threshold": threshold,
        "total_samples": len(y_true),
        "positive_rate": float(y_true.sum() / len(y_true)),
    }


def print_evaluation_report(metrics: Dict):
    """Print formatted evaluation report."""
    print("\n" + "=" * 50)
    print("MODEL EVALUATION REPORT")
    print("=" * 50)
    print(f"  AUC:        {metrics['auc']:.4f}")
    print(f"  Precision:  {metrics['precision']:.4f}")
    print(f"  Recall:     {metrics['recall']:.4f}")
    print(f"  F1 Score:   {metrics['f1']:.4f}")
    print(f"  Accuracy:   {metrics['accuracy']:.4f}")
    print(f"  Threshold:  {metrics['threshold']}")
    print(f"  Samples:    {metrics['total_samples']}")
    print(f"  Pos Rate:   {metrics['positive_rate']:.2%}")

    cm = metrics["confusion_matrix"]
    print(f"\n  Confusion Matrix:")
    print(f"    TN={cm[0][0]:5d}  FP={cm[0][1]:5d}")
    print(f"    FN={cm[1][0]:5d}  TP={cm[1][1]:5d}")
    print("=" * 50 + "\n")


def plot_roc_curve(y_true, y_pred_proba, save_path: Optional[str] = None):
    """Plot ROC curve."""
    import matplotlib.pyplot as plt

    fpr, tpr, _ = roc_curve(y_true, y_pred_proba)
    roc_auc = auc(fpr, tpr)

    fig, ax = plt.subplots(figsize=(8, 6))
    ax.plot(fpr, tpr, color="darkorange", lw=2, label=f"ROC (AUC = {roc_auc:.4f})")
    ax.plot([0, 1], [0, 1], color="navy", lw=1, linestyle="--")
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("Receiver Operating Characteristic")
    ax.legend(loc="lower right")

    if save_path:
        fig.savefig(save_path, dpi=150, bbox_inches="tight")
    plt.close(fig)


def plot_confusion_matrix(y_true, y_pred, save_path: Optional[str] = None):
    """Plot confusion matrix heatmap."""
    import matplotlib.pyplot as plt
    import seaborn as sns

    cm = confusion_matrix(y_true, y_pred)
    fig, ax = plt.subplots(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", ax=ax,
                xticklabels=["Ignored", "Actioned"],
                yticklabels=["Ignored", "Actioned"])
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title("Confusion Matrix")

    if save_path:
        fig.savefig(save_path, dpi=150, bbox_inches="tight")
    plt.close(fig)


def plot_precision_recall_curve(y_true, y_pred_proba, save_path: Optional[str] = None):
    """Plot precision-recall curve."""
    import matplotlib.pyplot as plt

    precision, recall, _ = precision_recall_curve(y_true, y_pred_proba)

    fig, ax = plt.subplots(figsize=(8, 6))
    ax.plot(recall, precision, color="darkorange", lw=2)
    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.set_title("Precision-Recall Curve")

    if save_path:
        fig.savefig(save_path, dpi=150, bbox_inches="tight")
    plt.close(fig)
