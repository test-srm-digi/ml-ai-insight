#!/usr/bin/env python3
"""CLI: Run the XGBoost training pipeline with evaluation and SHAP analysis."""
import json
import sys
from pathlib import Path

import click
import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from vuln_insight.data.sample_data import generate_sample_data
from vuln_insight.training.evaluator import (
    compute_metrics,
    plot_confusion_matrix,
    plot_precision_recall_curve,
    plot_roc_curve,
    print_evaluation_report,
)
from vuln_insight.training.trainer import VulnerabilityTrainer


@click.command()
@click.option("--data", "-d", default=None, type=click.Path(exists=True),
              help="Path to training CSV. Uses sample data if not provided.")
@click.option("--config", "-c", default="config/model_config.yaml",
              help="Model config YAML path.")
@click.option("--output-dir", "-o", default="models", help="Directory to save trained model.")
@click.option("--split", type=click.Choice(["time", "random"]), default="time",
              help="Train/test split strategy.")
@click.option("--embeddings/--no-embeddings", default=False,
              help="Use text embeddings (slow). Default: off.")
@click.option("--shap/--no-shap", "run_shap", default=True,
              help="Run SHAP analysis after training.")
@click.option("--plots/--no-plots", default=True,
              help="Generate evaluation plots (ROC, confusion matrix, PR curve).")
@click.option("--sample-size", default=1000,
              help="Number of records if using generated sample data.")
def train(data, config, output_dir, split, embeddings, run_shap, plots, sample_size):
    """Train the vulnerability risk prediction model."""
    # Load data
    if data:
        click.echo(f"Loading training data from {data}...")
        df = pd.read_csv(data)
    else:
        click.echo(f"No data file provided. Generating {sample_size} synthetic records...")
        df = generate_sample_data(n_records=sample_size)

    click.echo(f"Dataset: {len(df)} records, {len(df.columns)} columns")

    # Initialize trainer
    trainer = VulnerabilityTrainer(config_path=config)

    # Prepare features and labels
    click.echo("Preparing features and labels...")
    X, y = trainer.prepare_data(df, use_embeddings=embeddings)
    click.echo(f"Feature matrix: {X.shape[0]} samples x {X.shape[1]} features")
    click.echo(f"Label distribution: {y.value_counts().to_dict()}")

    # Train/test split
    if split == "time":
        click.echo("Splitting by time (temporal split)...")
        X_train, X_test, y_train, y_test = trainer.time_split(df, X, y)
    else:
        click.echo("Splitting randomly (stratified)...")
        X_train, X_test, y_train, y_test = trainer.random_split(X, y)

    click.echo(f"Train: {len(X_train)} samples | Test: {len(X_test)} samples")

    # Train model
    click.echo("\nTraining XGBoost model...")
    model = trainer.train(X_train, y_train, X_test, y_test)

    # Evaluate
    click.echo("\nEvaluating model...")
    import xgboost as xgb
    dtest = xgb.DMatrix(X_test, feature_names=list(X_test.columns))
    y_pred_proba = model.predict(dtest)
    metrics = compute_metrics(y_test.values, y_pred_proba)
    print_evaluation_report(metrics)

    # Save model
    trainer.save_model(output_dir)

    # Save metrics
    output_path = Path(output_dir)
    metrics_file = output_path / "evaluation_metrics.json"
    serializable_metrics = {k: v for k, v in metrics.items()}
    with open(metrics_file, "w") as f:
        json.dump(serializable_metrics, f, indent=2)
    click.echo(f"Metrics saved to {metrics_file}")

    # Generate plots
    if plots:
        plots_dir = output_path / "plots"
        plots_dir.mkdir(parents=True, exist_ok=True)

        click.echo("Generating evaluation plots...")
        y_pred = (y_pred_proba >= 0.5).astype(int)
        plot_roc_curve(y_test.values, y_pred_proba, str(plots_dir / "roc_curve.png"))
        plot_confusion_matrix(y_test.values, y_pred, str(plots_dir / "confusion_matrix.png"))
        plot_precision_recall_curve(y_test.values, y_pred_proba, str(plots_dir / "pr_curve.png"))
        click.echo(f"Plots saved to {plots_dir}")

    # SHAP analysis
    if run_shap:
        click.echo("\nRunning SHAP analysis...")
        from vuln_insight.training.explainer import explain_model, plot_shap_bar

        importance_df, shap_values = explain_model(model, X_test)

        # Save feature importance
        importance_file = output_path / "feature_importance.csv"
        importance_df.to_csv(importance_file, index=False)
        click.echo(f"Feature importance saved to {importance_file}")

        click.echo("\nTop 20 Features by SHAP importance:")
        for _, row in importance_df.head(20).iterrows():
            click.echo(f"  {row['feature']:40s}  {row['importance']:.6f}")

        if plots:
            plot_shap_bar(importance_df, top_n=20, save_path=str(plots_dir / "shap_bar.png"))

        # Save SHAP values
        shap_file = output_path / "shap_values.npy"
        np.save(str(shap_file), shap_values)
        click.echo(f"SHAP values saved to {shap_file}")

    click.echo(f"\nTraining complete. Model artifacts in {output_dir}/")


if __name__ == "__main__":
    train()
