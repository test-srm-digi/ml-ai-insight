#!/usr/bin/env python3
"""CLI: Score new vulnerabilities using a trained model + hybrid scoring."""
import json
import sys
from pathlib import Path

import click
import numpy as np
import pandas as pd
import xgboost as xgb

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from vuln_insight.data.csv_loader import load_csv
from vuln_insight.data.json_ingester import ingest_json
from vuln_insight.data.transformers import to_canonical
from vuln_insight.features.pipeline import FeaturePipeline
from vuln_insight.scoring.hybrid_scorer import HybridScorer
from vuln_insight.scoring.tier_classifier import tier_summary


@click.command()
@click.argument("data_path", type=click.Path(exists=True))
@click.option("--model-dir", "-m", default="models", help="Directory with trained model.")
@click.option("--output", "-o", default=None, help="Output CSV path. Default: stdout summary only.")
@click.option("--format", "input_format", type=click.Choice(["csv", "json", "auto"]),
              default="auto", help="Input format. 'auto' detects from extension.")
@click.option("--embeddings/--no-embeddings", default=False,
              help="Use text embeddings (must match training).")
@click.option("--top-n", default=20, help="Show top N riskiest in summary.")
@click.option("--json-output", is_flag=True, help="Output results as JSON instead of CSV.")
def predict(data_path, model_dir, output, input_format, embeddings, top_n, json_output):
    """Score vulnerabilities from a data file using the trained model."""
    model_path = Path(model_dir)

    # Load model
    model_file = model_path / "vulnerability_risk_model.json"
    if not model_file.exists():
        click.echo(f"Error: Model not found at {model_file}", err=True)
        click.echo("Run 'python scripts/train.py' first to train a model.", err=True)
        raise SystemExit(1)

    click.echo(f"Loading model from {model_dir}...")
    model = xgb.Booster()
    model.load_model(str(model_file))

    # Load feature names
    feature_names_file = model_path / "feature_names.json"
    with open(feature_names_file) as f:
        trained_feature_names = json.load(f)

    # Load data
    data_path_obj = Path(data_path)
    if input_format == "auto":
        if data_path_obj.suffix == ".json":
            input_format = "json"
        else:
            input_format = "csv"

    click.echo(f"Loading data from {data_path} (format: {input_format})...")
    if input_format == "json":
        df = ingest_json(data_path)
    else:
        df = load_csv(data_path)

    df = to_canonical(df)
    click.echo(f"Loaded {len(df)} vulnerabilities.")

    # Feature engineering
    click.echo("Extracting features...")
    pipeline = FeaturePipeline(use_embeddings=embeddings)
    features = pipeline.transform(df)

    # Align features with training — add missing columns as 0, drop extra
    for col in trained_feature_names:
        if col not in features.columns:
            features[col] = 0
    features = features[trained_feature_names]

    click.echo(f"Feature matrix: {features.shape[0]} x {features.shape[1]}")

    # Hybrid scoring
    click.echo("Computing hybrid risk scores...")
    scorer = HybridScorer(model)
    scores_df = scorer.score(features, df)

    # Build output
    result = df[["cve_id", "severity", "package_name", "repo"]].copy()
    result = result.loc[scores_df.index]
    result["ml_score"] = scores_df["ml_score"].round(4)
    result["risk_score"] = scores_df["risk_score"].round(4)
    result["tier"] = scores_df["tier"]

    result = result.sort_values("risk_score", ascending=False)

    # Summary
    click.echo(f"\n{'='*60}")
    click.echo("VULNERABILITY RISK SCORING RESULTS")
    click.echo(f"{'='*60}")
    summary = tier_summary(scores_df["tier"])
    total = summary["total"]
    for tier_key, tier_label in [("critical", "CRITICAL"), ("high", "HIGH"),
                                  ("medium", "MEDIUM"), ("low", "LOW")]:
        count = summary.get(tier_key, 0)
        pct = count / max(total, 1) * 100
        click.echo(f"  {tier_label:10s}: {count:5d} ({pct:5.1f}%)")
    click.echo(f"  {'TOTAL':10s}: {total:5d}")
    click.echo(f"  Avg Risk Score: {scores_df['risk_score'].mean():.4f}")
    click.echo(f"{'='*60}")

    # Top N riskiest
    click.echo(f"\nTop {top_n} Riskiest Vulnerabilities:")
    click.echo(f"{'CVE ID':<20s} {'Severity':<10s} {'Package':<20s} {'Risk':<8s} {'Tier':<10s}")
    click.echo("-" * 68)
    for _, row in result.head(top_n).iterrows():
        click.echo(
            f"{str(row['cve_id']):<20s} {str(row['severity']):<10s} "
            f"{str(row['package_name']):<20s} {row['risk_score']:<8.4f} {row['tier']:<10s}"
        )

    # Save output
    if output:
        Path(output).parent.mkdir(parents=True, exist_ok=True)
        if json_output:
            records = result.to_dict(orient="records")
            with open(output, "w") as f:
                json.dump(records, f, indent=2, default=str)
        else:
            result.to_csv(output, index=False)
        click.echo(f"\nResults saved to {output}")


if __name__ == "__main__":
    predict()
