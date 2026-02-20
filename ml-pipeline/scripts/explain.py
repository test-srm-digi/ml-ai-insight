#!/usr/bin/env python3
"""CLI: Generate LLM explanations for scored vulnerabilities via AWS Bedrock."""
import json
import sys
from pathlib import Path

import click
import numpy as np
import pandas as pd
import xgboost as xgb

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from vuln_insight.data.csv_loader import load_csv
from vuln_insight.data.transformers import to_canonical
from vuln_insight.features.pipeline import FeaturePipeline
from vuln_insight.scoring.hybrid_scorer import HybridScorer
from vuln_insight.training.explainer import explain_single_prediction


@click.group()
def cli():
    """Generate natural language explanations for vulnerability risk scores."""
    pass


@cli.command()
@click.argument("data_path", type=click.Path(exists=True))
@click.option("--model-dir", "-m", default="models", help="Directory with trained model.")
@click.option("--top-n", default=5, help="Number of top vulnerabilities to explain.")
@click.option("--output", "-o", default=None, help="Output JSON file path.")
@click.option("--embeddings/--no-embeddings", default=False,
              help="Use text embeddings (must match training).")
@click.option("--region", default="us-east-1", help="AWS region for Bedrock.")
@click.option("--model-id", default="anthropic.claude-3-sonnet-20240229-v1:0",
              help="Bedrock model ID.")
def batch(data_path, model_dir, top_n, output, embeddings, region, model_id):
    """Generate explanations for the top-N riskiest vulnerabilities in a dataset."""
    from vuln_insight.llm.bedrock_client import BedrockClient
    from vuln_insight.llm.insight_generator import InsightGenerator

    model_path = Path(model_dir)

    # Load model
    click.echo(f"Loading model from {model_dir}...")
    model = xgb.Booster()
    model.load_model(str(model_path / "vulnerability_risk_model.json"))

    with open(model_path / "feature_names.json") as f:
        trained_feature_names = json.load(f)

    # Load and process data
    click.echo(f"Loading data from {data_path}...")
    df = load_csv(data_path)
    df = to_canonical(df)

    click.echo("Extracting features...")
    pipeline = FeaturePipeline(use_embeddings=embeddings)
    features = pipeline.transform(df)

    for col in trained_feature_names:
        if col not in features.columns:
            features[col] = 0
    features = features[trained_feature_names]

    # Score
    click.echo("Computing risk scores...")
    scorer = HybridScorer(model)
    scores_df = scorer.score(features, df)

    # SHAP values for explainability
    click.echo("Computing SHAP values...")
    shap_file = model_path / "shap_values.npy"
    if shap_file.exists():
        shap_values = np.load(str(shap_file))
        click.echo(f"Loaded cached SHAP values from {shap_file}")
    else:
        from vuln_insight.training.explainer import explain_model
        _, shap_values = explain_model(model, features)

    # Generate LLM explanations
    click.echo(f"\nGenerating explanations for top {top_n} vulnerabilities via Bedrock...")
    bedrock = BedrockClient(region_name=region, model_id=model_id)
    generator = InsightGenerator(bedrock_client=bedrock)

    insights = generator.generate_batch_insights(
        scored_df=scores_df,
        raw_df=df,
        shap_values=shap_values,
        feature_names=trained_feature_names,
        top_n=top_n,
    )

    # Display results
    for i, insight in enumerate(insights, 1):
        click.echo(f"\n{'='*60}")
        click.echo(f"[{i}/{len(insights)}] {insight['cve_id']}")
        click.echo(f"Risk Score: {insight['risk_score']:.4f} | Tier: {insight['tier']}")
        click.echo(f"{'='*60}")
        click.echo(insight["explanation"])

    # Save
    if output:
        Path(output).parent.mkdir(parents=True, exist_ok=True)
        with open(output, "w") as f:
            json.dump(insights, f, indent=2, default=str)
        click.echo(f"\nExplanations saved to {output}")


@cli.command()
@click.argument("data_path", type=click.Path(exists=True))
@click.option("--model-dir", "-m", default="models", help="Directory with trained model.")
@click.option("--output", "-o", default=None, help="Output text file path.")
@click.option("--embeddings/--no-embeddings", default=False,
              help="Use text embeddings (must match training).")
@click.option("--region", default="us-east-1", help="AWS region for Bedrock.")
@click.option("--model-id", default="anthropic.claude-3-sonnet-20240229-v1:0",
              help="Bedrock model ID.")
def portfolio(data_path, model_dir, output, embeddings, region, model_id):
    """Generate a portfolio-level risk summary."""
    from vuln_insight.llm.bedrock_client import BedrockClient
    from vuln_insight.llm.insight_generator import InsightGenerator

    model_path = Path(model_dir)

    # Load model
    click.echo(f"Loading model from {model_dir}...")
    model = xgb.Booster()
    model.load_model(str(model_path / "vulnerability_risk_model.json"))

    with open(model_path / "feature_names.json") as f:
        trained_feature_names = json.load(f)

    # Load and process data
    click.echo(f"Loading data from {data_path}...")
    df = load_csv(data_path)
    df = to_canonical(df)

    click.echo("Extracting features...")
    pipeline = FeaturePipeline(use_embeddings=embeddings)
    features = pipeline.transform(df)

    for col in trained_feature_names:
        if col not in features.columns:
            features[col] = 0
    features = features[trained_feature_names]

    # Score
    click.echo("Computing risk scores...")
    scorer = HybridScorer(model)
    scores_df = scorer.score(features, df)

    # Generate portfolio summary
    click.echo("Generating portfolio summary via Bedrock...")
    bedrock = BedrockClient(region_name=region, model_id=model_id)
    generator = InsightGenerator(bedrock_client=bedrock)

    summary = generator.generate_portfolio_summary(scores_df, df)

    click.echo(f"\n{'='*60}")
    click.echo("PORTFOLIO RISK SUMMARY")
    click.echo(f"{'='*60}")
    click.echo(summary)

    if output:
        Path(output).parent.mkdir(parents=True, exist_ok=True)
        with open(output, "w") as f:
            f.write(summary)
        click.echo(f"\nSummary saved to {output}")


@cli.command("single")
@click.argument("data_path", type=click.Path(exists=True))
@click.option("--cve-id", required=True, help="CVE ID to explain.")
@click.option("--model-dir", "-m", default="models", help="Directory with trained model.")
@click.option("--embeddings/--no-embeddings", default=False,
              help="Use text embeddings (must match training).")
@click.option("--region", default="us-east-1", help="AWS region for Bedrock.")
@click.option("--model-id", default="anthropic.claude-3-sonnet-20240229-v1:0",
              help="Bedrock model ID.")
def single(data_path, cve_id, model_dir, embeddings, region, model_id):
    """Explain a single vulnerability by CVE ID."""
    from vuln_insight.llm.bedrock_client import BedrockClient
    from vuln_insight.llm.insight_generator import InsightGenerator

    model_path = Path(model_dir)

    # Load model
    model = xgb.Booster()
    model.load_model(str(model_path / "vulnerability_risk_model.json"))

    with open(model_path / "feature_names.json") as f:
        trained_feature_names = json.load(f)

    # Load and process data
    df = load_csv(data_path)
    df = to_canonical(df)

    # Find the CVE
    mask = df["cve_id"].astype(str) == cve_id
    if mask.sum() == 0:
        click.echo(f"Error: CVE '{cve_id}' not found in dataset.", err=True)
        raise SystemExit(1)

    click.echo(f"Found {mask.sum()} record(s) for {cve_id}")

    # Feature engineering
    pipeline = FeaturePipeline(use_embeddings=embeddings)
    features = pipeline.transform(df)

    for col in trained_feature_names:
        if col not in features.columns:
            features[col] = 0
    features = features[trained_feature_names]

    # Score
    scorer = HybridScorer(model)
    scores_df = scorer.score(features, df)

    # Get SHAP for this specific CVE
    idx = df.index[mask][0]
    loc = scores_df.index.get_loc(idx)

    row_features = features.iloc[[loc]]
    top_shap = explain_single_prediction(model, row_features, trained_feature_names)

    risk_score = float(scores_df.loc[idx, "risk_score"])
    tier = scores_df.loc[idx, "tier"]
    vuln_data = df.loc[idx].to_dict()

    # SHAP explanation (no LLM needed)
    click.echo(f"\n{'='*60}")
    click.echo(f"CVE: {cve_id}")
    click.echo(f"Risk Score: {risk_score:.4f} | Tier: {tier}")
    click.echo(f"Severity: {vuln_data.get('severity', 'N/A')} | CVSS: {vuln_data.get('cvss_score', 'N/A')}")
    click.echo(f"{'='*60}")
    click.echo("\nTop Contributing Factors (SHAP):")
    for feat_name, shap_val in top_shap:
        direction = "+" if shap_val > 0 else "-"
        click.echo(f"  {direction} {feat_name}: {shap_val:+.4f}")

    # LLM explanation
    click.echo("\nGenerating LLM explanation via Bedrock...")
    bedrock = BedrockClient(region_name=region, model_id=model_id)
    generator = InsightGenerator(bedrock_client=bedrock)

    explanation = generator.explain_single(vuln_data, top_shap, risk_score, tier)
    click.echo(f"\n{explanation}")


@cli.command("shap-only")
@click.argument("data_path", type=click.Path(exists=True))
@click.option("--model-dir", "-m", default="models", help="Directory with trained model.")
@click.option("--top-n", default=10, help="Number of top vulnerabilities to explain.")
@click.option("--embeddings/--no-embeddings", default=False,
              help="Use text embeddings (must match training).")
def shap_only(data_path, model_dir, top_n, embeddings):
    """Show SHAP-based explanations without calling Bedrock (offline mode)."""
    model_path = Path(model_dir)

    # Load model
    model = xgb.Booster()
    model.load_model(str(model_path / "vulnerability_risk_model.json"))

    with open(model_path / "feature_names.json") as f:
        trained_feature_names = json.load(f)

    # Load and process data
    df = load_csv(data_path)
    df = to_canonical(df)

    pipeline = FeaturePipeline(use_embeddings=embeddings)
    features = pipeline.transform(df)

    for col in trained_feature_names:
        if col not in features.columns:
            features[col] = 0
    features = features[trained_feature_names]

    # Score
    scorer = HybridScorer(model)
    scores_df = scorer.score(features, df)

    # Top N
    top_indices = scores_df.nlargest(top_n, "risk_score").index

    click.echo(f"\nSHAP Explanations for Top {top_n} Riskiest Vulnerabilities")
    click.echo(f"{'='*60}")

    for rank, idx in enumerate(top_indices, 1):
        loc = scores_df.index.get_loc(idx)
        row_features = features.iloc[[loc]]
        top_shap = explain_single_prediction(model, row_features, trained_feature_names)

        cve_id = df.loc[idx].get("cve_id", "N/A")
        risk_score = float(scores_df.loc[idx, "risk_score"])
        tier = scores_df.loc[idx, "tier"]

        click.echo(f"\n[{rank}] {cve_id} — Risk: {risk_score:.4f} ({tier})")
        click.echo(f"    Severity: {df.loc[idx].get('severity', 'N/A')} | "
                    f"CVSS: {df.loc[idx].get('cvss_score', 'N/A')} | "
                    f"Package: {df.loc[idx].get('package_name', 'N/A')}")
        click.echo("    Top SHAP factors:")
        for feat_name, shap_val in top_shap:
            direction = "increases" if shap_val > 0 else "decreases"
            click.echo(f"      - {feat_name} {direction} risk by {abs(shap_val):.4f}")


if __name__ == "__main__":
    cli()
