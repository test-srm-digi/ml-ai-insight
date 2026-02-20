"""FastAPI backend for the VulnInsight dashboard UI.

Provides endpoints for CSV upload, scoring, visualization data, and model info.
"""
import io
import json
import os
import sys
import tempfile
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from vuln_insight.data.csv_loader import load_csv, normalize_columns
from vuln_insight.data.sample_data import generate_sample_data
from vuln_insight.data.transformers import create_label, to_canonical
from vuln_insight.features.pipeline import FeaturePipeline
from vuln_insight.scoring.hybrid_scorer import HybridScorer, classify_tier
from vuln_insight.scoring.tier_classifier import tier_summary

app = FastAPI(title="VulnInsight Dashboard API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global state
_state = {
    "model": None,
    "feature_names": None,
    "last_results": None,
    "last_raw_df": None,
}

MODEL_DIR = os.environ.get("MODEL_PATH", str(Path(__file__).resolve().parent.parent.parent.parent / "models"))


def _load_model():
    """Load the trained XGBoost model if available."""
    if _state["model"] is not None:
        return True

    model_file = Path(MODEL_DIR) / "vulnerability_risk_model.json"
    feature_file = Path(MODEL_DIR) / "feature_names.json"

    if not model_file.exists():
        return False

    import xgboost as xgb
    _state["model"] = xgb.Booster()
    _state["model"].load_model(str(model_file))

    if feature_file.exists():
        with open(feature_file) as f:
            _state["feature_names"] = json.load(f)

    return True


def _score_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Run the full scoring pipeline on a DataFrame."""
    canonical = to_canonical(df)

    pipeline = FeaturePipeline(use_embeddings=False)
    features = pipeline.transform(canonical)

    if _state["feature_names"]:
        for col in _state["feature_names"]:
            if col not in features.columns:
                features[col] = 0
        features = features[_state["feature_names"]]

    scorer = HybridScorer(_state["model"])
    scores_df = scorer.score(features, canonical)

    result = canonical[["cve_id", "severity", "package_name", "repo",
                         "cvss_score", "epss_score"]].copy()
    result = result.loc[scores_df.index]
    result["ml_score"] = scores_df["ml_score"].round(4)
    result["risk_score"] = scores_df["risk_score"].round(4)
    result["tier"] = scores_df["tier"]

    if "cve_description" in canonical.columns:
        result["cve_description"] = canonical.loc[scores_df.index, "cve_description"]
    if "primary_cwe" in canonical.columns:
        result["primary_cwe"] = canonical.loc[scores_df.index, "primary_cwe"]
    if "user_action" in canonical.columns:
        result["user_action"] = canonical.loc[scores_df.index, "user_action"]

    result = result.sort_values("risk_score", ascending=False).reset_index(drop=True)
    return result, canonical


@app.get("/api/health")
def health():
    model_loaded = _state["model"] is not None
    return {"status": "ok", "model_loaded": model_loaded}


@app.get("/api/model/info")
def model_info():
    model_loaded = _load_model()
    return {
        "model_loaded": model_loaded,
        "model_dir": MODEL_DIR,
        "feature_count": len(_state["feature_names"]) if _state["feature_names"] else 0,
    }


@app.post("/api/upload")
async def upload_csv(file: UploadFile = File(...)):
    """Upload a CSV file, run scoring, return results."""
    if not _load_model():
        raise HTTPException(
            status_code=503,
            detail="No trained model found. Run 'python scripts/train.py' first.",
        )

    contents = await file.read()
    try:
        df = pd.read_csv(io.BytesIO(contents))
        df = normalize_columns(df)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse CSV: {str(e)}")

    result, canonical = _score_dataframe(df)
    _state["last_results"] = result
    _state["last_raw_df"] = canonical

    return _build_dashboard_response(result)


@app.post("/api/score/sample")
def score_sample(n: int = Query(default=500, ge=10, le=5000)):
    """Generate sample data, score it, and return results."""
    if not _load_model():
        raise HTTPException(
            status_code=503,
            detail="No trained model found. Run 'python scripts/train.py' first.",
        )

    df = generate_sample_data(n_records=n)
    result, canonical = _score_dataframe(df)
    _state["last_results"] = result
    _state["last_raw_df"] = canonical

    return _build_dashboard_response(result)


@app.get("/api/results")
def get_results():
    """Return the last scored results."""
    if _state["last_results"] is None:
        raise HTTPException(status_code=404, detail="No results yet. Upload a CSV first.")
    return _build_dashboard_response(_state["last_results"])


@app.get("/api/results/table")
def get_results_table(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=5, le=200),
    tier: str = Query(default=None),
    severity: str = Query(default=None),
    search: str = Query(default=None),
    sort_by: str = Query(default="risk_score"),
    sort_order: str = Query(default="desc"),
):
    """Return paginated, filterable vulnerability table."""
    if _state["last_results"] is None:
        raise HTTPException(status_code=404, detail="No results yet.")

    df = _state["last_results"].copy()

    if tier:
        df = df[df["tier"] == tier.upper()]
    if severity:
        df = df[df["severity"] == severity.upper()]
    if search:
        mask = (
            df["cve_id"].astype(str).str.contains(search, case=False, na=False)
            | df["package_name"].astype(str).str.contains(search, case=False, na=False)
            | df["repo"].astype(str).str.contains(search, case=False, na=False)
        )
        df = df[mask]

    ascending = sort_order == "asc"
    if sort_by in df.columns:
        df = df.sort_values(sort_by, ascending=ascending)

    total = len(df)
    start = (page - 1) * page_size
    end = start + page_size
    page_df = df.iloc[start:end]

    return {
        "data": page_df.fillna("").to_dict(orient="records"),
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": max(1, (total + page_size - 1) // page_size),
    }


@app.get("/api/vulnerability/{cve_id}")
def get_vulnerability_detail(cve_id: str):
    """Return detail for a specific vulnerability."""
    if _state["last_results"] is None:
        raise HTTPException(status_code=404, detail="No results yet.")

    mask = _state["last_results"]["cve_id"].astype(str) == cve_id
    if mask.sum() == 0:
        raise HTTPException(status_code=404, detail=f"CVE '{cve_id}' not found.")

    row = _state["last_results"][mask].iloc[0].to_dict()

    # SHAP explanation if available
    shap_features = []
    shap_file = Path(MODEL_DIR) / "shap_values.npy"
    feature_imp_file = Path(MODEL_DIR) / "feature_importance.csv"
    if feature_imp_file.exists():
        imp_df = pd.read_csv(feature_imp_file)
        shap_features = imp_df.head(10).to_dict(orient="records")

    row["top_shap_features"] = shap_features

    # Sanitize NaN/None
    for k, v in row.items():
        if isinstance(v, float) and (np.isnan(v) or np.isinf(v)):
            row[k] = None

    return row


def _build_dashboard_response(result: pd.DataFrame) -> dict:
    """Build the full dashboard response from scored results."""
    total = len(result)

    # Tier distribution
    tier_counts = result["tier"].value_counts().to_dict()
    tier_dist = []
    colors = {"CRITICAL": "#dc2626", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#22c55e"}
    for t in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = tier_counts.get(t, 0)
        tier_dist.append({
            "name": t,
            "value": count,
            "percentage": round(count / max(total, 1) * 100, 1),
            "color": colors[t],
        })

    # Severity distribution
    sev_counts = result["severity"].value_counts().to_dict()
    sev_dist = []
    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        sev_dist.append({"name": s, "value": sev_counts.get(s, 0)})

    # Risk score distribution (histogram buckets)
    risk_hist = []
    for bucket_start in np.arange(0, 1.0, 0.1):
        bucket_end = bucket_start + 0.1
        label = f"{bucket_start:.1f}-{bucket_end:.1f}"
        count = int(((result["risk_score"] >= bucket_start) & (result["risk_score"] < bucket_end)).sum())
        risk_hist.append({"range": label, "count": count})

    # Top repos by risk
    repo_risk = (
        result.groupby("repo")
        .agg(
            avg_risk=("risk_score", "mean"),
            max_risk=("risk_score", "max"),
            total_vulns=("cve_id", "count"),
            critical_count=("tier", lambda x: (x == "CRITICAL").sum()),
        )
        .sort_values("avg_risk", ascending=False)
        .head(10)
        .reset_index()
    )
    top_repos = repo_risk.to_dict(orient="records")

    # Top packages by vulnerability count
    pkg_counts = (
        result.groupby("package_name")
        .agg(
            total_vulns=("cve_id", "count"),
            avg_risk=("risk_score", "mean"),
            critical_count=("tier", lambda x: (x == "CRITICAL").sum()),
        )
        .sort_values("total_vulns", ascending=False)
        .head(10)
        .reset_index()
    )
    top_packages = pkg_counts.to_dict(orient="records")

    # Tier by severity heatmap
    tier_sev = result.groupby(["severity", "tier"]).size().reset_index(name="count")
    tier_sev_data = tier_sev.to_dict(orient="records")

    # Top 10 riskiest
    top10 = result.head(10).fillna("").to_dict(orient="records")

    return {
        "summary": {
            "total_vulnerabilities": total,
            "avg_risk_score": round(float(result["risk_score"].mean()), 4),
            "max_risk_score": round(float(result["risk_score"].max()), 4),
            "unique_repos": int(result["repo"].nunique()),
            "unique_packages": int(result["package_name"].nunique()),
        },
        "tier_distribution": tier_dist,
        "severity_distribution": sev_dist,
        "risk_histogram": risk_hist,
        "top_repos": top_repos,
        "top_packages": top_packages,
        "tier_severity_heatmap": tier_sev_data,
        "top_vulnerabilities": top10,
        "scored_at": datetime.utcnow().isoformat(),
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
