"""FastAPI sidecar for serving the vulnerability-insight ML model.

This lightweight service loads the trained XGBoost model once at startup and
exposes HTTP endpoints that the Java Spring Boot API calls to obtain
risk scores for vulnerability records.
"""
from __future__ import annotations

import logging
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd
import xgboost as xgb
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from vuln_insight.data.transformers import to_canonical
from vuln_insight.features.pipeline import FeaturePipeline
from vuln_insight.scoring.hybrid_scorer import HybridScorer

logger = logging.getLogger("vuln_insight.serving")

# ---------------------------------------------------------------------------
# Configuration (overridable via environment variables)
# ---------------------------------------------------------------------------
MODEL_PATH = os.getenv(
    "MODEL_PATH",
    str(Path(__file__).resolve().parents[4] / "models" / "xgb_model.json"),
)
PORT = int(os.getenv("PORT", "8000"))
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# ---------------------------------------------------------------------------
# Application state — populated during the lifespan startup event
# ---------------------------------------------------------------------------
_state: Dict[str, Any] = {}


# ---------------------------------------------------------------------------
# Lifespan: load model once on startup, release on shutdown
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load the XGBoost model and prepare the scoring pipeline."""
    logging.basicConfig(level=LOG_LEVEL)
    logger.info("Loading model from %s ...", MODEL_PATH)

    if not Path(MODEL_PATH).exists():
        raise RuntimeError(f"Model file not found: {MODEL_PATH}")

    booster = xgb.Booster()
    booster.load_model(MODEL_PATH)

    _state["model"] = booster
    _state["feature_pipeline"] = FeaturePipeline(use_embeddings=False)
    _state["scorer"] = HybridScorer(model=booster)
    _state["model_path"] = MODEL_PATH
    _state["startup_ts"] = time.time()

    logger.info("Model loaded successfully.")
    yield
    _state.clear()
    logger.info("Serving shut down.")


app = FastAPI(
    title="Vuln-Insight ML Sidecar",
    version="1.0.0",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Pydantic request / response schemas
# ---------------------------------------------------------------------------
class VulnerabilityRecord(BaseModel):
    """Single vulnerability record coming from the Java API."""
    cve_id: Optional[str] = ""
    title: Optional[str] = ""
    package_name: Optional[str] = ""
    package_version: Optional[str] = ""
    ecosystem: Optional[str] = ""
    severity: Optional[str] = "UNKNOWN"
    cvss_score: Optional[float] = 0.0
    cvss_vector: Optional[str] = ""
    epss_score: Optional[float] = 0.0
    epss_percentile: Optional[float] = 0.0
    published_date: Optional[str] = ""
    has_patch: Optional[bool] = False
    fix_versions: Optional[str] = ""
    cwes: Optional[str] = ""
    cve_description: Optional[str] = ""
    transitive_dep_count: Optional[int] = 0
    repo: Optional[str] = ""
    repo_criticality: Optional[float] = Field(default=0.5, ge=0.0, le=1.0)


class PredictionResult(BaseModel):
    """Scoring result for a single vulnerability."""
    cve_id: str
    ml_score: float
    risk_score: float
    tier: str
    normalized_cvss: float
    normalized_epss: float
    exposure_score: float


class PredictRequest(BaseModel):
    """Batch prediction request."""
    vulnerabilities: List[VulnerabilityRecord]


class PredictResponse(BaseModel):
    """Batch prediction response."""
    predictions: List[PredictionResult]
    model_path: str
    elapsed_ms: float


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.get("/health")
async def health():
    """Liveness / readiness probe."""
    return {
        "status": "ok",
        "uptime_s": round(time.time() - _state.get("startup_ts", time.time()), 2),
    }


@app.get("/info")
async def info():
    """Model and pipeline metadata."""
    return {
        "model_path": _state.get("model_path", ""),
        "feature_pipeline": "FeaturePipeline(use_embeddings=False)",
        "scorer": "HybridScorer (default weights)",
    }


@app.post("/predict", response_model=PredictResponse)
async def predict(request: PredictRequest):
    """Score a batch of vulnerability records.

    Accepts JSON identical to what the Java Spring Boot service sends and
    returns risk scores, tiers, and contributing factors.
    """
    if not request.vulnerabilities:
        raise HTTPException(status_code=400, detail="Empty vulnerability list.")

    start = time.perf_counter()

    try:
        # 1. Build a DataFrame from the incoming records
        records = [v.model_dump() for v in request.vulnerabilities]
        raw_df = pd.DataFrame(records)

        # 2. Canonicalize
        canonical_df = to_canonical(raw_df)

        # 3. Feature engineering
        feature_pipeline: FeaturePipeline = _state["feature_pipeline"]
        features_df = feature_pipeline.transform(canonical_df)

        # 4. Score
        scorer: HybridScorer = _state["scorer"]
        scores_df = scorer.score(features_df, canonical_df)

        # 5. Assemble response
        predictions = []
        for idx in scores_df.index:
            predictions.append(
                PredictionResult(
                    cve_id=str(canonical_df.at[idx, "cve_id"]),
                    ml_score=round(float(scores_df.at[idx, "ml_score"]), 6),
                    risk_score=round(float(scores_df.at[idx, "risk_score"]), 6),
                    tier=str(scores_df.at[idx, "tier"]),
                    normalized_cvss=round(float(scores_df.at[idx, "normalized_cvss"]), 6),
                    normalized_epss=round(float(scores_df.at[idx, "normalized_epss"]), 6),
                    exposure_score=round(float(scores_df.at[idx, "exposure_score"]), 6),
                )
            )

        elapsed = (time.perf_counter() - start) * 1000
        return PredictResponse(
            predictions=predictions,
            model_path=_state["model_path"],
            elapsed_ms=round(elapsed, 2),
        )

    except Exception as exc:
        logger.exception("Prediction failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Standalone entry-point (python -m vuln_insight.serving.app)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "vuln_insight.serving.app:app",
        host="0.0.0.0",
        port=PORT,
        log_level=LOG_LEVEL.lower(),
    )
