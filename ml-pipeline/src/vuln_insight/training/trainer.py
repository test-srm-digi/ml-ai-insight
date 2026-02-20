"""XGBoost training pipeline for vulnerability risk prediction."""
import json
from pathlib import Path
from typing import Tuple

import numpy as np
import pandas as pd
import xgboost as xgb
import yaml
from sklearn.model_selection import train_test_split

from vuln_insight.data.transformers import to_canonical, create_label
from vuln_insight.features.pipeline import FeaturePipeline


class VulnerabilityTrainer:
    def __init__(self, config_path: str = "config/model_config.yaml"):
        config_path = Path(config_path)
        if config_path.exists():
            with open(config_path) as f:
                self.config = yaml.safe_load(f)
        else:
            self.config = self._default_config()

        self.model = None
        self.feature_pipeline = None
        self.feature_names = None

    def _default_config(self):
        return {
            "training": {
                "objective": "binary:logistic",
                "eval_metric": "auc",
                "max_depth": 6,
                "eta": 0.05,
                "subsample": 0.8,
                "colsample_bytree": 0.8,
                "lambda": 1.0,
                "alpha": 0.5,
                "seed": 42,
                "num_boost_round": 500,
                "early_stopping_rounds": 50,
                "test_size": 0.2,
            },
            "embeddings": {"model_name": "all-MiniLM-L6-v2", "pca_components": 100},
        }

    def prepare_data(
        self, df: pd.DataFrame, use_embeddings: bool = True
    ) -> Tuple[pd.DataFrame, pd.Series]:
        """Transform raw data into features + labels."""
        df = to_canonical(df)
        df = create_label(df)
        df = df.dropna(subset=["label"])

        self.feature_pipeline = FeaturePipeline(use_embeddings=use_embeddings)
        X = self.feature_pipeline.transform(df)
        y = df["label"].astype(int)
        y = y.loc[X.index]

        self.feature_names = self.feature_pipeline.get_feature_names()
        return X, y

    def time_split(self, df: pd.DataFrame, X: pd.DataFrame, y: pd.Series) -> Tuple:
        """Split by time for proper temporal evaluation."""
        test_size = self.config["training"].get("test_size", 0.2)

        if "published_date" in df.columns:
            df_sorted = df.loc[X.index].copy()
            pub = pd.to_datetime(df_sorted["published_date"], errors="coerce", utc=True)
            sort_idx = pub.argsort()
            X = X.iloc[sort_idx]
            y = y.iloc[sort_idx]

        split_idx = int(len(X) * (1 - test_size))
        return X.iloc[:split_idx], X.iloc[split_idx:], y.iloc[:split_idx], y.iloc[split_idx:]

    def random_split(self, X: pd.DataFrame, y: pd.Series) -> Tuple:
        """Standard random train/test split."""
        test_size = self.config["training"].get("test_size", 0.2)
        seed = self.config["training"].get("seed", 42)
        return train_test_split(X, y, test_size=test_size, random_state=seed, stratify=y)

    def train(self, X_train, y_train, X_test, y_test):
        """Train XGBoost model with early stopping."""
        tc = self.config["training"]
        params = {
            "objective": tc.get("objective", "binary:logistic"),
            "eval_metric": tc.get("eval_metric", "auc"),
            "max_depth": tc.get("max_depth", 6),
            "eta": tc.get("eta", 0.05),
            "subsample": tc.get("subsample", 0.8),
            "colsample_bytree": tc.get("colsample_bytree", 0.8),
            "lambda": tc.get("lambda", 1.0),
            "alpha": tc.get("alpha", 0.5),
            "seed": tc.get("seed", 42),
        }

        dtrain = xgb.DMatrix(X_train, label=y_train, feature_names=list(X_train.columns))
        dtest = xgb.DMatrix(X_test, label=y_test, feature_names=list(X_test.columns))

        self.model = xgb.train(
            params,
            dtrain,
            num_boost_round=tc.get("num_boost_round", 500),
            evals=[(dtrain, "train"), (dtest, "test")],
            early_stopping_rounds=tc.get("early_stopping_rounds", 50),
            verbose_eval=50,
        )
        return self.model

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        """Predict probabilities for new data."""
        if self.model is None:
            raise ValueError("Model not trained. Call train() first.")
        dmatrix = xgb.DMatrix(X, feature_names=list(X.columns))
        return self.model.predict(dmatrix)

    def save_model(self, output_dir: str = "models"):
        """Save model and metadata."""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        self.model.save_model(str(output_dir / "vulnerability_risk_model.json"))

        with open(output_dir / "feature_names.json", "w") as f:
            json.dump(self.feature_names, f, indent=2)

        with open(output_dir / "training_config.yaml", "w") as f:
            yaml.dump(self.config, f)

        print(f"Model saved to {output_dir}")

    def load_model(self, model_dir: str = "models"):
        """Load a saved model."""
        model_dir = Path(model_dir)
        self.model = xgb.Booster()
        self.model.load_model(str(model_dir / "vulnerability_risk_model.json"))

        with open(model_dir / "feature_names.json") as f:
            self.feature_names = json.load(f)

        return self.model
