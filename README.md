# VulnInsight - ML-Powered Vulnerability Risk Intelligence

A complete ML system for prioritizing software vulnerabilities using XGBoost, 275+ engineered features, hybrid risk scoring, SHAP explainability, and LLM-powered explanations via AWS Bedrock.

## Architecture

```
                        +------------------+
                        |   React Dashboard|  (port 3000)
                        |   - CSV Upload   |
                        |   - Charts       |
                        |   - Vuln Table   |
                        +--------+---------+
                                 |
                        +--------v---------+
                        | Python FastAPI   |  (port 8000)
                        | Dashboard API    |
                        | + ML Sidecar     |
                        +--------+---------+
                                 |
              +------------------+------------------+
              |                                     |
    +---------v----------+              +-----------v---------+
    |  XGBoost Model     |              |  Java Spring Boot   | (port 8080)
    |  275 features      |              |  REST API           |
    |  SHAP explainer    |              |  /api/v1/score      |
    +--------------------+              |  /api/v1/explain    |
                                        +---------------------+
              |
    +---------v----------+
    |  AWS Bedrock       |
    |  (Claude LLM)      |
    |  Explanations      |
    +--------------------+
```

## Quick Start

### Prerequisites

- Python 3.10+
- Node.js 18+ (for the dashboard UI)
- Java 17+ and Gradle (for the Java API, optional)
- Docker & Docker Compose (for containerized setup)

### Option 1: Local Development (Fastest)

```bash
# 1. Clone and enter the project
cd ai-ml-insight

# 2. Install Python dependencies
cd ml-pipeline
pip install -r requirements.txt

# 3. Generate sample data
python scripts/ingest.py sample -n 1000 -o data/sample_data.csv

# 4. Train the model
python scripts/train.py --data data/sample_data.csv --no-embeddings --split time

# 5. Start the dashboard API
python -m vuln_insight.serving.dashboard_api
# API running at http://localhost:8000

# 6. In a new terminal — start the React UI
cd ../ui
npm install
npm start
# Dashboard running at http://localhost:3000
```

Open http://localhost:3000 in your browser. You can either:
- **Upload a CSV** with your vulnerability data
- **Click "Generate Sample Data"** to see the dashboard with synthetic data

### Option 2: Docker Compose (Full Stack)

```bash
# Make sure you have a trained model first (see Option 1, steps 2-4)
# Then from the project root:
docker-compose up --build

# Services:
#   Dashboard UI:   http://localhost:3000
#   Python API:     http://localhost:8000
#   Java API:       http://localhost:8080
#   MariaDB:        localhost:3306
```

### Option 3: CLI Only (No UI)

```bash
cd ml-pipeline
pip install -r requirements.txt

# Generate sample data
python scripts/ingest.py sample -n 1000

# Train
python scripts/train.py --no-embeddings

# Score new vulnerabilities
python scripts/predict.py data/sample_data.csv -m models -o results.csv

# SHAP explanations (no AWS needed)
python scripts/explain.py shap-only data/sample_data.csv -m models --top-n 10

# LLM explanations (requires AWS credentials)
python scripts/explain.py batch data/sample_data.csv -m models --top-n 5
```

---

## Project Structure

```
ai-ml-insight/
├── ml-pipeline/                    # Python ML package
│   ├── config/
│   │   ├── features.yaml          # 275-feature schema definition
│   │   ├── model_config.yaml      # XGBoost hyperparameters + scoring weights
│   │   └── db_config.yaml         # MariaDB connection config
│   ├── src/vuln_insight/
│   │   ├── data/                  # Data ingestion layer
│   │   │   ├── json_ingester.py   # Flatten JSON API responses
│   │   │   ├── csv_loader.py      # Load CSV/Excel with column normalization
│   │   │   ├── db_loader.py       # MariaDB via SQLAlchemy
│   │   │   ├── transformers.py    # Unify schemas to canonical form
│   │   │   └── sample_data.py     # Synthetic data generator
│   │   ├── features/              # 7 feature engineering blocks
│   │   │   ├── cve_core.py        # Block A: CVSS, EPSS, severity (~32 features)
│   │   │   ├── cwe_intelligence.py# Block B: CWE intelligence (~25 features)
│   │   │   ├── dependency.py      # Block C: Package/dependency (~40 features)
│   │   │   ├── repo_behavior.py   # Block D: Repo patterns (~40 features)
│   │   │   ├── time_exposure.py   # Block E: Time & exposure (~20 features)
│   │   │   ├── text_embeddings.py # Block F: Text embeddings (~105 features)
│   │   │   ├── user_behavior.py   # Block G: User behavior (~20 features)
│   │   │   └── pipeline.py        # Orchestrates all blocks
│   │   ├── training/              # Training pipeline
│   │   │   ├── trainer.py         # XGBoost training with time-based split
│   │   │   ├── evaluator.py       # Metrics, plots (AUC, precision, recall)
│   │   │   └── explainer.py       # SHAP analysis & feature importance
│   │   ├── scoring/               # Risk scoring
│   │   │   ├── hybrid_scorer.py   # ML + business rules hybrid formula
│   │   │   └── tier_classifier.py # CRITICAL/HIGH/MEDIUM/LOW tiering
│   │   ├── llm/                   # LLM explanations
│   │   │   ├── bedrock_client.py  # AWS Bedrock (Claude) integration
│   │   │   ├── prompt_templates.py# Prompt templates
│   │   │   └── insight_generator.py
│   │   └── serving/               # API servers
│   │       ├── app.py             # FastAPI ML sidecar
│   │       └── dashboard_api.py   # FastAPI dashboard backend
│   ├── scripts/                   # CLI tools
│   │   ├── ingest.py              # Data ingestion (CSV/JSON/DB/sample)
│   │   ├── train.py               # Model training
│   │   ├── predict.py             # Vulnerability scoring
│   │   └── explain.py             # LLM/SHAP explanations
│   └── requirements.txt
├── ui/                            # React dashboard
│   ├── src/
│   │   ├── App.js                 # Main application
│   │   ├── App.css                # Styling
│   │   ├── services/api.js        # Backend API client
│   │   └── components/
│   │       ├── Header.js          # App header
│   │       ├── UploadPanel.js     # CSV upload & sample generator
│   │       ├── SummaryCards.js    # KPI summary cards
│   │       ├── TierChart.js       # Pie chart for tier distribution
│   │       ├── RiskHistogram.js   # Risk score histogram
│   │       ├── TopRepos.js        # Top repos/packages bar charts
│   │       ├── VulnTable.js       # Paginated, filterable vuln table
│   │       └── VulnDetail.js      # Vulnerability detail modal
│   ├── Dockerfile
│   └── nginx.conf
├── api-service/                   # Java Spring Boot API
│   ├── src/main/java/com/vulninsight/api/
│   │   ├── controller/RiskController.java
│   │   ├── service/
│   │   │   ├── RiskScoringService.java
│   │   │   ├── PythonBridgeService.java
│   │   │   └── BedrockService.java
│   │   └── model/                 # DTOs
│   ├── build.gradle
│   └── Dockerfile
├── docker-compose.yml
└── README.md
```

---

## Feature Vector Schema (275 Features)

The model uses 275 engineered features across 7 blocks:

| Block | Name | Features | Description |
|-------|------|----------|-------------|
| A | CVE Core | ~32 | Severity, CVSS score, EPSS score, CVSS vector one-hot encoding, patch info, reference counts |
| B | CWE Intelligence | ~25 | Top-10 CWE one-hot, category flags (injection, web, memory, auth), historical exploit rates |
| C | Package/Dependency | ~40 | Version gap analysis, ecosystem one-hot (npm, pypi, maven, etc.), dependency depth, fix availability |
| D | Repo Behavioral | ~40 | Per-repo CVE history, fix rates, severity distribution, CVE velocity |
| E | Time & Exposure | ~20 | Detection delay, exposure window, risk acceleration, age-severity interaction |
| F | Text Embeddings | ~105 | Sentence-transformer (all-MiniLM-L6-v2) with PCA reduction to 100 dims + keyword flags |
| G | User Behavior | ~20 | Historical fix/skip/FP rates per CWE, package, severity, repo |

Full schema definition: `ml-pipeline/config/features.yaml`

---

## Risk Scoring Formula

### Hybrid Score

```
risk_score = 0.45 * ml_prediction
           + 0.20 * (cvss_score / 10)
           + 0.15 * epss_percentile
           + 0.10 * exposure_score
           + 0.10 * repo_criticality
```

### Hard Overrides

| Condition | Override |
|-----------|---------|
| CVE is withdrawn | Cap score at 0.10 |
| CVSS >= 9.0 AND exploit known | Floor score at 0.85 |

### Tier Thresholds

| Tier | Score Range |
|------|-------------|
| CRITICAL | > 0.80 |
| HIGH | > 0.60 |
| MEDIUM | > 0.40 |
| LOW | <= 0.40 |

---

## CLI Reference

### Ingest Data

```bash
# From CSV
python scripts/ingest.py csv /path/to/data.csv -o data/ingested.csv

# From JSON API response file
python scripts/ingest.py json /path/to/response.json -o data/ingested.csv

# From MariaDB
python scripts/ingest.py db -c config/db_config.yaml -o data/ingested.csv

# Generate synthetic data
python scripts/ingest.py sample -n 1000 -o data/sample_data.csv

# Show dataset info
python scripts/ingest.py info data/sample_data.csv
```

### Train Model

```bash
# Train with sample data (auto-generated)
python scripts/train.py --no-embeddings

# Train with your data
python scripts/train.py --data data/ingested.csv --split time --shap --plots

# Train with text embeddings (slower but more features)
python scripts/train.py --data data/ingested.csv --embeddings

# Custom output directory
python scripts/train.py --data data/ingested.csv -o models/v2
```

**Output**: Model files saved to `models/`:
- `vulnerability_risk_model.json` — XGBoost model
- `feature_names.json` — Feature column names
- `evaluation_metrics.json` — AUC, precision, recall, F1
- `feature_importance.csv` — SHAP feature importances
- `plots/` — ROC curve, confusion matrix, precision-recall curve, SHAP bar chart

### Score Vulnerabilities

```bash
# Score from CSV
python scripts/predict.py data/new_vulns.csv -m models -o scored_results.csv

# Score from JSON
python scripts/predict.py data/api_response.json -m models --format json

# Top 50 riskiest
python scripts/predict.py data/new_vulns.csv -m models --top-n 50

# JSON output
python scripts/predict.py data/new_vulns.csv -m models -o results.json --json-output
```

### Generate Explanations

```bash
# SHAP-only explanations (no AWS needed)
python scripts/explain.py shap-only data/scored.csv -m models --top-n 10

# Single CVE explanation with LLM
python scripts/explain.py single data/scored.csv --cve-id CVE-2024-1234 -m models

# Batch LLM explanations for top 5
python scripts/explain.py batch data/scored.csv -m models --top-n 5 -o explanations.json

# Portfolio-level summary
python scripts/explain.py portfolio data/scored.csv -m models -o summary.txt
```

---

## Dashboard UI

The React dashboard provides:

- **CSV Upload**: Drag-and-drop or click to upload vulnerability CSV files
- **Sample Data**: Generate synthetic data for testing
- **Summary KPIs**: Total vulns, critical/high counts, avg risk score
- **Tier Distribution**: Interactive pie chart
- **Risk Histogram**: Risk score distribution bar chart
- **Top Repos/Packages**: Horizontal bar charts of riskiest repos and most affected packages
- **Top 10 Table**: Riskiest vulnerabilities with severity badges and tier classification
- **Full Table View**: Paginated, sortable, filterable table with search
- **Vulnerability Detail Modal**: Click any CVE to see risk breakdown, SHAP feature importances, and description

---

## Java API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/score` | Score a single vulnerability |
| POST | `/api/v1/score/batch` | Score up to 100 vulnerabilities |
| GET | `/api/v1/model/info` | Model metadata and version |
| POST | `/api/v1/explain` | Score + LLM explanation |
| GET | `/actuator/health` | Health check |

Start the Java API:
```bash
cd api-service
./gradlew bootRun
```

---

## CSV Input Format

Your CSV should have columns matching these names (case-insensitive, spaces allowed):

| Column | Description | Required |
|--------|-------------|----------|
| CVE ID | CVE identifier (e.g., CVE-2024-1234) | Yes |
| Severity | CRITICAL, HIGH, MEDIUM, LOW | Yes |
| CVSS Score | Numeric 0-10 | Recommended |
| EPSS Score | Numeric 0-1 | Recommended |
| Repo | Repository name | Recommended |
| Current Version | Installed package version | Optional |
| Fix Package Versions | Available fix versions | Optional |
| CWE ID | Primary CWE (e.g., CWE-79) | Optional |
| CVE Description | Vulnerability description text | Optional |
| CVSS Vector | CVSS v3.x vector string | Optional |
| User Actions | fixed / skipped / false_positive | For training |
| Transitive Dependencies | Dependency count | Optional |
| Detection Time | When the CVE was detected | Optional |
| Sources | Data sources (comma-separated) | Optional |

---

## AWS Bedrock Setup (for LLM Explanations)

LLM explanations are optional. To enable them:

1. Configure AWS credentials:
   ```bash
   export AWS_ACCESS_KEY_ID=your_key
   export AWS_SECRET_ACCESS_KEY=your_secret
   export AWS_DEFAULT_REGION=us-east-1
   ```

2. Ensure you have access to Claude on Bedrock in your AWS account.

3. Use the `explain.py` CLI or the `/api/v1/explain` Java endpoint.

Without Bedrock, the system works fully — use `explain.py shap-only` for offline SHAP-based explanations.

---

## Configuration

### Model Config (`config/model_config.yaml`)

```yaml
xgboost:
  max_depth: 6
  eta: 0.05
  subsample: 0.8
  colsample_bytree: 0.8
  num_boost_round: 500
  early_stopping_rounds: 50

scoring:
  weights:
    ml: 0.45
    cvss: 0.20
    epss: 0.15
    exposure: 0.10
    repo_criticality: 0.10
```

### Database Config (`config/db_config.yaml`)

```yaml
host: localhost
port: 3306
user: vuln_user
password: vuln_password
database: vuln_db
```

---

## Development

```bash
# Install dev dependencies
cd ml-pipeline
pip install -r requirements.txt
pip install pytest

# Run tests
pytest tests/

# Start dashboard API in dev mode
python -m vuln_insight.serving.dashboard_api

# Start React UI in dev mode
cd ../ui
npm install
npm start
```
