# VulnInsight: ML-Powered Vulnerability Risk Intelligence

## Technical Deep-Dive for Engineering & Leadership

---

## 1. What Problem Are We Solving?

Security teams are overwhelmed by vulnerability alerts. A typical enterprise application portfolio generates thousands of CVEs (Common Vulnerabilities and Exposures) per month. The vast majority are noise -- low-risk findings that don't need immediate attention. But buried in that noise are the ones that **actually matter**.

**Today's approach (manual):**
- Engineer sees 500 new CVEs this week
- Sorts by CVSS score (a static severity rating)
- Spends hours triaging -- most are false positives or low-risk
- Misses a MEDIUM-severity CVE that is actually being actively exploited

**Our approach (ML-powered):**
- All 500 CVEs are fed through an ML model that has learned from historical fix/skip/ignore decisions
- Each CVE gets a **risk score** (0-1) that considers 129+ signals, not just CVSS
- A ranked, tiered output (CRITICAL / HIGH / MEDIUM / LOW) tells the team exactly where to focus
- Per-CVE explanations show **why** each score was assigned

---

## 2. System Architecture

```
                    DATA SOURCES
                    ============
     CSV Files    JSON API Responses    MariaDB
         |               |                |
         v               v                v
    csv_loader.py   json_ingester.py   db_loader.py
         |               |                |
         +-------+-------+-------+--------+
                 |
                 v
          transformers.py
     (Normalize to canonical schema)
                 |
                 v
    +------- FEATURE ENGINEERING --------+
    |  7 feature blocks = 129+ features  |
    |                                    |
    |  A. CVE Core (~32 features)        |
    |  B. CWE Intelligence (~25)         |
    |  C. Package/Dependency (~40)       |
    |  D. Repo Behavior (~20)            |
    |  E. Time & Exposure (~20)          |
    |  F. Text Embeddings (~105)         |
    |  G. User Behavior (~20)            |
    +------------------------------------+
                 |
                 v
         XGBoost Model (Training)
                 |
                 v
    +------- HYBRID RISK SCORING --------+
    |                                    |
    |  risk_score =                      |
    |    0.45 * ML prediction            |
    |  + 0.20 * normalized CVSS          |
    |  + 0.15 * EPSS percentile          |
    |  + 0.10 * exposure score           |
    |  + 0.10 * repo criticality         |
    |                                    |
    |  + business rule overrides         |
    +------------------------------------+
                 |
                 v
         Tier Classification
    (CRITICAL > 0.8 | HIGH > 0.6 |
     MEDIUM > 0.4 | LOW <= 0.4)
                 |
         +-------+-------+
         |               |
         v               v
    SHAP Explanations   Dashboard UI
    (why this score?)   (React + Charts)
```

---

## 3. The ML Model

### Algorithm: XGBoost (Gradient Boosted Decision Trees)

We chose **XGBoost** because:

| Factor | Why XGBoost Fits |
|--------|-----------------|
| **Tabular data** | XGBoost is the gold standard for structured/tabular datasets. Our data is rows of CVE records with numeric and categorical features -- not images or text sequences. |
| **Handles missing data natively** | Vulnerability data is messy. Many fields are optional. XGBoost learns optimal default directions for missing values without imputation. |
| **Feature importance built-in** | We can explain every prediction via SHAP values -- critical for security teams who need to trust the model. |
| **Fast training and inference** | Trains on 1000 records in seconds. Scores new CVEs in milliseconds. No GPU required. |
| **Robust to class imbalance** | Not all CVEs get fixed. The model handles the natural imbalance between "fixed" vs "ignored" outcomes. |

### What the Model Learns (Training Target)

The model is a **binary classifier** that predicts:

```
label = 1  -->  Vulnerability was ACTIONED (fixed, remediated, patched)
label = 0  -->  Vulnerability was IGNORED  (false_positive, skipped, deferred)
```

This is derived from the `user_action` column in historical data -- what security engineers actually **did** with each CVE in the past. The model learns the patterns that distinguish actionable vulnerabilities from noise.

### Training Process

```
1. Load data (CSV / JSON / MariaDB)
2. Normalize to canonical schema (38 standardized columns)
3. Create binary labels from user_action column
4. Extract 129+ features across 7 feature blocks
5. Time-based train/test split (80% train, 20% test)
   - NOT random split -- we split by published_date
   - Prevents future data from leaking into training
6. Train XGBoost with early stopping
   - 500 max boosting rounds
   - Stops if AUC doesn't improve for 50 rounds
   - Learning rate: 0.05
   - Max tree depth: 6
7. Evaluate: AUC, Precision, Recall, F1, Confusion Matrix
8. Generate SHAP explanations for feature importance
9. Save model artifacts (.json model, feature names, metrics)
```

### Key Hyperparameters

| Parameter | Value | Purpose |
|-----------|-------|---------|
| `objective` | `binary:logistic` | Binary classification, outputs probability 0-1 |
| `eval_metric` | `auc` | Optimize for ranking quality (area under ROC curve) |
| `max_depth` | 6 | Maximum tree depth -- prevents overfitting |
| `eta` (learning rate) | 0.05 | Small steps for better generalization |
| `subsample` | 0.8 | Use 80% of data per tree (bagging) |
| `colsample_bytree` | 0.8 | Use 80% of features per tree |
| `lambda` (L2 reg) | 1.0 | Ridge regularization |
| `alpha` (L1 reg) | 0.5 | Lasso regularization |
| `early_stopping_rounds` | 50 | Stop if no improvement in 50 rounds |

---

## 4. Feature Engineering (What the Model Sees)

The raw vulnerability data is transformed into 129+ numeric features that the model can learn from. Features are organized in 7 blocks:

### Block A: CVE Core Features (~32 features)

These are the fundamental facts about each vulnerability.

| Feature | What It Is | Why It Matters |
|---------|-----------|----------------|
| `severity_numeric` | CRITICAL=4, HIGH=3, MEDIUM=2, LOW=1 | Base severity level |
| `cvss_score` | 0-10 score from NVD | Industry-standard severity metric |
| `epss_score` | Exploit Prediction Scoring System (0-1) | Probability of being exploited in the wild |
| `epss_percentile` | EPSS relative ranking | How this CVE compares to all others |
| `days_since_published` | Age of the CVE | Older unpatched CVEs are higher risk |
| `days_since_modified` | Time since last update | Recent updates may indicate active exploitation |
| `has_patch` | 0 or 1 | Is a fix available? |
| `num_references` | Count of advisory references | More references = more attention from researchers |
| `attack_vector_network` | 0 or 1 (from CVSS vector) | Can be exploited over the network? |
| `privileges_required_none` | 0 or 1 (from CVSS vector) | No authentication needed to exploit? |
| `user_interaction_none` | 0 or 1 (from CVSS vector) | No user click/action needed to trigger? |
| ... + 20 more CVSS vector fields | One-hot encoded CVSS v3.1 components | Full attack surface characterization |

### Block B: CWE Intelligence (~25 features)

CWE (Common Weakness Enumeration) tells us the **type** of vulnerability.

| Feature | What It Is | Why It Matters |
|---------|-----------|----------------|
| `cwe_count` | Number of CWE classifications | Multi-weakness CVEs are often more severe |
| `is_cwe_79` | Is XSS? | Top-10 dangerous weakness type |
| `is_cwe_89` | Is SQL injection? | Top-10 dangerous weakness type |
| `cwe_is_injection` | CWE in injection family | Injection flaws are reliably exploitable |
| `cwe_is_auth_related` | CWE in authentication family | Auth bypasses are critical |
| `cwe_is_memory_related` | CWE in memory corruption family | RCE potential |
| `cwe_primary_encoded` | Label-encoded primary CWE | Allows model to learn CWE-specific patterns |

### Block C: Package/Dependency (~40 features)

Information about the affected software package.

| Feature | What It Is | Why It Matters |
|---------|-----------|----------------|
| `dependency_depth` | How deep in the dependency tree | Transitive deps are harder to patch |
| `is_direct_dependency` | Direct or transitive? | Direct deps are easier to remediate |
| `transitive_dep_count` | Number of transitive dependencies | More deps = more attack surface |
| `version_gap_major` | Major version difference to fix | Large upgrades are riskier to apply |
| `has_fix_available` | Is there a fixed version? | No fix = accept risk or rearchitect |
| `package_ecosystem_npm` | npm ecosystem? | One-hot for package ecosystem |
| `package_name_frequency` | How common is this package? | Popular packages get more scrutiny |

### Block D: Repo Behavioral (~20 features)

Aggregated statistics about the repository where the vulnerability was found.

| Feature | What It Is | Why It Matters |
|---------|-----------|----------------|
| `repo_total_cves` | Total CVEs in this repo | Repos with many CVEs may have systemic issues |
| `repo_cve_count_30d` | CVEs in last 30 days | Spike = something is wrong |
| `repo_fix_rate` | Historical fix rate for this repo | Repos that fix things are well-maintained |
| `repo_false_positive_rate` | Historical FP rate for this repo | High FP repos generate noise |
| `repo_avg_cvss` | Average CVSS across repo | Baseline severity for this codebase |
| `repo_cve_velocity` | CVEs per day over repo's lifetime | Rate of vulnerability discovery |

### Block E: Time & Exposure (~20 features)

Temporal signals that capture urgency and exploit likelihood.

| Feature | What It Is | Why It Matters |
|---------|-----------|----------------|
| `cve_age_days` | How old is the CVE? | Old unpatched CVEs accumulate risk |
| `detection_delay_days` | Time between publish and detection | Long delays = worse exposure |
| `exposure_window_days` | Days vulnerable if unpatched | Duration of risk |
| `is_exploit_known` | Known exploit exists? | Dramatically increases actual risk |
| `epss_cvss_ratio` | EPSS / (CVSS/10) | Divergence signals exploitability vs severity mismatch |
| `severity_age_interaction` | Severity * age | Old critical CVEs are worse than new ones |
| `reference_density` | References per day since published | High density = active research |

### Block F: Text Embeddings (~105 features)

Natural language understanding of CVE descriptions.

| Feature | What It Is | Why It Matters |
|---------|-----------|----------------|
| `description_length` | Character count | Longer descriptions often describe more complex issues |
| `description_has_exploit_mention` | Contains "exploit"? | Explicit exploit discussion |
| `description_has_rce_mention` | Contains "remote code execution"? | RCE is highest impact |
| `text_embed_0` ... `text_embed_99` | Sentence-transformer embeddings (PCA-reduced) | Semantic understanding of vulnerability description |

The embedding model is **all-MiniLM-L6-v2** (a sentence-transformer), which converts each CVE description into a 384-dimensional vector. We reduce to 100 dimensions via PCA to keep the model efficient. This allows the model to find patterns like "CVEs described in similar language tend to be actioned similarly."

### Block G: User Behavior (~20 features)

Historical patterns from how the team has handled similar vulnerabilities.

| Feature | What It Is | Why It Matters |
|---------|-----------|----------------|
| `historical_fix_rate_same_cwe` | Fix rate for same CWE type | "We always fix SQL injection" |
| `historical_fix_rate_same_package` | Fix rate for same package | "We always patch log4j" |
| `historical_fix_rate_same_severity` | Fix rate for same severity | "We always fix CRITICAL" |
| `historical_skip_rate_same_repo` | Skip rate for same repo | "This repo's findings are often noise" |
| `package_action_consistency` | Variability of actions per package | Consistent handling = clearer signal |
| `severity_action_alignment` | How severity correlates with action | Teams that follow severity have different patterns |

---

## 5. The Hybrid Risk Score

The final risk score is **not purely ML**. It combines the ML prediction with known security metrics and business rules:

```
risk_score = 0.45 * ml_score              (XGBoost prediction probability)
           + 0.20 * normalized_cvss        (CVSS score / 10)
           + 0.15 * epss_percentile        (EPSS exploit likelihood)
           + 0.10 * exposure_score         (network attack + no auth + known exploit)
           + 0.10 * repo_criticality       (production=1.0, internal=0.5, dev=0.3)
```

### Why Hybrid and Not Pure ML?

| Reason | Explanation |
|--------|-------------|
| **Transparency** | Stakeholders understand CVSS and EPSS. A pure ML score is a black box. |
| **Guardrails** | Even if the ML model makes an error, CVSS and EPSS provide safety. |
| **Regulatory** | Some compliance frameworks require consideration of standard severity scores. |
| **Cold start** | New vulnerability types with no training history still get scored via CVSS/EPSS. |

### Business Rule Overrides

Hard rules that cannot be overridden by the ML model:

| Rule | Effect |
|------|--------|
| CVE is in CISA KEV (Known Exploited Vulnerabilities) | Floor at 0.90 |
| CVSS >= 9.0 AND network-exploitable with known exploit | Floor at 0.85 |
| Advisory is withdrawn | Cap at 0.10 |

### Tier Classification

| Tier | Risk Score Range | Action |
|------|-----------------|--------|
| **CRITICAL** | > 0.80 | Fix immediately |
| **HIGH** | 0.60 - 0.80 | Fix this sprint |
| **MEDIUM** | 0.40 - 0.60 | Schedule for next cycle |
| **LOW** | <= 0.40 | Accept risk or backlog |

---

## 6. Model Explainability (SHAP)

Every prediction can be explained using **SHAP (SHapley Additive exPlanations)**, which assigns a contribution value to each feature for each individual prediction.

### How SHAP Works (Simplified)

For a CVE scored at risk = 0.82 (CRITICAL), SHAP tells us:

```
Base value (average prediction):     0.45
  + epss_cvss_ratio:                +0.12  (EPSS much higher than CVSS suggests)
  + severity_age_interaction:       +0.09  (Critical + old = dangerous)
  + cvss_score:                     +0.07  (High CVSS of 9.1)
  + historical_fix_rate_same_cwe:   +0.05  (Team always fixes this CWE type)
  + attack_vector_network:          +0.04  (Network-exploitable)
                                    ------
Final ML prediction:                 0.82
```

This answers the question: **"Why did the model flag this CVE?"**

### Top Features by SHAP Importance (from training)

Based on our trained model, these features have the highest average impact:

| Rank | Feature | Mean SHAP Importance |
|------|---------|---------------------|
| 1 | `epss_cvss_ratio` | 0.0455 |
| 2 | `severity_age_interaction` | 0.0422 |
| 3 | `cvss_score` | 0.0287 |
| 4 | `historical_fix_rate_same_cwe` | 0.0259 |
| 5 | `cwe_primary_encoded` | 0.0259 |
| 6 | `historical_fix_rate_same_package` | 0.0244 |
| 7 | `epss_score` | 0.0232 |
| 8 | `epss_percentile` | 0.0227 |
| 9 | `days_since_modified` | 0.0219 |
| 10 | `package_action_consistency` | 0.0218 |

**Key insight**: The model doesn't just look at CVSS score. It heavily weights the EPSS/CVSS ratio (are exploit signals divergent from severity?), temporal factors, and historical user behavior patterns.

---

## 7. Data Pipeline: End-to-End Flow

### Step 1: Data Ingestion

Three input paths:

| Source | Module | Use Case |
|--------|--------|----------|
| **CSV files** | `csv_loader.py` | Bulk import from spreadsheets/exports |
| **JSON API** | `json_ingester.py` | Real-time API response parsing |
| **MariaDB** | `db_loader.py` | Direct database connection |
| **Synthetic** | `sample_data.py` | Testing and development |

### Step 2: Schema Normalization

`transformers.py` converts any input format into a **canonical schema** with 38 standardized columns. This handles:
- Column name mapping (e.g., "CVSS Score" -> "cvss_score")
- Date parsing (ISO 8601, various formats -> UTC datetime)
- Severity normalization (case, spelling variations -> CRITICAL/HIGH/MEDIUM/LOW)
- CVSS score type coercion (string -> float)
- CWE parsing (comma-separated -> count + primary)
- Boolean normalization ("true"/"yes"/"1"/"patched" -> 1)

### Step 3: Label Creation

The `user_action` column is mapped to binary labels:

| User Action | Label | Meaning |
|------------|-------|---------|
| fixed | 1 | Team took action |
| remediated | 1 | Team took action |
| patched | 1 | Team took action |
| accepted | 1 | Team took action |
| false_positive | 0 | Not a real issue |
| skipped | 0 | Intentionally ignored |
| ignored | 0 | Intentionally ignored |
| deferred | 0 | Not prioritized |

### Step 4: Feature Engineering

The `FeaturePipeline` orchestrates all 7 blocks, producing a wide feature matrix. Each block runs independently and results are concatenated.

### Step 5: Training

Time-based split ensures we train on older data and test on newer data (prevents temporal leakage). XGBoost trains with early stopping on AUC.

### Step 6: Scoring

New vulnerabilities are scored through the same feature pipeline, then the hybrid scorer combines ML prediction with CVSS/EPSS/business rules.

---

## 8. Current Model Performance

Trained on synthetic data (1000 records, 129 features):

| Metric | Value | Notes |
|--------|-------|-------|
| **AUC** | 0.604 | Above random (0.5). Expected to improve significantly with real data. |
| **Accuracy** | 67.5% | Baseline: 69% (always predict majority class) |
| **Precision** | 42.1% | When model says "action", it's right 42% of time |
| **Recall** | 12.9% | Model catches 13% of actual actionable CVEs |
| **F1** | 0.198 | Harmonic mean of precision and recall |

**Why are metrics modest?** The model is trained on **randomly generated synthetic data** where the features have limited real-world correlation to the labels. With real historical vulnerability data where user actions actually correlate with CVE characteristics, we expect AUC of **0.75-0.85+**.

---

## 9. Dashboard UI

A React-based dashboard provides visual access to all scoring results:

| Component | What It Shows |
|-----------|--------------|
| **Upload Panel** | Drag-and-drop CSV upload, or generate sample data |
| **Summary Cards** | Total CVEs, Critical count, Average risk score, Repos scanned |
| **Tier Pie Chart** | Distribution across CRITICAL / HIGH / MEDIUM / LOW |
| **Risk Histogram** | Distribution of risk scores (0-1) |
| **Top Repos Chart** | Top 10 repositories by average risk |
| **Top Packages Chart** | Top 10 packages by vulnerability count |
| **Vulnerability Table** | Sortable, filterable, paginated table of all results |
| **CVE Detail Modal** | Click any CVE to see full detail + SHAP feature importance |

### Tech Stack

- **Frontend**: React 18, Recharts (charts), Axios (API calls)
- **Backend API**: Python FastAPI (serves scoring + dashboard data)
- **Charts**: Recharts for pie charts, bar charts, histograms

---

## 10. Technology Stack Summary

| Layer | Technology | Purpose |
|-------|-----------|---------|
| **ML Model** | XGBoost | Gradient boosted trees for binary classification |
| **Feature Engineering** | pandas, NumPy, scikit-learn | Data transformation and feature extraction |
| **Text Embeddings** | sentence-transformers (all-MiniLM-L6-v2) | CVE description semantic encoding |
| **Dimensionality Reduction** | PCA (scikit-learn) | Reduce 384-dim embeddings to 100-dim |
| **Explainability** | SHAP (TreeExplainer) | Per-prediction feature importance |
| **CVSS Parsing** | Custom parser | CVSS v3.1 vector string to one-hot features |
| **API** | FastAPI + Uvicorn | Python REST API for scoring and dashboard |
| **Dashboard** | React 18 + Recharts | Interactive data visualization |
| **Java API** | Spring Boot 3.2 | Enterprise REST API layer (optional) |
| **LLM Explanations** | AWS Bedrock (Claude) | Natural language vulnerability explanations |
| **Database** | MariaDB | Persistent storage (optional) |
| **Containerization** | Docker + Docker Compose | Full-stack deployment |

---

## 11. What Makes This Different from Just Using CVSS?

| Approach | Signals Used | Weakness |
|----------|-------------|----------|
| **CVSS only** | Static severity score (0-10) | Doesn't account for exploit likelihood, context, or organizational history |
| **CVSS + EPSS** | Severity + exploit probability | No organizational context, no learning from past decisions |
| **VulnInsight (ours)** | 129+ features including CVSS, EPSS, CWE type, package context, repo history, user behavior, text analysis, temporal patterns | Learns what YOUR team considers important and adapts |

### Concrete example:

```
CVE-2024-12345: SQL injection in lodash (CVSS 7.5, MEDIUM)

CVSS approach:       MEDIUM -> schedule for next quarter
CVSS + EPSS:         EPSS 0.92 -> high exploit probability, maybe bump to HIGH

VulnInsight:         Risk Score 0.87 -> CRITICAL
  Reasons:
  - EPSS/CVSS ratio is 3x normal (exploit signals far exceed severity rating)
  - This repo has fixed 95% of SQL injection CVEs historically
  - Package is a direct dependency in production
  - Similar CVEs in this CWE were exploited within 7 days
  - Network-exploitable with no authentication required
```

---

## 12. Future Enhancements

1. **Real data training** -- Connect to actual vulnerability management data for dramatically better model accuracy
2. **Continuous learning** -- Retrain periodically as new fix/skip decisions are made
3. **CISA KEV integration** -- Auto-flag vulnerabilities in the Known Exploited Vulnerabilities catalog
4. **Team-specific models** -- Different teams may have different risk appetites; train per-team models
5. **SLA prediction** -- Predict not just "fix or ignore" but "how many days to fix"
6. **Drift detection** -- Monitor for concept drift as vulnerability patterns evolve

---

## 13. How to Run It

```bash
# Install
cd ml-pipeline
pip3 install -r requirements.txt
pip3 install -e .

# Generate sample data
python3 scripts/ingest.py sample -n 1000 -o data/sample_data.csv

# Train the model
python3 scripts/train.py --data data/sample_data.csv --no-embeddings --split time

# Start the dashboard API
python3 -m vuln_insight.serving.dashboard_api

# In another terminal, start the React UI
cd ui && npm install && npm start

# Open http://localhost:3000
```
