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

## 9. LLM Explanation Layer (AWS Bedrock)

Beyond SHAP feature importances, we use **AWS Bedrock (Claude)** to generate natural language risk assessments. The LLM receives structured data from our ML pipeline and produces human-readable analysis in a strict 3-section format.

### How It Works

```
Scored CVE Data + SHAP Features + Repo Stats + Portfolio Context
                          |
                          v
              prompt_templates.py
         (assembles structured prompt)
                          |
                          v
              bedrock_client.py
         (sends to Claude via Bedrock API)
                          |
                          v
          _parse_structured_response()
         (splits into context/impact/remedy)
                          |
                          v
              3-section JSON response
         { context: "...", impact: "...", remedy: "..." }
```

### Credential Loading

The `BedrockClient` reads AWS credentials from environment variables or a `.env` file in `ml-pipeline/`. A custom `.env` parser (no `python-dotenv` dependency) loads credentials at module import time. Variables read:

| Variable | Purpose | Default |
|----------|---------|---------|
| `AWS_ACCESS_KEY_ID` | AWS access key | (required) |
| `AWS_SECRET_ACCESS_KEY` | AWS secret key | (required) |
| `AWS_SESSION_TOKEN` | Temporary session token | (optional) |
| `BEDROCK_REGION` | AWS region for Bedrock | `us-east-1` |
| `BEDROCK_MODEL_ID` | Claude model ID | `anthropic.claude-3-sonnet-20240229-v1:0` |

### The 3-Section Response Format

Every LLM response is parsed into exactly 3 sections:

| Section | Name | Purpose |
|---------|------|---------|
| **I** | **Context-Awareness & Summarisation** | The "What" and "Why" -- what this vulnerability is and why it matters in context |
| **II** | **Impact, Health & Blast Radius** | The "Risk" -- quantified exploitability, security debt, repo health metrics |
| **III** | **Remedy & Actionable Plans** | The "Action" -- shortest path to resolution with specific versions and priorities |

### Prompt Templates

There are 3 prompt templates, each producing the same 3-section output format:

#### 1. Single CVE Explanation Prompt (`build_structured_explanation_prompt`)

**When used**: Dashboard "Get AI Analysis" button per CVE, CLI `explain.py single`

**Data injected into prompt**:
- Vulnerability details: CVE ID, severity, CVSS, EPSS, CWE, package, version, eco system, repo, published date
- ML risk assessment: risk score, tier, ML model prediction
- SHAP top features: top 10 features with importance values and direction (increases/decreases risk)
- Dependency & patch info: transitive count, direct/transitive, patch availability, fix versions
- Repository context: total CVEs, fix rate, false positive rate, avg CVSS, critical count, unique packages/CWEs
- Portfolio context: total vulns across all repos, avg risk score, CRITICAL/HIGH counts, same-CWE count, same-package count
- EPSS/CVSS divergence detection: auto-computed note when EPSS signals diverge from severity
- CVE description: full text

**System prompt**: `"You are a senior security analyst AI. Analyse the following vulnerability data and provide a structured risk assessment."`

**Response instructions given to the LLM**:

```
## I. Context-Awareness & Summarisation
- What is this vulnerability and why does it matter in this specific context?
- How does the ML-based risk tier compare to the raw NVD severity? If they differ,
  explain why the model re-ranked it (using SHAP factors).
- Has this CWE type appeared before in this repo? Is there a recurrence pattern?
- Is the EPSS score divergent from CVSS in a meaningful way?
- Is this a direct or transitive dependency? What does that mean for remediation effort?

## II. Impact, Health & Blast Radius
- What is the exploitability profile? (network-exploitable? auth required? user interaction?)
- What is the EPSS-based exploit likelihood and how does it compare to the portfolio average?
- What is the security debt situation? (days since published, patch availability)
- What is the repository health? (fix rate, CVE velocity, critical count trends)
- Is this a transitive dependency risk? How deep in the dependency tree?
- How does this CVE's risk score compare to the portfolio average?

## III. Remedy & Actionable Plans
- Is a patch available? If yes, what version should they upgrade to?
- Based on historical data, how likely is this team to fix this type of issue? (cite fix rate)
- What is the recommended action? (Fix immediately / Schedule for next sprint / Accept risk)
- Are there architectural or configuration-level mitigations for this CWE class?
- What is the priority relative to other open vulnerabilities?
```

**Key constraint**: `"Only include points you can support with the data above. Be specific with numbers. Do not invent data not provided above."`

#### 2. Portfolio Summary Prompt (`build_portfolio_prompt`)

**When used**: Dashboard "AI Insights" tab, CLI `explain.py portfolio`

**Data injected into prompt**:
- Portfolio overview: total vulnerabilities, avg risk score, tier distribution (CRITICAL/HIGH/MEDIUM/LOW counts), unique repos, unique packages
- Top riskiest repositories: repo name, avg risk, CVE count, critical count, fix rate
- Top critical vulnerabilities: CVE ID, risk score, tier, package, CWE
- CWE patterns: most frequent CWEs with occurrence counts and fix rates
- Most affected packages: package name, CVE count, avg risk score

**System prompt**: `"You are a senior security analyst AI. Generate a structured portfolio-level risk assessment."`

**Response instructions given to the LLM**:

```
## I. Context-Awareness & Summarisation
- What is the overall security posture? Summarise in 2-3 sentences.
- Which CWE types keep recurring? Is there a systemic weakness pattern?
- How is risk distributed across repos? Is it concentrated or spread?
- Are there packages that contribute disproportionately to the vulnerability count?
- What does the CRITICAL/HIGH ratio tell us about urgency?

## II. Impact, Health & Blast Radius
- How many vulnerabilities are CRITICAL or HIGH tier? What percentage of total?
- Which repos have the highest risk concentration? What is their fix rate?
- What is the security debt profile? (avg risk score, critical count)
- Are there cross-cutting packages that affect multiple repos?
- What CWE clusters dominate? What does that imply about the attack surface?

## III. Remedy & Actionable Plans
- What are the top 3-5 actions that would reduce the most risk? (specific packages/repos)
- Which repos need the most attention based on fix rate and critical count?
- Are there "single upgrade" opportunities where one package upgrade fixes multiple CVEs?
- What CWE-class level mitigations could neutralise multiple vulnerabilities at once?
- What should be the remediation priority order?
```

#### 3. Release Comparison Prompt (`build_release_comparison_prompt`)

**When used**: Dashboard "Release Comparison" tab per repository, comparing two releases

**Data injected into prompt**:
- Repository name and the two release tags being compared (current vs previous)
- Per-release stats: total vulnerability count, average risk score, tier breakdown (CRITICAL/HIGH/MEDIUM/LOW), CWE patterns with counts, most affected packages, patch rate, fix rate
- Delta summary: vulnerability count change, average risk change, critical/high tier changes, new CVE count, resolved CVE count
- New CVEs: list of CVEs introduced in the current release (CVE ID, severity, risk score, package, CWE)
- Resolved CVEs: list of CVEs present in previous release but absent in current (CVE ID, severity, risk score, package)
- CWE drift: which weakness types are emerging vs receding between releases

**System prompt**: `"You are a senior security analyst AI. Analyse the following release-over-release vulnerability data for a single repository and provide a structured comparison assessment."`

**Response instructions given to the LLM**:

```
## I. Context-Awareness & Summarisation
- How has the security posture changed between these two releases?
- Is the vulnerability count increasing or decreasing? Is severity shifting?
- Are new CWE types emerging that weren't present in the previous release?
- Which packages are driving the changes?
- Is the overall risk trajectory improving or worsening?

## II. Impact, Health & Blast Radius
- How many CRITICAL/HIGH vulnerabilities were introduced vs resolved?
- What is the delta in average risk score? What does it mean?
- Are there newly introduced CVEs with high EPSS or known exploits?
- What CWE patterns are concentrating? Is there a systemic weakness developing?
- What is the patch rate trend? Are patches being applied between releases?

## III. Remedy & Actionable Plans
- What are the top newly introduced CVEs that need immediate attention?
- Are there "quick wins" -- new CVEs with available patches that can be fixed easily?
- What packages should be prioritised for upgrade between releases?
- Are there CWE-class level mitigations that would address multiple new CVEs?
- What should the team focus on before the next release?
```

**Key constraint**: `"Be specific about which CVEs, packages, and CWE types drive each observation. Cite numbers from the data. Do not speculate beyond what the data shows."`

#### 4. ML Pattern Analysis Prompt (`build_pattern_analysis_prompt`)

**When used**: CLI `explain.py` for model introspection

**Data injected**: Top 15 SHAP feature importances, cluster analysis data

**Response format**: 3 free-form sections -- Pattern Interpretation, Actionable Insights, Model Observations.

### Prompt Design Principles

| Principle | How We Apply It |
|-----------|----------------|
| **Data-grounded** | Every prompt includes "Only include points you can support with the data above. Do not invent data not provided." |
| **Specific over vague** | Instructions say "Be specific with numbers" and "cite the fix rate" |
| **Dynamic context** | Prompts are assembled programmatically -- sections for repo context, portfolio context, SHAP features are only included when data exists |
| **EPSS/CVSS divergence** | Auto-detected in code before prompt assembly. If EPSS >> normalised CVSS, a divergence note is injected. If high CVSS but low EPSS, a different note is injected. |
| **Concise output** | "Keep each section concise (3-6 bullet points)" prevents LLM verbosity |

### Response Parsing

The raw LLM text is parsed by `_parse_structured_response()` which scans for section headers (`## I.`, `## II.`, `## III.` and variants) and splits the text into a `{context, impact, remedy}` dictionary. If parsing fails (LLM didn't follow the format), all text goes into the `context` field as a fallback.

---

## 10. Dashboard UI

A React-based dashboard provides visual access to all scoring results and AI-powered explanations:

| Component | What It Shows |
|-----------|--------------|
| **Upload Panel** | Drag-and-drop CSV upload, or generate sample data |
| **Summary Cards** | Total CVEs, Critical count, Average risk score, Repos scanned |
| **Tier Pie Chart** | Distribution across CRITICAL / HIGH / MEDIUM / LOW |
| **Risk Histogram** | Distribution of risk scores (0-1) |
| **Top Repos Chart** | Top 10 repositories by average risk |
| **Top Packages Chart** | Top 10 packages by vulnerability count |
| **Vulnerability Table** | Sortable, filterable, paginated table of all results |
| **CVE Detail Modal** | Click any CVE to see full detail + SHAP feature importance + AI analysis |
| **AI Analysis (per-CVE)** | "Get AI Analysis" button in any CVE detail modal triggers a Bedrock call and displays a structured 3-section explanation (Context / Impact / Remedy) |
| **AI Insights Tab** | Dedicated portfolio-level tab that generates an AI risk summary covering security posture, blast radius, and prioritised remediation actions |
| **Release Comparison Tab** | Per-repository release-over-release comparison. Select a repo and two releases to see side-by-side stats (tier breakdown, avg risk, new/resolved CVEs), a delta summary card, and AI-powered release comparison analysis |

### AI Components

| React Component | File | Purpose |
|----------------|------|---------|
| `AiInsights` | `ui/src/components/AiInsights.js` | Reusable 3-section tabbed display (I. Context & Summary, II. Impact & Blast Radius, III. Remedy & Action Plan). Handles loading spinner, error with retry, and markdown-style rendering (bullet points, bold text). |
| `PortfolioInsights` | `ui/src/components/PortfolioInsights.js` | Portfolio-level AI analysis page. Shows summary stat cards (total vulns, avg risk, critical/high counts) and uses `AiInsights` for the LLM response. |
| `ReleaseComparison` | `ui/src/components/ReleaseComparison.js` | Release-over-release comparison per repository. Dropdown selectors for repo and release pair (auto-defaults to two most recent releases). Shows side-by-side comparison cards (Current Release ⇄ Delta ⇄ Previous Release) with tier breakdowns, top new/resolved CVE tables, and a "Generate Release Comparison AI Insight" button that calls the Bedrock endpoint and renders the 3-section AI analysis via `AiInsights`. |
| `VulnDetail` | `ui/src/components/VulnDetail.js` | CVE detail modal with risk breakdown, SHAP features, and a "Get AI Analysis" button that calls the per-CVE Bedrock endpoint and displays results via `AiInsights`. |

### Dashboard API Endpoints

The Python FastAPI backend (port 8000) serves both the dashboard data and AI explanation endpoints:

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Health check |
| GET | `/api/model/info` | Model metadata and feature count |
| POST | `/api/upload` | Upload CSV, run scoring, return dashboard data |
| POST | `/api/score/sample?n=500` | Generate sample data, score, return dashboard data |
| GET | `/api/results` | Return last scored results |
| GET | `/api/results/table` | Paginated, filterable vulnerability table |
| GET | `/api/vulnerability/{cve_id}` | Vulnerability detail with SHAP features |
| GET | `/api/explain/portfolio` | AI-generated 3-section portfolio risk summary |
| GET | `/api/explain/{cve_id}` | AI-generated 3-section explanation for a single CVE |
| GET | `/api/repos` | All repos with their releases, per-release summary stats (vuln count, critical count, avg risk) |
| GET | `/api/release-comparison/{repo}/stats` | Fast stats-only comparison between two releases (no LLM). Returns current/previous release stats and delta |
| GET | `/api/explain/release-comparison/{repo}` | AI-powered release comparison via Bedrock LLM. Returns stats + delta + 3-section context/impact/remedy |

### Tech Stack

- **Frontend**: React 18, Recharts (charts), Axios (API calls)
- **Backend API**: Python FastAPI (serves scoring + dashboard data + AI explanations)
- **Charts**: Recharts for pie charts, bar charts, histograms
- **AI Layer**: AWS Bedrock (Claude) via `bedrock_client.py`, called from FastAPI endpoints

---

## 11. Technology Stack Summary

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

## 12. What Makes This Different from Just Using CVSS?

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

## 13. Why ML & LLM? Why Not Just Build APIs Over the Database?

This is the most important architectural question. If we already have vulnerability data in MariaDB (or CSV, or JSON feeds), why can't we just write SQL queries and REST endpoints to power the dashboard? Why bring in XGBoost, SHAP, sentence-transformers, and AWS Bedrock?

The short answer: **traditional APIs give you data retrieval; ML + LLM give you intelligence, prediction, and contextual reasoning that no SQL query or business rule can replicate.**

### What Traditional Database APIs Can Do

If we only built SQL-based APIs, we could:

| Capability | SQL/API Approach |
|-----------|-----------------|
| List all CVEs by severity | `SELECT * FROM cves WHERE severity = 'CRITICAL' ORDER BY cvss_score DESC` |
| Count CVEs per repo | `SELECT repo, COUNT(*) FROM cves GROUP BY repo` |
| Filter by CVSS threshold | `WHERE cvss_score >= 7.0` |
| Show patch availability | `WHERE has_patch = 1` |
| Compare release counts | `SELECT release, COUNT(*) FROM cves WHERE repo = ? GROUP BY release` |

This is basic **data retrieval** -- it shows what's in the database, nothing more.

### What Traditional APIs CANNOT Do

| Limitation | Why It Matters |
|-----------|----------------|
| **Cannot predict which CVEs your team will actually fix** | Historical user behavior patterns (which CWE types get fixed, which packages get patched, which repos are well-maintained) require ML to learn and apply. No SQL query encodes "teams that fix SQL injection 95% of the time will likely fix this one too." |
| **Cannot learn non-linear feature interactions** | A CVE that is MEDIUM severity + high EPSS + network-exploitable + no auth + in a production repo = actually CRITICAL. This is a complex multi-dimensional decision that the ML model learns from 129+ signals interacting together. Writing `IF-THEN-ELSE` rules for all combinations is impossible and brittle. |
| **Cannot generate a risk score that adapts to your organisation** | CVSS is a one-size-fits-all score. Two companies with the same CVE should have different priorities because their repos, teams, tech stacks, and risk appetites differ. The ML model learns YOUR team's decision patterns and produces scores tailored to your context. |
| **Cannot explain WHY a vulnerability matters** | SQL can tell you "CVSS is 7.5." It cannot say "This CVE matters because the EPSS/CVSS ratio is 3x normal, your team fixes this CWE type 95% of the time, it's in a direct production dependency, and similar CVEs were exploited within 7 days." That requires SHAP + LLM. |
| **Cannot synthesise cross-cutting insights** | "Your portfolio has a systemic SQL injection problem concentrated in 3 repos, driven by an outdated ORM dependency" is not a SQL query. It requires pattern recognition across repos, packages, CWE types, and temporal trends -- then natural language generation to communicate it. |
| **Cannot reason about release-over-release trends** | Comparing two releases isn't just "count the CVEs." It's "are the NEW vulnerabilities more severe? Is a new CWE category emerging? Does the delta in patch rate signal a process regression?" This contextual reasoning requires LLM analysis. |

### The ML Layer: What It Adds

```
                    What SQL gives you              What ML adds
                    ==================              ============
 Data:              Raw rows from database    →     Scored, ranked, tiered results
 Ranking:           ORDER BY cvss_score       →     129-feature risk model that learns
                                                    from your team's historical decisions
 Priority:          Static severity buckets   →     Dynamic risk tiers calibrated to
                                                    your organisation's fix patterns
 Explainability:    (none)                    →     SHAP values showing WHY each CVE
                                                    was ranked where it was
 Adaptation:        (none)                    →     Model improves as more fix/skip
                                                    decisions are collected
 Cold start:        (none)                    →     Hybrid scoring ensures new CVE types
                                                    still get reasonable scores via
                                                    CVSS/EPSS fallback
```

### The LLM Layer: What It Adds on Top of ML

The ML model outputs numbers (risk scores, tiers, SHAP values). The LLM converts those numbers into **actionable human intelligence**:

| ML Output | LLM Transformation |
|-----------|-------------------|
| `risk_score: 0.87, tier: CRITICAL` | "This CVE is ranked CRITICAL because the ML model detected a significant divergence between EPSS exploit probability (0.92) and CVSS severity (7.5). The model elevated it because your team has historically fixed 95% of SQL injection CVEs in this repo." |
| `delta: {vuln_count: +12, critical: +3}` | "Release v2.1.0 introduced 12 new vulnerabilities, 3 of which are CRITICAL. This is a significant regression compared to v2.0.0 and is primarily driven by new transitive dependencies in the `spring-security` package. Recommend blocking the release until the 3 critical CVEs are patched." |
| `portfolio: {avg_risk: 0.62, top_cwe: CWE-79}` | "Your portfolio has an above-average risk posture (0.62 avg, MEDIUM-HIGH). XSS vulnerabilities (CWE-79) account for 23% of all findings across 7 repos, suggesting a systemic input validation gap. A single investment in a shared sanitisation library could neutralise 40+ CVEs." |

### The Architecture Layers Working Together

```
Layer 1: DATABASE (Data Storage)
  → "Here are 500 CVEs with their CVSS scores and metadata"
  → Value: Data availability ✓
  → Missing: Intelligence ✗

Layer 2: ML MODEL (Pattern Recognition + Scoring)
  → "Here are those 500 CVEs ranked by a 129-feature risk model that
     learned from your team's past decisions, with SHAP explanations"
  → Value: Data availability ✓, Intelligent ranking ✓, Explainability ✓
  → Missing: Human-readable synthesis ✗

Layer 3: LLM (Contextual Reasoning + Communication)
  → "Here are those 500 CVEs with risk scores + a natural language
     brief: what matters most, why, what to do first, and how this
     release compares to the last one"
  → Value: Data ✓, Intelligence ✓, Explainability ✓, Actionability ✓
```

### Real-World Example: Same Data, Three Approaches

**Scenario**: Security team receives 500 new CVEs this week for 10 repositories.

**Approach 1: SQL APIs only**
- Dashboard shows 500 CVEs sorted by CVSS
- 47 are CRITICAL (CVSS >= 9.0), 120 are HIGH (7.0-8.9)
- Team starts at the top and works down -- estimated 3 days of triage
- They miss a MEDIUM CVE (CVSS 6.5) that has EPSS 0.95 and is being actively exploited

**Approach 2: SQL APIs + ML Scoring**
- Dashboard shows 500 CVEs ranked by hybrid risk score
- Only 18 are tier CRITICAL (risk > 0.80) -- the model filtered out noise
- The MEDIUM/CVSS-6.5 CVE is ranked #3 because EPSS, user behavior, and CWE patterns all signal high risk
- Team triages 18 critical items in 2 hours, not 3 days
- SHAP shows exactly why each was flagged

**Approach 3: SQL APIs + ML Scoring + LLM (our approach)**
- Everything from Approach 2, PLUS:
- Portfolio AI brief: "Critical risk is concentrated in `auth-service` and `payment-gateway`. Both share a vulnerable `jsonwebtoken` dependency -- upgrading to v9.0.2 in both repos resolves 14 CVEs in one action."
- Release comparison: "Release v3.2.0 of `search-service` introduced 8 new CVEs, 2 CRITICAL. This is a regression from v3.1.0 which had resolved 5 CVEs. The regression is driven by a new `elasticsearch-client` dependency."
- Per-CVE analysis: "CVE-2024-12345 is scored CRITICAL despite MEDIUM CVSS because EPSS is 3x higher than expected, this CWE type is fixed 95% of the time by this team, and the package is a direct production dependency."

### Summary: Three Layers, Three Distinct Value Propositions

| Layer | Question It Answers | Cannot Be Replaced By |
|-------|--------------------|-----------------------|
| **Database + APIs** | "What vulnerabilities exist?" | -- (foundation) |
| **ML Model** | "Which ones actually matter for MY team?" | SQL queries, static rules, CVSS thresholds |
| **LLM** | "Why do they matter and what should I do?" | Template strings, canned reports, dashboards |

The database is necessary but not sufficient. The ML model adds intelligence that adapts to your team. The LLM adds communication that turns data into decisions. Each layer builds on the one below it -- removing any one collapses the value of the layers above.

---

## 14. Future Enhancements

1. **Real data training** -- Connect to actual vulnerability management data for dramatically better model accuracy
2. **Continuous learning** -- Retrain periodically as new fix/skip decisions are made
3. **CISA KEV integration** -- Auto-flag vulnerabilities in the Known Exploited Vulnerabilities catalog
4. **Team-specific models** -- Different teams may have different risk appetites; train per-team models
5. **SLA prediction** -- Predict not just "fix or ignore" but "how many days to fix"
6. **Drift detection** -- Monitor for concept drift as vulnerability patterns evolve

---

## 15. How to Run It

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
