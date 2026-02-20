"""Prompt templates for structured LLM vulnerability explanations.

All responses follow a 3-section format:
  I.  Context & Summarisation — the "What" and "Why"
  II. Impact, Health & Blast Radius — the "Risk"
  III. Remedy & Actionable Plans — the "Action"
"""
import json
from typing import Optional


def build_structured_explanation_prompt(
    vuln_data: dict,
    shap_features: list,
    risk_score: float,
    tier: str,
    repo_stats: Optional[dict] = None,
    portfolio_context: Optional[dict] = None,
) -> str:
    """Build a prompt for a single CVE that produces Context / Impact / Remedy sections.

    Only references data fields we actually have.
    """
    # Format SHAP features
    shap_lines = ""
    if shap_features:
        shap_lines = "\n".join(
            f"  - {name}: {val:+.4f} ({'increases' if val > 0 else 'decreases'} risk)"
            for name, val in shap_features
        )
    else:
        shap_lines = "  (SHAP features not available)"

    # Repo context block
    repo_block = ""
    if repo_stats:
        repo_block = f"""
## Repository Context ({vuln_data.get('repo', 'N/A')})
- Total CVEs in this repo: {repo_stats.get('repo_total_cves', 'N/A')}
- CVEs in last 30 days: {repo_stats.get('repo_cve_count_30d', 'N/A')}
- Historical fix rate: {_fmt_pct(repo_stats.get('repo_fix_rate'))}
- Historical false positive rate: {_fmt_pct(repo_stats.get('repo_false_positive_rate'))}
- Average CVSS in this repo: {_fmt_float(repo_stats.get('repo_avg_cvss'))}
- Critical CVEs in this repo: {repo_stats.get('repo_critical_count', 'N/A')}
- Unique packages affected: {repo_stats.get('repo_unique_packages', 'N/A')}
- Unique CWEs seen: {repo_stats.get('repo_unique_cwes', 'N/A')}"""

    # Portfolio context
    portfolio_block = ""
    if portfolio_context:
        portfolio_block = f"""
## Portfolio Context
- Total vulnerabilities across all repos: {portfolio_context.get('total_vulnerabilities', 'N/A')}
- Portfolio average risk score: {_fmt_float(portfolio_context.get('avg_risk_score'))}
- CRITICAL count: {portfolio_context.get('critical_count', 'N/A')}
- HIGH count: {portfolio_context.get('high_count', 'N/A')}
- CWE {vuln_data.get('primary_cwe', '?')} occurrence count: {portfolio_context.get('same_cwe_count', 'N/A')}
- Package {vuln_data.get('package_name', '?')} total CVEs: {portfolio_context.get('same_pkg_count', 'N/A')}"""

    # Dependency info
    dep_info = ""
    transitive = vuln_data.get("transitive_dep_count", 0)
    has_patch = vuln_data.get("has_patch", False)
    fix_ver = vuln_data.get("fix_versions", "")
    dep_info = f"""
## Dependency & Patch Info
- Transitive dependency count: {transitive}
- Is direct dependency: {"Yes" if transitive == 0 else "No (transitive)"}
- Patch available: {"Yes" if has_patch else "No"}
- Fix version(s): {fix_ver if fix_ver else "None available"}"""

    # EPSS vs CVSS divergence
    cvss = float(vuln_data.get("cvss_score", 0))
    epss = float(vuln_data.get("epss_score", 0))
    divergence_note = ""
    if cvss > 0:
        normalised_cvss = cvss / 10.0
        if epss > normalised_cvss * 1.5:
            divergence_note = f"\n**Note**: EPSS ({epss:.4f}) is significantly higher than normalised CVSS ({normalised_cvss:.2f}), indicating exploit likelihood exceeds what severity alone suggests."
        elif epss < normalised_cvss * 0.3 and cvss >= 7.0:
            divergence_note = f"\n**Note**: Despite high CVSS ({cvss}), EPSS ({epss:.4f}) is very low, suggesting this vulnerability is rarely exploited in practice."

    return f"""You are a senior security analyst AI. Analyse the following vulnerability data and provide a structured risk assessment.

## Vulnerability Details
- CVE ID: {vuln_data.get('cve_id', 'N/A')}
- Title: {vuln_data.get('title', 'N/A')}
- Severity (NVD): {vuln_data.get('severity', 'N/A')}
- CVSS Score: {cvss}
- EPSS Score: {epss} (probability of exploitation)
- EPSS Percentile: {vuln_data.get('epss_percentile', 'N/A')}
- Primary CWE: {vuln_data.get('primary_cwe', 'N/A')}
- Package: {vuln_data.get('package_name', 'N/A')}
- Package Version: {vuln_data.get('package_version', 'N/A')}
- Ecosystem: {vuln_data.get('ecosystem', 'N/A')}
- Repository: {vuln_data.get('repo', 'N/A')}
- Published: {vuln_data.get('published_date', 'N/A')}
- Days since published: {vuln_data.get('days_since_published', 'N/A')}
{divergence_note}

## ML Risk Assessment
- Risk Score: {risk_score:.3f} (0-1 scale)
- Risk Tier: {tier}
- ML Model Prediction: {vuln_data.get('ml_score', 'N/A')}

## Top Contributing Factors (SHAP Analysis)
{shap_lines}
{dep_info}
{repo_block}
{portfolio_block}

## CVE Description
{vuln_data.get('cve_description', 'No description available.')}

---

Respond in EXACTLY the following 3-section structure. Only include points you can support with the data above. Be specific with numbers.

## I. Context-Awareness & Summarisation
Provide a narrative about this vulnerability:
- What is this vulnerability and why does it matter in this specific context?
- How does the ML-based risk tier ({tier}) compare to the raw NVD severity ({vuln_data.get('severity', 'N/A')})? If they differ, explain why the model re-ranked it (using SHAP factors).
- Has this CWE type ({vuln_data.get('primary_cwe', 'N/A')}) appeared before in this repo? Is there a recurrence pattern?
- Is the EPSS score divergent from CVSS in a meaningful way?
- Is this a direct or transitive dependency? What does that mean for remediation effort?

## II. Impact, Health & Blast Radius
Quantify the actual risk:
- What is the exploitability profile? (network-exploitable? auth required? user interaction needed?)
- What is the EPSS-based exploit likelihood and how does it compare to the portfolio average?
- What is the security debt situation? (days since published, patch availability)
- What is the repository health? (fix rate, CVE velocity, critical count trends)
- Is this a transitive dependency risk? How deep in the dependency tree?
- How does this CVE's risk score compare to the portfolio average?

## III. Remedy & Actionable Plans
Provide the shortest path to resolution:
- Is a patch available? If yes, what version should they upgrade to?
- Based on historical data, how likely is this team to fix this type of issue? (cite the fix rate)
- What is the recommended action? (Fix immediately / Schedule for next sprint / Accept risk / Investigate further)
- Are there any architectural or configuration-level mitigations for this CWE class?
- What is the priority relative to other open vulnerabilities?

Keep each section concise (3-6 bullet points). Use specific numbers from the data. Do not invent data not provided above."""


def build_portfolio_prompt(summary_data: dict) -> str:
    """Build a prompt for portfolio-level 3-section summary."""
    tier_counts = summary_data.get("tier_counts", {})
    top_repos = summary_data.get("top_repos", [])
    top_cves = summary_data.get("top_cves", [])
    cwe_patterns = summary_data.get("cwe_patterns", [])
    pkg_patterns = summary_data.get("pkg_patterns", [])
    severity_dist = summary_data.get("severity_distribution", {})
    repo_health = summary_data.get("repo_health", [])

    repos_text = "\n".join(
        f"  - {r['repo']}: avg risk {r['avg_risk']:.3f}, {r['cve_count']} CVEs, "
        f"critical: {r.get('critical_count', 0)}, fix rate: {_fmt_pct(r.get('fix_rate'))}"
        for r in top_repos
    ) if top_repos else "  No repo data available."

    cves_text = "\n".join(
        f"  - {c['cve_id']}: score {c['risk_score']:.3f} ({c['tier']}), "
        f"package: {c.get('package_name', '?')}, CWE: {c.get('primary_cwe', '?')}"
        for c in top_cves
    ) if top_cves else "  No CVE data available."

    cwe_text = "\n".join(
        f"  - {c['cwe']}: {c['count']} occurrences ({_fmt_pct(c.get('fix_rate'))} fix rate)"
        for c in cwe_patterns
    ) if cwe_patterns else "  No CWE pattern data."

    pkg_text = "\n".join(
        f"  - {p['package']}: {p['count']} CVEs, avg risk: {_fmt_float(p.get('avg_risk'))}"
        for p in pkg_patterns
    ) if pkg_patterns else "  No package data."

    return f"""You are a senior security analyst AI. Generate a structured portfolio-level risk assessment.

## Portfolio Overview
- Total Vulnerabilities: {summary_data.get('total_vulnerabilities', 0)}
- Average Risk Score: {_fmt_float(summary_data.get('avg_risk_score'))}
- Tier Distribution:
  - CRITICAL: {tier_counts.get('CRITICAL', 0)}
  - HIGH: {tier_counts.get('HIGH', 0)}
  - MEDIUM: {tier_counts.get('MEDIUM', 0)}
  - LOW: {tier_counts.get('LOW', 0)}
- Unique Repositories: {summary_data.get('unique_repos', 'N/A')}
- Unique Packages: {summary_data.get('unique_packages', 'N/A')}

## Top Riskiest Repositories
{repos_text}

## Top Critical Vulnerabilities
{cves_text}

## CWE Patterns (Most Frequent Weakness Types)
{cwe_text}

## Most Affected Packages
{pkg_text}

---

Respond in EXACTLY the following 3-section structure. Only include points you can support with data above. Be specific with numbers.

## I. Context-Awareness & Summarisation
Provide an executive narrative:
- What is the overall security posture? Summarise in 2-3 sentences.
- Which CWE types keep recurring? Is there a systemic weakness pattern (e.g. injection-heavy, auth-heavy)?
- How is risk distributed across repos? Is it concentrated or spread?
- Are there packages that contribute disproportionately to the vulnerability count?
- What does the CRITICAL/HIGH ratio tell us about urgency?

## II. Impact, Health & Blast Radius
Quantify the portfolio risk:
- How many vulnerabilities are CRITICAL or HIGH tier? What percentage of total?
- Which repos have the highest risk concentration? What is their fix rate?
- What is the security debt profile? (avg risk score, critical count)
- Are there cross-cutting packages that affect multiple repos?
- What CWE clusters dominate? What does that imply about the attack surface?

## III. Remedy & Actionable Plans
Provide prioritised actions:
- What are the top 3-5 actions that would reduce the most risk? Be specific (which packages, which repos).
- Which repos need the most attention based on fix rate and critical count?
- Are there "single upgrade" opportunities where upgrading one package fixes multiple CVEs?
- What CWE-class level mitigations could neutralise multiple vulnerabilities at once? (e.g. CSP for XSS)
- What should be the remediation priority order?

Keep each section concise (4-8 bullet points). Use specific numbers from the data. Do not invent data not provided above."""


def build_pattern_analysis_prompt(patterns_data: dict) -> str:
    """Build a prompt for ML pattern analysis."""
    top_features = patterns_data.get("top_features", [])
    clusters = patterns_data.get("clusters", [])

    features_text = "\n".join(
        f"  {i+1}. {f['feature']}: importance {f['importance']:.4f}"
        for i, f in enumerate(top_features[:15])
    ) if top_features else "  No feature data."

    cluster_text = json.dumps(clusters, indent=2) if clusters else "  No cluster data."

    return f"""You are a data scientist specialising in security ML. Analyse the following model patterns.

## Top Feature Importances (SHAP)
{features_text}

## Cluster Analysis
{cluster_text}

Please provide:
1. **Pattern Interpretation**: What do the top features tell us about vulnerability risk drivers?
2. **Actionable Insights**: What concrete steps can improve security posture based on these patterns?
3. **Model Observations**: Any concerns about feature quality, potential biases, or areas for model improvement?

Keep the analysis technical but actionable."""


def _fmt_pct(val) -> str:
    if val is None:
        return "N/A"
    try:
        return f"{float(val) * 100:.1f}%"
    except (TypeError, ValueError):
        return str(val)


def _fmt_float(val) -> str:
    if val is None:
        return "N/A"
    try:
        return f"{float(val):.3f}"
    except (TypeError, ValueError):
        return str(val)
