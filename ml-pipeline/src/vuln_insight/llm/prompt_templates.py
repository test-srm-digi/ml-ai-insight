"""Prompt templates for LLM vulnerability explanations."""
import json


def build_explanation_prompt(
    vuln_data: dict, shap_features: list, risk_score: float, tier: str
) -> str:
    """Build a prompt for explaining a single vulnerability risk score.

    Args:
        vuln_data: CVE metadata dict.
        shap_features: List of (feature_name, shap_value) tuples, top contributors.
        risk_score: Hybrid risk score (0-1).
        tier: Risk tier (CRITICAL, HIGH, MEDIUM, LOW).
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

    return f"""You are a security analyst AI. Analyze the following vulnerability and explain its risk assessment.

## Vulnerability Details
- CVE ID: {vuln_data.get('cve_id', 'N/A')}
- Title: {vuln_data.get('title', 'N/A')}
- Severity: {vuln_data.get('severity', 'N/A')}
- CVSS Score: {vuln_data.get('cvss_score', 'N/A')}
- EPSS Score: {vuln_data.get('epss_score', 'N/A')}
- Package: {vuln_data.get('package_name', 'N/A')}
- Repository: {vuln_data.get('repo', 'N/A')}
- Has Patch: {vuln_data.get('has_patch', 'N/A')}

## ML Risk Assessment
- Risk Score: {risk_score:.3f}
- Risk Tier: {tier}

## Top Contributing Factors (SHAP Analysis)
{shap_lines}

## Description
{vuln_data.get('cve_description', 'No description available.')}

Please provide:
1. **Plain English Explanation**: Why did this vulnerability receive a {tier} risk rating? Explain in 2-3 sentences suitable for a developer or security engineer.
2. **Recommended Action**: What should the team do? (Fix now, schedule fix, accept risk, investigate further, mark as false positive)
3. **Urgency Assessment**: How urgent is remediation? Consider the exploit likelihood, exposure, and business impact.

Keep the response concise and actionable."""


def build_portfolio_prompt(summary_data: dict) -> str:
    """Build a prompt for portfolio-level risk summary.

    Args:
        summary_data: Dict with aggregated stats.
    """
    tier_counts = summary_data.get("tier_counts", {})
    top_repos = summary_data.get("top_repos", [])
    top_cves = summary_data.get("top_cves", [])
    cwe_patterns = summary_data.get("cwe_patterns", [])

    repos_text = "\n".join(
        f"  - {r['repo']}: avg risk {r['avg_risk']:.3f}, {r['cve_count']} CVEs"
        for r in top_repos
    ) if top_repos else "  No repo data available."

    cves_text = "\n".join(
        f"  - {c['cve_id']}: score {c['risk_score']:.3f} ({c['tier']})"
        for c in top_cves
    ) if top_cves else "  No CVE data available."

    cwe_text = "\n".join(
        f"  - {c['cwe']}: {c['count']} occurrences"
        for c in cwe_patterns
    ) if cwe_patterns else "  No CWE pattern data."

    return f"""You are a security analyst AI. Generate an executive summary of the vulnerability portfolio.

## Portfolio Overview
- Total Vulnerabilities: {summary_data.get('total_vulnerabilities', 0)}
- Average Risk Score: {summary_data.get('avg_risk_score', 0):.3f}
- Tier Distribution:
  - CRITICAL: {tier_counts.get('CRITICAL', 0)}
  - HIGH: {tier_counts.get('HIGH', 0)}
  - MEDIUM: {tier_counts.get('MEDIUM', 0)}
  - LOW: {tier_counts.get('LOW', 0)}

## Top 3 Riskiest Repositories
{repos_text}

## Top 5 Critical Vulnerabilities
{cves_text}

## Common CWE Patterns
{cwe_text}

Please provide:
1. **Executive Summary**: 3-4 sentence overview of the security posture.
2. **Top 3 Recommendations**: Prioritized actions the security team should take.
3. **Trend Analysis**: What patterns do you see? Which areas need the most attention?

Keep the response structured and actionable for a security leadership audience."""


def build_pattern_analysis_prompt(patterns_data: dict) -> str:
    """Build a prompt for ML pattern analysis.

    Args:
        patterns_data: Dict with SHAP importances and cluster info.
    """
    top_features = patterns_data.get("top_features", [])
    clusters = patterns_data.get("clusters", [])

    features_text = "\n".join(
        f"  {i+1}. {f['feature']}: importance {f['importance']:.4f}"
        for i, f in enumerate(top_features[:15])
    ) if top_features else "  No feature data."

    cluster_text = json.dumps(clusters, indent=2) if clusters else "  No cluster data."

    return f"""You are a data scientist specializing in security ML. Analyze the following model patterns.

## Top Feature Importances (SHAP)
{features_text}

## Cluster Analysis
{cluster_text}

Please provide:
1. **Pattern Interpretation**: What do the top features tell us about vulnerability risk drivers?
2. **Actionable Insights**: What concrete steps can improve security posture based on these patterns?
3. **Model Observations**: Any concerns about feature quality, potential biases, or areas for model improvement?

Keep the analysis technical but actionable."""
