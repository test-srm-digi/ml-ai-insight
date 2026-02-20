"""JSON API response ingester.

Flattens nested vulnerability scan JSON responses (OSV/GitHub/NVD aggregated format)
into a flat DataFrame suitable for feature engineering.
"""
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Union

import pandas as pd


def ingest_json(json_data: Union[str, dict, Path]) -> pd.DataFrame:
    """Ingest a JSON API response and flatten into a DataFrame.

    Args:
        json_data: Either a dict, a JSON string, or a Path to a JSON file.

    Returns:
        DataFrame with one row per vulnerability, columns matching canonical schema.
    """
    if isinstance(json_data, (str, Path)):
        path = Path(json_data)
        if path.exists():
            with open(path) as f:
                data = json.load(f)
        else:
            data = json.loads(json_data)
    else:
        data = json_data

    query_info = data.get("query", {})
    vulnerabilities = data.get("vulnerabilities", [])

    rows = []
    for vuln in vulnerabilities:
        row = _extract_flat_record(vuln, query_info)
        rows.append(row)

    if not rows:
        return pd.DataFrame()

    return pd.DataFrame(rows)


def ingest_json_batch(json_files: List[Union[str, Path]]) -> pd.DataFrame:
    """Ingest multiple JSON API responses and concatenate."""
    frames = []
    for f in json_files:
        df = ingest_json(f)
        if not df.empty:
            frames.append(df)
    if not frames:
        return pd.DataFrame()
    return pd.concat(frames, ignore_index=True)


def _extract_flat_record(vuln: dict, query_info: dict) -> dict:
    """Extract a flat dict from a single vulnerability entry."""
    epss = vuln.get("epss", {}) or {}
    patch_info = vuln.get("patchInfo", {}) or {}
    cvss_metrics = vuln.get("cvssMetrics", {}) or {}

    # Extract CWEs
    cwes = vuln.get("cwes", []) or []
    weaknesses = vuln.get("weaknesses", []) or []
    all_cwes = list(cwes)
    for w in weaknesses:
        for c in w.get("cwes", []):
            cwe_id = c.get("id", "") if isinstance(c, dict) else str(c)
            if cwe_id and cwe_id not in all_cwes:
                all_cwes.append(cwe_id)

    # Extract fix versions
    fix_versions = []
    patches = patch_info.get("patches", []) or []
    for p in patches:
        fix_versions.extend(p.get("fixedVersions", []))

    # Extract affected package ranges count
    affected_packages = vuln.get("affectedPackages", []) or []
    num_affected_ranges = sum(
        len(ap.get("ranges", []) or []) for ap in affected_packages
    )

    # Source string
    source = vuln.get("source", "")

    record = {
        # Identifiers
        "cve_id": vuln.get("cve", vuln.get("id", "")),
        "vuln_id": vuln.get("id", ""),
        "title": vuln.get("title", ""),

        # Package info from query
        "package_name": query_info.get("package", ""),
        "package_version": query_info.get("version", ""),
        "ecosystem": query_info.get("ecosystem", ""),
        "purl": query_info.get("purl", ""),

        # Severity
        "severity": (vuln.get("severity") or "UNKNOWN").upper(),
        "cvss_score": vuln.get("cvssScore"),
        "cvss_vector": vuln.get("cvssVector", ""),

        # CVSS metrics (raw dict for later parsing)
        "cvss_attack_vector": cvss_metrics.get("attackVector", ""),
        "cvss_attack_complexity": cvss_metrics.get("attackComplexity", ""),
        "cvss_privileges_required": cvss_metrics.get("privilegesRequired", ""),
        "cvss_user_interaction": cvss_metrics.get("userInteraction", ""),
        "cvss_scope": cvss_metrics.get("scope", ""),
        "cvss_confidentiality": cvss_metrics.get("confidentialityImpact", ""),
        "cvss_integrity": cvss_metrics.get("integrityImpact", ""),
        "cvss_availability": cvss_metrics.get("availabilityImpact", ""),

        # EPSS
        "epss_score": epss.get("score"),
        "epss_percentile": epss.get("percentile"),

        # Dates
        "published_date": vuln.get("publishedDate", ""),
        "modified_date": vuln.get("modifiedDate", ""),

        # Patch info
        "has_patch": patch_info.get("isPatched", False) if patch_info else False,
        "fix_versions": ",".join(fix_versions) if fix_versions else "",
        "patch_recommendation": patch_info.get("recommendation", "") if patch_info else "",

        # References
        "num_references": len(vuln.get("references", []) or []),
        "references": ",".join(vuln.get("references", []) or []),

        # CWE / weaknesses
        "cwes": ",".join(all_cwes),
        "cwe_count": len(all_cwes),
        "primary_cwe": all_cwes[0] if all_cwes else "",

        # Description
        "cve_description": vuln.get("description", ""),

        # Affected packages
        "num_affected_ranges": num_affected_ranges,
        "num_affected_packages": len(affected_packages),

        # Source
        "sources": source,
        "num_sources": len([s.strip() for s in source.split(",") if s.strip()]) if source else 0,

        # Is withdrawn
        "is_withdrawn": 1 if "withdrawn" in (vuln.get("title", "") or "").lower() else 0,
    }

    return record
