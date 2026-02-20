"""CVSS vector string parser.

Parses CVSS v3.x vector strings like:
  CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L

into one-hot binary features.
"""
from typing import Dict, Optional


# Maps each CVSS metric key to its possible values
CVSS_METRICS = {
    "AV": {"N": "network", "L": "local", "A": "adjacent", "P": "physical"},
    "AC": {"L": "low", "H": "high"},
    "PR": {"N": "none", "L": "low", "H": "high"},
    "UI": {"R": "required", "N": "none"},
    "S":  {"C": "changed", "U": "unchanged"},
    "C":  {"N": "none", "L": "low", "H": "high"},
    "I":  {"N": "none", "L": "low", "H": "high"},
    "A":  {"N": "none", "L": "low", "H": "high"},
}

# Friendly prefix names for the feature columns
METRIC_PREFIXES = {
    "AV": "attack_vector",
    "AC": "attack_complexity",
    "PR": "privileges_required",
    "UI": "user_interaction",
    "S":  "scope",
    "C":  "confidentiality",
    "I":  "integrity",
    "A":  "availability",
}


def parse_cvss_vector(vector_str: Optional[str]) -> Dict[str, int]:
    """Parse a CVSS v3.x vector string into one-hot binary feature dict.

    Args:
        vector_str: CVSS vector like "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L"

    Returns:
        Dict mapping feature names to 0/1 values. Example:
        {
            "attack_vector_network": 1,
            "attack_vector_local": 0,
            "attack_vector_adjacent": 0,
            "attack_vector_physical": 0,
            "attack_complexity_low": 0,
            "attack_complexity_high": 1,
            ...
        }
    """
    features = {}

    # Initialize all features to 0
    for metric_key, values in CVSS_METRICS.items():
        prefix = METRIC_PREFIXES[metric_key]
        for val_name in values.values():
            features[f"{prefix}_{val_name}"] = 0

    if not vector_str or not isinstance(vector_str, str):
        return features

    # Strip CVSS version prefix if present
    parts = vector_str.strip()
    if parts.startswith("CVSS:"):
        # Remove "CVSS:3.1/" prefix
        slash_idx = parts.find("/")
        if slash_idx >= 0:
            parts = parts[slash_idx + 1:]
        else:
            return features

    # Parse each metric
    for segment in parts.split("/"):
        if ":" not in segment:
            continue
        key, val = segment.split(":", 1)
        key = key.strip().upper()
        val = val.strip().upper()

        if key in CVSS_METRICS and val in CVSS_METRICS[key]:
            prefix = METRIC_PREFIXES[key]
            value_name = CVSS_METRICS[key][val]
            features[f"{prefix}_{value_name}"] = 1

    return features


def parse_cvss_metrics_dict(metrics: Optional[Dict[str, str]]) -> Dict[str, int]:
    """Parse CVSS metrics from a dictionary (JSON API format).

    Args:
        metrics: Dict like {"attackVector": "Network", "attackComplexity": "High", ...}

    Returns:
        Same one-hot binary feature dict as parse_cvss_vector.
    """
    features = {}

    # Initialize all features to 0
    for metric_key, values in CVSS_METRICS.items():
        prefix = METRIC_PREFIXES[metric_key]
        for val_name in values.values():
            features[f"{prefix}_{val_name}"] = 0

    if not metrics or not isinstance(metrics, dict):
        return features

    # Mapping from JSON API field names to our metric keys and value names
    field_map = {
        "attackVector": ("attack_vector", {
            "network": "network", "local": "local",
            "adjacent": "adjacent", "physical": "physical"
        }),
        "attackComplexity": ("attack_complexity", {
            "low": "low", "high": "high"
        }),
        "privilegesRequired": ("privileges_required", {
            "none": "none", "low": "low", "high": "high"
        }),
        "userInteraction": ("user_interaction", {
            "required": "required", "none": "none"
        }),
        "scope": ("scope", {
            "changed": "changed", "unchanged": "unchanged"
        }),
        "confidentialityImpact": ("confidentiality", {
            "none": "none", "low": "low", "high": "high"
        }),
        "integrityImpact": ("integrity", {
            "none": "none", "low": "low", "high": "high"
        }),
        "availabilityImpact": ("availability", {
            "none": "none", "low": "low", "high": "high"
        }),
    }

    for json_key, (prefix, val_map) in field_map.items():
        raw_val = metrics.get(json_key, "")
        if raw_val:
            normalized = raw_val.strip().lower()
            if normalized in val_map:
                features[f"{prefix}_{val_map[normalized]}"] = 1

    return features


def get_cvss_feature_names() -> list:
    """Return ordered list of all CVSS one-hot feature names."""
    names = []
    for metric_key, values in CVSS_METRICS.items():
        prefix = METRIC_PREFIXES[metric_key]
        for val_name in values.values():
            names.append(f"{prefix}_{val_name}")
    return names
