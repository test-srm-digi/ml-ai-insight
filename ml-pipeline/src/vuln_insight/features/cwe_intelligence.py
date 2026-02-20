"""Block B: CWE Intelligence Features (~25 features).

Extracts CWE type indicators, category groupings, historical exploit rates,
and label-encoded primary CWE.
"""
import numpy as np
import pandas as pd


# Top-10 most dangerous CWEs for one-hot encoding
TOP_CWES = [79, 89, 22, 78, 601, 94, 287, 502, 918, 1286]

# CWE category families
CWE_INJECTION = {79, 89, 94, 78, 74}
CWE_WEB = {79, 601, 352, 918}
CWE_MEMORY = {119, 120, 787, 125, 416}
CWE_AUTH = {287, 862, 863, 306}
CWE_CRYPTO = {326, 327, 328, 330}

# Historical exploit rates (from MITRE/NVD research, approximate)
CWE_EXPLOIT_RATES = {
    79: 0.65, 89: 0.72, 22: 0.55, 78: 0.80, 601: 0.30,
    94: 0.75, 287: 0.50, 502: 0.70, 918: 0.45, 1286: 0.20,
    74: 0.60, 119: 0.68, 120: 0.65, 787: 0.70, 352: 0.35,
    862: 0.40, 863: 0.38, 306: 0.55, 416: 0.72, 125: 0.60,
    326: 0.25, 327: 0.30, 328: 0.28, 330: 0.22,
}

# Global frequency scores (normalized 0-1, approximate from NVD data)
CWE_GLOBAL_FREQUENCY = {
    79: 0.95, 89: 0.85, 22: 0.70, 78: 0.50, 601: 0.40,
    94: 0.45, 287: 0.60, 502: 0.55, 918: 0.35, 1286: 0.15,
    74: 0.65, 119: 0.75, 120: 0.50, 787: 0.80, 352: 0.55,
    862: 0.30, 863: 0.28, 306: 0.35, 416: 0.45, 125: 0.40,
    326: 0.20, 327: 0.25, 328: 0.18, 330: 0.15,
}

# Label encoding for top-50 CWEs (unknown=0)
CWE_LABEL_ENCODING = {
    "CWE-79": 1, "CWE-89": 2, "CWE-22": 3, "CWE-78": 4, "CWE-601": 5,
    "CWE-94": 6, "CWE-287": 7, "CWE-502": 8, "CWE-918": 9, "CWE-1286": 10,
    "CWE-74": 11, "CWE-119": 12, "CWE-120": 13, "CWE-787": 14, "CWE-352": 15,
    "CWE-862": 16, "CWE-863": 17, "CWE-306": 18, "CWE-416": 19, "CWE-125": 20,
    "CWE-190": 21, "CWE-200": 22, "CWE-269": 23, "CWE-276": 24, "CWE-400": 25,
    "CWE-434": 26, "CWE-476": 27, "CWE-522": 28, "CWE-611": 29, "CWE-668": 30,
    "CWE-732": 31, "CWE-755": 32, "CWE-770": 33, "CWE-798": 34, "CWE-843": 35,
    "CWE-862": 36, "CWE-908": 37, "CWE-909": 38, "CWE-917": 39, "CWE-1021": 40,
    "CWE-326": 41, "CWE-327": 42, "CWE-328": 43, "CWE-330": 44, "CWE-20": 45,
    "CWE-77": 46, "CWE-295": 47, "CWE-384": 48, "CWE-532": 49, "CWE-943": 50,
}


def _parse_cwe_ids(cwe_str: str) -> set:
    """Parse comma-separated CWE string into set of integer IDs."""
    if not cwe_str or str(cwe_str) == "nan":
        return set()
    ids = set()
    for part in str(cwe_str).split(","):
        part = part.strip().upper()
        # Extract numeric part from "CWE-79" or just "79"
        num_str = part.replace("CWE-", "").replace("CWE", "")
        try:
            ids.add(int(num_str))
        except (ValueError, TypeError):
            continue
    return ids


def extract_cwe_features(df: pd.DataFrame) -> pd.DataFrame:
    """Extract ~25 CWE intelligence features."""
    features = pd.DataFrame(index=df.index)

    # Parse CWE IDs for each row
    cwes_col = df.get("cwes", pd.Series("", index=df.index))
    cwe_sets = cwes_col.apply(_parse_cwe_ids)

    # CWE count
    features["cwe_count"] = cwe_sets.apply(len)

    # Top-10 one-hot
    for cwe_id in TOP_CWES:
        features[f"is_cwe_{cwe_id}"] = cwe_sets.apply(lambda s: 1 if cwe_id in s else 0)

    # Category flags
    features["cwe_is_injection"] = cwe_sets.apply(lambda s: 1 if s & CWE_INJECTION else 0)
    features["cwe_is_web_related"] = cwe_sets.apply(lambda s: 1 if s & CWE_WEB else 0)
    features["cwe_is_memory_related"] = cwe_sets.apply(lambda s: 1 if s & CWE_MEMORY else 0)
    features["cwe_is_auth_related"] = cwe_sets.apply(lambda s: 1 if s & CWE_AUTH else 0)
    features["cwe_is_crypto_related"] = cwe_sets.apply(lambda s: 1 if s & CWE_CRYPTO else 0)
    features["cwe_is_deserialization"] = cwe_sets.apply(lambda s: 1 if 502 in s else 0)

    # Historical exploit rate (max across all CWEs in row)
    features["cwe_historical_exploit_rate"] = cwe_sets.apply(
        lambda s: max((CWE_EXPLOIT_RATES.get(c, 0.0) for c in s), default=0.0)
    )

    # Global frequency (max across all CWEs)
    features["cwe_global_frequency"] = cwe_sets.apply(
        lambda s: max((CWE_GLOBAL_FREQUENCY.get(c, 0.0) for c in s), default=0.0)
    )

    # Primary CWE label encoding
    primary_cwe = df.get("primary_cwe", pd.Series("", index=df.index))
    features["cwe_primary_encoded"] = primary_cwe.apply(
        lambda x: CWE_LABEL_ENCODING.get(str(x).strip().upper(), 0)
    )

    return features
