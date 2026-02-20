"""Generate sample/synthetic vulnerability data for testing and development.

Creates realistic-looking vulnerability records matching the canonical schema
so the ML pipeline can be tested end-to-end without real data.
"""
import random
from datetime import datetime, timedelta, timezone

import numpy as np
import pandas as pd


# Realistic package names by ecosystem
PACKAGES = {
    "npm": ["express", "lodash", "axios", "react", "webpack", "next", "vue", "moment"],
    "pypi": ["django", "flask", "requests", "numpy", "pandas", "boto3", "celery"],
    "maven": ["spring-boot", "jackson-databind", "log4j-core", "guava", "commons-io"],
    "go": ["golang.org/x/crypto", "github.com/gin-gonic/gin", "google.golang.org/grpc"],
}

CWE_IDS = [
    "CWE-79", "CWE-89", "CWE-22", "CWE-78", "CWE-601", "CWE-94",
    "CWE-287", "CWE-502", "CWE-918", "CWE-1286", "CWE-74", "CWE-119",
    "CWE-120", "CWE-787", "CWE-352", "CWE-862", "CWE-863",
]

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEVERITY_WEIGHTS = [0.05, 0.20, 0.45, 0.30]

REPOS = [
    "frontend-app", "backend-api", "data-service", "auth-service",
    "payment-gateway", "admin-dashboard", "mobile-bff", "analytics-engine",
    "notification-service", "search-service",
]

USER_ACTIONS = ["fixed", "skipped", "false_positive", "ignored", "remediated"]
ACTION_WEIGHTS = [0.35, 0.25, 0.20, 0.10, 0.10]


def generate_sample_data(n_records: int = 1000, seed: int = 42) -> pd.DataFrame:
    """Generate n_records of synthetic vulnerability data.

    Args:
        n_records: Number of records to generate.
        seed: Random seed for reproducibility.

    Returns:
        DataFrame matching the canonical schema.
    """
    rng = np.random.RandomState(seed)
    random.seed(seed)

    records = []
    base_date = datetime(2023, 1, 1, tzinfo=timezone.utc)

    for i in range(n_records):
        ecosystem = random.choice(list(PACKAGES.keys()))
        package = random.choice(PACKAGES[ecosystem])
        severity = random.choices(SEVERITIES, weights=SEVERITY_WEIGHTS, k=1)[0]

        # CVSS score correlated with severity
        cvss_base = {"CRITICAL": 9.0, "HIGH": 7.0, "MEDIUM": 4.5, "LOW": 2.0}[severity]
        cvss_score = round(max(0, min(10, cvss_base + rng.normal(0, 0.8))), 1)

        # EPSS correlated with severity
        epss_base = {"CRITICAL": 0.7, "HIGH": 0.3, "MEDIUM": 0.05, "LOW": 0.01}[severity]
        epss_score = round(max(0, min(1, epss_base + rng.normal(0, 0.1))), 5)
        epss_percentile = round(max(0, min(1, epss_score * 1.2 + rng.normal(0, 0.1))), 5)

        # Dates
        pub_offset = timedelta(days=rng.randint(0, 730))
        published_date = base_date + pub_offset
        modified_date = published_date + timedelta(days=rng.randint(0, 90))
        detection_offset = timedelta(days=rng.randint(1, 60))
        detection_time = published_date + detection_offset

        # Patch
        has_patch = random.random() < 0.65
        fix_version = f"{rng.randint(1, 10)}.{rng.randint(0, 30)}.{rng.randint(0, 20)}"

        # CWEs
        n_cwes = random.choices([1, 2, 3], weights=[0.7, 0.2, 0.1], k=1)[0]
        cwes = random.sample(CWE_IDS, min(n_cwes, len(CWE_IDS)))

        # CVSS vector
        av = random.choice(["N", "L", "A", "P"])
        ac = random.choice(["L", "H"])
        pr = random.choice(["N", "L", "H"])
        ui = random.choice(["R", "N"])
        s = random.choice(["C", "U"])
        c = random.choice(["N", "L", "H"])
        ii = random.choice(["N", "L", "H"])
        a = random.choice(["N", "L", "H"])
        cvss_vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{ii}/A:{a}"

        repo = random.choice(REPOS)

        # User action — more likely to fix high/critical
        if severity in ("CRITICAL", "HIGH"):
            action = random.choices(
                USER_ACTIONS, weights=[0.50, 0.15, 0.15, 0.10, 0.10], k=1
            )[0]
        else:
            action = random.choices(
                USER_ACTIONS, weights=[0.20, 0.30, 0.25, 0.15, 0.10], k=1
            )[0]

        records.append({
            "cve_id": f"CVE-{2023 + rng.randint(0, 3)}-{rng.randint(10000, 99999)}",
            "vuln_id": f"GHSA-{''.join(random.choices('abcdefghijklmnop', k=4))}-"
                       f"{''.join(random.choices('abcdefghijklmnop', k=4))}-"
                       f"{''.join(random.choices('abcdefghijklmnop', k=4))}",
            "title": f"Vulnerability in {package} ({cwes[0]})",
            "repo": repo,
            "release": f"v{rng.randint(1, 5)}.{rng.randint(0, 20)}.{rng.randint(0, 50)}",
            "package_name": package,
            "package_version": f"{rng.randint(1, 8)}.{rng.randint(0, 30)}.{rng.randint(0, 15)}",
            "ecosystem": ecosystem,
            "purl": f"pkg:{ecosystem}/{package}@{rng.randint(1,5)}.{rng.randint(0,20)}.{rng.randint(0,10)}",
            "severity": severity,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "epss_score": epss_score,
            "epss_percentile": epss_percentile,
            "published_date": published_date.isoformat(),
            "modified_date": modified_date.isoformat(),
            "release_date": (published_date - timedelta(days=rng.randint(30, 365))).isoformat(),
            "detection_time": detection_time.isoformat(),
            "has_patch": has_patch,
            "fix_versions": fix_version if has_patch else "",
            "patch_recommendation": f"Upgrade {package} to version {fix_version} or later" if has_patch else "",
            "cwes": ",".join(cwes),
            "cwe_count": len(cwes),
            "primary_cwe": cwes[0],
            "cve_description": _generate_description(package, cwes[0], severity),
            "num_references": rng.randint(1, 10),
            "sources": random.choice(["OSV, GitHub, NVD", "GitHub, NVD", "NVD", "OSV, GitHub"]),
            "num_sources": rng.randint(1, 4),
            "transitive_dep_count": rng.randint(0, 50),
            "is_withdrawn": 0,
            "user_action": action,
            "status": "open" if action in ("skipped", "ignored") else "resolved",
            "licence": random.choice(["MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "GPL-3.0"]),
        })

    df = pd.DataFrame(records)

    # Add a few withdrawn advisories
    withdrawn_mask = rng.random(len(df)) < 0.02
    df.loc[withdrawn_mask, "is_withdrawn"] = 1
    df.loc[withdrawn_mask, "title"] = df.loc[withdrawn_mask, "title"].apply(
        lambda t: f"Withdrawn Advisory: {t}"
    )

    return df


def _generate_description(package: str, cwe: str, severity: str) -> str:
    """Generate a realistic CVE description."""
    cwe_desc = {
        "CWE-79": "cross-site scripting (XSS)",
        "CWE-89": "SQL injection",
        "CWE-22": "path traversal",
        "CWE-78": "OS command injection",
        "CWE-601": "open redirect",
        "CWE-94": "code injection",
        "CWE-287": "improper authentication",
        "CWE-502": "deserialization of untrusted data",
        "CWE-918": "server-side request forgery (SSRF)",
        "CWE-74": "injection",
        "CWE-119": "buffer overflow",
        "CWE-120": "classic buffer overflow",
        "CWE-787": "out-of-bounds write",
        "CWE-352": "cross-site request forgery (CSRF)",
        "CWE-1286": "improper validation of syntactic correctness of input",
    }

    vuln_type = cwe_desc.get(cwe, "security vulnerability")

    templates = [
        f"A {vuln_type} vulnerability was discovered in {package}. "
        f"This {severity.lower()} severity issue allows an attacker to exploit "
        f"the application through specially crafted input.",
        f"{package} is vulnerable to {vuln_type}. "
        f"An attacker could leverage this vulnerability to compromise the system. "
        f"The issue has been classified as {severity.lower()} severity.",
        f"A vulnerability in {package} allows {vuln_type} via untrusted user input. "
        f"This has been rated as {severity.lower()} severity based on CVSS scoring.",
    ]

    return random.choice(templates)


def save_sample_csv(path: str = "sample_data.csv", n_records: int = 1000):
    """Generate and save sample data as CSV for testing."""
    df = generate_sample_data(n_records)
    df.to_csv(path, index=False)
    print(f"Saved {n_records} sample records to {path}")
    return df
