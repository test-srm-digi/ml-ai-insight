"""AWS Bedrock integration for generating vulnerability risk explanations.

Reads credentials from environment variables or .env file:
  AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN
  BEDROCK_REGION, BEDROCK_MODEL_ID
"""
import json
import os
from pathlib import Path
from typing import Optional

import boto3


def _load_env():
    """Load .env file from ml-pipeline root if it exists."""
    env_paths = [
        Path(__file__).resolve().parent.parent.parent.parent / ".env",
        Path.cwd() / ".env",
    ]
    for env_path in env_paths:
        if env_path.exists():
            with open(env_path) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, _, value = line.partition("=")
                    key = key.strip()
                    value = value.strip().strip("'\"")
                    if value and key not in os.environ:
                        os.environ[key] = value
            break


_load_env()


class BedrockClient:
    def __init__(
        self,
        region_name: Optional[str] = None,
        model_id: Optional[str] = None,
    ):
        self.region = region_name or os.environ.get("BEDROCK_REGION", "us-east-1")
        self.model_id = model_id or os.environ.get(
            "BEDROCK_MODEL_ID", "anthropic.claude-3-sonnet-20240229-v1:0"
        )

        session_kwargs = {}
        access_key = os.environ.get("AWS_ACCESS_KEY_ID")
        secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY")
        session_token = os.environ.get("AWS_SESSION_TOKEN")

        if access_key and secret_key:
            session_kwargs["aws_access_key_id"] = access_key
            session_kwargs["aws_secret_access_key"] = secret_key
            if session_token:
                session_kwargs["aws_session_token"] = session_token

        session = boto3.Session(**session_kwargs)
        self.client = session.client("bedrock-runtime", region_name=self.region)

    def invoke(self, prompt: str, max_tokens: int = 2048, temperature: float = 0.3) -> str:
        """Send a prompt to Bedrock and return the response text."""
        body = json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [{"role": "user", "content": prompt}],
        })

        response = self.client.invoke_model(
            modelId=self.model_id,
            body=body,
            contentType="application/json",
            accept="application/json",
        )

        response_body = json.loads(response["body"].read())
        return response_body["content"][0]["text"]

    def explain_vulnerability(
        self, vuln_data: dict, shap_features: list, risk_score: float, tier: str,
        repo_stats: Optional[dict] = None, portfolio_context: Optional[dict] = None,
    ) -> dict:
        """Generate a structured 3-section explanation for a vulnerability.

        Returns dict with keys: context, impact, remedy.
        """
        from vuln_insight.llm.prompt_templates import build_structured_explanation_prompt

        prompt = build_structured_explanation_prompt(
            vuln_data, shap_features, risk_score, tier, repo_stats, portfolio_context
        )
        raw = self.invoke(prompt, max_tokens=2048)
        return _parse_structured_response(raw)

    def generate_portfolio_summary(self, summary_data: dict) -> dict:
        """Generate a portfolio-level 3-section summary.

        Returns dict with keys: context, impact, remedy.
        """
        from vuln_insight.llm.prompt_templates import build_portfolio_prompt

        prompt = build_portfolio_prompt(summary_data)
        raw = self.invoke(prompt, max_tokens=3000)
        return _parse_structured_response(raw)

    def generate_release_comparison(self, comparison_data: dict) -> dict:
        """Generate a release-over-release comparison analysis for a repository.

        Returns dict with keys: context, impact, remedy.
        """
        from vuln_insight.llm.prompt_templates import build_release_comparison_prompt

        prompt = build_release_comparison_prompt(comparison_data)
        raw = self.invoke(prompt, max_tokens=3000)
        return _parse_structured_response(raw)


def _parse_structured_response(raw_text: str) -> dict:
    """Parse LLM response into context/impact/remedy sections."""
    sections = {"context": "", "impact": "", "remedy": ""}

    current = None
    lines = raw_text.strip().split("\n")

    for line in lines:
        lower = line.strip().lower()
        if any(k in lower for k in ["## i.", "## context", "# context", "**i.", "**context"]):
            current = "context"
            continue
        elif any(k in lower for k in ["## ii.", "## impact", "# impact", "**ii.", "**impact"]):
            current = "impact"
            continue
        elif any(k in lower for k in ["## iii.", "## remedy", "# remedy", "**iii.", "**remedy"]):
            current = "remedy"
            continue

        if current:
            sections[current] += line + "\n"

    # If parsing failed, put everything in context
    if not any(sections.values()):
        sections["context"] = raw_text

    # Clean up whitespace
    for k in sections:
        sections[k] = sections[k].strip()

    return sections
