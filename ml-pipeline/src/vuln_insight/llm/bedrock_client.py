"""AWS Bedrock integration for generating vulnerability risk explanations."""
import json
from typing import Optional

import boto3


class BedrockClient:
    def __init__(
        self,
        region_name: str = "us-east-1",
        model_id: str = "anthropic.claude-3-sonnet-20240229-v1:0",
    ):
        self.client = boto3.client("bedrock-runtime", region_name=region_name)
        self.model_id = model_id

    def invoke(self, prompt: str, max_tokens: int = 1024, temperature: float = 0.3) -> str:
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
        self, vuln_data: dict, shap_features: list, risk_score: float, tier: str
    ) -> str:
        """Generate a natural language explanation for a vulnerability risk score."""
        from vuln_insight.llm.prompt_templates import build_explanation_prompt

        prompt = build_explanation_prompt(vuln_data, shap_features, risk_score, tier)
        return self.invoke(prompt)

    def generate_portfolio_summary(self, summary_data: dict) -> str:
        """Generate a portfolio-level risk summary."""
        from vuln_insight.llm.prompt_templates import build_portfolio_prompt

        prompt = build_portfolio_prompt(summary_data)
        return self.invoke(prompt, max_tokens=2048)
