package com.vulninsight.api.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulninsight.api.model.RiskScoreResponse;
import com.vulninsight.api.model.VulnerabilityRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.bedrockruntime.BedrockRuntimeClient;
import software.amazon.awssdk.services.bedrockruntime.model.InvokeModelRequest;
import software.amazon.awssdk.services.bedrockruntime.model.InvokeModelResponse;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/**
 * Invokes AWS Bedrock (Claude) to produce a natural-language explanation
 * of a vulnerability risk score.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class BedrockService {

    private final BedrockRuntimeClient bedrockRuntimeClient;
    private final ObjectMapper objectMapper;

    @Value("${aws.bedrock.model-id}")
    private String modelId;

    @Value("${aws.bedrock.max-tokens}")
    private int maxTokens;

    /**
     * Generate a human-readable explanation for the given vulnerability and its
     * computed risk score.
     */
    public String generateExplanation(VulnerabilityRequest req, RiskScoreResponse scored) {
        try {
            String prompt = buildPrompt(req, scored);

            // Build the Messages API request body for Claude on Bedrock
            Map<String, Object> requestBody = Map.of(
                    "anthropic_version", "bedrock-2023-05-31",
                    "max_tokens", maxTokens,
                    "messages", List.of(
                            Map.of(
                                    "role", "user",
                                    "content", prompt
                            )
                    )
            );

            String jsonBody = objectMapper.writeValueAsString(requestBody);

            InvokeModelRequest invokeRequest = InvokeModelRequest.builder()
                    .modelId(modelId)
                    .contentType("application/json")
                    .accept("application/json")
                    .body(SdkBytes.fromString(jsonBody, StandardCharsets.UTF_8))
                    .build();

            InvokeModelResponse invokeResponse = bedrockRuntimeClient.invokeModel(invokeRequest);

            String responseJson = invokeResponse.body().asUtf8String();
            var responseNode = objectMapper.readTree(responseJson);

            // Claude Messages API returns content[0].text
            if (responseNode.has("content") && responseNode.get("content").isArray()) {
                return responseNode.get("content").get(0).get("text").asText();
            }

            log.warn("Unexpected Bedrock response structure for {}", req.cveId());
            return "Explanation unavailable – unexpected model response format.";

        } catch (Exception ex) {
            log.error("Bedrock invocation failed for {}: {}", req.cveId(), ex.getMessage(), ex);
            return "Explanation unavailable – the AI model could not be reached. " +
                   "Risk tier: " + scored.tier() + ", score: " + scored.riskScore() + ".";
        }
    }

    // ---------------------------------------------------------------- helpers

    private String buildPrompt(VulnerabilityRequest req, RiskScoreResponse scored) {
        return String.format("""
                You are a cybersecurity analyst. Provide a concise, actionable explanation \
                (3-5 sentences) of why the following vulnerability received its risk score.

                CVE ID: %s
                CVSS Score: %.1f
                EPSS Score: %.4f
                Known Exploit: %s
                Withdrawn: %s
                Exposure Score: %.2f
                Repository Criticality: %.2f
                Description: %s

                Computed Risk Score: %.4f
                Tier: %s
                ML Score: %.4f
                Overrides Applied: %s

                Focus on the practical impact and recommended priority for remediation. \
                Do not repeat raw numbers; instead, interpret them for a security engineer audience.""",
                req.cveId(),
                req.cvssScore(),
                req.epssScore(),
                req.hasKnownExploit(),
                req.isWithdrawn(),
                req.safeExposureScore(),
                req.safeRepoCriticality(),
                req.description() != null ? req.description() : "N/A",
                scored.riskScore(),
                scored.tier(),
                scored.mlScore(),
                scored.overridesApplied()
        );
    }
}
