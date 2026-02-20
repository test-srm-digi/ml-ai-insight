package com.vulninsight.api.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;

/**
 * Response payload carrying the computed risk score for a single vulnerability.
 */
public record RiskScoreResponse(

        @JsonProperty("cve_id")
        String cveId,

        @JsonProperty("risk_score")
        double riskScore,

        @JsonProperty("tier")
        String tier,

        @JsonProperty("ml_score")
        double mlScore,

        @JsonProperty("cvss_normalized")
        double cvssNormalized,

        @JsonProperty("epss_score")
        double epssScore,

        @JsonProperty("exposure_score")
        double exposureScore,

        @JsonProperty("repo_criticality")
        double repoCriticality,

        @JsonProperty("ml_fallback_used")
        boolean mlFallbackUsed,

        @JsonProperty("overrides_applied")
        String overridesApplied,

        @JsonProperty("scored_at")
        Instant scoredAt
) {
}
