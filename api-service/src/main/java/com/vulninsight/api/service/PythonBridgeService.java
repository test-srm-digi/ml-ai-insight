package com.vulninsight.api.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.vulninsight.api.model.ModelInfoResponse;
import com.vulninsight.api.model.VulnerabilityRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.time.Instant;
import java.util.Map;

/**
 * Communicates with the Python ML sidecar via non-blocking WebClient calls.
 *
 * If the sidecar is unreachable or returns an error, the service falls back to
 * a default ML score of 0.5 so that the API remains available.
 */
@Slf4j
@Service
public class PythonBridgeService {

    private static final double FALLBACK_ML_SCORE = 0.5;

    private final WebClient sidecarWebClient;

    public PythonBridgeService(@Qualifier("sidecarWebClient") WebClient sidecarWebClient) {
        this.sidecarWebClient = sidecarWebClient;
    }

    // ---------------------------------------------------------------- predict

    /**
     * Request an ML prediction from the Python sidecar.
     *
     * POST /predict
     * Body: { "cve_id": "...", "cvss_score": ..., "epss_score": ..., ... }
     *
     * Expected response: { "ml_score": 0.73 }
     */
    public MlResult predict(VulnerabilityRequest req) {
        try {
            Map<String, Object> payload = Map.of(
                    "cve_id",            req.cveId(),
                    "cvss_score",        req.cvssScore(),
                    "epss_score",        req.epssScore(),
                    "has_known_exploit", req.hasKnownExploit(),
                    "exposure_score",    req.safeExposureScore(),
                    "repo_criticality",  req.safeRepoCriticality()
            );

            JsonNode body = sidecarWebClient.post()
                    .uri("/predict")
                    .bodyValue(payload)
                    .retrieve()
                    .bodyToMono(JsonNode.class)
                    .block();   // blocking here is acceptable; endpoint is synchronous

            if (body != null && body.has("ml_score")) {
                double score = body.get("ml_score").asDouble();
                log.debug("Sidecar returned ml_score={} for {}", score, req.cveId());
                return new MlResult(score, false);
            }

            log.warn("Sidecar response missing 'ml_score' field – using fallback for {}", req.cveId());
            return new MlResult(FALLBACK_ML_SCORE, true);

        } catch (WebClientResponseException ex) {
            log.error("Sidecar HTTP error {} for {}: {}", ex.getStatusCode(), req.cveId(), ex.getMessage());
            return new MlResult(FALLBACK_ML_SCORE, true);
        } catch (Exception ex) {
            log.error("Sidecar unreachable for {}: {}", req.cveId(), ex.getMessage());
            return new MlResult(FALLBACK_ML_SCORE, true);
        }
    }

    // -------------------------------------------------------------- model info

    /**
     * Fetch model metadata from the sidecar.
     *
     * GET /model/info
     */
    public ModelInfoResponse fetchModelInfo() {
        try {
            JsonNode body = sidecarWebClient.get()
                    .uri("/model/info")
                    .retrieve()
                    .bodyToMono(JsonNode.class)
                    .block();

            if (body != null) {
                return new ModelInfoResponse(
                        getTextOrDefault(body, "model_name",    "unknown"),
                        getTextOrDefault(body, "model_version", "unknown"),
                        getTextOrDefault(body, "status",        "unknown"),
                        getTextOrDefault(body, "last_trained",  "unknown"),
                        body.has("feature_count") ? body.get("feature_count").asInt() : 0,
                        true,
                        Instant.now()
                );
            }
        } catch (Exception ex) {
            log.error("Failed to fetch model info from sidecar: {}", ex.getMessage());
        }

        // Return a degraded-but-valid response when sidecar is down
        return new ModelInfoResponse("unknown", "unknown", "unavailable", "unknown", 0, false, Instant.now());
    }

    // ---------------------------------------------------------------- helpers

    private String getTextOrDefault(JsonNode node, String field, String defaultValue) {
        return node.has(field) ? node.get(field).asText() : defaultValue;
    }

    /**
     * Simple carrier for an ML prediction result and whether the fallback was used.
     */
    public record MlResult(double score, boolean fallbackUsed) {}
}
