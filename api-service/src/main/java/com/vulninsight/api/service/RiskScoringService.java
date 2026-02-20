package com.vulninsight.api.service;

import com.vulninsight.api.model.RiskScoreResponse;
import com.vulninsight.api.model.VulnerabilityRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;

/**
 * Core risk-scoring engine.
 *
 * Hybrid formula (weights sum to 1.0):
 *   0.45 * ml_score
 * + 0.20 * cvss_normalized   (cvss / 10)
 * + 0.15 * epss_score
 * + 0.10 * exposure_score
 * + 0.10 * repo_criticality
 *
 * Hard overrides:
 *   - Withdrawn CVEs are capped at 0.10
 *   - CVSS >= 9.0 with known exploit floors at 0.85
 *
 * Tier classification:
 *   CRITICAL  > 0.80
 *   HIGH      > 0.60
 *   MEDIUM    > 0.40
 *   LOW       otherwise
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RiskScoringService {

    private static final double W_ML       = 0.45;
    private static final double W_CVSS     = 0.20;
    private static final double W_EPSS     = 0.15;
    private static final double W_EXPOSURE = 0.10;
    private static final double W_REPO     = 0.10;

    private static final double CRITICAL_THRESHOLD = 0.80;
    private static final double HIGH_THRESHOLD     = 0.60;
    private static final double MEDIUM_THRESHOLD   = 0.40;

    private final PythonBridgeService pythonBridgeService;

    /**
     * Score a single vulnerability.
     */
    public RiskScoreResponse score(VulnerabilityRequest req) {
        // 1. Obtain ML prediction from sidecar (with fallback)
        PythonBridgeService.MlResult mlResult = pythonBridgeService.predict(req);

        double mlScore         = mlResult.score();
        boolean mlFallbackUsed = mlResult.fallbackUsed();

        // 2. Normalize inputs
        double cvssNormalized  = req.cvssScore() / 10.0;
        double epss            = req.epssScore();
        double exposure        = req.safeExposureScore();
        double repoCriticality = req.safeRepoCriticality();

        // 3. Weighted combination
        double raw = W_ML * mlScore
                   + W_CVSS * cvssNormalized
                   + W_EPSS * epss
                   + W_EXPOSURE * exposure
                   + W_REPO * repoCriticality;

        // 4. Apply hard overrides
        String overridesApplied = "none";

        if (req.isWithdrawn()) {
            raw = Math.min(raw, 0.10);
            overridesApplied = "withdrawn_cap";
            log.info("CVE {} is withdrawn – capping score at 0.10", req.cveId());
        } else if (req.cvssScore() >= 9.0 && req.hasKnownExploit()) {
            raw = Math.max(raw, 0.85);
            overridesApplied = "critical_exploit_floor";
            log.info("CVE {} has CVSS>=9 + exploit – flooring score at 0.85", req.cveId());
        }

        // 5. Clamp to [0, 1]
        double finalScore = Math.max(0.0, Math.min(1.0, raw));

        // 6. Classify tier
        String tier = classifyTier(finalScore);

        return new RiskScoreResponse(
                req.cveId(),
                round4(finalScore),
                tier,
                round4(mlScore),
                round4(cvssNormalized),
                round4(epss),
                round4(exposure),
                round4(repoCriticality),
                mlFallbackUsed,
                overridesApplied,
                Instant.now()
        );
    }

    // -------------------------------------------------------------- helpers

    private String classifyTier(double score) {
        if (score > CRITICAL_THRESHOLD) return "CRITICAL";
        if (score > HIGH_THRESHOLD)     return "HIGH";
        if (score > MEDIUM_THRESHOLD)   return "MEDIUM";
        return "LOW";
    }

    private double round4(double value) {
        return Math.round(value * 10_000.0) / 10_000.0;
    }
}
