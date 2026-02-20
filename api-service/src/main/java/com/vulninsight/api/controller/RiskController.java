package com.vulninsight.api.controller;

import com.vulninsight.api.model.*;
import com.vulninsight.api.service.BedrockService;
import com.vulninsight.api.service.PythonBridgeService;
import com.vulninsight.api.service.RiskScoringService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * REST controller exposing the vulnerability risk scoring API.
 *
 * Endpoints:
 *   POST /api/v1/score         – score a single vulnerability
 *   POST /api/v1/score/batch   – score a batch of vulnerabilities
 *   GET  /api/v1/model/info    – retrieve ML model metadata
 *   POST /api/v1/explain       – generate a natural-language explanation via Bedrock
 */
@Slf4j
@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class RiskController {

    private final RiskScoringService riskScoringService;
    private final PythonBridgeService pythonBridgeService;
    private final BedrockService bedrockService;

    // ------------------------------------------------------------------ score
    @PostMapping("/score")
    public ResponseEntity<RiskScoreResponse> score(@Valid @RequestBody VulnerabilityRequest request) {
        log.info("Scoring request received for CVE: {}", request.cveId());

        RiskScoreResponse response = riskScoringService.score(request);

        log.info("CVE {} scored: risk={} tier={}", request.cveId(), response.riskScore(), response.tier());
        return ResponseEntity.ok(response);
    }

    // ------------------------------------------------------------- score/batch
    @PostMapping("/score/batch")
    public ResponseEntity<BatchScoreResponse> scoreBatch(@Valid @RequestBody BatchScoreRequest request) {
        log.info("Batch scoring request received – {} items", request.vulnerabilities().size());

        List<RiskScoreResponse> results = new ArrayList<>();
        int failures = 0;

        for (VulnerabilityRequest vuln : request.vulnerabilities()) {
            try {
                results.add(riskScoringService.score(vuln));
            } catch (Exception ex) {
                log.error("Failed to score CVE {}: {}", vuln.cveId(), ex.getMessage());
                failures++;
            }
        }

        BatchScoreResponse response = new BatchScoreResponse(results, results.size(), failures);
        log.info("Batch complete – {} scored, {} failures", results.size(), failures);
        return ResponseEntity.ok(response);
    }

    // -------------------------------------------------------------- model/info
    @GetMapping("/model/info")
    public ResponseEntity<ModelInfoResponse> modelInfo() {
        log.debug("Model info request received");

        ModelInfoResponse info = pythonBridgeService.fetchModelInfo();
        return ResponseEntity.ok(info);
    }

    // ----------------------------------------------------------------- explain
    @PostMapping("/explain")
    public ResponseEntity<Map<String, Object>> explain(@Valid @RequestBody VulnerabilityRequest request) {
        log.info("Explanation request received for CVE: {}", request.cveId());

        // First, compute the risk score so we can include it in the explanation context
        RiskScoreResponse scored = riskScoringService.score(request);

        String explanation = bedrockService.generateExplanation(request, scored);

        Map<String, Object> body = Map.of(
                "cve_id", request.cveId(),
                "risk_score", scored.riskScore(),
                "tier", scored.tier(),
                "explanation", explanation
        );

        return ResponseEntity.ok(body);
    }
}
