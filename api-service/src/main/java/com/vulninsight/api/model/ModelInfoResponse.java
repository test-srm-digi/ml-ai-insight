package com.vulninsight.api.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;

/**
 * Response payload describing the currently loaded ML model metadata.
 */
public record ModelInfoResponse(

        @JsonProperty("model_name")
        String modelName,

        @JsonProperty("model_version")
        String modelVersion,

        @JsonProperty("status")
        String status,

        @JsonProperty("last_trained")
        String lastTrained,

        @JsonProperty("feature_count")
        int featureCount,

        @JsonProperty("sidecar_reachable")
        boolean sidecarReachable,

        @JsonProperty("checked_at")
        Instant checkedAt
) {
}
