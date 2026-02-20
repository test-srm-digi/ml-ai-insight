package com.vulninsight.api.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Response payload for a batch scoring request.
 */
public record BatchScoreResponse(

        @JsonProperty("results")
        List<RiskScoreResponse> results,

        @JsonProperty("total")
        int total,

        @JsonProperty("failures")
        int failures
) {
}
