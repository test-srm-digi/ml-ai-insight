package com.vulninsight.api.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;

import java.util.List;

/**
 * Inbound request for batch scoring of multiple vulnerabilities.
 */
public record BatchScoreRequest(

        @NotEmpty(message = "vulnerabilities list must not be empty")
        @Size(max = 100, message = "batch size must not exceed 100")
        @Valid
        @JsonProperty("vulnerabilities")
        List<VulnerabilityRequest> vulnerabilities
) {
}
