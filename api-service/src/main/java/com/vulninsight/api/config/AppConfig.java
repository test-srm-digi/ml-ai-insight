package com.vulninsight.api.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.bedrockruntime.BedrockRuntimeClient;

import java.time.Duration;

@Configuration
public class AppConfig {

    @Value("${sidecar.base-url}")
    private String sidecarBaseUrl;

    @Value("${sidecar.timeout-ms}")
    private int sidecarTimeoutMs;

    @Value("${aws.region}")
    private String awsRegion;

    /**
     * Non-blocking WebClient configured for the Python ML sidecar.
     */
    @Bean
    public WebClient sidecarWebClient(WebClient.Builder builder) {
        HttpClient httpClient = HttpClient.create()
                .responseTimeout(Duration.ofMillis(sidecarTimeoutMs));

        return builder
                .baseUrl(sidecarBaseUrl)
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .build();
    }

    /**
     * AWS Bedrock Runtime client for Claude model invocations.
     */
    @Bean
    public BedrockRuntimeClient bedrockRuntimeClient() {
        return BedrockRuntimeClient.builder()
                .region(Region.of(awsRegion))
                .credentialsProvider(DefaultCredentialsProvider.create())
                .build();
    }
}
