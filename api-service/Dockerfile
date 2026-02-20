# ============================================================
# Stage 1 – Build
# ============================================================
FROM gradle:8.7-jdk17 AS builder

WORKDIR /app

# Copy build files first for layer caching
COPY build.gradle settings.gradle ./
RUN gradle dependencies --no-daemon || true

# Copy source and build
COPY src/ src/
RUN gradle bootJar --no-daemon

# ============================================================
# Stage 2 – Runtime
# ============================================================
FROM eclipse-temurin:17-jre-jammy

LABEL maintainer="vuln-insight-team"
LABEL description="Vulnerability Risk Intelligence API Service"

RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app

COPY --from=builder /app/build/libs/api-service.jar app.jar

RUN chown -R appuser:appuser /app
USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8080/actuator/health || exit 1

ENTRYPOINT ["java", "-XX:+UseContainerSupport", "-XX:MaxRAMPercentage=75.0", "-jar", "app.jar"]
