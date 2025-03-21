package de.muenchen.refarch.gateway.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

@Service
@RequiredArgsConstructor
@Slf4j
public class SsoStatusService {

    private final WebClient.Builder webClientBuilder;

    @Value("${spring.cloud.gateway.routes[1].uri:http://localhost:8083}")
    private String gatewayBaseUrl;

    public Mono<Boolean> getSsoStatus() {
        return webClientBuilder
                .baseUrl(gatewayBaseUrl)
                .build()
                .get()
                .uri("/api/backend-service/settings")
                .retrieve()
                .bodyToMono(SettingsResponse.class)
                .map(SettingsResponse::isSsoEnabled)
                .onErrorResume(e -> {
                    log.error("Failed to fetch SSO status from backend", e);
                    return Mono.just(true); // Default to SSO enabled on error
                });
    }

    private static final class SettingsResponse {
        private boolean ssoEnabled;

        public boolean isSsoEnabled() {
            return ssoEnabled;
        }

        public void setSsoEnabled(final boolean ssoEnabled) {
            this.ssoEnabled = ssoEnabled;
        }
    }
}
