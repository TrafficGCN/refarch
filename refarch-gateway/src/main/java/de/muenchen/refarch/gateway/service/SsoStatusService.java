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

    @Value("${spring.cloud.gateway.routes[1].uri:http://localhost:39146}")
    private String backendUrl;

    public Mono<Boolean> getSsoStatus() {
        final String url = backendUrl + "api/settings";
        log.info("Fetching SSO status directly from backend: {}", url);
        return webClientBuilder
                .build()
                .get()
                .uri(url)
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
