package de.muenchen.refarch.gateway.configuration;

import de.muenchen.refarch.gateway.service.SsoStatusService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import reactor.core.publisher.Mono;

@RequiredArgsConstructor
@Slf4j
public class SsoAccessEvaluator implements ReactiveAuthorizationManager<AuthorizationContext> {

    private final SsoStatusService ssoStatusService;

    @Override
    public Mono<AuthorizationDecision> check(final Mono<Authentication> authentication, final AuthorizationContext context) {
        log.info("Checking authorization for path: {}", context.getExchange().getRequest().getPath());
        return ssoStatusService.getSsoStatus()
                .flatMap(ssoEnabled -> {
                    log.info("SSO status: {}", ssoEnabled);
                    if (!ssoEnabled) {
                        log.info("SSO is disabled, allowing access");
                        return Mono.just(new AuthorizationDecision(true));
                    }
                    // For SSO enabled case, we need to check authentication
                    return authentication
                            .map(auth -> {
                                log.info("Authentication status: {}", auth.isAuthenticated());
                                // If authenticated, allow access
                                if (auth.isAuthenticated()) {
                                    log.info("User is authenticated, allowing access");
                                    return new AuthorizationDecision(true);
                                }
                                // If not authenticated, deny access to trigger login
                                log.info("User is not authenticated, denying access to trigger login");
                                return new AuthorizationDecision(false);
                            })
                            // If no authentication exists, deny access to trigger login
                            .defaultIfEmpty(new AuthorizationDecision(false))
                            .doOnNext(decision -> log.info("Final authorization decision: {}", decision.isGranted()));
                });
    }
}
