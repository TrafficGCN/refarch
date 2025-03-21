package de.muenchen.refarch.gateway.configuration;

import de.muenchen.refarch.gateway.service.SsoStatusService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import reactor.core.publisher.Mono;

@RequiredArgsConstructor
public class SsoAccessEvaluator implements ReactiveAuthorizationManager<AuthorizationContext> {

    private final SsoStatusService ssoStatusService;

    @Override
    public Mono<AuthorizationDecision> check(final Mono<Authentication> authentication, final AuthorizationContext context) {
        return ssoStatusService.getSsoStatus()
                .flatMap(ssoEnabled -> {
                    if (!ssoEnabled) {
                        return Mono.just(new AuthorizationDecision(true));
                    }
                    return authentication.map(auth -> new AuthorizationDecision(auth.isAuthenticated()));
                });
    }
}
