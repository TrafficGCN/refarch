package de.muenchen.refarch.gateway;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import de.muenchen.refarch.gateway.service.SsoStatusService;
import reactor.core.publisher.Mono;

@TestConfiguration
public class OAuthSecurityMockConfiguration {
    @Bean
    public ReactiveJwtDecoder jwtDecoder() {
        return mock(ReactiveJwtDecoder.class);
    }

    @Bean
    public ReactiveClientRegistrationRepository clientRegistrationRepository() {
        return mock(ReactiveClientRegistrationRepository.class);
    }

    @Bean
    public SsoStatusService ssoStatusService() {
        final SsoStatusService mock = mock(SsoStatusService.class);
        when(mock.getSsoStatus()).thenReturn(Mono.just(true));
        return mock;
    }
}
