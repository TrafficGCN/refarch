package de.muenchen.refarch.gateway.configuration;

import de.muenchen.refarch.gateway.service.SsoStatusService;
import java.time.Duration;
import java.net.URI;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import reactor.core.publisher.Mono;

@Configuration
@Profile("!no-security")
@RequiredArgsConstructor
@Slf4j
public class SecurityConfiguration {

    private final CsrfProtectionMatcher csrfProtectionMatcher;
    private final SsoStatusService ssoStatusService;

    /**
     * Same lifetime as SSO Session (e.g. 10 hours).
     */
    @Value("${spring.session.timeout:36000}")
    private long springSessionTimeoutSeconds;

    @Bean
    @Order(0)
    public SecurityWebFilterChain clientAccessFilterChain(final ServerHttpSecurity http) {
        http
                .securityMatcher(ServerWebExchangeMatchers.pathMatchers("/clients/**"))
                .authorizeExchange(authorizeExchangeSpec -> authorizeExchangeSpec
                        .pathMatchers(HttpMethod.OPTIONS, "/clients/**").permitAll()
                        .anyExchange().authenticated())
                .cors(corsSpec -> {
                })
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
        return http.build();
    }

    @Bean
    @Order(1)
    public SecurityWebFilterChain springSecurityFilterChain(final ServerHttpSecurity http) {
        http
                .logout(ServerHttpSecurity.LogoutSpec::disable)
                .authorizeExchange(authorizeExchangeSpec -> {
                    // permitAll
                    authorizeExchangeSpec.pathMatchers(HttpMethod.OPTIONS, "/api/**").permitAll()
                            .pathMatchers("/api/*/info",
                                    "/actuator/health",
                                    "/actuator/health/liveness",
                                    "/actuator/health/readiness",
                                    "/actuator/info",
                                    "/actuator/metrics")
                            .permitAll()
                            .pathMatchers(HttpMethod.OPTIONS, "/public/**").permitAll()
                            .pathMatchers(HttpMethod.GET, "/public/**").permitAll()
                            // Dynamic authentication based on SSO status
                            .anyExchange().access(new SsoAccessEvaluator(ssoStatusService));
                })
                .cors(corsSpec -> {
                })
                .csrf(csrfSpec -> {
                    /*
                     * Custom csrf request handler for spa and BREACH attack protection.
                     * https://docs.spring.io/spring-security/reference/6.1-SNAPSHOT/servlet/exploits/csrf.html#csrf-
                     * integration-javascript-spa
                     */
                    csrfSpec.csrfTokenRequestHandler(new SpaServerCsrfTokenRequestHandler());
                    /*
                     * The necessary subscription for csrf token attachment to {@link ServerHttpResponse}
                     * is done in class {@link CsrfTokenAppendingHelperFilter}.
                     */
                    csrfSpec.csrfTokenRepository(CookieServerCsrfTokenRepository.withHttpOnlyFalse());
                    csrfSpec.requireCsrfProtectionMatcher(csrfProtectionMatcher);
                })
                // Enable OAuth2 client first
                .oauth2Client(Customizer.withDefaults())
                // Then configure OAuth2 login
                .oauth2Login(oAuth2LoginSpec -> {
                    oAuth2LoginSpec.authenticationSuccessHandler(new RedirectServerAuthenticationSuccessHandler() {
                        @Override
                        public Mono<Void> onAuthenticationSuccess(final WebFilterExchange webFilterExchange, final Authentication authentication) {
                            log.info("Authentication successful, setting session timeout");
                            webFilterExchange.getExchange().getSession().subscribe(
                                    webSession -> webSession.setMaxIdleTime(Duration.ofSeconds(springSessionTimeoutSeconds)));
                            return super.onAuthenticationSuccess(webFilterExchange, authentication);
                        }
                    });
                    // Configure the login page
                    oAuth2LoginSpec.loginPage("/oauth2/authorization/sso");
                })
                // Configure exception handling to redirect to login
                .exceptionHandling(exceptionHandlingSpec -> {
                    exceptionHandlingSpec.authenticationEntryPoint((exchange, ex) -> {
                        log.info("Authentication entry point called for path: {}", exchange.getRequest().getPath());
                        log.info("Redirecting to: /oauth2/authorization/sso");
                        exchange.getResponse().getHeaders().setLocation(URI.create("/oauth2/authorization/sso"));
                        exchange.getResponse().setStatusCode(org.springframework.http.HttpStatus.UNAUTHORIZED);
                        return exchange.getResponse().setComplete();
                    });
                });

        return http.build();
    }

}
