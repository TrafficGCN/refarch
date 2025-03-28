package de.muenchen.refarch.gateway.filter;

import io.micrometer.tracing.Span;
import io.micrometer.tracing.Tracer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * This class adds the sleuth headers "X-B3-SpanId" and "X-B3-TraceId" to each route response.
 */
@Component
@Slf4j
public class DistributedTracingFilter implements WebFilter {

    public static final String TRACE_ID = "TraceId";
    public static final String SPAN_ID = "SpanId";

    @Autowired
    private Tracer tracer;

    /**
     * This method adds the zipkin headers "X-B3-SpanId" and "X-B3-TraceId" to each response in
     * {@link ServerWebExchange}.
     *
     * @param serverWebExchange the current server exchange without zipkin headers
     * @param webFilterChain provides a way to delegate to the next filter
     * @return {@code Mono<Void>} to indicate when request processing for adding zipkin headers is
     *         complete
     */
    @Override
    public Mono<Void> filter(final ServerWebExchange serverWebExchange,
            final WebFilterChain webFilterChain) {
        final ServerHttpResponse response = serverWebExchange.getResponse();
        response.beforeCommit(() -> {
            final Span span = tracer.currentSpan();
            if (span != null) {
                final MultiValueMap<String, String> headers = response.getHeaders();
                headers.add(TRACE_ID, span.context().traceId());
                headers.add(SPAN_ID, span.context().spanId());
            } else {
                log.debug("Traceinformation missing - Skip Trace Header insertion");
            }
            return Mono.empty();
        });
        return webFilterChain.filter(serverWebExchange);
    }

}
