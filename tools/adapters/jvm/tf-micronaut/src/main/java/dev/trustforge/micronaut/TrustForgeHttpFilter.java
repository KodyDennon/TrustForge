package dev.trustforge.micronaut;

import dev.trustforge.Client;
import dev.trustforge.TrustForgeException;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.MutableHttpResponse;
import io.micronaut.http.annotation.Filter;
import io.micronaut.http.filter.HttpServerFilter;
import io.micronaut.http.filter.ServerFilterChain;
import org.reactivestreams.Publisher;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@Filter("/**")
public class TrustForgeHttpFilter implements HttpServerFilter {

    private final Client client;

    public TrustForgeHttpFilter(Client client) {
        this.client = client;
    }

    @Override
    public Publisher<MutableHttpResponse<?>> doFilter(HttpRequest<?> request, ServerFilterChain chain) {
        Client.Request r = new Client.Request()
                .action("http:" + request.getMethodName().toLowerCase())
                .resource(request.getPath());
        try {
            Client.Decision d = client.decide(r);
            if (!d.allow()) {
                return Mono.just(HttpResponse.status(io.micronaut.http.HttpStatus.FORBIDDEN)
                        .body("{\"error\":\"trustforge_denied\"}"));
            }
        } catch (TrustForgeException e) {
            return Mono.just(HttpResponse.status(io.micronaut.http.HttpStatus.SERVICE_UNAVAILABLE)
                    .body("{\"error\":\"trustforge_unavailable\"}"));
        }
        return Flux.from(chain.proceed(request));
    }
}
