package dev.trustforge.micronaut;

import dev.trustforge.Client;
import io.micronaut.http.HttpRequest;
import io.micronaut.http.HttpResponse;
import io.micronaut.http.filter.ServerFilterChain;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class TrustForgeMicronautTest {

    @Test
    void filter_allows_when_decision_allows() {
        Client client = mock(Client.class);
        when(client.decide(any())).thenReturn(new Client.Decision(true, "ok", null));
        TrustForgeHttpFilter filter = new TrustForgeHttpFilter(client);
        ServerFilterChain chain = req -> Mono.just(HttpResponse.ok("hi"));
        Object resp = Mono.from(filter.doFilter(HttpRequest.GET("/x"), chain)).block();
        assertNotNull(resp);
        assertEquals(io.micronaut.http.HttpStatus.OK, ((HttpResponse<?>) resp).getStatus());
    }

    @Test
    void filter_returns_403_when_denied() {
        Client client = mock(Client.class);
        when(client.decide(any())).thenReturn(new Client.Decision(false, "nope", null));
        TrustForgeHttpFilter filter = new TrustForgeHttpFilter(client);
        ServerFilterChain chain = req -> Mono.just(HttpResponse.ok("hi"));
        HttpResponse<?> resp = (HttpResponse<?>) Mono.from(filter.doFilter(HttpRequest.GET("/x"), chain)).block();
        assertEquals(io.micronaut.http.HttpStatus.FORBIDDEN, resp.getStatus());
    }

    @Test
    void filter_returns_503_when_daemon_unavailable() {
        Client client = mock(Client.class);
        when(client.decide(any())).thenThrow(new dev.trustforge.TrustForgeException("oops"));
        TrustForgeHttpFilter filter = new TrustForgeHttpFilter(client);
        ServerFilterChain chain = req -> Mono.just(HttpResponse.ok("hi"));
        HttpResponse<?> resp = (HttpResponse<?>) Mono.from(filter.doFilter(HttpRequest.GET("/x"), chain)).block();
        assertEquals(io.micronaut.http.HttpStatus.SERVICE_UNAVAILABLE, resp.getStatus());
    }

    @Test
    void factory_builds_client_with_default_url() {
        Client c = new TrustForgeClientFactory().trustForgeClient("http://127.0.0.1:7878");
        assertNotNull(c);
    }
}
