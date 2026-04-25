package dev.trustforge.vertx;

import dev.trustforge.Client;
import dev.trustforge.TrustForgeException;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.ext.web.RoutingContext;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class TrustForgeVertxTest {

    private RoutingContext mockCtx() {
        RoutingContext rc = mock(RoutingContext.class);
        HttpServerRequest req = mock(HttpServerRequest.class);
        HttpServerResponse resp = mock(HttpServerResponse.class);
        when(req.method()).thenReturn(HttpMethod.GET);
        when(req.path()).thenReturn("/x");
        when(rc.request()).thenReturn(req);
        when(rc.response()).thenReturn(resp);
        when(resp.setStatusCode(anyInt())).thenReturn(resp);
        when(resp.putHeader(anyString(), anyString())).thenReturn(resp);
        return rc;
    }

    @Test
    void allow_calls_next() {
        Client client = mock(Client.class);
        when(client.decide(any())).thenReturn(new Client.Decision(true, "ok", null));
        TrustForgeHandler h = new TrustForgeHandler(client);
        RoutingContext rc = mockCtx();
        h.handle(rc);
        verify(rc).next();
    }

    @Test
    void deny_writes_403() {
        Client client = mock(Client.class);
        when(client.decide(any())).thenReturn(new Client.Decision(false, "no", null));
        TrustForgeHandler h = new TrustForgeHandler(client);
        RoutingContext rc = mockCtx();
        h.handle(rc);
        verify(rc.response()).setStatusCode(403);
        verify(rc, never()).next();
    }

    @Test
    void daemon_failure_writes_503() {
        Client client = mock(Client.class);
        when(client.decide(any())).thenThrow(new TrustForgeException("oops"));
        TrustForgeHandler h = new TrustForgeHandler(client);
        RoutingContext rc = mockCtx();
        h.handle(rc);
        verify(rc.response()).setStatusCode(503);
    }

    @Test
    void create_factory_returns_handler() {
        TrustForgeHandler h = TrustForgeHandler.create("http://127.0.0.1:7878");
        assertNotNull(h);
    }
}
