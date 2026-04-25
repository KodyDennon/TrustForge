package dev.trustforge.quarkus;

import dev.trustforge.Client;
import dev.trustforge.TrustForgeException;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.lang.annotation.Annotation;
import java.net.URI;
import java.util.Date;
import java.util.List;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class TrustForgeQuarkusTest {

    private ContainerRequestContext mockCtx() {
        ContainerRequestContext ctx = mock(ContainerRequestContext.class);
        UriInfo uri = mock(UriInfo.class);
        when(uri.getPath()).thenReturn("/x");
        when(ctx.getUriInfo()).thenReturn(uri);
        when(ctx.getMethod()).thenReturn("GET");
        return ctx;
    }

    @Test
    void allow_does_not_abort() throws IOException {
        Client client = mock(Client.class);
        when(client.decide(any())).thenReturn(new Client.Decision(true, "ok", null));
        TrustForgeContainerFilter f = new TrustForgeContainerFilter(client);
        ContainerRequestContext ctx = mockCtx();
        f.filter(ctx);
        verify(ctx, never()).abortWith(any());
    }

    @Test
    void deny_aborts_with_403() throws IOException {
        Client client = mock(Client.class);
        when(client.decide(any())).thenReturn(new Client.Decision(false, "no", null));
        TrustForgeContainerFilter f = new TrustForgeContainerFilter(client);
        ContainerRequestContext ctx = mockCtx();
        f.filter(ctx);
        verify(ctx).abortWith(argThat(r -> r.getStatus() == 403));
    }

    @Test
    void daemon_failure_aborts_with_503() throws IOException {
        Client client = mock(Client.class);
        when(client.decide(any())).thenThrow(new TrustForgeException("nope"));
        TrustForgeContainerFilter f = new TrustForgeContainerFilter(client);
        ContainerRequestContext ctx = mockCtx();
        f.filter(ctx);
        verify(ctx).abortWith(argThat(r -> r.getStatus() == 503));
    }

    @Test
    void producer_makes_client() {
        Client c = new TrustForgeProducer().trustForgeClient("http://127.0.0.1:7878");
        assertNotNull(c);
    }
}
