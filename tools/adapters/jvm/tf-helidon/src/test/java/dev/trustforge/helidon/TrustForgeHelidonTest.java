package dev.trustforge.helidon;

import dev.trustforge.Client;
import dev.trustforge.TrustForgeException;
import io.helidon.http.HttpPrologue;
import io.helidon.http.Method;
import io.helidon.webserver.http.ServerRequest;
import io.helidon.webserver.http.ServerResponse;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class TrustForgeHelidonTest {

    private ServerRequest mockReq() {
        ServerRequest req = mock(ServerRequest.class);
        HttpPrologue prologue = mock(HttpPrologue.class);
        when(prologue.method()).thenReturn(Method.GET);
        when(req.prologue()).thenReturn(prologue);
        io.helidon.http.HttpPath path = mock(io.helidon.http.HttpPath.class);
        when(path.rawPath()).thenReturn("/x");
        when(req.path()).thenReturn(path);
        return req;
    }

    @Test
    void allow_calls_next() {
        Client client = mock(Client.class);
        when(client.decide(any())).thenReturn(new Client.Decision(true, "ok", null));
        TrustForgeService svc = new TrustForgeService(client);
        ServerResponse resp = mock(ServerResponse.class);
        svc.handler().handle(mockReq(), resp);
        verify(resp).next();
    }

    @Test
    void deny_writes_403() {
        Client client = mock(Client.class);
        when(client.decide(any())).thenReturn(new Client.Decision(false, "no", null));
        TrustForgeService svc = new TrustForgeService(client);
        ServerResponse resp = mock(ServerResponse.class);
        when(resp.status(any())).thenReturn(resp);
        when(resp.header(anyString(), anyString())).thenReturn(resp);
        svc.handler().handle(mockReq(), resp);
        verify(resp).status(io.helidon.http.Status.FORBIDDEN_403);
    }

    @Test
    void daemon_failure_writes_503() {
        Client client = mock(Client.class);
        when(client.decide(any())).thenThrow(new TrustForgeException("nope"));
        TrustForgeService svc = new TrustForgeService(client);
        ServerResponse resp = mock(ServerResponse.class);
        when(resp.status(any())).thenReturn(resp);
        when(resp.header(anyString(), anyString())).thenReturn(resp);
        svc.handler().handle(mockReq(), resp);
        verify(resp).status(io.helidon.http.Status.SERVICE_UNAVAILABLE_503);
    }
}
