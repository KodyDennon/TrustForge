package dev.trustforge.sparkjava;

import dev.trustforge.Client;
import dev.trustforge.TrustForgeException;
import org.junit.jupiter.api.Test;
import spark.HaltException;
import spark.Request;
import spark.Response;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class TrustForgeSparkTest {

    private Request mockReq() {
        Request req = mock(Request.class);
        when(req.requestMethod()).thenReturn("GET");
        when(req.pathInfo()).thenReturn("/x");
        return req;
    }

    @Test
    void allow_does_not_halt() {
        Client client = mock(Client.class);
        when(client.decide(any())).thenReturn(new Client.Decision(true, "ok", null));
        TrustForgeBeforeFilter f = new TrustForgeBeforeFilter(client);
        Response resp = mock(Response.class);
        // Should complete without throwing.
        assertDoesNotThrow(() -> f.handle(mockReq(), resp));
    }

    @Test
    void deny_halts_with_403() {
        Client client = mock(Client.class);
        when(client.decide(any())).thenReturn(new Client.Decision(false, "no", null));
        TrustForgeBeforeFilter f = new TrustForgeBeforeFilter(client);
        Response resp = mock(Response.class);
        HaltException ex = assertThrows(HaltException.class, () -> f.handle(mockReq(), resp));
        assertEquals(403, ex.statusCode());
    }

    @Test
    void daemon_failure_halts_with_503() {
        Client client = mock(Client.class);
        when(client.decide(any())).thenThrow(new TrustForgeException("nope"));
        TrustForgeBeforeFilter f = new TrustForgeBeforeFilter(client);
        Response resp = mock(Response.class);
        HaltException ex = assertThrows(HaltException.class, () -> f.handle(mockReq(), resp));
        assertEquals(503, ex.statusCode());
    }
}
