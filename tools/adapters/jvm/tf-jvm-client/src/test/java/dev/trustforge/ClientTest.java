package dev.trustforge;

import com.github.tomakehurst.wiremock.WireMockServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.junit.jupiter.api.Assertions.*;

class ClientTest {

    private WireMockServer wm;
    private Client client;

    @BeforeEach
    void setup() {
        wm = new WireMockServer(wireMockConfig().dynamicPort());
        wm.start();
        client = new Client("http://localhost:" + wm.port());
    }

    @AfterEach
    void teardown() {
        if (wm != null) wm.stop();
    }

    @Test
    void allow_decision_is_parsed() {
        wm.stubFor(post(urlEqualTo("/v1/decide"))
                .willReturn(okJson("{\"allow\":true,\"reason\":\"ok\"}")));
        Client.Decision d = client.decide(new Client.Request().action("read"));
        assertTrue(d.allow());
        assertEquals("ok", d.reason());
    }

    @Test
    void deny_decision_is_parsed() {
        wm.stubFor(post(urlEqualTo("/v1/decide"))
                .willReturn(okJson("{\"allow\":false,\"reason\":\"denied\"}")));
        Client.Decision d = client.decide(new Client.Request().action("write"));
        assertFalse(d.allow());
        assertEquals("denied", d.reason());
    }

    @Test
    void obligation_id_is_parsed() {
        wm.stubFor(post(urlEqualTo("/v1/decide"))
                .willReturn(okJson("{\"allow\":true,\"obligation_id\":\"ob-123\"}")));
        Client.Decision d = client.decide(new Client.Request().action("read"));
        assertEquals("ob-123", d.obligationId());
    }

    @Test
    void request_serializes_actor_and_attributes() {
        Client.Request r = new Client.Request()
                .actor("tf:actor:agent:example.com/x")
                .instance("tf:instance:agent:example.com/x/host/sess-1")
                .action("read")
                .resource("file:/tmp/x")
                .attribute("ip", "10.0.0.1");
        String body = Client.encode(r);
        assertTrue(body.contains("\"actor\":\"tf:actor:agent:example.com/x\""));
        assertTrue(body.contains("\"action\":\"read\""));
        assertTrue(body.contains("\"attributes\""));
        assertTrue(body.contains("\"ip\":\"10.0.0.1\""));
    }

    @Test
    void server_error_throws() {
        wm.stubFor(post(urlEqualTo("/v1/decide"))
                .willReturn(aResponse().withStatus(500).withBody("boom")));
        assertThrows(TrustForgeException.class,
                () -> client.decide(new Client.Request().action("read")));
    }

    @Test
    void missing_action_rejected() {
        assertThrows(IllegalArgumentException.class,
                () -> client.decide(new Client.Request()));
    }
}
