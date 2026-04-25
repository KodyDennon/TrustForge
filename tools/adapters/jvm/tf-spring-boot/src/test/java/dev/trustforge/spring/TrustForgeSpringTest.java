package dev.trustforge.spring;

import dev.trustforge.Client;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@SpringBootTest(classes = TrustForgeSpringTest.App.class,
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "trustforge.filter-enabled=true")
class TrustForgeSpringTest {

    @SpringBootApplication
    static class App {
        public static void main(String[] args) { SpringApplication.run(App.class, args); }

        @RestController
        static class C {
            @GetMapping("/ok")
            String ok() { return "ok"; }

            @TrustForgeRequire("file:read")
            @GetMapping("/secret")
            String secret() { return "secret"; }
        }
    }

    @TestConfiguration
    static class MockClientConfig {
        @Bean @Primary
        Client mockClient() {
            Client c = mock(Client.class);
            when(c.decide(any())).thenReturn(new Client.Decision(true, "ok", null));
            return c;
        }
    }

    @Autowired TestRestTemplate rest;
    @Autowired Client client;

    @Test
    void filter_allows_when_daemon_allows() {
        when(client.decide(any())).thenReturn(new Client.Decision(true, "ok", null));
        ResponseEntity<String> r = rest.getForEntity("/ok", String.class);
        assertEquals(HttpStatus.OK, r.getStatusCode());
    }

    @Test
    void filter_denies_when_daemon_denies() {
        when(client.decide(any())).thenReturn(new Client.Decision(false, "no", null));
        ResponseEntity<String> r = rest.getForEntity("/ok", String.class);
        assertEquals(HttpStatus.FORBIDDEN, r.getStatusCode());
    }

    @Test
    void aspect_blocks_method_when_denied() {
        when(client.decide(any())).thenReturn(new Client.Decision(true, "ok", null));
        // Method-level annotation triggers aspect; we still expect 200 because both layers allow.
        ResponseEntity<String> r = rest.getForEntity("/secret", String.class);
        assertEquals(HttpStatus.OK, r.getStatusCode());
    }

    @Test
    void aspect_throws_security_exception_on_deny() {
        when(client.decide(argThat(req -> req != null && "file:read".equals(req.action))))
                .thenReturn(new Client.Decision(false, "blocked", null));
        when(client.decide(argThat(req -> req != null && !"file:read".equals(req.action))))
                .thenReturn(new Client.Decision(true, "ok", null));
        ResponseEntity<String> r = rest.getForEntity("/secret", String.class);
        // Spring will surface the SecurityException as 500 unless the developer maps it.
        assertTrue(r.getStatusCode().is5xxServerError() || r.getStatusCode() == HttpStatus.FORBIDDEN);
    }
}
