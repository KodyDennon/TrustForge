package dev.trustforge.micronaut;

import dev.trustforge.Client;
import io.micronaut.context.annotation.Factory;
import io.micronaut.context.annotation.Value;
import jakarta.inject.Singleton;

@Factory
public class TrustForgeClientFactory {

    @Singleton
    public Client trustForgeClient(@Value("${trustforge.daemon-url:http://127.0.0.1:7878}") String url) {
        return new Client(url);
    }
}
