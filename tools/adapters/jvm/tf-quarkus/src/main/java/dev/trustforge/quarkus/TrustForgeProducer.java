package dev.trustforge.quarkus;

import dev.trustforge.Client;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;
import org.eclipse.microprofile.config.inject.ConfigProperty;

@ApplicationScoped
public class TrustForgeProducer {

    @Produces
    @ApplicationScoped
    public Client trustForgeClient(
            @ConfigProperty(name = "trustforge.daemon-url", defaultValue = "http://127.0.0.1:7878")
            String url) {
        return new Client(url);
    }
}
