package dev.trustforge.quarkus;

import dev.trustforge.Client;
import dev.trustforge.TrustForgeException;
import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;

import java.io.IOException;

@Provider
public class TrustForgeContainerFilter implements ContainerRequestFilter {

    @Inject
    Client client;

    public TrustForgeContainerFilter() {}

    public TrustForgeContainerFilter(Client client) {
        this.client = client;
    }

    @Override
    public void filter(ContainerRequestContext ctx) throws IOException {
        Client.Request r = new Client.Request()
                .action("http:" + ctx.getMethod().toLowerCase())
                .resource(ctx.getUriInfo().getPath());
        try {
            Client.Decision d = client.decide(r);
            if (!d.allow()) {
                ctx.abortWith(Response.status(Response.Status.FORBIDDEN)
                        .entity("{\"error\":\"trustforge_denied\"}")
                        .type("application/json")
                        .build());
            }
        } catch (TrustForgeException e) {
            ctx.abortWith(Response.status(Response.Status.SERVICE_UNAVAILABLE)
                    .entity("{\"error\":\"trustforge_unavailable\"}")
                    .type("application/json")
                    .build());
        }
    }
}
