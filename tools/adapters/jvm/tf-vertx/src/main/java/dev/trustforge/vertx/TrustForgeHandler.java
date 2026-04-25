package dev.trustforge.vertx;

import dev.trustforge.Client;
import dev.trustforge.TrustForgeException;
import io.vertx.core.Handler;
import io.vertx.ext.web.RoutingContext;

/**
 * Vert.x Web routing handler that consults the local tf-daemon before
 * dispatching to the next handler.
 */
public class TrustForgeHandler implements Handler<RoutingContext> {

    private final Client client;

    public TrustForgeHandler(Client client) {
        this.client = client;
    }

    public static TrustForgeHandler create(String daemonUrl) {
        return new TrustForgeHandler(new Client(daemonUrl));
    }

    @Override
    public void handle(RoutingContext rc) {
        Client.Request r = new Client.Request()
                .action("http:" + rc.request().method().name().toLowerCase())
                .resource(rc.request().path());
        try {
            Client.Decision d = client.decide(r);
            if (!d.allow()) {
                rc.response().setStatusCode(403)
                        .putHeader("content-type", "application/json")
                        .end("{\"error\":\"trustforge_denied\"}");
                return;
            }
        } catch (TrustForgeException e) {
            rc.response().setStatusCode(503)
                    .putHeader("content-type", "application/json")
                    .end("{\"error\":\"trustforge_unavailable\"}");
            return;
        }
        rc.next();
    }
}
