package dev.trustforge.helidon;

import dev.trustforge.Client;
import dev.trustforge.TrustForgeException;
import io.helidon.http.Status;
import io.helidon.webserver.http.Handler;
import io.helidon.webserver.http.HttpRules;
import io.helidon.webserver.http.HttpService;
import io.helidon.webserver.http.ServerRequest;
import io.helidon.webserver.http.ServerResponse;

/**
 * Helidon SE 4 middleware. Register with:
 * <pre>
 *   WebServer.builder().routing(r -> r.register("/", TrustForgeService.create(url)))...
 * </pre>
 */
public class TrustForgeService implements HttpService {

    private final Client client;

    public TrustForgeService(Client client) {
        this.client = client;
    }

    public static TrustForgeService create(String daemonUrl) {
        return new TrustForgeService(new Client(daemonUrl));
    }

    @Override
    public void routing(HttpRules rules) {
        rules.any(handler());
    }

    public Handler handler() {
        return (req, res) -> {
            Client.Request r = new Client.Request()
                    .action("http:" + req.prologue().method().text().toLowerCase())
                    .resource(req.path().rawPath());
            try {
                Client.Decision d = client.decide(r);
                if (!d.allow()) {
                    res.status(Status.FORBIDDEN_403)
                       .header("content-type", "application/json")
                       .send("{\"error\":\"trustforge_denied\"}");
                    return;
                }
            } catch (TrustForgeException e) {
                res.status(Status.SERVICE_UNAVAILABLE_503)
                   .header("content-type", "application/json")
                   .send("{\"error\":\"trustforge_unavailable\"}");
                return;
            }
            res.next();
        };
    }
}
