package dev.trustforge.sparkjava;

import dev.trustforge.Client;
import dev.trustforge.TrustForgeException;
import spark.Filter;
import spark.Request;
import spark.Response;
import spark.Spark;

/**
 * SparkJava {@code before()} filter.  Usage:
 *
 * <pre>
 *   Spark.before(TrustForgeBeforeFilter.create("http://127.0.0.1:7878"));
 * </pre>
 */
public class TrustForgeBeforeFilter implements Filter {

    private final Client client;

    public TrustForgeBeforeFilter(Client client) {
        this.client = client;
    }

    public static TrustForgeBeforeFilter create(String daemonUrl) {
        return new TrustForgeBeforeFilter(new Client(daemonUrl));
    }

    @Override
    public void handle(Request request, Response response) {
        Client.Request r = new Client.Request()
                .action("http:" + request.requestMethod().toLowerCase())
                .resource(request.pathInfo());
        try {
            Client.Decision d = client.decide(r);
            if (!d.allow()) {
                response.type("application/json");
                Spark.halt(403, "{\"error\":\"trustforge_denied\"}");
            }
        } catch (TrustForgeException e) {
            response.type("application/json");
            Spark.halt(503, "{\"error\":\"trustforge_unavailable\"}");
        }
    }
}
