package dev.trustforge.spring;

import dev.trustforge.Client;
import dev.trustforge.TrustForgeException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/** Coarse-grained filter that consults tf-daemon for every request. */
public class TrustForgeFilter extends OncePerRequestFilter {

    private final Client client;

    public TrustForgeFilter(Client client) {
        this.client = client;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse resp, FilterChain chain)
            throws ServletException, IOException {
        Client.Request r = new Client.Request()
                .action("http:" + req.getMethod().toLowerCase())
                .resource(req.getRequestURI())
                .attribute("remote", req.getRemoteAddr() == null ? "" : req.getRemoteAddr());
        try {
            Client.Decision d = client.decide(r);
            if (!d.allow()) {
                resp.setStatus(HttpServletResponse.SC_FORBIDDEN);
                resp.setContentType("application/json");
                resp.getWriter().write("{\"error\":\"trustforge_denied\",\"reason\":\""
                        + (d.reason() == null ? "" : d.reason()) + "\"}");
                return;
            }
        } catch (TrustForgeException e) {
            resp.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
            resp.getWriter().write("{\"error\":\"trustforge_unavailable\"}");
            return;
        }
        chain.doFilter(req, resp);
    }
}
