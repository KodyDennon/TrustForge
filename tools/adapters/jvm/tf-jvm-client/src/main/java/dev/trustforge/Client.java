package dev.trustforge;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

/**
 * Minimal HTTP client for the local tf-daemon's POST /v1/decide endpoint.
 *
 * <p>The daemon owns all authorization logic; this client merely forwards a
 * decision request and parses the JSON response. Per TrustForge architecture,
 * adapters MUST NOT make authorization decisions themselves.</p>
 */
public final class Client {

    private final HttpClient http;
    private final URI endpoint;
    private final Duration timeout;

    public Client(String baseUrl) {
        this(baseUrl, Duration.ofSeconds(2));
    }

    public Client(String baseUrl, Duration timeout) {
        this(baseUrl, timeout, HttpClient.newBuilder().connectTimeout(timeout).build());
    }

    /** Test-friendly constructor allowing a pre-built HttpClient. */
    public Client(String baseUrl, Duration timeout, HttpClient http) {
        if (baseUrl == null || baseUrl.isEmpty()) {
            throw new IllegalArgumentException("baseUrl is required");
        }
        String trimmed = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.endpoint = URI.create(trimmed + "/v1/decide");
        this.timeout = timeout;
        this.http = http;
    }

    /** Result of a decision call. */
    public static final class Decision {
        private final boolean allow;
        private final String reason;
        private final String obligationId;

        public Decision(boolean allow, String reason, String obligationId) {
            this.allow = allow;
            this.reason = reason;
            this.obligationId = obligationId;
        }

        public boolean allow() { return allow; }
        public String reason() { return reason; }
        public String obligationId() { return obligationId; }
    }

    /** Decision request payload. */
    public static final class Request {
        public String actor;
        public String instance;
        public String action;
        public String resource;
        public Map<String, String> attributes = new HashMap<>();

        public Request action(String a) { this.action = a; return this; }
        public Request resource(String r) { this.resource = r; return this; }
        public Request actor(String a) { this.actor = a; return this; }
        public Request instance(String i) { this.instance = i; return this; }
        public Request attribute(String k, String v) { this.attributes.put(k, v); return this; }
    }

    /** Synchronous decision call. */
    public Decision decide(Request request) throws TrustForgeException {
        if (request == null || request.action == null) {
            throw new IllegalArgumentException("request.action is required");
        }
        String body = encode(request);
        HttpRequest httpReq = HttpRequest.newBuilder()
                .uri(endpoint)
                .timeout(timeout)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        try {
            HttpResponse<String> resp = http.send(httpReq, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() / 100 != 2) {
                throw new TrustForgeException("tf-daemon returned status " + resp.statusCode() + ": " + resp.body());
            }
            return parse(resp.body());
        } catch (java.io.IOException | InterruptedException e) {
            if (e instanceof InterruptedException) Thread.currentThread().interrupt();
            throw new TrustForgeException("tf-daemon request failed", e);
        }
    }

    static String encode(Request r) {
        StringBuilder sb = new StringBuilder(128);
        sb.append('{');
        boolean first = true;
        first = appendField(sb, first, "actor", r.actor);
        first = appendField(sb, first, "instance", r.instance);
        first = appendField(sb, first, "action", r.action);
        first = appendField(sb, first, "resource", r.resource);
        if (r.attributes != null && !r.attributes.isEmpty()) {
            if (!first) sb.append(',');
            sb.append("\"attributes\":{");
            boolean innerFirst = true;
            for (Map.Entry<String, String> e : r.attributes.entrySet()) {
                if (!innerFirst) sb.append(',');
                sb.append('"').append(escape(e.getKey())).append("\":\"").append(escape(e.getValue())).append('"');
                innerFirst = false;
            }
            sb.append('}');
        }
        sb.append('}');
        return sb.toString();
    }

    private static boolean appendField(StringBuilder sb, boolean first, String key, String val) {
        if (val == null) return first;
        if (!first) sb.append(',');
        sb.append('"').append(key).append("\":\"").append(escape(val)).append('"');
        return false;
    }

    static Decision parse(String body) {
        boolean allow = readBool(body, "allow", false);
        String reason = readString(body, "reason");
        String obligationId = readString(body, "obligation_id");
        return new Decision(allow, reason, obligationId);
    }

    private static boolean readBool(String body, String key, boolean dflt) {
        int idx = body.indexOf("\"" + key + "\"");
        if (idx < 0) return dflt;
        int colon = body.indexOf(':', idx);
        if (colon < 0) return dflt;
        int end = colon + 1;
        while (end < body.length() && Character.isWhitespace(body.charAt(end))) end++;
        if (body.startsWith("true", end)) return true;
        if (body.startsWith("false", end)) return false;
        return dflt;
    }

    private static String readString(String body, String key) {
        int idx = body.indexOf("\"" + key + "\"");
        if (idx < 0) return null;
        int colon = body.indexOf(':', idx);
        if (colon < 0) return null;
        int qStart = body.indexOf('"', colon + 1);
        if (qStart < 0) return null;
        int qEnd = body.indexOf('"', qStart + 1);
        if (qEnd < 0) return null;
        return body.substring(qStart + 1, qEnd);
    }

    private static String escape(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 2);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default: sb.append(c);
            }
        }
        return sb.toString();
    }
}
