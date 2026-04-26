// TrustForge minimal-API endpoint filter.
//
// Usage:
//   app.MapGet("/orders/{id}", handler)
//      .RequireTrustforge("orders.read");
//
// Each call delegates to tf-daemon's /v1/decide for the supplied action.

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Trustforge.AspNetCore;
using Trustforge.Sdk;

namespace Trustforge.MinimalApi;

/// <summary>Endpoint filter that authorises a single minimal-API endpoint.</summary>
public sealed class TrustforgeEndpointFilter : IEndpointFilter
{
    private readonly string _action;

    public TrustforgeEndpointFilter(string action)
    {
        if (string.IsNullOrWhiteSpace(action))
        {
            throw new ArgumentException("action is required", nameof(action));
        }
        _action = action;
    }

    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var http = context.HttpContext;
        var sp = http.RequestServices;
        var client = sp.GetRequiredService<DecideClient>();
        var options = sp.GetRequiredService<TrustforgeOptions>();

        var traceId = http.Request.Headers["x-tf-trace-id"].FirstOrDefault() ?? DecideClient.NewTraceId();
        var req = new DecideRequest(
            Action: _action,
            TraceId: traceId,
            HostToken: ExtractBearer(http),
            Target: http.Request.Path.Value,
            Context: new Dictionary<string, object?>
            {
                ["method"] = http.Request.Method,
                ["client"] = http.Connection.RemoteIpAddress?.ToString() ?? string.Empty,
            });

        DecideResponse resp;
        try
        {
            resp = await client.DecideAsync(req, http.RequestAborted).ConfigureAwait(false);
        }
        catch (TrustforgeException ex)
        {
            if (options.Mode == AdapterMode.ObserveOnly)
            {
                http.Items[TrustforgeContextKeys.Decision] =
                    TrustforgeMiddleware.ObserveOnlyFallback(_action, ex.Message);
                return await next(context).ConfigureAwait(false);
            }
            return Results.Problem(
                title: "trustforge daemon error",
                detail: ex.Message,
                statusCode: StatusCodes.Status503ServiceUnavailable);
        }

        http.Items[TrustforgeContextKeys.Decision] = resp;

        if (options.Mode == AdapterMode.ObserveOnly)
        {
            return await next(context).ConfigureAwait(false);
        }
        if (resp.IsDeny)
        {
            return Results.Problem(
                title: "denied",
                detail: string.IsNullOrEmpty(resp.Reason) ? "denied" : resp.Reason,
                statusCode: StatusCodes.Status403Forbidden);
        }
        if (resp.IsApprovalRequired)
        {
            http.Response.Headers["x-tf-approval-id"] = resp.ApprovalId ?? string.Empty;
            return Results.Problem(
                title: "approval required",
                detail: string.IsNullOrEmpty(resp.Reason) ? "approval required" : resp.Reason,
                statusCode: StatusCodes.Status401Unauthorized);
        }

        return await next(context).ConfigureAwait(false);
    }

    private static string? ExtractBearer(HttpContext ctx)
    {
        var auth = ctx.Request.Headers["Authorization"].FirstOrDefault();
        if (!string.IsNullOrEmpty(auth) && auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            var token = auth.Substring(7).Trim();
            if (token.Length > 0) return token;
        }
        if (ctx.Request.Cookies.TryGetValue("tf_session", out var cookie) && !string.IsNullOrEmpty(cookie))
        {
            return cookie;
        }
        return null;
    }
}

/// <summary>Routing extensions.</summary>
public static class TrustforgeRouteHandlerExtensions
{
    /// <summary>
    /// Apply a TrustForge endpoint filter to an endpoint.
    /// </summary>
    /// <param name="builder">The route handler builder.</param>
    /// <param name="action">The action name sent to tf-daemon (e.g. <c>"orders.read"</c>).</param>
    public static RouteHandlerBuilder RequireTrustforge(this RouteHandlerBuilder builder, string action)
    {
        return builder.AddEndpointFilter(new TrustforgeEndpointFilter(action));
    }

    /// <summary>Apply a TrustForge endpoint filter to a group of endpoints.</summary>
    public static RouteGroupBuilder RequireTrustforge(this RouteGroupBuilder builder, string action)
    {
        builder.AddEndpointFilter(new TrustforgeEndpointFilter(action));
        return builder;
    }
}
