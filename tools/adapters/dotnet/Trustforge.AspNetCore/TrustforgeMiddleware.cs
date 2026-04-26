// TrustForge ASP.NET Core middleware + IAsyncActionFilter.
//
// The middleware authorises every request against tf-daemon's /v1/decide
// endpoint, attaches the parsed DecideResponse to HttpContext.Items under
// the key "tf:decision", and short-circuits with a 403 / 401 when the
// adapter is in Enforce mode.

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Trustforge.Sdk;

namespace Trustforge.AspNetCore;

/// <summary>HttpContext.Items key for the decision returned by tf-daemon.</summary>
public static class TrustforgeContextKeys
{
    public const string Decision = "tf:decision";
}

/// <summary>Adapter configuration.</summary>
public sealed class TrustforgeOptions
{
    public string DaemonUrl { get; set; } = DecideClient.DefaultDaemonUrl;
    public string? AdminToken { get; set; }
    public AdapterMode Mode { get; set; } = AdapterMode.Enforce;
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(5);

    /// <summary>
    /// Maps an HttpContext to the action string sent to tf-daemon. The default
    /// is <c>"http.{METHOD} {path}"</c> (e.g. <c>"http.GET /healthz"</c>).
    /// </summary>
    public Func<HttpContext, string> ActionFactory { get; set; } =
        ctx => $"http.{ctx.Request.Method} {ctx.Request.Path}";

    /// <summary>Optional path predicate; return false to skip enforcement.</summary>
    public Func<HttpContext, bool> ShouldEnforce { get; set; } = _ => true;
}

/// <summary>The middleware itself.</summary>
public sealed class TrustforgeMiddleware
{
    private readonly RequestDelegate _next;
    private readonly DecideClient _client;
    private readonly TrustforgeOptions _options;
    private readonly ILogger<TrustforgeMiddleware> _logger;

    public TrustforgeMiddleware(
        RequestDelegate next,
        DecideClient client,
        TrustforgeOptions options,
        ILogger<TrustforgeMiddleware> logger)
    {
        _next = next;
        _client = client;
        _options = options;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext ctx)
    {
        if (!_options.ShouldEnforce(ctx))
        {
            await _next(ctx).ConfigureAwait(false);
            return;
        }

        var traceId = ctx.Request.Headers["x-tf-trace-id"].FirstOrDefault()
                      ?? DecideClient.NewTraceId();
        var hostToken = ExtractBearer(ctx);
        var action = _options.ActionFactory(ctx);

        var req = new DecideRequest(
            Action: action,
            TraceId: traceId,
            HostToken: hostToken,
            Target: ctx.Request.Path.Value,
            Context: new Dictionary<string, object?>
            {
                ["method"] = ctx.Request.Method,
                ["client"] = ctx.Connection.RemoteIpAddress?.ToString() ?? string.Empty,
            });

        DecideResponse resp;
        try
        {
            resp = await _client.DecideAsync(req, ctx.RequestAborted).ConfigureAwait(false);
        }
        catch (TrustforgeException ex)
        {
            if (_options.Mode == AdapterMode.ObserveOnly)
            {
                _logger.LogWarning(ex, "trustforge: daemon unavailable in observe-only mode");
                ctx.Items[TrustforgeContextKeys.Decision] = ObserveOnlyFallback(action, ex.Message);
                await _next(ctx).ConfigureAwait(false);
                return;
            }
            ctx.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            await ctx.Response.WriteAsync($"trustforge daemon error: {ex.Message}").ConfigureAwait(false);
            return;
        }

        ctx.Items[TrustforgeContextKeys.Decision] = resp;

        if (_options.Mode == AdapterMode.ObserveOnly)
        {
            await _next(ctx).ConfigureAwait(false);
            return;
        }

        if (resp.IsDeny)
        {
            ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
            await ctx.Response.WriteAsync(string.IsNullOrEmpty(resp.Reason) ? "denied" : resp.Reason)
                .ConfigureAwait(false);
            return;
        }

        if (resp.IsApprovalRequired)
        {
            ctx.Response.Headers["x-tf-approval-id"] = resp.ApprovalId ?? string.Empty;
            ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await ctx.Response.WriteAsync(string.IsNullOrEmpty(resp.Reason) ? "approval required" : resp.Reason)
                .ConfigureAwait(false);
            return;
        }

        await _next(ctx).ConfigureAwait(false);
    }

    private static string? ExtractBearer(HttpContext ctx)
    {
        var auth = ctx.Request.Headers["Authorization"].FirstOrDefault();
        if (!string.IsNullOrEmpty(auth) && auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            var token = auth.Substring(7).Trim();
            if (token.Length > 0)
            {
                return token;
            }
        }
        if (ctx.Request.Cookies.TryGetValue("tf_session", out var cookie) && !string.IsNullOrEmpty(cookie))
        {
            return cookie;
        }
        return null;
    }

    public static DecideResponse ObserveOnlyFallback(string action, string reason)
    {
        return new DecideResponse(
            Decision: "log-only",
            Reason: $"observe-only: {reason}",
            DangerTags: new[] { action });
    }
}

/// <summary>
/// Per-action filter. Apply <c>[ServiceFilter(typeof(TrustforgeActionFilter))]</c>
/// on a controller / action to authorise that action specifically.
/// </summary>
public sealed class TrustforgeActionFilter : IAsyncActionFilter
{
    private readonly DecideClient _client;
    private readonly TrustforgeOptions _options;

    public TrustforgeActionFilter(DecideClient client, TrustforgeOptions options)
    {
        _client = client;
        _options = options;
    }

    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        var ctx = context.HttpContext;
        if (ctx.Items.TryGetValue(TrustforgeContextKeys.Decision, out var existing) && existing is DecideResponse)
        {
            await next().ConfigureAwait(false);
            return;
        }

        var traceId = ctx.Request.Headers["x-tf-trace-id"].FirstOrDefault() ?? DecideClient.NewTraceId();
        var action = _options.ActionFactory(ctx);
        var req = new DecideRequest(action, traceId,
            Target: ctx.Request.Path.Value,
            Context: new Dictionary<string, object?>
            {
                ["method"] = ctx.Request.Method,
            });

        DecideResponse resp;
        try
        {
            resp = await _client.DecideAsync(req, ctx.RequestAborted).ConfigureAwait(false);
        }
        catch (TrustforgeException ex)
        {
            if (_options.Mode == AdapterMode.ObserveOnly)
            {
                ctx.Items[TrustforgeContextKeys.Decision] =
                    TrustforgeMiddleware.ObserveOnlyFallback(action, ex.Message);
                await next().ConfigureAwait(false);
                return;
            }
            context.Result = new Microsoft.AspNetCore.Mvc.ObjectResult($"trustforge daemon error: {ex.Message}")
            {
                StatusCode = StatusCodes.Status503ServiceUnavailable,
            };
            return;
        }

        ctx.Items[TrustforgeContextKeys.Decision] = resp;
        if (_options.Mode == AdapterMode.ObserveOnly)
        {
            await next().ConfigureAwait(false);
            return;
        }
        if (resp.IsDeny)
        {
            context.Result = new Microsoft.AspNetCore.Mvc.ObjectResult(
                string.IsNullOrEmpty(resp.Reason) ? "denied" : resp.Reason)
            {
                StatusCode = StatusCodes.Status403Forbidden,
            };
            return;
        }
        if (resp.IsApprovalRequired)
        {
            ctx.Response.Headers["x-tf-approval-id"] = resp.ApprovalId ?? string.Empty;
            context.Result = new Microsoft.AspNetCore.Mvc.ObjectResult(
                string.IsNullOrEmpty(resp.Reason) ? "approval required" : resp.Reason)
            {
                StatusCode = StatusCodes.Status401Unauthorized,
            };
            return;
        }
        await next().ConfigureAwait(false);
    }
}

/// <summary>DI extensions: <c>AddTrustforge()</c> and <c>UseTrustforge()</c>.</summary>
public static class TrustforgeServiceExtensions
{
    public static IServiceCollection AddTrustforge(this IServiceCollection services,
        Action<TrustforgeOptions>? configure = null)
    {
        var opts = new TrustforgeOptions();
        configure?.Invoke(opts);
        services.TryAddSingleton(opts);
        services.TryAddSingleton(_ => new DecideClient(opts.DaemonUrl, opts.AdminToken, opts.Timeout));
        services.AddScoped<TrustforgeActionFilter>();
        return services;
    }

    public static IApplicationBuilder UseTrustforge(this IApplicationBuilder app)
    {
        return app.UseMiddleware<TrustforgeMiddleware>();
    }
}
