// TrustForge SignalR IHubFilter.
//
// Authorises every Hub method invocation against tf-daemon's /v1/decide.
// The action sent is "signalr.{HubName}.{MethodName}" by default.

using Microsoft.AspNetCore.SignalR;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Trustforge.Sdk;

namespace Trustforge.SignalR;

public sealed class TrustforgeSignalROptions
{
    public string DaemonUrl { get; set; } = DecideClient.DefaultDaemonUrl;
    public string? AdminToken { get; set; }
    public AdapterMode Mode { get; set; } = AdapterMode.Enforce;
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(5);
    public Func<HubInvocationContext, string> ActionFactory { get; set; } =
        ctx => $"signalr.{ctx.Hub.GetType().Name}.{ctx.HubMethodName}";
}

/// <summary>
/// Hub filter that calls tf-daemon for every method invocation. Add via:
/// <c>services.AddSignalR(o =&gt; o.AddFilter&lt;TrustforgeHubFilter&gt;());</c>
/// </summary>
public sealed class TrustforgeHubFilter : IHubFilter
{
    private readonly DecideClient _client;
    private readonly TrustforgeSignalROptions _options;
    private readonly ILogger<TrustforgeHubFilter>? _logger;

    public TrustforgeHubFilter(DecideClient client, TrustforgeSignalROptions options, ILogger<TrustforgeHubFilter>? logger = null)
    {
        _client = client;
        _options = options;
        _logger = logger;
    }

    public async ValueTask<object?> InvokeMethodAsync(
        HubInvocationContext invocationContext,
        Func<HubInvocationContext, ValueTask<object?>> next)
    {
        var action = _options.ActionFactory(invocationContext);
        var traceId = DecideClient.NewTraceId();

        var http = invocationContext.Context.GetHttpContext();
        string? hostToken = null;
        if (http != null)
        {
            var auth = http.Request.Headers["Authorization"].FirstOrDefault();
            if (!string.IsNullOrEmpty(auth) && auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                hostToken = auth.Substring(7).Trim();
                if (hostToken.Length == 0) hostToken = null;
            }
        }

        var req = new DecideRequest(
            Action: action,
            TraceId: traceId,
            HostToken: hostToken,
            Target: invocationContext.HubMethodName,
            Context: new Dictionary<string, object?>
            {
                ["connection_id"] = invocationContext.Context.ConnectionId,
                ["hub"] = invocationContext.Hub.GetType().FullName ?? string.Empty,
                ["method"] = invocationContext.HubMethodName,
                ["arg_count"] = invocationContext.HubMethodArguments.Count,
            });

        DecideResponse resp;
        try
        {
            resp = await _client.DecideAsync(req, invocationContext.Context.ConnectionAborted).ConfigureAwait(false);
        }
        catch (TrustforgeException ex)
        {
            if (_options.Mode == AdapterMode.ObserveOnly)
            {
                _logger?.LogWarning(ex, "trustforge: daemon unavailable in observe-only mode (signalr)");
                return await next(invocationContext).ConfigureAwait(false);
            }
            throw new HubException($"trustforge daemon error: {ex.Message}");
        }

        if (_options.Mode == AdapterMode.ObserveOnly)
        {
            return await next(invocationContext).ConfigureAwait(false);
        }
        if (resp.IsDeny)
        {
            throw new HubException(string.IsNullOrEmpty(resp.Reason) ? "denied" : resp.Reason);
        }
        if (resp.IsApprovalRequired)
        {
            var detail = string.IsNullOrEmpty(resp.Reason) ? "approval required" : resp.Reason;
            throw new HubException($"approval-required: {detail} (id={resp.ApprovalId ?? string.Empty})");
        }
        return await next(invocationContext).ConfigureAwait(false);
    }

    public Task OnConnectedAsync(HubLifetimeContext context, Func<HubLifetimeContext, Task> next)
        => next(context);

    public Task OnDisconnectedAsync(HubLifetimeContext context, Exception? exception, Func<HubLifetimeContext, Exception?, Task> next)
        => next(context, exception);
}

public static class TrustforgeSignalRExtensions
{
    public static IServiceCollection AddTrustforgeSignalR(this IServiceCollection services,
        Action<TrustforgeSignalROptions>? configure = null)
    {
        var opts = new TrustforgeSignalROptions();
        configure?.Invoke(opts);
        services.TryAddSingleton(opts);
        services.TryAddSingleton(_ => new DecideClient(opts.DaemonUrl, opts.AdminToken, opts.Timeout));
        services.TryAddSingleton<TrustforgeHubFilter>();
        return services;
    }
}
