// TrustForge Orleans grain interceptor.
//
// Implements IIncomingGrainCallFilter so every grain method invocation is
// authorised against tf-daemon's /v1/decide. The default action is
// "orleans.{InterfaceName}.{MethodName}".

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Orleans;
using Trustforge.Sdk;

namespace Trustforge.Orleans;

public sealed class TrustforgeOrleansOptions
{
    public string DaemonUrl { get; set; } = DecideClient.DefaultDaemonUrl;
    public string? AdminToken { get; set; }
    public AdapterMode Mode { get; set; } = AdapterMode.Enforce;
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(5);
    public Func<IIncomingGrainCallContext, string> ActionFactory { get; set; } =
        ctx =>
        {
            var iface = ctx.InterfaceMethod?.DeclaringType?.Name ?? "Unknown";
            var method = ctx.InterfaceMethod?.Name ?? "Unknown";
            return $"orleans.{iface}.{method}";
        };
}

/// <summary>
/// Thrown when a grain call is denied by tf-daemon.
/// </summary>
[GenerateSerializer]
public sealed class TrustforgeDeniedException : Exception
{
    [Id(0)] public string Reason { get; init; } = string.Empty;
    [Id(1)] public string Decision { get; init; } = "deny";
    [Id(2)] public string? ApprovalId { get; init; }

    public TrustforgeDeniedException() { }
    public TrustforgeDeniedException(string message) : base(message) { Reason = message; }
}

/// <summary>Incoming grain call filter that delegates to tf-daemon.</summary>
public sealed class TrustforgeGrainInterceptor : IIncomingGrainCallFilter
{
    private readonly DecideClient _client;
    private readonly TrustforgeOrleansOptions _options;
    private readonly ILogger<TrustforgeGrainInterceptor>? _logger;

    public TrustforgeGrainInterceptor(
        DecideClient client,
        TrustforgeOrleansOptions options,
        ILogger<TrustforgeGrainInterceptor>? logger = null)
    {
        _client = client;
        _options = options;
        _logger = logger;
    }

    public async Task Invoke(IIncomingGrainCallContext context)
    {
        var action = _options.ActionFactory(context);
        var traceId = DecideClient.NewTraceId();

        string target = string.Empty;
        try
        {
            target = context.Grain?.GetType().FullName ?? string.Empty;
        }
        catch
        {
            // Grain identity may not always be reachable in test contexts.
        }

        var req = new DecideRequest(
            Action: action,
            TraceId: traceId,
            Target: target,
            Context: new Dictionary<string, object?>
            {
                ["interface"] = context.InterfaceMethod?.DeclaringType?.FullName ?? string.Empty,
                ["method"] = context.InterfaceMethod?.Name ?? string.Empty,
            });

        DecideResponse resp;
        try
        {
            resp = await _client.DecideAsync(req).ConfigureAwait(false);
        }
        catch (TrustforgeException ex)
        {
            if (_options.Mode == AdapterMode.ObserveOnly)
            {
                _logger?.LogWarning(ex, "trustforge: daemon unavailable in observe-only mode (orleans)");
                await context.Invoke().ConfigureAwait(false);
                return;
            }
            throw new TrustforgeDeniedException($"trustforge daemon error: {ex.Message}")
            {
                Decision = "deny",
                Reason = ex.Message,
            };
        }

        if (_options.Mode == AdapterMode.ObserveOnly)
        {
            await context.Invoke().ConfigureAwait(false);
            return;
        }
        if (resp.IsDeny)
        {
            throw new TrustforgeDeniedException(string.IsNullOrEmpty(resp.Reason) ? "denied" : resp.Reason)
            {
                Decision = resp.Decision,
                Reason = resp.Reason,
            };
        }
        if (resp.IsApprovalRequired)
        {
            throw new TrustforgeDeniedException(string.IsNullOrEmpty(resp.Reason) ? "approval required" : resp.Reason)
            {
                Decision = resp.Decision,
                Reason = resp.Reason,
                ApprovalId = resp.ApprovalId,
            };
        }
        await context.Invoke().ConfigureAwait(false);
    }
}

public static class TrustforgeOrleansExtensions
{
    public static IServiceCollection AddTrustforgeOrleans(this IServiceCollection services,
        Action<TrustforgeOrleansOptions>? configure = null)
    {
        var opts = new TrustforgeOrleansOptions();
        configure?.Invoke(opts);
        services.TryAddSingleton(opts);
        services.TryAddSingleton(_ => new DecideClient(opts.DaemonUrl, opts.AdminToken, opts.Timeout));
        services.AddSingleton<IIncomingGrainCallFilter, TrustforgeGrainInterceptor>();
        return services;
    }
}
