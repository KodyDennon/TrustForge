// Tests for Trustforge.Orleans TrustforgeGrainInterceptor.
//
// IIncomingGrainCallContext is an interface — we hand-build a minimal fake
// so we can drive Invoke(...) without spinning up an Orleans silo.

using System.Reflection;
using Orleans;
using Orleans.Runtime;
using Orleans.Serialization.Invocation;
using Trustforge.Orleans;
using Trustforge.Sdk;
using Xunit;

namespace Trustforge.Orleans.Tests;

public interface IFakeGrain : IGrainWithIntegerKey
{
    Task DoWorkAsync(string arg);
}

internal sealed class FakeGrainCallContext : IIncomingGrainCallContext
{
    public IGrainContext TargetContext { get; init; } = null!;
    public object? Grain { get; init; }
    public GrainId SourceId => default;
    public GrainId TargetId => default;
    public GrainInterfaceType InterfaceType => default;
    public string InterfaceName => InterfaceMethod?.DeclaringType?.Name ?? string.Empty;
    public string MethodName => InterfaceMethod?.Name ?? string.Empty;
    public MethodInfo? Method => InterfaceMethod;
    public MethodInfo? ImplementationMethod { get; init; }
    public MethodInfo? InterfaceMethod { get; init; }
    public object?[] Arguments { get; init; } = Array.Empty<object?>();
    public IInvokable Request { get; init; } = null!;
    public object? Result { get; set; }
    public Response Response { get; set; } = null!;

    public Func<Task>? OnInvoke { get; init; }
    public bool Invoked { get; private set; }
    public Task Invoke()
    {
        Invoked = true;
        return OnInvoke?.Invoke() ?? Task.CompletedTask;
    }
}

public sealed class GrainInterceptorTests : IAsyncLifetime
{
    private MockDaemon _daemon = null!;
    public Task InitializeAsync() { _daemon = new MockDaemon(); return Task.CompletedTask; }
    public Task DisposeAsync() { _daemon.Dispose(); return Task.CompletedTask; }

    private (TrustforgeGrainInterceptor interceptor, FakeGrainCallContext ctx) Build(AdapterMode mode = AdapterMode.Enforce)
    {
        var client = new DecideClient(_daemon.Url);
        var opts = new TrustforgeOrleansOptions { DaemonUrl = _daemon.Url, Mode = mode };
        var interceptor = new TrustforgeGrainInterceptor(client, opts);
        var method = typeof(IFakeGrain).GetMethod(nameof(IFakeGrain.DoWorkAsync))!;
        var ctx = new FakeGrainCallContext
        {
            InterfaceMethod = method,
            ImplementationMethod = method,
            Arguments = new object?[] { "hi" },
        };
        return (interceptor, ctx);
    }

    [Fact]
    public async Task Allow_InvokesGrain()
    {
        _daemon.Handler = _ => new { decision = "allow", reason = "ok" };
        var (i, ctx) = Build();
        await i.Invoke(ctx);
        Assert.True(ctx.Invoked);
    }

    [Fact]
    public async Task Deny_ThrowsTrustforgeDeniedException_AndDoesNotInvoke()
    {
        _daemon.Handler = _ => new { decision = "deny", reason = "nope" };
        var (i, ctx) = Build();
        var ex = await Assert.ThrowsAsync<TrustforgeDeniedException>(() => i.Invoke(ctx));
        Assert.Contains("nope", ex.Message);
        Assert.False(ctx.Invoked);
    }

    [Fact]
    public async Task ApprovalRequired_ThrowsTrustforgeDeniedException()
    {
        _daemon.Handler = _ => new { decision = "approval-required", reason = "review", approval_id = "ap-5" };
        var (i, ctx) = Build();
        var ex = await Assert.ThrowsAsync<TrustforgeDeniedException>(() => i.Invoke(ctx));
        Assert.Equal("ap-5", ex.ApprovalId);
        Assert.False(ctx.Invoked);
    }

    [Fact]
    public async Task ObserveOnly_DoesNotThrow_OnDeny()
    {
        _daemon.Handler = _ => new { decision = "deny", reason = "nope" };
        var (i, ctx) = Build(AdapterMode.ObserveOnly);
        await i.Invoke(ctx);
        Assert.True(ctx.Invoked);
    }

    [Fact]
    public async Task ActionFormatIsOrleansInterfaceMethod()
    {
        _daemon.Handler = _ => new { decision = "allow", reason = "ok" };
        var (i, ctx) = Build();
        await i.Invoke(ctx);
        Assert.NotEmpty(_daemon.Requests);
        Assert.Equal("orleans.IFakeGrain.DoWorkAsync", _daemon.Requests[0].GetProperty("action").GetString());
    }
}
