// Tests for Trustforge.SignalR TrustforgeHubFilter.
//
// We exercise the filter directly with a hand-built HubInvocationContext
// rather than spinning up a full SignalR connection, since IHubFilter is a
// pure delegate-style interface and unit-testable in isolation.

using System.Reflection;
using System.Security.Claims;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.SignalR;
using Trustforge.Sdk;
using Trustforge.SignalR;
using Xunit;

namespace Trustforge.SignalR.Tests;

public class FakeHub : Hub
{
    public Task DoWork(string arg) => Task.CompletedTask;
}

internal sealed class FakeHubCallerContext : HubCallerContext
{
    public override string ConnectionId => "conn-123";
    public override string? UserIdentifier => "user-1";
    public override ClaimsPrincipal? User => null;
    public override IDictionary<object, object?> Items { get; } = new Dictionary<object, object?>();
    public override IFeatureCollection Features { get; } = new FeatureCollection();
    public override CancellationToken ConnectionAborted => CancellationToken.None;
    public override void Abort() { }
}

public sealed class HubFilterTests : IAsyncLifetime
{
    private MockDaemon _daemon = null!;
    public Task InitializeAsync() { _daemon = new MockDaemon(); return Task.CompletedTask; }
    public Task DisposeAsync() { _daemon.Dispose(); return Task.CompletedTask; }

    private (TrustforgeHubFilter filter, HubInvocationContext ctx) Build(AdapterMode mode = AdapterMode.Enforce)
    {
        var client = new DecideClient(_daemon.Url);
        var opts = new TrustforgeSignalROptions { DaemonUrl = _daemon.Url, Mode = mode };
        var filter = new TrustforgeHubFilter(client, opts);
        var hub = new FakeHub();
        var method = typeof(FakeHub).GetMethod(nameof(FakeHub.DoWork), BindingFlags.Public | BindingFlags.Instance)!;
        var sp = new Microsoft.Extensions.DependencyInjection.ServiceCollection().BuildServiceProvider();
        var ctx = new HubInvocationContext(
            new FakeHubCallerContext(),
            sp,
            hub,
            method,
            new object?[] { "hello" });
        return (filter, ctx);
    }

    [Fact]
    public async Task Allow_InvokesNext()
    {
        _daemon.Handler = _ => new { decision = "allow", reason = "ok" };
        var (filter, ctx) = Build();
        var invoked = false;
        var result = await filter.InvokeMethodAsync(ctx, c => { invoked = true; return ValueTask.FromResult<object?>("done"); });
        Assert.True(invoked);
        Assert.Equal("done", result);
    }

    [Fact]
    public async Task Deny_ThrowsHubException()
    {
        _daemon.Handler = _ => new { decision = "deny", reason = "nope" };
        var (filter, ctx) = Build();
        var ex = await Assert.ThrowsAsync<HubException>(async () =>
            await filter.InvokeMethodAsync(ctx, _ => ValueTask.FromResult<object?>(null)));
        Assert.Contains("nope", ex.Message);
    }

    [Fact]
    public async Task ApprovalRequired_ThrowsHubException()
    {
        _daemon.Handler = _ => new { decision = "approval-required", reason = "review", approval_id = "ap-3" };
        var (filter, ctx) = Build();
        var ex = await Assert.ThrowsAsync<HubException>(async () =>
            await filter.InvokeMethodAsync(ctx, _ => ValueTask.FromResult<object?>(null)));
        Assert.Contains("approval-required", ex.Message);
        Assert.Contains("ap-3", ex.Message);
    }

    [Fact]
    public async Task ObserveOnly_DoesNotThrowOnDeny()
    {
        _daemon.Handler = _ => new { decision = "deny", reason = "nope" };
        var (filter, ctx) = Build(AdapterMode.ObserveOnly);
        var invoked = false;
        await filter.InvokeMethodAsync(ctx, c => { invoked = true; return ValueTask.FromResult<object?>("done"); });
        Assert.True(invoked);
    }

    [Fact]
    public async Task ActionNameContainsHubAndMethod()
    {
        _daemon.Handler = _ => new { decision = "allow", reason = "ok" };
        var (filter, ctx) = Build();
        await filter.InvokeMethodAsync(ctx, _ => ValueTask.FromResult<object?>(null));
        Assert.NotEmpty(_daemon.Requests);
        var action = _daemon.Requests[0].GetProperty("action").GetString();
        Assert.Equal("signalr.FakeHub.DoWork", action);
    }
}

