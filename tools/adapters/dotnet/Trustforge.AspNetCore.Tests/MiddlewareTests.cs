// Tests for Trustforge.AspNetCore middleware. Uses Microsoft.AspNetCore.TestHost
// directly (rather than WebApplicationFactory) so we don't need a Program.Main.

using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Trustforge.AspNetCore;
using Trustforge.Sdk;
using Xunit;

namespace Trustforge.AspNetCore.Tests;

public sealed class MiddlewareTests : IAsyncLifetime
{
    private MockDaemon _daemon = null!;

    public Task InitializeAsync() { _daemon = new MockDaemon(); return Task.CompletedTask; }
    public Task DisposeAsync() { _daemon.Dispose(); return Task.CompletedTask; }

    private async Task<IHost> StartHostAsync(AdapterMode mode = AdapterMode.Enforce)
    {
        var builder = Host.CreateDefaultBuilder()
            .ConfigureWebHost(web =>
            {
                web.UseTestServer();
                web.ConfigureServices(services =>
                {
                    services.AddTrustforge(o =>
                    {
                        o.DaemonUrl = _daemon.Url;
                        o.Mode = mode;
                    });
                });
                web.Configure(app =>
                {
                    app.UseTrustforge();
                    app.Run(async ctx =>
                    {
                        var d = ctx.Items[TrustforgeContextKeys.Decision] as DecideResponse;
                        await ctx.Response.WriteAsync($"ok decision={d?.Decision ?? "none"}");
                    });
                });
            });
        var host = await builder.StartAsync();
        return host;
    }

    [Fact]
    public async Task Allow_PassesThrough_AndAttachesDecision()
    {
        _daemon.Handler = _ => new { decision = "allow", reason = "ok", proof_id = "p1" };
        using var host = await StartHostAsync();
        var c = host.GetTestClient();
        var r = await c.GetAsync("/foo");
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        Assert.Contains("decision=allow", await r.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Deny_Returns403()
    {
        _daemon.Handler = _ => new { decision = "deny", reason = "nope" };
        using var host = await StartHostAsync();
        var c = host.GetTestClient();
        var r = await c.GetAsync("/foo");
        Assert.Equal(HttpStatusCode.Forbidden, r.StatusCode);
        Assert.Contains("nope", await r.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task ApprovalRequired_Returns401_WithApprovalHeader()
    {
        _daemon.Handler = _ => new { decision = "approval-required", reason = "needs review", approval_id = "ap-42" };
        using var host = await StartHostAsync();
        var c = host.GetTestClient();
        var r = await c.GetAsync("/foo");
        Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
        Assert.True(r.Headers.Contains("x-tf-approval-id"));
        Assert.Equal("ap-42", string.Join(",", r.Headers.GetValues("x-tf-approval-id")));
    }

    [Fact]
    public async Task ObserveOnly_PassesThrough_EvenOnDeny()
    {
        _daemon.Handler = _ => new { decision = "deny", reason = "nope" };
        using var host = await StartHostAsync(AdapterMode.ObserveOnly);
        var c = host.GetTestClient();
        var r = await c.GetAsync("/foo");
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        Assert.Contains("decision=deny", await r.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task RequestPayloadHasExpectedFields()
    {
        _daemon.Handler = _ => new { decision = "allow", reason = "ok" };
        using var host = await StartHostAsync();
        var c = host.GetTestClient();
        c.DefaultRequestHeaders.Add("Authorization", "Bearer secret-token");
        c.DefaultRequestHeaders.Add("x-tf-trace-id", "tf-trace-xyz");
        await c.GetAsync("/widgets");

        Assert.NotEmpty(_daemon.Requests);
        var req = _daemon.Requests[0];
        Assert.Equal("tf-trace-xyz", req.GetProperty("trace_id").GetString());
        Assert.Equal("secret-token", req.GetProperty("host_token").GetString());
        Assert.Equal("/widgets", req.GetProperty("target").GetString());
        Assert.Contains("http.GET", req.GetProperty("action").GetString());
    }
}
