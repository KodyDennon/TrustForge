// Tests for Trustforge.MinimalApi RequireTrustforge() endpoint filter.
// Uses Microsoft.AspNetCore.TestHost so no Program.Main is required.

using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Trustforge.AspNetCore;
using Trustforge.MinimalApi;
using Trustforge.Sdk;
using Xunit;

namespace Trustforge.MinimalApi.Tests;

public sealed class EndpointFilterTests : IAsyncLifetime
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
                    services.AddRouting();
                    services.AddTrustforge(o =>
                    {
                        o.DaemonUrl = _daemon.Url;
                        o.Mode = mode;
                    });
                });
                web.Configure(app =>
                {
                    app.UseRouting();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapGet("/orders/{id}", (string id) => Results.Ok($"order-{id}"))
                                 .RequireTrustforge("orders.read");
                        endpoints.MapGet("/public", () => Results.Ok("public"));
                    });
                });
            });
        return await builder.StartAsync();
    }

    [Fact]
    public async Task Allow_PassesThrough()
    {
        _daemon.Handler = _ => new { decision = "allow", reason = "ok" };
        using var host = await StartHostAsync();
        var r = await host.GetTestClient().GetAsync("/orders/42");
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        Assert.Contains("order-42", await r.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Deny_Returns403()
    {
        _daemon.Handler = _ => new { decision = "deny", reason = "no access" };
        using var host = await StartHostAsync();
        var r = await host.GetTestClient().GetAsync("/orders/42");
        Assert.Equal(HttpStatusCode.Forbidden, r.StatusCode);
    }

    [Fact]
    public async Task ApprovalRequired_Returns401_WithApprovalHeader()
    {
        _daemon.Handler = _ => new { decision = "approval-required", reason = "review", approval_id = "ap-9" };
        using var host = await StartHostAsync();
        var r = await host.GetTestClient().GetAsync("/orders/42");
        Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
        Assert.True(r.Headers.Contains("x-tf-approval-id"));
        Assert.Equal("ap-9", string.Join(",", r.Headers.GetValues("x-tf-approval-id")));
    }

    [Fact]
    public async Task FilterIsScopedToEndpoint()
    {
        _daemon.Handler = _ => new { decision = "deny", reason = "no" };
        using var host = await StartHostAsync();
        var r = await host.GetTestClient().GetAsync("/public");
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
        Assert.Empty(_daemon.Requests);
    }

    [Fact]
    public async Task ObserveOnly_PassesThroughOnDeny()
    {
        _daemon.Handler = _ => new { decision = "deny", reason = "no" };
        using var host = await StartHostAsync(AdapterMode.ObserveOnly);
        var r = await host.GetTestClient().GetAsync("/orders/42");
        Assert.Equal(HttpStatusCode.OK, r.StatusCode);
    }

    [Fact]
    public async Task ActionNameSentToDaemon()
    {
        _daemon.Handler = _ => new { decision = "allow", reason = "ok" };
        using var host = await StartHostAsync();
        await host.GetTestClient().GetAsync("/orders/42");
        Assert.NotEmpty(_daemon.Requests);
        Assert.Equal("orders.read", _daemon.Requests[0].GetProperty("action").GetString());
    }
}
