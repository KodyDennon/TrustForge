// Tests for Trustforge.OWIN middleware via Microsoft.Owin.Testing.TestServer.

using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.Owin.Testing;
using Owin;
using Trustforge.OWIN;
using Xunit;

namespace Trustforge.OWIN.Tests
{
    public sealed class OwinMiddlewareTests
    {
        private static TestServer Server(MockDaemon daemon, AdapterMode mode = AdapterMode.Enforce)
        {
            return TestServer.Create(app =>
            {
                app.Use(typeof(TrustforgeOwinMiddleware), new TrustforgeOwinOptions
                {
                    DaemonUrl = daemon.Url,
                    Mode = mode,
                });
                app.Run(async ctx =>
                {
                    ctx.Response.StatusCode = 200;
                    await ctx.Response.WriteAsync("ok");
                });
            });
        }

        [Fact]
        public async Task Allow_PassesThrough()
        {
            using (var d = new MockDaemon())
            {
                d.Handler = _ => new { decision = "allow", reason = "ok" };
                using (var s = Server(d))
                {
                    var r = await s.HttpClient.GetAsync("/foo");
                    Assert.Equal(HttpStatusCode.OK, r.StatusCode);
                    Assert.Equal("ok", await r.Content.ReadAsStringAsync());
                }
            }
        }

        [Fact]
        public async Task Deny_Returns403()
        {
            using (var d = new MockDaemon())
            {
                d.Handler = _ => new { decision = "deny", reason = "nope" };
                using (var s = Server(d))
                {
                    var r = await s.HttpClient.GetAsync("/foo");
                    Assert.Equal(HttpStatusCode.Forbidden, r.StatusCode);
                    Assert.Contains("nope", await r.Content.ReadAsStringAsync());
                }
            }
        }

        [Fact]
        public async Task ApprovalRequired_Returns401()
        {
            using (var d = new MockDaemon())
            {
                d.Handler = _ => new { decision = "approval-required", reason = "needs review", approval_id = "ap-7" };
                using (var s = Server(d))
                {
                    var r = await s.HttpClient.GetAsync("/foo");
                    Assert.Equal(HttpStatusCode.Unauthorized, r.StatusCode);
                    Assert.True(r.Headers.Contains("x-tf-approval-id"));
                }
            }
        }

        [Fact]
        public async Task ObserveOnly_DoesNotBlockOnDeny()
        {
            using (var d = new MockDaemon())
            {
                d.Handler = _ => new { decision = "deny", reason = "nope" };
                using (var s = Server(d, AdapterMode.ObserveOnly))
                {
                    var r = await s.HttpClient.GetAsync("/foo");
                    Assert.Equal(HttpStatusCode.OK, r.StatusCode);
                }
            }
        }
    }
}
