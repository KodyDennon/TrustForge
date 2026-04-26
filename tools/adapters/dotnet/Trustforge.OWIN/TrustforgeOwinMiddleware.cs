// TrustForge OWIN middleware.
//
// Targets net48 + Microsoft.Owin. Re-implements the small subset of the
// shared SDK needed for OWIN — net48 cannot depend on the .NET 8 SDK
// project. The wire format is identical.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Owin;

namespace Trustforge.OWIN
{
    public enum AdapterMode
    {
        Enforce,
        ObserveOnly,
    }

    public sealed class DecideRequestDto
    {
        [JsonPropertyName("action")] public string action { get; set; } = string.Empty;
        [JsonPropertyName("trace_id")] public string trace_id { get; set; } = string.Empty;
        [JsonPropertyName("actor")] public string? actor { get; set; }
        [JsonPropertyName("host_token")] public string? host_token { get; set; }
        [JsonPropertyName("host_token_kind")] public string? host_token_kind { get; set; }
        [JsonPropertyName("target")] public string? target { get; set; }
        [JsonPropertyName("context")] public Dictionary<string, object?>? context { get; set; }
    }

    public sealed class DecideResponseDto
    {
        [JsonPropertyName("decision")] public string decision { get; set; } = "deny";
        [JsonPropertyName("reason")] public string reason { get; set; } = string.Empty;
        [JsonPropertyName("approval_id")] public string? approval_id { get; set; }
        [JsonPropertyName("proof_id")] public string proof_id { get; set; } = string.Empty;
        [JsonPropertyName("actor_resolved")] public string actor_resolved { get; set; } = string.Empty;
        [JsonPropertyName("trust_level")] public string trust_level { get; set; } = string.Empty;
        [JsonPropertyName("authority_mode")] public string authority_mode { get; set; } = "layered";
        [JsonPropertyName("danger_tags")] public List<string> danger_tags { get; set; } = new List<string>();

        public bool IsAllow => decision == "allow";
        public bool IsDeny => decision == "deny";
        public bool IsApprovalRequired => decision == "approval-required" || decision == "escalate";
    }

    public sealed class TrustforgeOwinOptions
    {
        public string DaemonUrl { get; set; } = "http://127.0.0.1:8787";
        public string? AdminToken { get; set; }
        public AdapterMode Mode { get; set; } = AdapterMode.Enforce;
        public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(5);
        public Func<IOwinContext, string> ActionFactory { get; set; } =
            ctx => "http." + ctx.Request.Method + " " + ctx.Request.Path;
    }

    /// <summary>OWIN middleware that delegates each request to tf-daemon.</summary>
    public sealed class TrustforgeOwinMiddleware : OwinMiddleware
    {
        public const string DecisionEnvironmentKey = "tf:decision";

        private static readonly JsonSerializerOptions JsonOptions = new JsonSerializerOptions
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            PropertyNameCaseInsensitive = true,
        };

        private readonly TrustforgeOwinOptions _options;
        private readonly HttpClient _http;
        private readonly bool _ownsHttp;

        public TrustforgeOwinMiddleware(OwinMiddleware next, TrustforgeOwinOptions options, HttpClient? http = null)
            : base(next)
        {
            _options = options ?? throw new ArgumentNullException(nameof(options));
            if (http == null)
            {
                _http = new HttpClient { Timeout = _options.Timeout };
                _ownsHttp = true;
            }
            else
            {
                _http = http;
                _ownsHttp = false;
            }
            _http.DefaultRequestHeaders.Accept.Clear();
            _http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            if (!string.IsNullOrEmpty(_options.AdminToken))
            {
                _http.DefaultRequestHeaders.Authorization =
                    new AuthenticationHeaderValue("Bearer", _options.AdminToken);
            }
        }

        public override async Task Invoke(IOwinContext context)
        {
            var traceId = context.Request.Headers.Get("x-tf-trace-id") ?? NewTraceId();
            var hostToken = ExtractBearer(context);
            var action = _options.ActionFactory(context);

            var req = new DecideRequestDto
            {
                action = action,
                trace_id = traceId,
                host_token = hostToken,
                target = context.Request.Path.Value,
                context = new Dictionary<string, object?>
                {
                    ["method"] = context.Request.Method,
                    ["client"] = context.Request.RemoteIpAddress ?? string.Empty,
                },
            };

            DecideResponseDto? resp;
            try
            {
                resp = await DecideAsync(req, context.Request.CallCancelled).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                if (_options.Mode == AdapterMode.ObserveOnly)
                {
                    context.Environment[DecisionEnvironmentKey] = ObserveOnlyFallback(action, ex.Message);
                    await Next.Invoke(context).ConfigureAwait(false);
                    return;
                }
                context.Response.StatusCode = (int)HttpStatusCode.ServiceUnavailable;
                await context.Response.WriteAsync("trustforge daemon error: " + ex.Message).ConfigureAwait(false);
                return;
            }

            context.Environment[DecisionEnvironmentKey] = resp;

            if (_options.Mode == AdapterMode.ObserveOnly)
            {
                await Next.Invoke(context).ConfigureAwait(false);
                return;
            }

            if (resp.IsDeny)
            {
                context.Response.StatusCode = (int)HttpStatusCode.Forbidden;
                await context.Response.WriteAsync(string.IsNullOrEmpty(resp.reason) ? "denied" : resp.reason)
                    .ConfigureAwait(false);
                return;
            }
            if (resp.IsApprovalRequired)
            {
                context.Response.Headers.Set("x-tf-approval-id", resp.approval_id ?? string.Empty);
                context.Response.StatusCode = (int)HttpStatusCode.Unauthorized;
                await context.Response.WriteAsync(string.IsNullOrEmpty(resp.reason) ? "approval required" : resp.reason)
                    .ConfigureAwait(false);
                return;
            }
            await Next.Invoke(context).ConfigureAwait(false);
        }

        private async Task<DecideResponseDto> DecideAsync(DecideRequestDto req, CancellationToken ct)
        {
            var url = _options.DaemonUrl.TrimEnd('/') + "/v1/decide";
            var json = JsonSerializer.Serialize(req, JsonOptions);
            using (var content = new StringContent(json, Encoding.UTF8, "application/json"))
            using (var http = await _http.PostAsync(url, content, ct).ConfigureAwait(false))
            {
                var body = await http.Content.ReadAsStringAsync().ConfigureAwait(false);
                if ((int)http.StatusCode >= 400)
                {
                    throw new InvalidOperationException("tf-daemon /v1/decide returned " + (int)http.StatusCode + ": " + body);
                }
                var parsed = JsonSerializer.Deserialize<DecideResponseDto>(body, JsonOptions);
                if (parsed == null)
                {
                    throw new InvalidOperationException("tf-daemon /v1/decide returned null body");
                }
                return parsed;
            }
        }

        private static DecideResponseDto ObserveOnlyFallback(string action, string reason)
        {
            return new DecideResponseDto
            {
                decision = "log-only",
                reason = "observe-only: " + reason,
                danger_tags = new List<string> { action },
            };
        }

        private static string? ExtractBearer(IOwinContext ctx)
        {
            var auth = ctx.Request.Headers.Get("Authorization");
            if (!string.IsNullOrEmpty(auth) && auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                var token = auth.Substring(7).Trim();
                if (token.Length > 0) return token;
            }
            var cookie = ctx.Request.Cookies["tf_session"];
            return string.IsNullOrEmpty(cookie) ? null : cookie;
        }

        private static string NewTraceId() => "tf-" + Guid.NewGuid().ToString("N").Substring(0, 16);

        public void DisposeHttp()
        {
            if (_ownsHttp) _http.Dispose();
        }
    }

    public static class TrustforgeOwinExtensions
    {
        public static Owin.IAppBuilder UseTrustforge(this Owin.IAppBuilder app, TrustforgeOwinOptions? options = null)
        {
            return app.Use(typeof(TrustforgeOwinMiddleware), options ?? new TrustforgeOwinOptions());
        }
    }
}
