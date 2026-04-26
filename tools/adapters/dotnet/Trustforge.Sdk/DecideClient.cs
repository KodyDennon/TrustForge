// TrustForge .NET SDK — shared HTTP client for tf-daemon /v1/decide.
//
// Wire format MUST stay byte-compatible with
// conformance/decide-protocol-vectors.yaml and the Python/TS SDKs.
// Field names are snake_case on the wire; .NET records use PascalCase
// with [JsonPropertyName] mappings.

using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Trustforge.Sdk;

/// <summary>
/// Thrown when tf-daemon returns a non-2xx response or a transport error
/// occurs while calling <c>/v1/decide</c>.
/// </summary>
public sealed class TrustforgeException : Exception
{
    public int Status { get; }
    public string? Body { get; }

    public TrustforgeException(string message, int status, string? body = null, Exception? inner = null)
        : base(message, inner)
    {
        Status = status;
        Body = body;
    }
}

/// <summary>
/// Wire-format request for <c>POST /v1/decide</c>. Matches the Python
/// <c>DecideRequest</c> exactly. Unset (null) optional fields are omitted
/// from the JSON payload.
/// </summary>
public sealed record DecideRequest(
    [property: JsonPropertyName("action")] string Action,
    [property: JsonPropertyName("trace_id")] string TraceId,
    [property: JsonPropertyName("actor")] string? Actor = null,
    [property: JsonPropertyName("host_token")] string? HostToken = null,
    [property: JsonPropertyName("host_token_kind")] string? HostTokenKind = null,
    [property: JsonPropertyName("target")] string? Target = null,
    [property: JsonPropertyName("context")] IReadOnlyDictionary<string, object?>? Context = null
);

/// <summary>
/// Wire-format response from <c>POST /v1/decide</c>. Matches the Python
/// <c>DecideResponse</c> exactly. Unknown fields are ignored.
/// </summary>
public sealed record DecideResponse(
    [property: JsonPropertyName("decision")] string Decision,
    [property: JsonPropertyName("reason")] string Reason = "",
    [property: JsonPropertyName("approval_id")] string? ApprovalId = null,
    [property: JsonPropertyName("proof_id")] string ProofId = "",
    [property: JsonPropertyName("actor_resolved")] string ActorResolved = "",
    [property: JsonPropertyName("trust_level")] string TrustLevel = "",
    [property: JsonPropertyName("authority_mode")] string AuthorityMode = "layered",
    [property: JsonPropertyName("danger_tags")] IReadOnlyList<string>? DangerTags = null
)
{
    public bool IsAllow => Decision == "allow";
    public bool IsDeny => Decision == "deny";
    public bool IsApprovalRequired => Decision is "approval-required" or "escalate";
    public bool IsLogOnly => Decision == "log-only";
}

/// <summary>
/// Adapter operating mode. <c>Enforce</c> blocks on deny/approval-required;
/// <c>ObserveOnly</c> never blocks but surfaces decisions for logging.
/// </summary>
public enum AdapterMode
{
    Enforce,
    ObserveOnly,
}

/// <summary>
/// Thin async client over <c>tf-daemon</c>'s <c>/v1/decide</c>. Exactly one
/// endpoint is supported; framework adapters only need this.
/// </summary>
public sealed class DecideClient : IDisposable
{
    public const string DefaultDaemonUrl = "http://127.0.0.1:8787";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNameCaseInsensitive = true,
    };

    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private readonly string _daemonUrl;

    public DecideClient(string? daemonUrl = null, string? adminToken = null, TimeSpan? timeout = null, HttpClient? httpClient = null)
    {
        _daemonUrl = (daemonUrl ?? DefaultDaemonUrl).TrimEnd('/');
        if (string.IsNullOrEmpty(_daemonUrl))
        {
            throw new ArgumentException("daemonUrl is required", nameof(daemonUrl));
        }

        if (httpClient is null)
        {
            _http = new HttpClient { Timeout = timeout ?? TimeSpan.FromSeconds(5) };
            _ownsHttp = true;
        }
        else
        {
            _http = httpClient;
            _ownsHttp = false;
        }

        _http.DefaultRequestHeaders.Accept.Clear();
        _http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        if (!string.IsNullOrEmpty(adminToken))
        {
            _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", adminToken);
        }
    }

    public string DaemonUrl => _daemonUrl;

    /// <summary>POST /v1/decide. Returns parsed <see cref="DecideResponse"/>.</summary>
    public async Task<DecideResponse> DecideAsync(DecideRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        var url = _daemonUrl + "/v1/decide";
        HttpResponseMessage resp;
        try
        {
            resp = await _http.PostAsJsonAsync(url, request, JsonOptions, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            throw new TrustforgeException($"tf-daemon /v1/decide network error: {ex.Message}", 0, null, ex);
        }
        catch (TaskCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TrustforgeException($"tf-daemon /v1/decide timed out: {ex.Message}", 0, null, ex);
        }

        var status = (int)resp.StatusCode;
        string body;
        try
        {
            body = await resp.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            throw new TrustforgeException($"tf-daemon /v1/decide read error: {ex.Message}", status, null, ex);
        }

        if (status >= 400)
        {
            throw new TrustforgeException($"tf-daemon /v1/decide returned {status}", status, body);
        }

        DecideResponse? parsed;
        try
        {
            parsed = JsonSerializer.Deserialize<DecideResponse>(body, JsonOptions);
        }
        catch (JsonException ex)
        {
            throw new TrustforgeException($"tf-daemon /v1/decide returned invalid JSON: {ex.Message}", status, body, ex);
        }

        if (parsed is null)
        {
            throw new TrustforgeException("tf-daemon /v1/decide returned null body", status, body);
        }
        return parsed;
    }

    public void Dispose()
    {
        if (_ownsHttp)
        {
            _http.Dispose();
        }
    }

    /// <summary>Generate a trace id of the form <c>tf-XXXXXXXXXXXXXXXX</c>.</summary>
    public static string NewTraceId()
    {
        return "tf-" + Guid.NewGuid().ToString("N").Substring(0, 16);
    }
}
