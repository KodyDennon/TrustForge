// Tiny in-process HTTP listener that emulates tf-daemon's /v1/decide.

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace Trustforge.OWIN.Tests
{
    public sealed class MockDaemon : IDisposable
    {
        private readonly HttpListener _listener;
        private readonly CancellationTokenSource _cts = new CancellationTokenSource();
        private readonly Task _loop;
        private static readonly JsonSerializerOptions JsonOptions = new JsonSerializerOptions
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            PropertyNameCaseInsensitive = true,
        };

        public Func<JsonElement, object> Handler { get; set; } = _ => new
        {
            decision = "allow",
            reason = "ok",
            proof_id = "prf-test",
        };

        public List<JsonElement> Requests { get; } = new List<JsonElement>();
        public string Url { get; }

        public MockDaemon()
        {
            var port = GetFreePort();
            Url = "http://127.0.0.1:" + port;
            _listener = new HttpListener();
            _listener.Prefixes.Add("http://127.0.0.1:" + port + "/");
            _listener.Start();
            _loop = Task.Run(LoopAsync);
        }

        private async Task LoopAsync()
        {
            while (!_cts.IsCancellationRequested)
            {
                HttpListenerContext ctx;
                try { ctx = await _listener.GetContextAsync().ConfigureAwait(false); }
                catch { return; }
                try
                {
                    using (var sr = new StreamReader(ctx.Request.InputStream))
                    {
                        var body = await sr.ReadToEndAsync().ConfigureAwait(false);
                        JsonElement parsed;
                        try { parsed = JsonSerializer.Deserialize<JsonElement>(body); }
                        catch { parsed = default; }
                        lock (Requests) { Requests.Add(parsed); }
                        var resp = Handler(parsed);
                        var json = JsonSerializer.Serialize(resp, JsonOptions);
                        var bytes = Encoding.UTF8.GetBytes(json);
                        ctx.Response.StatusCode = 200;
                        ctx.Response.ContentType = "application/json";
                        ctx.Response.ContentLength64 = bytes.Length;
                        await ctx.Response.OutputStream.WriteAsync(bytes, 0, bytes.Length).ConfigureAwait(false);
                        ctx.Response.OutputStream.Close();
                    }
                }
                catch
                {
                    try { ctx.Response.StatusCode = 500; ctx.Response.Close(); } catch { }
                }
            }
        }

        private static int GetFreePort()
        {
            var l = new TcpListener(IPAddress.Loopback, 0);
            l.Start();
            var port = ((IPEndPoint)l.LocalEndpoint).Port;
            l.Stop();
            return port;
        }

        public void Dispose()
        {
            _cts.Cancel();
            try { _listener.Stop(); } catch { }
            try { _loop.Wait(TimeSpan.FromSeconds(2)); } catch { }
            _listener.Close();
        }
    }
}
